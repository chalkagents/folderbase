//! Capability-confined publication for mutable and append-only `.folderbase` state.
//!
//! Display paths are retained only for diagnostics. Every filesystem operation
//! is relative to a retained, no-follow directory capability.

use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(not(windows))]
use cap_fs_ext::DirExt;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use same_file::Handle;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{FolderbaseError, Result, root_attestation::metadata_is_link_or_reparse};

const STATE_COMPONENT: &str = ".folderbase";
const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) struct PublishedBlob {
    pub(crate) digest: String,
    pub(crate) bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateAccess {
    ReadOnly,
    Mutable,
}

pub(crate) struct FolderbaseState {
    root: Dir,
    root_identity: Handle,
    state: Dir,
    state_identity: Handle,
    display_root: PathBuf,
    access: StateAccess,
}

impl FolderbaseState {
    pub(crate) fn open(root: &Path) -> Result<Self> {
        let access = StateAccess::Mutable;
        let root_cap = open_root_nofollow(root, access)?;
        let state = match open_directory_nofollow(
            &root_cap,
            OsStr::new(STATE_COMPONENT),
            &root.join(STATE_COMPONENT),
            access,
        ) {
            Ok(state) => state,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let builder = private_directory_builder();
                match root_cap.create_dir_with(STATE_COMPONENT, &builder) {
                    Ok(()) => sync_directory(&root_cap, root)?,
                    Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(FolderbaseError::io(root.join(STATE_COMPONENT), source));
                    }
                }
                open_directory_nofollow(
                    &root_cap,
                    OsStr::new(STATE_COMPONENT),
                    &root.join(STATE_COMPONENT),
                    access,
                )
                .map_err(|source| FolderbaseError::io(root.join(STATE_COMPONENT), source))?
            }
            Err(source) => {
                return Err(FolderbaseError::io(root.join(STATE_COMPONENT), source));
            }
        };
        let root_identity = directory_identity(&root_cap, root)?;
        let state_identity = directory_identity(&state, &root.join(STATE_COMPONENT))?;
        Ok(Self {
            root: root_cap,
            root_identity,
            state,
            state_identity,
            display_root: root.to_path_buf(),
            access,
        })
    }

    pub(crate) fn open_existing(root: &Path) -> Result<Self> {
        Self::open_existing_with_access(root, StateAccess::Mutable)
    }

    pub(crate) fn open_existing_read_only(root: &Path) -> Result<Self> {
        Self::open_existing_with_access(root, StateAccess::ReadOnly)
    }

    fn open_existing_with_access(root: &Path, access: StateAccess) -> Result<Self> {
        let root_cap = open_root_nofollow(root, access)?;
        let state = open_directory_nofollow(
            &root_cap,
            OsStr::new(STATE_COMPONENT),
            &root.join(STATE_COMPONENT),
            access,
        )
        .map_err(|source| FolderbaseError::io(root.join(STATE_COMPONENT), source))?;
        let root_identity = directory_identity(&root_cap, root)?;
        let state_identity = directory_identity(&state, &root.join(STATE_COMPONENT))?;
        Ok(Self {
            root: root_cap,
            root_identity,
            state,
            state_identity,
            display_root: root.to_path_buf(),
            access,
        })
    }

    pub(crate) fn ensure_private_dir(&self, relative: &Path) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let mut directory = self.state.try_clone().map_err(|source| {
            FolderbaseError::io(self.display_root.join(STATE_COMPONENT), source)
        })?;
        let mut display = self.display_root.join(STATE_COMPONENT);
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
            };
            display.push(name);
            directory = match open_directory_nofollow(&directory, name, &display, self.access) {
                Ok(child) => child,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    let builder = private_directory_builder();
                    match directory.create_dir_with(name, &builder) {
                        Ok(()) => sync_directory(&directory, &display)?,
                        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(source) => return Err(FolderbaseError::io(&display, source)),
                    }
                    open_directory_nofollow(&directory, name, &display, self.access)
                        .map_err(|source| FolderbaseError::io(&display, source))?
                }
                Err(source) => return Err(FolderbaseError::io(&display, source)),
            };
        }
        Ok(())
    }

    pub(crate) fn read_bounded(
        &self,
        relative: &Path,
        maximum_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        let relative = state_relative(relative)?;
        let (parent, name) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        let mut options = CapOpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = match parent.open_with(&name, &options) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(FolderbaseError::io(display, source)),
        };
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > maximum_bytes
        {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "state record is unsafe or exceeds its bounded size".to_owned(),
            });
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "state record exceeds its bounded size".to_owned(),
            });
        }
        Ok(Some(bytes))
    }

    pub(crate) fn publish_new(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        self.publish_new_with_hook(relative, bytes, || {})
    }

    pub(crate) fn open_lock_file(&self, relative: &Path) -> Result<File> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        let mut options = CapOpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std();
        if !file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?
            .is_file()
        {
            return Err(FolderbaseError::UnsafePath(display));
        }
        Ok(file)
    }

    pub(crate) fn publish_reader_sha256(
        &self,
        directory: &Path,
        mut reader: impl Read,
        source_label: &Path,
        maximum_bytes: u64,
    ) -> Result<PublishedBlob> {
        let relative = state_relative(directory)?;
        self.require_mutable(&relative)?;
        let parent = self.open_dir(&relative)?;
        let display = self.display_path(&relative);
        let temporary = OsString::from(format!(".blob-{}.tmp", Uuid::now_v7()));
        let mut options = CapOpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut staged = parent
            .open_with(&temporary, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let mut hasher = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        let copy_result = (|| -> Result<()> {
            let mut bounded = reader.by_ref().take(maximum_bytes.saturating_add(1));
            loop {
                let read = bounded
                    .read(&mut buffer)
                    .map_err(|source| FolderbaseError::io(source_label, source))?;
                if read == 0 {
                    break;
                }
                bytes = bytes.checked_add(read as u64).ok_or_else(|| {
                    FolderbaseError::InvalidRecord {
                        path: source_label.to_path_buf(),
                        message: "content length exceeds supported range".to_owned(),
                    }
                })?;
                if bytes > maximum_bytes {
                    return Err(FolderbaseError::InvalidRecord {
                        path: source_label.to_path_buf(),
                        message: "source grew beyond its approved byte length".to_owned(),
                    });
                }
                staged
                    .write_all(&buffer[..read])
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                hasher.update(&buffer[..read]);
            }
            staged
                .sync_all()
                .map_err(|source| FolderbaseError::io(&display, source))
        })();
        drop(staged);
        if let Err(error) = copy_result {
            let _ = parent.remove_file(&temporary);
            return Err(error);
        }

        let digest = format!("{:x}", hasher.finalize());
        match parent.hard_link(&temporary, &parent, &digest) {
            Ok(()) => {
                parent
                    .remove_file(&temporary)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                sync_directory(&parent, &display)?;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                parent
                    .remove_file(&temporary)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
            }
            Err(source) => {
                let _ = parent.remove_file(&temporary);
                return Err(FolderbaseError::io(display, source));
            }
        }
        verify_blob(
            &parent,
            OsStr::new(&digest),
            bytes,
            &self.display_path(&relative.join(&digest)),
        )?;
        Ok(PublishedBlob { digest, bytes })
    }

    pub(crate) fn verify_sha256_blob(
        &self,
        directory: &Path,
        digest: &str,
        bytes: u64,
    ) -> Result<()> {
        let relative = state_relative(directory)?;
        let parent = self.open_dir(&relative)?;
        verify_blob(
            &parent,
            OsStr::new(digest),
            bytes,
            &self.display_path(&relative.join(digest)),
        )
    }

    /// Copy one verified immutable content blob into a private restore stage.
    ///
    /// The copy intentionally receives its own inode so applying executable
    /// fidelity cannot mutate the content-addressed source blob.
    pub(crate) fn stage_restore_blob(
        &self,
        source: &Path,
        stage: &Path,
        digest: &str,
        bytes: u64,
        executable: bool,
    ) -> Result<()> {
        let source = state_relative(source)?;
        let stage = state_relative(stage)?;
        self.require_mutable(&stage)?;
        let (source_parent, source_name) = self.open_parent(&source)?;
        let source_display = self.display_path(&source);
        let mut read_options = CapOpenOptions::new();
        read_options.read(true).follow(FollowSymlinks::No);
        let mut source_file = source_parent
            .open_with(&source_name, &read_options)
            .map_err(|source| FolderbaseError::io(&source_display, source))?;
        verify_open_regular_metadata(&source_file, bytes, &source_display)?;

        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        let mut write_options = CapOpenOptions::new();
        write_options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            write_options.mode(if executable { 0o700 } else { 0o600 });
        }
        match stage_parent.open_with(&stage_name, &write_options) {
            Ok(mut staged) => {
                let copy_result = copy_exact_sha256(
                    &mut source_file,
                    &mut staged,
                    bytes,
                    digest,
                    &source_display,
                    &stage_display,
                )
                .and_then(|()| {
                    staged
                        .sync_all()
                        .map_err(|source| FolderbaseError::io(&stage_display, source))
                });
                drop(staged);
                if let Err(error) = copy_result {
                    let _ = stage_parent.remove_file(&stage_name);
                    return Err(error);
                }
                sync_directory(&stage_parent, &stage_display)?;
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(FolderbaseError::io(stage_display, source)),
        }
        verify_regular_file(
            &stage_parent,
            &stage_name,
            digest,
            bytes,
            executable,
            &stage_display,
        )
    }

    /// Hard-link a retained private stage into an absent workspace path.
    ///
    /// An existing destination is accepted only when it is the exact same
    /// filesystem object as the retained stage. This permits durable retry
    /// without treating same-byte foreign content as transaction-owned.
    pub(crate) fn publish_workspace_restore(
        &self,
        stage: &Path,
        destination: &Path,
        digest: &str,
        bytes: u64,
        executable: bool,
    ) -> Result<bool> {
        let stage = state_relative(stage)?;
        let destination = safe_workspace_relative(destination)?;
        self.require_mutable(&stage)?;
        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        verify_regular_file(
            &stage_parent,
            &stage_name,
            digest,
            bytes,
            executable,
            &stage_display,
        )?;
        let (destination_parent, destination_name) = self.open_workspace_parent(&destination)?;
        let destination_display = self.display_root.join(&destination);
        match stage_parent.hard_link(&stage_name, &destination_parent, &destination_name) {
            Ok(()) => {
                sync_directory(&destination_parent, &destination_display)?;
                verify_regular_file(
                    &destination_parent,
                    &destination_name,
                    digest,
                    bytes,
                    executable,
                    &destination_display,
                )?;
                Ok(true)
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let stage_identity =
                    regular_file_identity(&stage_parent, &stage_name, &stage_display)?;
                let destination_identity = regular_file_identity(
                    &destination_parent,
                    &destination_name,
                    &destination_display,
                )
                .map_err(|_| FolderbaseError::WouldOverwrite(destination_display.clone()))?;
                if stage_identity != destination_identity {
                    return Err(FolderbaseError::WouldOverwrite(destination_display));
                }
                verify_regular_file(
                    &destination_parent,
                    &destination_name,
                    digest,
                    bytes,
                    executable,
                    &self.display_root.join(&destination),
                )?;
                Ok(false)
            }
            Err(source) => Err(FolderbaseError::io(destination_display, source)),
        }
    }

    pub(crate) fn workspace_path_is_absent(&self, relative: &Path) -> Result<bool> {
        let relative = safe_workspace_relative(relative)?;
        let (parent, name) = self.open_workspace_parent(&relative)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => Ok(false),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(source) => Err(FolderbaseError::io(
                self.display_root.join(relative),
                source,
            )),
        }
    }

    /// Revalidate one published restore against its retained private stage.
    ///
    /// Success proves that the ambient Folderbase root is still the retained
    /// physical root, every destination ancestor remains inside this
    /// Folderbase boundary, and the destination still names the exact staged
    /// filesystem object with its sealed bytes and executable fidelity.
    pub(crate) fn verify_workspace_restore(
        &self,
        stage: &Path,
        destination: &Path,
        digest: &str,
        bytes: u64,
        executable: bool,
    ) -> Result<()> {
        let stage = state_relative(stage)?;
        let destination = safe_workspace_relative(destination)?;
        self.require_mutable(&stage)?;
        self.verify_still_attached()?;

        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        let mut stage_file =
            open_regular_file_nofollow(&stage_parent, &stage_name, &stage_display)?;
        let stage_identity = open_regular_file_identity(&stage_file, &stage_display)?;
        verify_open_regular_file(&mut stage_file, digest, bytes, executable, &stage_display)?;

        let destination_display = self.display_root.join(&destination);
        let (destination_parent, destination_name) = self.open_workspace_parent(&destination)?;
        let mut destination_file = open_regular_file_nofollow(
            &destination_parent,
            &destination_name,
            &destination_display,
        )
        .map_err(|_| FolderbaseError::WouldOverwrite(destination_display.clone()))?;
        let destination_identity =
            open_regular_file_identity(&destination_file, &destination_display)
                .map_err(|_| FolderbaseError::WouldOverwrite(destination_display.clone()))?;
        if destination_identity != stage_identity {
            return Err(FolderbaseError::WouldOverwrite(destination_display));
        }
        verify_open_regular_file(
            &mut destination_file,
            digest,
            bytes,
            executable,
            &destination_display,
        )?;

        // Reopen through the retained root after byte verification. This
        // closes over ordinary replacement races and repeats the boundary
        // walk immediately before the coordinator advances durable state.
        let (visible_parent, visible_name) = self.open_workspace_parent(&destination)?;
        let mut visible_file =
            open_regular_file_nofollow(&visible_parent, &visible_name, &destination_display)
                .map_err(|_| FolderbaseError::WouldOverwrite(destination_display.clone()))?;
        let visible_identity = open_regular_file_identity(&visible_file, &destination_display)
            .map_err(|_| FolderbaseError::WouldOverwrite(destination_display.clone()))?;
        if visible_identity != stage_identity {
            return Err(FolderbaseError::WouldOverwrite(destination_display));
        }
        verify_open_regular_file(
            &mut visible_file,
            digest,
            bytes,
            executable,
            &destination_display,
        )?;
        self.verify_still_attached()
    }

    #[cfg(test)]
    fn verify_sha256_blob_with_hook(
        &self,
        directory: &Path,
        digest: &str,
        bytes: u64,
        after_metadata: impl FnOnce(),
    ) -> Result<()> {
        let relative = state_relative(directory)?;
        let parent = self.open_dir(&relative)?;
        verify_blob_with_hook(
            &parent,
            OsStr::new(digest),
            bytes,
            &self.display_path(&relative.join(digest)),
            after_metadata,
        )
    }

    fn publish_new_with_hook(
        &self,
        relative: &Path,
        bytes: &[u8],
        after_parent_open: impl FnOnce(),
    ) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = self.open_parent(&relative)?;
        after_parent_open();
        let display = self.display_path(&relative);
        let temporary = OsString::from(format!(".publish-{}.tmp", Uuid::now_v7()));
        write_staged(&parent, &temporary, bytes, &display)?;
        match parent.hard_link(&temporary, &parent, &name) {
            Ok(()) => {
                parent
                    .remove_file(&temporary)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                sync_directory(&parent, &display)?;
                verify_exact_file(&parent, &name, bytes, &display)
            }
            Err(source) => {
                let _ = parent.remove_file(&temporary);
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    Err(FolderbaseError::WouldOverwrite(display))
                } else {
                    Err(FolderbaseError::io(display, source))
                }
            }
        }
    }

    pub(crate) fn replace(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        let temporary = OsString::from(format!(".replace-{}.tmp", Uuid::now_v7()));
        write_staged(&parent, &temporary, bytes, &display)?;
        if let Err(source) = parent.rename(&temporary, &parent, &name) {
            let _ = parent.remove_file(&temporary);
            return Err(FolderbaseError::io(display, source));
        }
        sync_directory(&parent, &display)?;
        verify_exact_file(&parent, &name, bytes, &display)
    }

    pub(crate) fn remove_durable(&self, relative: &Path) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        match parent.remove_file(&name) {
            Ok(()) => sync_directory(&parent, &display),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(FolderbaseError::io(display, source)),
        }
    }

    pub(crate) fn verify_still_attached(&self) -> Result<()> {
        let visible_root = open_root_nofollow(&self.display_root, self.access)?;
        let visible_root_identity = directory_identity(&visible_root, &self.display_root)?;
        if visible_root_identity != self.root_identity {
            return Err(FolderbaseError::UnsafePath(self.display_root.clone()));
        }
        let visible = open_directory_nofollow(
            &visible_root,
            OsStr::new(STATE_COMPONENT),
            &self.display_root.join(STATE_COMPONENT),
            self.access,
        )
        .map_err(|source| FolderbaseError::io(self.display_root.join(STATE_COMPONENT), source))?;
        let visible_identity =
            directory_identity(&visible, &self.display_root.join(STATE_COMPONENT))?;
        if visible_identity != self.state_identity {
            return Err(FolderbaseError::UnsafePath(
                self.display_root.join(STATE_COMPONENT),
            ));
        }
        Ok(())
    }

    fn open_parent(&self, relative: &Path) -> Result<(Dir, OsString)> {
        let name = relative
            .file_name()
            .ok_or_else(|| FolderbaseError::UnsafePath(relative.to_path_buf()))?
            .to_os_string();
        let mut directory = self.state.try_clone().map_err(|source| {
            FolderbaseError::io(self.display_root.join(STATE_COMPONENT), source)
        })?;
        let mut display = self.display_root.join(STATE_COMPONENT);
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                let Component::Normal(component) = component else {
                    return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
                };
                display.push(component);
                directory = open_directory_nofollow(&directory, component, &display, self.access)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
            }
        }
        Ok((directory, name))
    }

    fn open_dir(&self, relative: &Path) -> Result<Dir> {
        let mut directory = self.state.try_clone().map_err(|source| {
            FolderbaseError::io(self.display_root.join(STATE_COMPONENT), source)
        })?;
        let mut display = self.display_root.join(STATE_COMPONENT);
        for component in relative.components() {
            let Component::Normal(component) = component else {
                return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
            };
            display.push(component);
            directory = open_directory_nofollow(&directory, component, &display, self.access)
                .map_err(|source| FolderbaseError::io(&display, source))?;
        }
        Ok(directory)
    }

    fn open_workspace_parent(&self, relative: &Path) -> Result<(Dir, OsString)> {
        let name = relative
            .file_name()
            .ok_or_else(|| FolderbaseError::UnsafePath(relative.to_path_buf()))?
            .to_os_string();
        let mut directory = self
            .root
            .try_clone()
            .map_err(|source| FolderbaseError::io(&self.display_root, source))?;
        let mut display = self.display_root.clone();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                let Component::Normal(component) = component else {
                    return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
                };
                display.push(component);
                directory = open_directory_nofollow(&directory, component, &display, self.access)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                if contains_folderbase_marker(&directory, &display)? {
                    return Err(FolderbaseError::UnsafePath(display));
                }
            }
        }
        Ok((directory, name))
    }

    fn require_mutable(&self, relative: &Path) -> Result<()> {
        if self.access == StateAccess::Mutable {
            return Ok(());
        }
        Err(FolderbaseError::io(
            self.display_path(relative),
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only Folderbase state capability cannot mutate",
            ),
        ))
    }

    fn display_path(&self, relative: &Path) -> PathBuf {
        self.display_root.join(STATE_COMPONENT).join(relative)
    }
}

fn state_relative(path: &Path) -> Result<PathBuf> {
    let relative = path
        .strip_prefix(STATE_COMPONENT)
        .unwrap_or(path)
        .to_path_buf();
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(relative)
}

fn safe_workspace_relative(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() || path.to_str().is_none() {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    let mut safe = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
        };
        if name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(STATE_COMPONENT))
        {
            return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
        }
        safe.push(name);
    }
    Ok(safe)
}

fn contains_folderbase_marker(directory: &Dir, display: &Path) -> Result<bool> {
    let Some(state_name) = unique_matching_child(directory, display, is_folderbase_state_name)?
    else {
        return Ok(false);
    };
    let state_display = display.join(&state_name);
    let state = match open_directory_nofollow(
        directory,
        &state_name,
        &state_display,
        StateAccess::ReadOnly,
    ) {
        Ok(state) => state,
        Err(source) => return Err(FolderbaseError::io(state_display, source)),
    };
    let Some(marker) = unique_matching_child(&state, &state_display, is_folderbase_manifest_name)?
    else {
        return Ok(false);
    };
    let marker_display = state_display.join(&marker);
    let metadata = match state.symlink_metadata(marker) {
        Ok(metadata) => metadata,
        Err(source) => return Err(FolderbaseError::io(marker_display, source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FolderbaseError::UnsafePath(marker_display));
    }
    Ok(true)
}

fn unique_matching_child(
    directory: &Dir,
    display: &Path,
    matches: impl Fn(&OsStr) -> bool,
) -> Result<Option<OsString>> {
    let mut found = None;
    for entry in directory
        .entries()
        .map_err(|source| FolderbaseError::io(display, source))?
    {
        let entry = entry.map_err(|source| FolderbaseError::io(display, source))?;
        let name = entry.file_name();
        if matches(&name) {
            if found.is_some() {
                return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
            }
            found = Some(name);
        }
    }
    Ok(found)
}

fn is_folderbase_state_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case(STATE_COMPONENT))
}

fn is_folderbase_manifest_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case("manifest.json"))
}

fn verify_open_regular_metadata(
    file: &cap_std::fs::File,
    bytes: u64,
    display: &Path,
) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != bytes {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "restore source metadata does not match".to_owned(),
        });
    }
    Ok(())
}

fn copy_exact_sha256(
    reader: &mut impl Read,
    writer: &mut impl Write,
    bytes: u64,
    digest: &str,
    source_display: &Path,
    destination_display: &Path,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut bounded = reader.take(bytes.saturating_add(1));
    loop {
        let read = bounded
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(source_display, source))?;
        if read == 0 {
            break;
        }
        observed =
            observed
                .checked_add(read as u64)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: source_display.to_path_buf(),
                    message: "restore source length exceeds supported range".to_owned(),
                })?;
        if observed > bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: source_display.to_path_buf(),
                message: "restore source grew beyond its sealed byte length".to_owned(),
            });
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|source| FolderbaseError::io(destination_display, source))?;
        hasher.update(&buffer[..read]);
    }
    if observed != bytes || format!("{:x}", hasher.finalize()) != digest {
        return Err(FolderbaseError::InvalidRecord {
            path: source_display.to_path_buf(),
            message: "restore source bytes do not match the sealed digest".to_owned(),
        });
    }
    Ok(())
}

fn regular_file_identity(parent: &Dir, name: &OsStr, display: &Path) -> Result<Handle> {
    let file = open_regular_file_nofollow(parent, name, display)?;
    open_regular_file_identity(&file, display)
}

fn open_regular_file_nofollow(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> Result<cap_std::fs::File> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent
        .open_with(name, &options)
        .map_err(|source| FolderbaseError::io(display, source))?;
    let metadata = file
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std()
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    Ok(file)
}

fn open_regular_file_identity(file: &cap_std::fs::File, display: &Path) -> Result<Handle> {
    let file = file
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std();
    Handle::from_file(file).map_err(|source| FolderbaseError::io(display, source))
}

fn verify_regular_file(
    parent: &Dir,
    name: &OsStr,
    digest: &str,
    bytes: u64,
    executable: bool,
    display: &Path,
) -> Result<()> {
    let mut file = open_regular_file_nofollow(parent, name, display)?;
    verify_open_regular_file(&mut file, digest, bytes, executable, display)
}

fn verify_open_regular_file(
    file: &mut cap_std::fs::File,
    digest: &str,
    bytes: u64,
    executable: bool,
    display: &Path,
) -> Result<()> {
    #[cfg(not(unix))]
    let _ = executable;
    verify_open_regular_metadata(&file, bytes, display)?;
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        let observed = file
            .metadata()
            .map_err(|source| FolderbaseError::io(display, source))?
            .permissions()
            .mode()
            & 0o111
            != 0;
        if observed != executable {
            return Err(FolderbaseError::InvalidRecord {
                path: display.to_path_buf(),
                message: "restore executable fidelity does not match".to_owned(),
            });
        }
    }
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut bounded = Read::by_ref(file).take(bytes.saturating_add(1));
    loop {
        let read = bounded
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(display, source))?;
        if read == 0 {
            break;
        }
        observed += read as u64;
        if observed > bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: display.to_path_buf(),
                message: "restore file grew beyond its sealed byte length".to_owned(),
            });
        }
        hasher.update(&buffer[..read]);
    }
    if observed != bytes || format!("{:x}", hasher.finalize()) != digest {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "restore file bytes do not match the sealed digest".to_owned(),
        });
    }
    Ok(())
}

fn private_directory_builder() -> cap_std::fs::DirBuilder {
    let builder = cap_std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    }
    #[cfg(not(unix))]
    builder
}

fn write_staged(parent: &Dir, name: &OsStr, bytes: &[u8], display: &Path) -> Result<()> {
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = parent
        .open_with(name, &options)
        .map_err(|source| FolderbaseError::io(display, source))?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = parent.remove_file(name);
        return Err(FolderbaseError::io(display, source));
    }
    Ok(())
}

fn verify_blob(parent: &Dir, name: &OsStr, bytes: u64, display: &Path) -> Result<()> {
    verify_blob_with_hook(parent, name, bytes, display, || {})
}

fn verify_blob_with_hook(
    parent: &Dir,
    name: &OsStr,
    bytes: u64,
    display: &Path,
    after_metadata: impl FnOnce(),
) -> Result<()> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|source| FolderbaseError::io(display, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != bytes {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "content-addressed blob metadata does not match".to_owned(),
        });
    }
    after_metadata();
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut bounded = Read::by_ref(&mut file).take(bytes.saturating_add(1));
    loop {
        let read = bounded
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(display, source))?;
        if read == 0 {
            break;
        }
        observed =
            observed
                .checked_add(read as u64)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: display.to_path_buf(),
                    message: "content-addressed blob length exceeds supported range".to_owned(),
                })?;
        if observed > bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: display.to_path_buf(),
                message: "content-addressed blob grew beyond its expected byte length".to_owned(),
            });
        }
        hasher.update(&buffer[..read]);
    }
    if observed != bytes || format!("{:x}", hasher.finalize()) != name.to_string_lossy() {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "content-addressed blob digest does not match".to_owned(),
        });
    }
    Ok(())
}

fn verify_exact_file(parent: &Dir, name: &OsStr, expected: &[u8], display: &Path) -> Result<()> {
    verify_exact_file_with_hook(parent, name, expected, display, || {})
}

fn verify_exact_file_with_hook(
    parent: &Dir,
    name: &OsStr,
    expected: &[u8],
    display: &Path,
    after_metadata: impl FnOnce(),
) -> Result<()> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|source| FolderbaseError::io(display, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != expected.len() as u64
    {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "published state record metadata changed".to_owned(),
        });
    }
    after_metadata();
    let mut observed = Vec::with_capacity(expected.len().min(COPY_BUFFER_BYTES));
    Read::by_ref(&mut file)
        .take((expected.len() as u64).saturating_add(1))
        .read_to_end(&mut observed)
        .map_err(|source| FolderbaseError::io(display, source))?;
    if observed.len() > expected.len() {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "published state record grew beyond its expected byte length".to_owned(),
        });
    }
    if observed != expected {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "published state record bytes changed".to_owned(),
        });
    }
    Ok(())
}

fn open_root_nofollow(root: &Path, _access: StateAccess) -> Result<Dir> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        let desired_access = match _access {
            StateAccess::ReadOnly => GENERIC_READ,
            StateAccess::Mutable => GENERIC_READ | GENERIC_WRITE,
        };
        options
            .access_mode(desired_access)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options
        .open(root)
        .map_err(|source| FolderbaseError::io(root, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(root, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderbaseError::UnsafePath(root.to_path_buf()));
    }
    Ok(Dir::from_std_file(file))
}

#[cfg(not(windows))]
fn open_directory_nofollow(
    parent: &Dir,
    name: &OsStr,
    _display: &Path,
    _access: StateAccess,
) -> std::io::Result<Dir> {
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
fn open_directory_nofollow(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    access: StateAccess,
) -> std::io::Result<Dir> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    if access == StateAccess::Mutable {
        options.write(true);
    }
    let desired_access = match access {
        StateAccess::ReadOnly => GENERIC_READ,
        StateAccess::Mutable => GENERIC_READ | GENERIC_WRITE,
    };
    options
        .access_mode(desired_access)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let file = parent.open_with(name, &options)?.into_std();
    let metadata = file.metadata()?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::other(format!(
            "unsafe directory capability: {}",
            display.display()
        )));
    }
    Ok(Dir::from_std_file(file))
}

fn directory_identity(directory: &Dir, display: &Path) -> Result<Handle> {
    let file = directory
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std_file();
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    Handle::from_file(file).map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(target_os = "linux")]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    let expected_identity = directory_identity(directory, display)?;
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory
        .open_with(Path::new("."), &options)
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std();
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    let observed_identity = Handle::from_file(
        file.try_clone()
            .map_err(|source| FolderbaseError::io(display, source))?,
    )
    .map_err(|source| FolderbaseError::io(display, source))?;
    if observed_identity != expected_identity {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    file.sync_all()
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(not(target_os = "linux"))]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    directory
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std_file()
        .sync_all()
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use tempfile::{TempDir, tempdir};

    use super::*;

    const RESTORE_SOURCE: &str = ".folderbase/source";
    const RESTORE_STAGE: &str = ".folderbase/transactions/restore-stage";
    const RESTORE_DESTINATION: &str = "project/restored.bin";

    fn prepared_workspace_restore(
        expected: &[u8],
        executable: bool,
    ) -> (TempDir, FolderbaseState, String) {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::create_dir_all(fixture.path().join(".folderbase/transactions")).expect("transactions");
        fs::create_dir(fixture.path().join("project")).expect("workspace parent");
        fs::write(fixture.path().join(RESTORE_SOURCE), expected).expect("restore source");
        let digest = format!("{:x}", Sha256::digest(expected));
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");
        state
            .stage_restore_blob(
                Path::new(RESTORE_SOURCE),
                Path::new(RESTORE_STAGE),
                &digest,
                expected.len() as u64,
                executable,
            )
            .expect("private restore stage");
        state
            .publish_workspace_restore(
                Path::new(RESTORE_STAGE),
                Path::new(RESTORE_DESTINATION),
                &digest,
                expected.len() as u64,
                executable,
            )
            .expect("workspace restore");
        (fixture, state, digest)
    }

    #[test]
    fn workspace_restore_revalidation_accepts_the_exact_retained_stage() {
        let expected = b"sealed opaque bytes\0\xff";
        let (_fixture, state, digest) = prepared_workspace_restore(expected, false);

        state
            .verify_workspace_restore(
                Path::new(RESTORE_STAGE),
                Path::new(RESTORE_DESTINATION),
                &digest,
                expected.len() as u64,
                false,
            )
            .expect("exact retained restore");
    }

    #[test]
    fn workspace_restore_revalidation_rejects_a_same_byte_replacement() {
        let expected = b"sealed opaque bytes";
        let (fixture, state, digest) = prepared_workspace_restore(expected, false);
        let destination = fixture.path().join(RESTORE_DESTINATION);
        fs::remove_file(&destination).expect("remove transaction-owned link");
        fs::write(&destination, expected).expect("foreign same-byte replacement");

        assert!(matches!(
            state.verify_workspace_restore(
                Path::new(RESTORE_STAGE),
                Path::new(RESTORE_DESTINATION),
                &digest,
                expected.len() as u64,
                false,
            ),
            Err(FolderbaseError::WouldOverwrite(path)) if path == destination
        ));
    }

    #[test]
    fn workspace_restore_revalidation_rejects_in_place_byte_mutation() {
        let expected = b"sealed opaque bytes";
        let (fixture, state, digest) = prepared_workspace_restore(expected, false);
        fs::write(
            fixture.path().join(RESTORE_DESTINATION),
            b"mutated opaque byte",
        )
        .expect("mutate retained inode in place");

        assert!(matches!(
            state.verify_workspace_restore(
                Path::new(RESTORE_STAGE),
                Path::new(RESTORE_DESTINATION),
                &digest,
                expected.len() as u64,
                false,
            ),
            Err(FolderbaseError::InvalidRecord { message, .. })
                if message.contains("restore file")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_restore_revalidation_rejects_executable_fidelity_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let expected = b"#!/bin/sh\nexit 0\n";
        let (fixture, state, digest) = prepared_workspace_restore(expected, true);
        let destination = fixture.path().join(RESTORE_DESTINATION);
        let mut permissions = fs::metadata(&destination).expect("metadata").permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&destination, permissions).expect("remove executable fidelity");

        assert!(matches!(
            state.verify_workspace_restore(
                Path::new(RESTORE_STAGE),
                Path::new(RESTORE_DESTINATION),
                &digest,
                expected.len() as u64,
                true,
            ),
            Err(FolderbaseError::InvalidRecord { message, .. })
                if message.contains("executable fidelity")
        ));
    }

    #[test]
    fn workspace_restore_revalidation_rejects_a_new_case_folded_nested_boundary() {
        let expected = b"sealed opaque bytes";
        let (fixture, state, digest) = prepared_workspace_restore(expected, false);
        fs::create_dir(fixture.path().join("project/.FOLDERBASE")).expect("nested state");
        fs::write(
            fixture.path().join("project/.FOLDERBASE/MANIFEST.JSON"),
            b"{}",
        )
        .expect("nested manifest");

        assert!(matches!(
            state.verify_workspace_restore(
                Path::new(RESTORE_STAGE),
                Path::new(RESTORE_DESTINATION),
                &digest,
                expected.len() as u64,
                false,
            ),
            Err(FolderbaseError::UnsafePath(path))
                if path == fixture.path().join("project")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn attachment_revalidation_rejects_an_ambient_replacement_root() {
        let fixture = tempdir().expect("fixture");
        let root = fixture.path().join("live");
        let detached = fixture.path().join("detached");
        fs::create_dir(&root).expect("root");
        fs::create_dir(root.join(".folderbase")).expect("state");
        let state = FolderbaseState::open_existing(&root).expect("state capability");

        fs::rename(&root, &detached).expect("detach retained physical root");
        fs::create_dir(&root).expect("replacement root");
        fs::create_dir(root.join(".folderbase")).expect("replacement state");

        assert!(matches!(
            state.verify_still_attached(),
            Err(FolderbaseError::UnsafePath(path)) if path == root
        ));
    }

    #[test]
    fn nested_folderbase_marker_names_are_ascii_case_folded() {
        assert!(is_folderbase_state_name(OsStr::new(".folderbase")));
        assert!(is_folderbase_state_name(OsStr::new(".FOLDERBASE")));
        assert!(is_folderbase_manifest_name(OsStr::new("manifest.json")));
        assert!(is_folderbase_manifest_name(OsStr::new("MANIFEST.JSON")));
        assert!(!is_folderbase_state_name(OsStr::new(".folderbase-other")));
        assert!(!is_folderbase_manifest_name(OsStr::new(
            "manifest.json.bak"
        )));
    }

    #[cfg(unix)]
    #[test]
    fn retained_parent_capability_never_redirects_publication_through_a_swapped_symlink() {
        use std::os::unix::fs::symlink;

        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::create_dir_all(fixture.path().join(".folderbase/local")).expect("local");
        let outside = tempdir().expect("outside");
        let state = FolderbaseState::open(fixture.path()).expect("capability state");
        state
            .publish_new_with_hook(Path::new("local/proof.json"), b"confined\n", || {
                fs::rename(
                    fixture.path().join(".folderbase/local"),
                    fixture.path().join(".folderbase/detached-local"),
                )
                .expect("detach retained parent");
                symlink(outside.path(), fixture.path().join(".folderbase/local"))
                    .expect("redirect ambient path");
            })
            .expect("publication remains capability-confined");

        assert!(!outside.path().join("proof.json").exists());
        assert_eq!(
            fs::read(fixture.path().join(".folderbase/detached-local/proof.json"))
                .expect("detached safe orphan"),
            b"confined\n"
        );
        assert!(
            state.verify_still_attached().is_ok(),
            "the state root remains attached even though one descendant moved"
        );
    }

    #[test]
    fn source_streaming_stops_at_one_byte_beyond_the_approved_length() {
        struct CountingReader {
            read: u64,
        }

        impl io::Read for CountingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer.fill(b'x');
                self.read += buffer.len() as u64;
                Ok(buffer.len())
            }
        }

        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::create_dir_all(fixture.path().join(".folderbase/versions/blobs/sha256"))
            .expect("blob store");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");
        let mut reader = CountingReader { read: 0 };
        let error = match state.publish_reader_sha256(
            Path::new(".folderbase/versions/blobs/sha256"),
            &mut reader,
            Path::new("growing-source"),
            1024,
        ) {
            Ok(_) => panic!("growth beyond the approved length must stop"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            FolderbaseError::InvalidRecord { message, .. }
                if message.contains("grew beyond")
        ));
        assert_eq!(reader.read, 1025);
        assert_eq!(
            fs::read_dir(fixture.path().join(".folderbase/versions/blobs/sha256"))
                .expect("blob directory")
                .count(),
            0,
            "failed bounded streams leave no staging or published blob"
        );
    }

    #[test]
    fn read_only_state_capability_reads_existing_records_without_mutation_authority() {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::write(fixture.path().join(".folderbase/proof"), b"read-only").expect("proof");

        let state =
            FolderbaseState::open_existing_read_only(fixture.path()).expect("read-only state");
        assert_eq!(
            state
                .read_bounded(Path::new(".folderbase/proof"), 64)
                .expect("bounded read"),
            Some(b"read-only".to_vec())
        );
        assert!(matches!(
            state.publish_new(Path::new(".folderbase/forbidden"), b"no"),
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn read_only_blob_verification_stops_after_concurrent_growth_beyond_expected_bytes() {
        let fixture = tempdir().expect("fixture");
        let blob_directory = fixture.path().join(".folderbase/versions/blobs/sha256");
        fs::create_dir_all(&blob_directory).expect("blob directory");
        let expected = b"sealed opaque bytes";
        let digest = format!("{:x}", Sha256::digest(expected));
        let blob = blob_directory.join(&digest);
        fs::write(&blob, expected).expect("expected blob");
        let state =
            FolderbaseState::open_existing_read_only(fixture.path()).expect("read-only state");

        let error = state
            .verify_sha256_blob_with_hook(
                Path::new(".folderbase/versions/blobs/sha256"),
                &digest,
                expected.len() as u64,
                || {
                    fs::OpenOptions::new()
                        .append(true)
                        .open(&blob)
                        .expect("open blob after metadata check")
                        .write_all(b"x")
                        .expect("grow blob beyond its sealed length");
                },
            )
            .expect_err("concurrent blob growth must fail bounded verification");

        assert!(matches!(
            error,
            FolderbaseError::InvalidRecord { message, .. }
                if message.contains("content-addressed blob")
        ));
    }

    #[test]
    fn exact_state_record_verification_stops_after_growth_beyond_expected_bytes() {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        let expected = b"bounded state record";
        let record = fixture.path().join(".folderbase/proof");
        fs::write(&record, expected).expect("expected record");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");

        let error = verify_exact_file_with_hook(
            &state.state,
            OsStr::new("proof"),
            expected,
            &record,
            || {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&record)
                    .expect("open record after metadata check")
                    .write_all(b"x")
                    .expect("grow record beyond expected length");
            },
        )
        .expect_err("concurrent state-record growth must fail bounded verification");

        assert!(matches!(
            error,
            FolderbaseError::InvalidRecord { message, .. }
                if message.contains("published state record")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_state_publication_flushes_nofollow_directory_capabilities() {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");
        state
            .ensure_private_dir(Path::new(".folderbase/local"))
            .expect("directory creation and flush");
        state
            .publish_new(Path::new(".folderbase/local/proof"), b"durable")
            .expect("publication and directory flush");
        state
            .replace(Path::new(".folderbase/local/proof"), b"replaced")
            .expect("replacement and directory flush");
        assert_eq!(
            fs::read(fixture.path().join(".folderbase/local/proof")).expect("proof"),
            b"replaced"
        );
    }

    #[cfg(windows)]
    #[test]
    fn mutating_state_open_rejects_a_directory_junction_root() {
        use std::process::Command;

        let fixture = tempdir().expect("fixture");
        let actual = fixture.path().join("actual");
        let junction = fixture.path().join("junction");
        fs::create_dir(&actual).expect("actual root");
        fs::create_dir(actual.join(".folderbase")).expect("actual state");
        let output = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                junction.to_str().expect("junction path"),
                actual.to_str().expect("actual path"),
            ])
            .output()
            .expect("create junction");
        assert!(
            output.status.success(),
            "mklink /J failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(matches!(
            FolderbaseState::open_existing(&junction),
            Err(FolderbaseError::UnsafePath(path)) if path == junction
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_publication_flushes_writable_directory_capabilities() {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");
        state
            .ensure_private_dir(Path::new(".folderbase/local"))
            .expect("directory creation and flush");
        state
            .publish_new(Path::new(".folderbase/local/proof"), b"durable")
            .expect("publication and directory flush");
        state
            .replace(Path::new(".folderbase/local/proof"), b"replaced")
            .expect("replacement and directory flush");
        assert_eq!(
            fs::read(fixture.path().join(".folderbase/local/proof")).expect("proof"),
            b"replaced"
        );
    }
}
