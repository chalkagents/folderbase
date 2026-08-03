//! Capability-confined publication for mutable and append-only `.folderbase` state.
//!
//! Display paths are retained only for diagnostics. Every filesystem operation
//! is relative to a retained, no-follow directory capability.

use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(not(windows))]
use cap_fs_ext::DirExt;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::ffi::CString;
use uuid::Uuid;

use crate::{
    FolderbaseError, Result,
    folderbase_restore_authority::{stable_file_identity_sha256, stable_file_link_count},
    physical_identity::PhysicalIdentity,
    root_attestation::metadata_is_link_or_reparse,
    traversal_policy::{NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary},
};

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
    root_identity: PhysicalIdentity,
    state: Dir,
    state_identity: PhysicalIdentity,
    display_root: PathBuf,
    access: StateAccess,
}

pub(crate) enum WorkspaceTarget {
    Absent,
    Directory(Dir),
    RegularFile(cap_std::fs::File),
}

struct WorkspaceTargetCapability {
    parent: Dir,
    parent_identity: PhysicalIdentity,
    relative: PathBuf,
    name: OsString,
    parent_display: PathBuf,
    display: PathBuf,
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

    pub(crate) fn read_bounded_if_present(
        &self,
        relative: &Path,
        maximum_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        match self.read_bounded(relative, maximum_bytes) {
            Ok(record) => Ok(record),
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn private_directory_names(
        &self,
        relative: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<OsString>> {
        let relative = relative.strip_prefix(STATE_COMPONENT).unwrap_or(relative);
        let (directory, display) = if relative.as_os_str().is_empty() {
            (
                self.state.try_clone().map_err(|source| {
                    FolderbaseError::io(self.display_root.join(STATE_COMPONENT), source)
                })?,
                self.display_root.join(STATE_COMPONENT),
            )
        } else {
            let relative = state_relative(relative)?;
            (self.open_dir(&relative)?, self.display_path(&relative))
        };
        let mut names = Vec::new();
        for entry in directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&display, source))?
        {
            let entry = entry.map_err(|source| FolderbaseError::io(&display, source))?;
            if names.len() >= maximum_entries {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: "private directory exceeds its bounded entry limit".to_owned(),
                });
            }
            names.push(entry.file_name());
        }
        Ok(names)
    }

    pub(crate) fn private_directory_names_if_present(
        &self,
        relative: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<OsString>> {
        let relative = state_relative(relative)?;
        match self.open_dir(&relative) {
            Ok(directory) => {
                let display = self.display_path(&relative);
                let mut names = Vec::new();
                for entry in directory
                    .read_dir(".")
                    .map_err(|source| FolderbaseError::io(&display, source))?
                {
                    let entry = entry.map_err(|source| FolderbaseError::io(&display, source))?;
                    if names.len() >= maximum_entries {
                        return Err(FolderbaseError::InvalidRecord {
                            path: display,
                            message: "private directory exceeds its bounded entry limit".to_owned(),
                        });
                    }
                    names.push(entry.file_name());
                }
                Ok(names)
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn sanitize_private_single_file_namespace(
        &self,
        relative: &Path,
        retained_file: &OsStr,
    ) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let directory = self.open_dir(&relative)?;
        let display = self.display_path(&relative);
        sanitize_private_directory_queued(directory, display, self.access, retained_file)
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
                let copy_result =
                    copy_exact_sha256(
                        &mut source_file,
                        &mut staged,
                        bytes,
                        digest,
                        &source_display,
                        &stage_display,
                    )
                    .and_then(|()| {
                        #[cfg(unix)]
                        {
                            use cap_std::fs::PermissionsExt;

                            staged
                                .set_permissions(cap_std::fs::Permissions::from_mode(
                                    if executable { 0o700 } else { 0o600 },
                                ))
                                .map_err(|source| FolderbaseError::io(&stage_display, source))?;
                        }
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
    #[cfg(test)]
    pub(crate) fn publish_workspace_restore(
        &self,
        stage: &Path,
        destination: &Path,
        digest: &str,
        bytes: u64,
        executable: bool,
    ) -> Result<bool> {
        self.publish_workspace_restore_with_hook(
            stage,
            destination,
            digest,
            bytes,
            executable,
            |_| {},
        )
    }

    pub(crate) fn publish_workspace_restore_with_hook(
        &self,
        stage: &Path,
        destination: &Path,
        digest: &str,
        bytes: u64,
        executable: bool,
        mut checkpoint: impl FnMut(bool),
    ) -> Result<bool> {
        let stage = state_relative(stage)?;
        let destination = safe_workspace_relative(destination)?;
        self.require_mutable(&stage)?;
        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        let mut stage_file =
            open_regular_file_nofollow(&stage_parent, &stage_name, &stage_display)?;
        verify_open_regular_file(&mut stage_file, digest, bytes, executable, &stage_display)?;
        let target = self.open_workspace_target_capability(&destination)?;
        checkpoint(false);
        let visible_parent = self.reopen_workspace_target_capability(&target)?;
        match visible_parent.symlink_metadata(&target.name) {
            Ok(_) => {
                let destination_identity =
                    regular_file_identity(&visible_parent, &target.name, &target.display)
                        .map_err(|_| FolderbaseError::WouldOverwrite(target.display.clone()))?;
                if open_regular_file_identity(&stage_file, &stage_display)? != destination_identity
                {
                    return Err(FolderbaseError::WouldOverwrite(target.display));
                }
                require_restore_link_count(&stage_file, 2, &target.display)?;
                verify_regular_file(
                    &visible_parent,
                    &target.name,
                    digest,
                    bytes,
                    executable,
                    &target.display,
                )?;
                self.reopen_workspace_target_capability(&target)?;
                return Ok(false);
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(FolderbaseError::io(&target.display, source)),
        }
        require_restore_link_count(&stage_file, 1, &target.display)?;
        match stage_parent.hard_link(&stage_name, &target.parent, &target.name) {
            Ok(()) => {
                checkpoint(true);
                require_restore_link_count(&stage_file, 2, &target.display)?;
                sync_directory(&target.parent, &target.display)?;
                let visible_parent = self.reopen_workspace_target_capability(&target)?;
                verify_regular_file(
                    &visible_parent,
                    &target.name,
                    digest,
                    bytes,
                    executable,
                    &target.display,
                )?;
                require_restore_link_count(&stage_file, 2, &target.display)?;
                self.reopen_workspace_target_capability(&target)?;
                Ok(true)
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let stage_identity =
                    regular_file_identity(&stage_parent, &stage_name, &stage_display)?;
                let visible_parent = self.reopen_workspace_target_capability(&target)?;
                let destination_identity =
                    regular_file_identity(&visible_parent, &target.name, &target.display)
                        .map_err(|_| FolderbaseError::WouldOverwrite(target.display.clone()))?;
                if stage_identity != destination_identity {
                    return Err(FolderbaseError::WouldOverwrite(target.display));
                }
                require_restore_link_count(&stage_file, 2, &target.display)?;
                verify_regular_file(
                    &visible_parent,
                    &target.name,
                    digest,
                    bytes,
                    executable,
                    &target.display,
                )?;
                require_restore_link_count(&stage_file, 2, &target.display)?;
                self.reopen_workspace_target_capability(&target)?;
                Ok(false)
            }
            Err(source) => Err(FolderbaseError::io(target.display, source)),
        }
    }

    pub(crate) fn workspace_path_is_absent(&self, relative: &Path) -> Result<bool> {
        let relative = safe_workspace_relative(relative)?;
        let target = self.open_workspace_target_capability(&relative)?;
        let absent = match target.parent.symlink_metadata(&target.name) {
            Ok(_) => false,
            Err(source) if source.kind() == io::ErrorKind::NotFound => true,
            Err(source) => return Err(FolderbaseError::io(&target.display, source)),
        };
        self.reopen_workspace_target_capability(&target)?;
        Ok(absent)
    }

    /// Open one exact workspace target through the retained root without
    /// following a symlink/reparse point or crossing a nested Folderbase.
    pub(crate) fn open_workspace_target_nofollow(
        &self,
        relative: &Path,
    ) -> Result<WorkspaceTarget> {
        let relative = safe_workspace_relative(relative)?;
        let target = match self.open_workspace_target_capability(&relative) {
            Ok(target) => target,
            Err(FolderbaseError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(WorkspaceTarget::Absent);
            }
            Err(error) => return Err(error),
        };
        let metadata = match target.parent.symlink_metadata(&target.name) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                self.reopen_workspace_target_capability(&target)?;
                return Ok(WorkspaceTarget::Absent);
            }
            Err(source) => return Err(FolderbaseError::io(&target.display, source)),
        };
        let opened = if metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(target.display));
        } else if metadata.is_dir() {
            let directory =
                open_directory_nofollow(&target.parent, &target.name, &target.display, self.access)
                    .map_err(|source| FolderbaseError::io(&target.display, source))?;
            if classify_nested_folderbase_boundary(&directory, &target.display)?
                != NestedFolderbaseBoundaryKind::None
            {
                return Err(FolderbaseError::UnsafePath(target.display));
            }
            WorkspaceTarget::Directory(directory)
        } else if metadata.is_file() {
            WorkspaceTarget::RegularFile(open_regular_file_nofollow(
                &target.parent,
                &target.name,
                &target.display,
            )?)
        } else {
            return Err(FolderbaseError::UnsafePath(target.display));
        };
        self.reopen_workspace_target_capability(&target)?;
        Ok(opened)
    }

    pub(crate) fn open_private_target_nofollow(&self, relative: &Path) -> Result<WorkspaceTarget> {
        let relative = state_relative(relative)?;
        let (parent, name) = match self.open_parent(&relative) {
            Ok(target) => target,
            Err(FolderbaseError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(WorkspaceTarget::Absent);
            }
            Err(error) => return Err(error),
        };
        let display = self.display_path(&relative);
        let metadata = match parent.symlink_metadata(&name) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(WorkspaceTarget::Absent);
            }
            Err(source) => return Err(FolderbaseError::io(&display, source)),
        };
        if metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(display));
        }
        if metadata.is_dir() {
            let directory = open_directory_nofollow(&parent, &name, &display, self.access)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            Ok(WorkspaceTarget::Directory(directory))
        } else if metadata.is_file() {
            Ok(WorkspaceTarget::RegularFile(open_regular_file_nofollow(
                &parent, &name, &display,
            )?))
        } else {
            Err(FolderbaseError::UnsafePath(display))
        }
    }

    pub(crate) fn workspace_directory_names(
        &self,
        relative: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<OsString>> {
        let directory = if relative.as_os_str().is_empty() {
            self.clone_root_capability()?
        } else {
            let WorkspaceTarget::Directory(directory) =
                self.open_workspace_target_nofollow(relative)?
            else {
                return Err(FolderbaseError::UnsafePath(
                    self.display_root.join(relative),
                ));
            };
            directory
        };
        let display = self.display_root.join(relative);
        let mut names = Vec::new();
        for entry in directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&display, source))?
        {
            let entry = entry.map_err(|source| FolderbaseError::io(&display, source))?;
            if names.len() >= maximum_entries {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: "workspace directory exceeds its bounded entry limit".to_owned(),
                });
            }
            names.push(entry.file_name());
        }
        Ok(names)
    }

    /// Open one ordinary workspace file through the retained physical-root
    /// capability without consulting the ambient root path.
    pub(crate) fn open_workspace_regular_file(&self, relative: &Path) -> Result<File> {
        let relative = safe_workspace_relative(relative)?;
        let target = self.open_workspace_target_capability(&relative)?;
        let file = open_regular_file_nofollow(&target.parent, &target.name, &target.display)?;
        self.reopen_workspace_target_capability(&target)?;
        Ok(file.into_std())
    }

    /// Detect a user edit made through the exact workspace object published
    /// by a restore transaction. A separately-created replacement is never
    /// classified as transaction-owned, even when its bytes happen to match.
    pub(crate) fn workspace_restore_was_modified_in_place(
        &self,
        stage: &Path,
        destination: &Path,
        digest: &str,
        bytes: u64,
        executable: bool,
    ) -> Result<bool> {
        let stage = state_relative(stage)?;
        let destination = safe_workspace_relative(destination)?;
        self.verify_still_attached()?;

        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        let mut stage_file =
            open_regular_file_nofollow(&stage_parent, &stage_name, &stage_display)?;
        let stage_identity = open_regular_file_identity(&stage_file, &stage_display)?;

        let target = self.open_workspace_target_capability(&destination)?;
        let destination_file =
            open_regular_file_nofollow(&target.parent, &target.name, &target.display)?;
        let destination_identity = open_regular_file_identity(&destination_file, &target.display)?;
        if destination_identity != stage_identity {
            self.reopen_workspace_target_capability(&target)?;
            return Ok(false);
        }

        let modified = match verify_open_regular_file(
            &mut stage_file,
            digest,
            bytes,
            executable,
            &stage_display,
        ) {
            Ok(()) => false,
            Err(FolderbaseError::InvalidRecord { .. }) => true,
            Err(error) => return Err(error),
        };
        self.reopen_workspace_target_capability(&target)?;
        Ok(modified)
    }

    /// Return a durable device-local identity for the exact inode shared by a
    /// restore stage and its visible workspace publication.
    pub(crate) fn workspace_restore_identity_sha256(
        &self,
        stage: &Path,
        destination: &Path,
    ) -> Result<String> {
        let stage = state_relative(stage)?;
        let destination = safe_workspace_relative(destination)?;
        self.verify_still_attached()?;

        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        let stage_file = open_regular_file_nofollow(&stage_parent, &stage_name, &stage_display)?;
        let stage_identity = open_regular_file_identity(&stage_file, &stage_display)?;

        let target = self.open_workspace_target_capability(&destination)?;
        let destination_file =
            open_regular_file_nofollow(&target.parent, &target.name, &target.display)?;
        if open_regular_file_identity(&destination_file, &target.display)? != stage_identity {
            return Err(FolderbaseError::InvalidRecord {
                path: target.display,
                message: "restore destination no longer names the staged file".to_owned(),
            });
        }
        let stage_stable = stable_regular_file_identity_sha256(&stage_file, &stage_display)?;
        if stable_regular_file_identity_sha256(&destination_file, &target.display)? != stage_stable
        {
            return Err(FolderbaseError::InvalidRecord {
                path: target.display,
                message: "restore destination stable identity changed".to_owned(),
            });
        }
        self.reopen_workspace_target_capability(&target)?;
        Ok(stage_stable)
    }

    /// Inspect the exact retained-stage/workspace inode relationship during
    /// capture planning without requesting access to either file's content.
    pub(crate) fn planned_workspace_restore_identity_sha256(
        &self,
        stage: &Path,
        destination: &Path,
    ) -> Result<String> {
        let stage = state_relative(stage)?;
        let destination = safe_workspace_relative(destination)?;
        self.verify_still_attached()?;

        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        let stage_identity =
            planning_regular_file_identity(&stage_parent, &stage_name, &stage_display)?;

        let target = self.open_workspace_target_capability(&destination)?;
        let destination_identity =
            planning_regular_file_identity(&target.parent, &target.name, &target.display)?;
        if destination_identity != stage_identity {
            return Err(FolderbaseError::InvalidRecord {
                path: target.display.clone(),
                message: "restore destination no longer names the staged file".to_owned(),
            });
        }

        let rechecked_stage =
            planning_regular_file_identity(&stage_parent, &stage_name, &stage_display)?;
        let rechecked_destination =
            planning_regular_file_identity(&target.parent, &target.name, &target.display)?;
        if rechecked_stage != stage_identity || rechecked_destination != destination_identity {
            return Err(FolderbaseError::InvalidRecord {
                path: target.display,
                message: "restore destination identity changed during planning".to_owned(),
            });
        }
        self.reopen_workspace_target_capability(&target)?;
        Ok(stage_identity)
    }

    /// Verify both exact publication identity and sealed file fidelity when
    /// every private hard link has already been retired.
    pub(crate) fn verify_workspace_regular_file_identity_and_fidelity(
        &self,
        destination: &Path,
        expected_identity_sha256: &str,
        digest: &str,
        bytes: u64,
        executable: bool,
    ) -> Result<()> {
        self.verify_workspace_regular_file_identity_inner(
            destination,
            expected_identity_sha256,
            Some((digest, bytes, executable)),
        )
    }

    fn verify_workspace_regular_file_identity_inner(
        &self,
        destination: &Path,
        expected_identity_sha256: &str,
        expected_fidelity: Option<(&str, u64, bool)>,
    ) -> Result<()> {
        let destination = safe_workspace_relative(destination)?;
        let target = self.open_workspace_target_capability(&destination)?;
        let mut destination_file =
            open_regular_file_nofollow(&target.parent, &target.name, &target.display)?;
        if stable_regular_file_identity_sha256(&destination_file, &target.display)?
            != expected_identity_sha256
        {
            return Err(FolderbaseError::InvalidRecord {
                path: target.display,
                message: "workspace file no longer has the restore publication identity".to_owned(),
            });
        }
        if let Some((digest, bytes, executable)) = expected_fidelity {
            verify_open_regular_file(
                &mut destination_file,
                digest,
                bytes,
                executable,
                &target.display,
            )?;
        }

        let visible_parent = self.reopen_workspace_target_capability(&target)?;
        let mut visible_file =
            open_regular_file_nofollow(&visible_parent, &target.name, &target.display)?;
        if stable_regular_file_identity_sha256(&visible_file, &target.display)?
            != expected_identity_sha256
        {
            return Err(FolderbaseError::InvalidRecord {
                path: target.display,
                message: "workspace file identity changed during restore verification".to_owned(),
            });
        }
        if let Some((digest, bytes, executable)) = expected_fidelity {
            verify_open_regular_file(
                &mut visible_file,
                digest,
                bytes,
                executable,
                &target.display,
            )?;
        }
        self.reopen_workspace_target_capability(&target).map(drop)
    }

    /// Retain and revalidate the exact private authority link for a restore.
    ///
    /// This performs no rename or unlink. The transaction-unique stage stays
    /// linked to the visible workspace file so later capture can distinguish
    /// one Folderbase authority link from ordinary user-created hard links.
    pub(crate) fn retain_workspace_restore_authority_with_hook(
        &self,
        stage: &Path,
        destination: &Path,
        expected_identity_sha256: &str,
        expected_fidelity: Option<(&str, u64, bool)>,
        mut checkpoint: impl FnMut(bool),
    ) -> Result<()> {
        let stage = state_relative(stage)?;
        let destination = safe_workspace_relative(destination)?;
        self.require_mutable(&stage)?;
        self.verify_still_attached()?;

        let (stage_parent, stage_name) = self.open_parent(&stage)?;
        let stage_display = self.display_path(&stage);
        let stage_file = open_regular_file_nofollow(&stage_parent, &stage_name, &stage_display)?;
        let target = self.open_workspace_target_capability(&destination)?;

        for after_stage_boundary in [false, true] {
            verify_restore_retained_stage(
                &stage_parent,
                &stage_name,
                &stage_display,
                &stage_file,
                expected_identity_sha256,
            )?;
            verify_restore_retirement_publication(
                &stage_file,
                &stage_display,
                &target.parent,
                &target.name,
                &target.display,
                expected_identity_sha256,
                expected_fidelity,
            )?;
            checkpoint(after_stage_boundary);
            self.reopen_workspace_target_capability(&target)?;
        }
        verify_restore_retained_stage(
            &stage_parent,
            &stage_name,
            &stage_display,
            &stage_file,
            expected_identity_sha256,
        )?;
        verify_restore_retirement_publication(
            &stage_file,
            &stage_display,
            &target.parent,
            &target.name,
            &target.display,
            expected_identity_sha256,
            expected_fidelity,
        )?;
        self.reopen_workspace_target_capability(&target).map(drop)
    }

    /// Legacy destructive retirement is compiled out. Restore authorities are
    /// retained until a future explicit maintenance protocol can prune them
    /// without reintroducing pathname overwrite or check-then-unlink races.
    #[cfg(any())]
    #[allow(dead_code)]
    /// Retire only the exact private stage for a restore-owned workspace file.
    ///
    /// A transaction-owned rescue hard link protects the staged inode across
    /// the unlink boundary. Both private names and the visible destination are
    /// revalidated through retained directory capabilities. Any replacement or
    /// uncertainty fails closed while the rescue remains durable.
    pub(crate) fn retire_workspace_restore_stage_with_hook(
        &self,
        stage: &Path,
        rescue: &Path,
        destination: &Path,
        expected_identity_sha256: &str,
        expected_fidelity: Option<(&str, u64, bool)>,
        mut checkpoint: impl FnMut(bool),
    ) -> Result<bool> {
        let stage = state_relative(stage)?;
        let rescue = state_relative(rescue)?;
        let mut stage_quarantine_name = stage
            .file_name()
            .ok_or_else(|| FolderbaseError::UnsafePath(self.display_path(&stage)))?
            .to_os_string();
        stage_quarantine_name.push(".folderbase-quarantine");
        let stage_quarantine = stage.with_file_name(stage_quarantine_name);
        let mut rescue_quarantine_name = rescue
            .file_name()
            .ok_or_else(|| FolderbaseError::UnsafePath(self.display_path(&rescue)))?
            .to_os_string();
        rescue_quarantine_name.push(".folderbase-quarantine");
        let rescue_quarantine = rescue.with_file_name(rescue_quarantine_name);
        let destination = safe_workspace_relative(destination)?;
        for private in [&stage, &stage_quarantine, &rescue, &rescue_quarantine] {
            self.require_mutable(private)?;
        }
        let private_parent = stage.parent();
        if private_parent != stage_quarantine.parent()
            || private_parent != rescue.parent()
            || private_parent != rescue_quarantine.parent()
            || stage == stage_quarantine
            || stage == rescue
            || stage == rescue_quarantine
            || stage_quarantine == rescue
            || stage_quarantine == rescue_quarantine
            || rescue == rescue_quarantine
        {
            return Err(FolderbaseError::UnsafePath(self.display_path(&rescue)));
        }
        self.verify_still_attached()?;

        let (stage_parent, stage_name) = match self.open_parent(&stage) {
            Ok(parent) => parent,
            Err(FolderbaseError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let (stage_quarantine_parent, stage_quarantine_name) =
            self.open_parent(&stage_quarantine)?;
        let (rescue_parent, rescue_name) = self.open_parent(&rescue)?;
        let (rescue_quarantine_parent, rescue_quarantine_name) =
            self.open_parent(&rescue_quarantine)?;
        let stage_display = self.display_path(&stage);
        let stage_quarantine_display = self.display_path(&stage_quarantine);
        let rescue_display = self.display_path(&rescue);
        let rescue_quarantine_display = self.display_path(&rescue_quarantine);
        let destination_display = self.display_root.join(&destination);
        let (destination_parent, destination_name) = self.open_workspace_parent(&destination)?;

        let open_optional =
            |parent: &Dir, name: &OsStr, display: &Path| match open_regular_file_nofollow(
                parent, name, display,
            ) {
                Ok(file) => Ok(Some(file)),
                Err(FolderbaseError::Io { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    Ok(None)
                }
                Err(error) => Err(error),
            };
        let stage_file = open_optional(&stage_parent, &stage_name, &stage_display)?;
        let stage_quarantine_file = open_optional(
            &stage_quarantine_parent,
            &stage_quarantine_name,
            &stage_quarantine_display,
        )?;
        let rescue_file = open_optional(&rescue_parent, &rescue_name, &rescue_display)?;
        let rescue_quarantine_file = open_optional(
            &rescue_quarantine_parent,
            &rescue_quarantine_name,
            &rescue_quarantine_display,
        )?;

        let retained_file = stage_file
            .as_ref()
            .or(stage_quarantine_file.as_ref())
            .or(rescue_file.as_ref())
            .or(rescue_quarantine_file.as_ref());
        let Some(retained_file) = retained_file else {
            return Ok(false);
        };
        let retained_display = if stage_file.is_some() {
            &stage_display
        } else if stage_quarantine_file.is_some() {
            &stage_quarantine_display
        } else if rescue_file.is_some() {
            &rescue_display
        } else {
            &rescue_quarantine_display
        };
        let retained_identity = open_regular_file_identity(retained_file, retained_display)?;
        for (file, display) in [
            (stage_file.as_ref(), &stage_display),
            (stage_quarantine_file.as_ref(), &stage_quarantine_display),
            (rescue_file.as_ref(), &rescue_display),
            (rescue_quarantine_file.as_ref(), &rescue_quarantine_display),
        ] {
            if let Some(file) = file {
                if open_regular_file_identity(file, display)? != retained_identity {
                    return Err(FolderbaseError::InvalidRecord {
                        path: display.to_path_buf(),
                        message: "restore private names do not share one retained inode".to_owned(),
                    });
                }
                if stable_regular_file_identity_sha256(file, display)? != expected_identity_sha256 {
                    return Err(FolderbaseError::InvalidRecord {
                        path: display.to_path_buf(),
                        message: "restore private name no longer has the published identity"
                            .to_owned(),
                    });
                }
            }
        }

        let destination_file = open_regular_file_nofollow(
            &destination_parent,
            &destination_name,
            &destination_display,
        )?;
        if open_regular_file_identity(&destination_file, &destination_display)? != retained_identity
        {
            return Err(FolderbaseError::InvalidRecord {
                path: retained_display.to_path_buf(),
                message: "restore private state no longer owns the workspace file".to_owned(),
            });
        }
        if stable_regular_file_identity_sha256(&destination_file, &destination_display)?
            != expected_identity_sha256
        {
            return Err(FolderbaseError::InvalidRecord {
                path: destination_display,
                message: "workspace file no longer has the restore publication identity".to_owned(),
            });
        }
        if let Some((digest, bytes, executable)) = expected_fidelity {
            let mut fidelity_file = retained_file
                .try_clone()
                .map_err(|source| FolderbaseError::io(retained_display.to_path_buf(), source))?;
            verify_open_regular_file(
                &mut fidelity_file,
                digest,
                bytes,
                executable,
                retained_display,
            )?;
        }

        if rescue_file.is_none() && rescue_quarantine_file.is_none() {
            let (source_parent, source_name) = if stage_file.is_some() {
                (&stage_parent, &stage_name)
            } else {
                (&stage_quarantine_parent, &stage_quarantine_name)
            };
            match source_parent.hard_link(source_name, &rescue_parent, &rescue_name) {
                Ok(()) => sync_directory(&rescue_parent, &rescue_display)?,
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(FolderbaseError::io(&rescue_display, source)),
            }
            if regular_file_identity(&rescue_parent, &rescue_name, &rescue_display)?
                != retained_identity
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: rescue_display,
                    message: "restore rescue captured a different filesystem object".to_owned(),
                });
            }
        }

        if stage_file.is_some() && stage_quarantine_file.is_some() {
            return Err(FolderbaseError::InvalidRecord {
                path: stage_quarantine_display,
                message: "restore stage and quarantine both exist".to_owned(),
            });
        }
        if stage_file.is_some() {
            if regular_file_identity(&stage_parent, &stage_name, &stage_display)?
                != retained_identity
                || regular_file_identity(&rescue_parent, &rescue_name, &rescue_display)?
                    != retained_identity
                || regular_file_identity(
                    &destination_parent,
                    &destination_name,
                    &destination_display,
                )? != retained_identity
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: stage_display,
                    message: "restore ownership changed before stage quarantine".to_owned(),
                });
            }
            checkpoint(false);
            verify_restore_retirement_publication(
                retained_file,
                retained_display,
                &destination_parent,
                &destination_name,
                &destination_display,
                expected_identity_sha256,
                expected_fidelity,
            )?;
            stage_parent
                .rename(
                    &stage_name,
                    &stage_quarantine_parent,
                    &stage_quarantine_name,
                )
                .map_err(|source| FolderbaseError::io(&stage_quarantine_display, source))?;
            sync_directory(&stage_parent, &stage_display)?;
            if regular_file_identity(
                &stage_quarantine_parent,
                &stage_quarantine_name,
                &stage_quarantine_display,
            )? != retained_identity
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: stage_quarantine_display,
                    message: "restore stage quarantine preserved a replacement".to_owned(),
                });
            }
        }

        let stage_is_quarantined = stage_file.is_some() || stage_quarantine_file.is_some();
        if stage_is_quarantined
            && (regular_file_identity(
                &stage_quarantine_parent,
                &stage_quarantine_name,
                &stage_quarantine_display,
            )? != retained_identity
                || regular_file_identity(&rescue_parent, &rescue_name, &rescue_display)?
                    != retained_identity
                || regular_file_identity(
                    &destination_parent,
                    &destination_name,
                    &destination_display,
                )? != retained_identity)
        {
            return Err(FolderbaseError::InvalidRecord {
                path: stage_quarantine_display,
                message: "restore ownership changed after stage quarantine".to_owned(),
            });
        }
        if stage_is_quarantined {
            stage_quarantine_parent
                .remove_file(&stage_quarantine_name)
                .map_err(|source| FolderbaseError::io(&stage_quarantine_display, source))?;
            sync_directory(&stage_quarantine_parent, &stage_quarantine_display)?;
        }

        if rescue_file.is_some() && rescue_quarantine_file.is_some() {
            return Err(FolderbaseError::InvalidRecord {
                path: rescue_quarantine_display,
                message: "restore rescue and quarantine both exist".to_owned(),
            });
        }
        let rescue_is_normal = rescue_file.is_some() || rescue_quarantine_file.is_none();
        if rescue_is_normal {
            if regular_file_identity(&rescue_parent, &rescue_name, &rescue_display)?
                != retained_identity
                || regular_file_identity(
                    &destination_parent,
                    &destination_name,
                    &destination_display,
                )? != retained_identity
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: rescue_display,
                    message: "restore ownership changed before rescue quarantine".to_owned(),
                });
            }
            checkpoint(true);
            verify_restore_retirement_publication(
                retained_file,
                retained_display,
                &destination_parent,
                &destination_name,
                &destination_display,
                expected_identity_sha256,
                expected_fidelity,
            )?;
            rescue_parent
                .rename(
                    &rescue_name,
                    &rescue_quarantine_parent,
                    &rescue_quarantine_name,
                )
                .map_err(|source| FolderbaseError::io(&rescue_quarantine_display, source))?;
            sync_directory(&rescue_parent, &rescue_display)?;
        }

        let moved_rescue_identity = regular_file_identity(
            &rescue_quarantine_parent,
            &rescue_quarantine_name,
            &rescue_quarantine_display,
        )?;
        if moved_rescue_identity != retained_identity {
            if regular_file_identity(&destination_parent, &destination_name, &destination_display)?
                == retained_identity
            {
                match destination_parent.hard_link(&destination_name, &rescue_parent, &rescue_name)
                {
                    Ok(()) => sync_directory(&rescue_parent, &rescue_display)?,
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => return Err(FolderbaseError::io(&rescue_display, source)),
                }
            }
            return Err(FolderbaseError::InvalidRecord {
                path: rescue_quarantine_display,
                message: "restore rescue quarantine preserved a replacement".to_owned(),
            });
        }
        if regular_file_identity(&destination_parent, &destination_name, &destination_display)?
            != retained_identity
        {
            return Err(FolderbaseError::InvalidRecord {
                path: rescue_quarantine_display,
                message: "restore destination changed after rescue quarantine".to_owned(),
            });
        }
        rescue_quarantine_parent
            .remove_file(&rescue_quarantine_name)
            .map_err(|source| FolderbaseError::io(&rescue_quarantine_display, source))?;
        sync_directory(&rescue_quarantine_parent, &rescue_quarantine_display)?;
        let destination_file = open_regular_file_nofollow(
            &destination_parent,
            &destination_name,
            &destination_display,
        )?;
        if stable_regular_file_identity_sha256(&destination_file, &destination_display)?
            != expected_identity_sha256
        {
            return Err(FolderbaseError::InvalidRecord {
                path: destination_display,
                message: "workspace file identity changed during restore retirement".to_owned(),
            });
        }
        self.verify_still_attached()?;
        Ok(true)
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

        let target = self.open_workspace_target_capability(&destination)?;
        let mut destination_file =
            open_regular_file_nofollow(&target.parent, &target.name, &target.display)
                .map_err(|_| FolderbaseError::WouldOverwrite(target.display.clone()))?;
        let destination_identity =
            open_regular_file_identity(&destination_file, &target.display)
                .map_err(|_| FolderbaseError::WouldOverwrite(target.display.clone()))?;
        if destination_identity != stage_identity {
            return Err(FolderbaseError::WouldOverwrite(target.display));
        }
        verify_open_regular_file(
            &mut destination_file,
            digest,
            bytes,
            executable,
            &target.display,
        )?;

        // Reopen through the retained root after byte verification. This
        // closes over ordinary replacement races and repeats the boundary
        // walk immediately before the coordinator advances durable state.
        let visible_parent = self.reopen_workspace_target_capability(&target)?;
        let mut visible_file =
            open_regular_file_nofollow(&visible_parent, &target.name, &target.display)
                .map_err(|_| FolderbaseError::WouldOverwrite(target.display.clone()))?;
        let visible_identity = open_regular_file_identity(&visible_file, &target.display)
            .map_err(|_| FolderbaseError::WouldOverwrite(target.display.clone()))?;
        if visible_identity != stage_identity {
            return Err(FolderbaseError::WouldOverwrite(target.display));
        }
        verify_open_regular_file(
            &mut visible_file,
            digest,
            bytes,
            executable,
            &target.display,
        )?;
        self.reopen_workspace_target_capability(&target).map(drop)
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
        self.replace_with_before_publish(relative, bytes, || Ok(()))
    }

    pub(crate) fn replace_with_before_publish(
        &self,
        relative: &Path,
        bytes: &[u8],
        before_publish: impl FnOnce() -> io::Result<()>,
    ) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        let temporary = OsString::from(format!(".replace-{}.tmp", Uuid::now_v7()));
        write_staged(&parent, &temporary, bytes, &display)?;
        if let Err(source) = before_publish() {
            let _ = parent.remove_file(&temporary);
            return Err(FolderbaseError::io(display, source));
        }
        if let Err(source) = parent.rename(&temporary, &parent, &name) {
            let _ = parent.remove_file(&temporary);
            return Err(FolderbaseError::io(display, source));
        }
        sync_directory(&parent, &display)?;
        verify_exact_file(&parent, &name, bytes, &display)
    }

    pub(crate) fn compare_exchange_exact_owned_with_hook(
        &self,
        relative: &Path,
        expected: &[u8],
        replacement: &[u8],
        exchange_owner: &str,
        before_exchange: impl FnOnce(),
    ) -> Result<()> {
        self.compare_exchange_exact_owned_with_hooks(
            relative,
            expected,
            replacement,
            exchange_owner,
            before_exchange,
            || Ok(()),
        )
    }

    pub(crate) fn compare_exchange_exact_owned_with_hooks(
        &self,
        relative: &Path,
        expected: &[u8],
        replacement: &[u8],
        exchange_owner: &str,
        before_exchange: impl FnOnce(),
        after_platform_exchange: impl FnOnce() -> io::Result<()>,
    ) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        validate_exchange_owner(exchange_owner, &display)?;
        let temporary = OsString::from(format!(".exchange-{exchange_owner}.tmp"));
        let parent_display = display
            .parent()
            .expect("state record has a parent")
            .to_path_buf();
        write_staged(&parent, &temporary, replacement, &display)?;
        before_exchange();
        if let Err(source) = atomic_exchange_with_hook(
            &parent,
            &parent_display,
            &temporary,
            &name,
            exchange_owner,
            after_platform_exchange,
        ) {
            let _ = parent.remove_file(&temporary);
            return Err(FolderbaseError::io(display, source));
        }
        if verify_exact_file(&parent, &temporary, expected, &display).is_err() {
            if let Err(source) = atomic_exchange_with_hook(
                &parent,
                &parent_display,
                &temporary,
                &name,
                exchange_owner,
                || Ok(()),
            ) {
                return Err(FolderbaseError::io(display, source));
            }
            if verify_exact_file(&parent, &temporary, replacement, &display).is_ok() {
                let _ = parent.remove_file(&temporary);
                let _ = sync_directory(&parent, &display);
            } else {
                let recovery =
                    OsString::from(format!("manifest.concurrent-{exchange_owner}.recovery"));
                let _ = parent.rename(&temporary, &parent, &recovery);
                let _ = sync_directory(&parent, &display);
            }
            return Err(FolderbaseError::WouldOverwrite(display));
        }
        parent
            .remove_file(&temporary)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        sync_directory(&parent, &display)?;
        verify_exact_file(&parent, &name, replacement, &display)
    }

    pub(crate) fn recover_owned_exchange_artifacts(
        &self,
        relative: &Path,
        exchange_owner: &str,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, _) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        validate_exchange_owner(exchange_owner, &display)?;
        let mut removed = false;
        for artifact in [
            OsString::from(format!(".exchange-{exchange_owner}.tmp")),
            OsString::from(format!(".exchange-backup-{exchange_owner}.tmp")),
        ] {
            match parent.symlink_metadata(&artifact) {
                Ok(_) => {}
                Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => return Err(FolderbaseError::io(&display, source)),
            }
            if verify_exact_file(&parent, &artifact, expected, &display).is_err()
                && verify_exact_file(&parent, &artifact, replacement, &display).is_err()
            {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: format!(
                        "owned exchange artifact {} does not match either sealed state",
                        artifact.to_string_lossy()
                    ),
                });
            }
            parent
                .remove_file(&artifact)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            removed = true;
        }
        if removed {
            sync_directory(&parent, &display)?;
        }
        Ok(())
    }

    pub(crate) fn remove_durable(&self, relative: &Path) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = match self.open_parent(&relative) {
            Ok(parent) => parent,
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let display = self.display_path(&relative);
        match parent.remove_file(&name) {
            Ok(()) => sync_directory(&parent, &display),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(FolderbaseError::io(display, source)),
        }
    }

    pub(crate) fn remove_private_leaf_durable(&self, relative: &Path) -> Result<()> {
        let relative = state_relative(relative)?;
        self.require_mutable(&relative)?;
        let (parent, name) = match self.open_parent(&relative) {
            Ok(parent) => parent,
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let display = self.display_path(&relative);
        match remove_private_leaf(&parent, &name, &display) {
            Ok(()) => {
                let parent_display = display.parent().unwrap_or(&display);
                sync_directory(&parent, parent_display)
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Err(error) => Err(error),
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

    pub(crate) fn display_root(&self) -> &Path {
        &self.display_root
    }

    pub(crate) fn verify_root_identity(&self, expected: &PhysicalIdentity) -> Result<()> {
        if &self.root_identity != expected {
            return Err(FolderbaseError::UnsafePath(self.display_root.clone()));
        }
        self.verify_still_attached()
    }

    pub(crate) fn classify_attached_root_boundary(&self) -> Result<NestedFolderbaseBoundaryKind> {
        self.verify_still_attached()?;
        classify_nested_folderbase_boundary(&self.root, &self.display_root)
    }

    /// Clone the exact retained root authority for a sibling deep module.
    ///
    /// The clone names the same directory object even if the ambient display
    /// path is concurrently renamed or replaced. Callers must use
    /// `display_root` only for diagnostics.
    pub(crate) fn clone_root_capability(&self) -> Result<Dir> {
        self.root
            .try_clone()
            .map_err(|source| FolderbaseError::io(&self.display_root, source))
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
                if classify_nested_folderbase_boundary(&directory, &display)?
                    != NestedFolderbaseBoundaryKind::None
                {
                    return Err(FolderbaseError::UnsafePath(display));
                }
            }
        }
        Ok((directory, name))
    }

    fn open_workspace_target_capability(
        &self,
        relative: &Path,
    ) -> Result<WorkspaceTargetCapability> {
        self.verify_still_attached()?;
        let (parent, name) = self.open_workspace_parent(relative)?;
        let parent_display = relative.parent().map_or_else(
            || self.display_root.clone(),
            |path| self.display_root.join(path),
        );
        let parent_identity = directory_identity(&parent, &parent_display)?;
        self.verify_still_attached()?;
        Ok(WorkspaceTargetCapability {
            parent,
            parent_identity,
            relative: relative.to_path_buf(),
            name,
            parent_display,
            display: self.display_root.join(relative),
        })
    }

    fn reopen_workspace_target_capability(
        &self,
        target: &WorkspaceTargetCapability,
    ) -> Result<Dir> {
        self.verify_still_attached()?;
        let (parent, name) = self.open_workspace_parent(&target.relative)?;
        if name != target.name
            || directory_identity(&parent, &target.parent_display)? != target.parent_identity
        {
            return Err(FolderbaseError::UnsafePath(target.parent_display.clone()));
        }
        self.verify_still_attached()?;
        Ok(parent)
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

fn sanitize_private_directory_queued(
    directory: Dir,
    display: PathBuf,
    access: StateAccess,
    retained_file: &OsStr,
) -> Result<()> {
    sanitize_private_directory_queued_with_root_entry_visibility(
        directory,
        display,
        access,
        retained_file,
        |_, _| true,
    )
}

fn sanitize_private_directory_queued_with_root_entry_visibility(
    directory: Dir,
    display: PathBuf,
    access: StateAccess,
    retained_file: &OsStr,
    mut root_entry_is_visible: impl FnMut(usize, &OsStr) -> bool,
) -> Result<()> {
    let queue_name = OsString::from(format!(".sanitize-{}.tmp", Uuid::now_v7()));
    let queue_display = display.join(&queue_name);
    directory
        .create_dir_with(&queue_name, &private_directory_builder())
        .map_err(|source| FolderbaseError::io(&queue_display, source))?;
    let queue = open_directory_nofollow(&directory, &queue_name, &queue_display, access)
        .map_err(|source| FolderbaseError::io(&queue_display, source))?;
    sync_directory(&directory, &display)?;

    let mut pass = 0_usize;
    loop {
        let mut root_changed = false;
        for entry in directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&display, source))?
        {
            let entry = entry.map_err(|source| FolderbaseError::io(&display, source))?;
            let name = entry.file_name();
            if !root_entry_is_visible(pass, &name) {
                continue;
            }
            if name == queue_name {
                continue;
            }
            let child_display = display.join(&name);
            let metadata = match directory.symlink_metadata(&name) {
                Ok(metadata) => metadata,
                Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => return Err(FolderbaseError::io(&child_display, source)),
            };
            if retained_file == name.as_os_str() && private_metadata_is_regular_file(&metadata) {
                continue;
            }
            if private_metadata_is_directory(&metadata) {
                let queued_name = private_sanitize_work_name();
                directory
                    .rename(&name, &queue, &queued_name)
                    .map_err(|source| FolderbaseError::io(&child_display, source))?;
            } else {
                remove_private_leaf(&directory, &name, &child_display)?;
            }
            root_changed = true;
        }
        if !root_changed {
            break;
        }
        sync_directory(&directory, &display)?;
        sync_directory(&queue, &queue_display)?;
        pass = pass.saturating_add(1);
    }

    drain_private_sanitize_queue(&queue, &queue_display, access)?;
    directory
        .remove_dir(&queue_name)
        .map_err(|source| FolderbaseError::io(&queue_display, source))?;
    sync_directory(&directory, &display)
}

fn drain_private_sanitize_queue(
    queue: &Dir,
    queue_display: &Path,
    access: StateAccess,
) -> Result<()> {
    loop {
        let mut observed = false;
        for entry in queue
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(queue_display, source))?
        {
            observed = true;
            let entry = entry.map_err(|source| FolderbaseError::io(queue_display, source))?;
            let name = entry.file_name();
            let work_display = queue_display.join(&name);
            let metadata = match queue.symlink_metadata(&name) {
                Ok(metadata) => metadata,
                Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => return Err(FolderbaseError::io(&work_display, source)),
            };
            if !private_metadata_is_directory(&metadata) {
                remove_private_leaf(queue, &name, &work_display)?;
                continue;
            }
            let work = open_directory_nofollow(queue, &name, &work_display, access)
                .map_err(|source| FolderbaseError::io(&work_display, source))?;
            loop {
                let mut work_observed = false;
                let mut moved_directory = false;
                for child in work
                    .read_dir(".")
                    .map_err(|source| FolderbaseError::io(&work_display, source))?
                {
                    work_observed = true;
                    let child =
                        child.map_err(|source| FolderbaseError::io(&work_display, source))?;
                    let child_name = child.file_name();
                    let child_display = work_display.join(&child_name);
                    let child_metadata = match work.symlink_metadata(&child_name) {
                        Ok(metadata) => metadata,
                        Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                        Err(source) => return Err(FolderbaseError::io(&child_display, source)),
                    };
                    if private_metadata_is_directory(&child_metadata) {
                        let queued_name = private_sanitize_work_name();
                        work.rename(&child_name, queue, &queued_name)
                            .map_err(|source| FolderbaseError::io(&child_display, source))?;
                        moved_directory = true;
                    } else {
                        remove_private_leaf(&work, &child_name, &child_display)?;
                    }
                }
                if !work_observed {
                    break;
                }
                if moved_directory {
                    sync_directory(queue, queue_display)?;
                }
                sync_directory(&work, &work_display)?;
            }
            drop(work);
            queue
                .remove_dir(&name)
                .map_err(|source| FolderbaseError::io(&work_display, source))?;
        }
        if !observed {
            return Ok(());
        }
        sync_directory(queue, queue_display)?;
    }
}

fn private_sanitize_work_name() -> OsString {
    OsString::from(format!("work-{}", Uuid::now_v7()))
}

fn private_metadata_is_regular_file(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_file() && !private_metadata_is_link_or_reparse(metadata)
}

fn private_metadata_is_directory(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_dir() && !private_metadata_is_link_or_reparse(metadata)
}

fn private_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    false
}

fn remove_private_leaf(parent: &Dir, name: &OsStr, display: &Path) -> Result<()> {
    match parent.remove_file(name) {
        Ok(()) => Ok(()),
        #[cfg(windows)]
        Err(source)
            if matches!(
                source.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::IsADirectory
            ) =>
        {
            parent
                .remove_dir(name)
                .map_err(|source| FolderbaseError::io(display, source))
        }
        Err(source) => Err(FolderbaseError::io(display, source)),
    }
}

#[cfg(target_os = "macos")]
fn atomic_exchange_with_hook(
    parent: &Dir,
    _parent_display: &Path,
    left: &OsStr,
    right: &OsStr,
    _exchange_owner: &str,
    after_exchange: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

    let left = CString::new(left.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in exchange path"))?;
    let right = CString::new(right.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in exchange path"))?;
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 {
        after_exchange()
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn atomic_exchange_with_hook(
    parent: &Dir,
    _parent_display: &Path,
    left: &OsStr,
    right: &OsStr,
    _exchange_owner: &str,
    after_exchange: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

    let left = CString::new(left.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in exchange path"))?;
    let right = CString::new(right.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in exchange path"))?;
    const RENAME_EXCHANGE: libc::c_uint = 2;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        after_exchange()
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn atomic_exchange_with_hook(
    parent: &Dir,
    parent_display: &Path,
    left: &OsStr,
    right: &OsStr,
    exchange_owner: &str,
    after_exchange: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let replaced = parent_display.join(right);
    let replacement = parent_display.join(left);
    let backup_name = OsString::from(format!(".exchange-backup-{exchange_owner}.tmp"));
    let backup = parent_display.join(&backup_name);
    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let replaced_wide = wide(&replaced);
    let replacement_wide = wide(&replacement);
    let backup_wide = wide(&backup);
    let result = unsafe {
        ReplaceFileW(
            replaced_wide.as_ptr(),
            replacement_wide.as_ptr(),
            backup_wide.as_ptr(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    after_exchange()?;
    parent.rename(&backup_name, parent, left)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn atomic_exchange_with_hook(
    _parent: &Dir,
    _parent_display: &Path,
    _left: &OsStr,
    _right: &OsStr,
    _exchange_owner: &str,
    _after_exchange: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic file exchange is unavailable on this platform",
    ))
}

fn validate_exchange_owner(exchange_owner: &str, display: &Path) -> Result<()> {
    if !matches!(
        Uuid::parse_str(exchange_owner),
        Ok(owner) if owner.hyphenated().to_string() == exchange_owner
    ) {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "exchange owner is not a canonical UUID".to_owned(),
        });
    }
    Ok(())
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

fn regular_file_identity(parent: &Dir, name: &OsStr, display: &Path) -> Result<PhysicalIdentity> {
    let file = open_regular_file_nofollow(parent, name, display)?;
    open_regular_file_identity(&file, display)
}

#[cfg(unix)]
fn planning_regular_file_identity(parent: &Dir, name: &OsStr, display: &Path) -> Result<String> {
    use cap_std::fs::MetadataExt;

    let metadata = parent
        .symlink_metadata(name)
        .map_err(|source| FolderbaseError::io(display, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    Ok(
        crate::folderbase_restore_authority::stable_unix_file_identity_sha256(
            metadata.dev(),
            metadata.ino(),
        ),
    )
}

#[cfg(windows)]
fn planning_regular_file_identity(parent: &Dir, name: &OsStr, display: &Path) -> Result<String> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = CapOpenOptions::new();
    options
        .access_mode(0)
        .follow(FollowSymlinks::No)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let file = parent
        .open_with(name, &options)
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std();
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    stable_file_identity_sha256(&file).map_err(|source| FolderbaseError::io(display, source))
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

fn open_regular_file_identity(
    file: &cap_std::fs::File,
    display: &Path,
) -> Result<PhysicalIdentity> {
    let file = file
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std();
    PhysicalIdentity::from_file(&file).map_err(|source| FolderbaseError::io(display, source))
}

fn verify_restore_retirement_publication(
    retained_file: &cap_std::fs::File,
    retained_display: &Path,
    destination_parent: &Dir,
    destination_name: &OsStr,
    destination_display: &Path,
    expected_identity_sha256: &str,
    expected_fidelity: Option<(&str, u64, bool)>,
) -> Result<()> {
    if stable_regular_file_identity_sha256(retained_file, retained_display)?
        != expected_identity_sha256
    {
        return Err(FolderbaseError::InvalidRecord {
            path: retained_display.to_path_buf(),
            message: "restore private state no longer has the published identity".to_owned(),
        });
    }
    let mut retained_fidelity = retained_file
        .try_clone()
        .map_err(|source| FolderbaseError::io(retained_display, source))?;
    if let Some((digest, bytes, executable)) = expected_fidelity {
        verify_open_regular_file(
            &mut retained_fidelity,
            digest,
            bytes,
            executable,
            retained_display,
        )?;
    }

    let mut destination_file =
        open_regular_file_nofollow(destination_parent, destination_name, destination_display)?;
    if stable_regular_file_identity_sha256(&destination_file, destination_display)?
        != expected_identity_sha256
        || open_regular_file_identity(&destination_file, destination_display)?
            != open_regular_file_identity(retained_file, retained_display)?
    {
        return Err(FolderbaseError::InvalidRecord {
            path: destination_display.to_path_buf(),
            message: "workspace file no longer has the restore publication identity".to_owned(),
        });
    }
    if let Some((digest, bytes, executable)) = expected_fidelity {
        verify_open_regular_file(
            &mut destination_file,
            digest,
            bytes,
            executable,
            destination_display,
        )?;
    }
    Ok(())
}

fn verify_restore_retained_stage(
    stage_parent: &Dir,
    stage_name: &OsStr,
    stage_display: &Path,
    retained_file: &cap_std::fs::File,
    expected_identity_sha256: &str,
) -> Result<()> {
    let visible_stage = open_regular_file_nofollow(stage_parent, stage_name, stage_display)?;
    if open_regular_file_identity(&visible_stage, stage_display)?
        != open_regular_file_identity(retained_file, stage_display)?
        || stable_regular_file_identity_sha256(&visible_stage, stage_display)?
            != expected_identity_sha256
    {
        return Err(FolderbaseError::InvalidRecord {
            path: stage_display.to_path_buf(),
            message: "restore authority path no longer names the retained stage".to_owned(),
        });
    }
    require_restore_link_count(retained_file, 2, stage_display)?;
    Ok(())
}

fn require_restore_link_count(
    file: &cap_std::fs::File,
    expected: u64,
    display: &Path,
) -> Result<()> {
    let file = file
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std();
    let actual =
        stable_file_link_count(&file).map_err(|source| FolderbaseError::io(display, source))?;
    if actual != expected {
        return Err(FolderbaseError::RestoreNamespaceRepairRequired(
            display.to_path_buf(),
        ));
    }
    Ok(())
}

fn stable_regular_file_identity_sha256(file: &cap_std::fs::File, display: &Path) -> Result<String> {
    let file = file
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std();
    stable_file_identity_sha256(&file).map_err(|source| FolderbaseError::io(display, source))
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
    file.seek(SeekFrom::Start(0))
        .map_err(|source| FolderbaseError::io(display, source))?;
    #[cfg(not(unix))]
    let _ = executable;
    verify_open_regular_metadata(file, bytes, display)?;
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
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        };
        options
            // The directory handle is namespace authority, not a data stream.
            // Child reads and mutations open their own capability-relative
            // handles, so requesting GENERIC_READ/WRITE here only rejects
            // valid Windows directory ACLs without adding authority.
            .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
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
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    };

    let mut options = CapOpenOptions::new();
    options
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES)
        .follow(FollowSymlinks::No)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    let _ = access;
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

fn directory_identity(directory: &Dir, display: &Path) -> Result<PhysicalIdentity> {
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
    PhysicalIdentity::from_file(&file).map_err(|source| FolderbaseError::io(display, source))
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
    let observed_identity = PhysicalIdentity::from_file(&file)
        .map_err(|source| FolderbaseError::io(display, source))?;
    if observed_identity != expected_identity {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    file.sync_all()
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    directory
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std_file()
        .sync_all()
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(windows)]
fn sync_directory(_directory: &Dir, _display: &Path) -> Result<()> {
    // Windows does not provide the POSIX directory-fsync contract, and
    // FlushFileBuffers rejects directory handles with ERROR_ACCESS_DENIED.
    // File publication still flushes each staged regular file before its
    // no-clobber namespace transition.
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use tempfile::{TempDir, tempdir};

    use super::*;

    const RESTORE_SOURCE: &str = ".folderbase/source";
    const RESTORE_STAGE: &str = ".folderbase/transactions/restore-stage";
    const RESTORE_DESTINATION: &str = "project/restored.bin";

    #[test]
    fn private_namespace_sanitizer_rescans_after_a_root_entry_is_skipped() {
        let fixture = tempdir().expect("fixture");
        let index_root = fixture.path().join(".folderbase/local/query-index-v1");
        fs::create_dir_all(&index_root).expect("private namespace");
        fs::write(index_root.join("index.json"), b"retained\n").expect("retained record");
        fs::write(index_root.join("visible-junk"), b"junk\n").expect("visible crash junk");
        fs::write(index_root.join("skipped-junk"), b"junk\n").expect("crash junk");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");
        let directory = state
            .open_dir(Path::new("local/query-index-v1"))
            .expect("private directory capability");
        let mut skipped = false;

        sanitize_private_directory_queued_with_root_entry_visibility(
            directory,
            index_root.clone(),
            StateAccess::Mutable,
            OsStr::new("index.json"),
            |pass, name| {
                if pass == 0 && name == OsStr::new("skipped-junk") {
                    skipped = true;
                    false
                } else {
                    true
                }
            },
        )
        .expect("sanitize private namespace");

        assert!(
            skipped,
            "the seam must omit original junk on the first pass"
        );
        let names = fs::read_dir(&index_root)
            .expect("sanitized namespace")
            .map(|entry| entry.expect("namespace entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [OsString::from("index.json")]);
    }

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

    #[cfg(unix)]
    #[test]
    fn exact_private_leaf_removal_unlinks_a_directory_link_without_following_it() {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::create_dir_all(fixture.path().join(".folderbase/local")).expect("private parent");
        let outside = tempdir().expect("outside target");
        fs::write(outside.path().join("sentinel"), b"outside\n").expect("outside sentinel");
        let link = fixture.path().join(".folderbase/local/query-index-v1");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &link).expect("directory link");
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside.path(), &link)
            .expect("GitHub Windows runner can create directory symlinks");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");

        state
            .remove_private_leaf_durable(Path::new(".folderbase/local/query-index-v1"))
            .expect("unlink exact private leaf");

        assert!(!link.exists());
        assert_eq!(
            fs::read(outside.path().join("sentinel")).expect("outside sentinel remains"),
            b"outside\n"
        );
    }

    #[cfg(windows)]
    #[test]
    fn exact_private_leaf_removal_unlinks_a_windows_junction_without_following_it() {
        use std::process::Command;

        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::create_dir_all(fixture.path().join(".folderbase/local")).expect("private parent");
        let outside = tempdir().expect("outside target");
        fs::write(outside.path().join("sentinel"), b"outside\n").expect("outside sentinel");
        let link = fixture
            .path()
            .join(".folderbase")
            .join("local")
            .join("query-index-v1");
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(outside.path())
            .output()
            .expect("create directory junction");
        assert!(
            output.status.success(),
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");

        state
            .remove_private_leaf_durable(Path::new(".folderbase/local/query-index-v1"))
            .expect("unlink exact private leaf");

        assert!(!link.exists());
        assert_eq!(
            fs::read(outside.path().join("sentinel")).expect("outside sentinel remains"),
            b"outside\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_restore_stage_fidelity_is_independent_of_process_umask() {
        const CHILD_MARKER: &str = "FOLDERBASE_RESTRICTIVE_UMASK_CHILD";
        const TEST_NAME: &str = "folderbase_state::tests::executable_restore_stage_fidelity_is_independent_of_process_umask";

        if std::env::var_os(CHILD_MARKER).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("current unit-test executable"),
            )
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_MARKER, "1")
            .output()
            .expect("run restrictive-umask test in an isolated serial process");
            assert!(
                output.status.success(),
                "restrictive-umask child failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        struct ScopedUmask(libc::mode_t);

        impl ScopedUmask {
            fn replace(mask: libc::mode_t) -> Self {
                // SAFETY: this runs in an isolated single-test child process,
                // and Drop restores the previous process-global mask.
                Self(unsafe { libc::umask(mask) })
            }
        }

        impl Drop for ScopedUmask {
            fn drop(&mut self) {
                // SAFETY: this restores the mask captured by `replace` in the
                // same isolated process before it exits.
                unsafe {
                    libc::umask(self.0);
                }
            }
        }

        use std::os::unix::fs::PermissionsExt;

        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::create_dir(fixture.path().join(".folderbase/transactions")).expect("transactions");
        let expected = b"#!/bin/sh\nexit 0\n";
        fs::write(fixture.path().join(RESTORE_SOURCE), expected).expect("restore source");
        let digest = format!("{:x}", Sha256::digest(expected));
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");

        let _umask = ScopedUmask::replace(0o777);
        state
            .stage_restore_blob(
                Path::new(RESTORE_SOURCE),
                Path::new(RESTORE_STAGE),
                &digest,
                expected.len() as u64,
                true,
            )
            .expect("executable staging is independent of the creation mask");

        let mode = fs::metadata(fixture.path().join(RESTORE_STAGE))
            .expect("staged metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
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

    #[test]
    fn exchange_recovery_reclaims_only_exact_owned_artifacts() {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        let manifest = fixture.path().join(".folderbase/manifest.json");
        let expected = b"legacy manifest\n";
        let replacement = b"ordinary manifest\n";
        fs::write(&manifest, expected).expect("manifest");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");
        let owner = Uuid::now_v7().to_string();
        let owned = fixture
            .path()
            .join(format!(".folderbase/.exchange-{owner}.tmp"));
        let foreign = fixture
            .path()
            .join(".folderbase/.exchange-backup-foreign.tmp");
        fs::write(&owned, replacement).expect("owned artifact");
        fs::write(&foreign, expected).expect("foreign artifact");

        state
            .recover_owned_exchange_artifacts(
                Path::new(".folderbase/manifest.json"),
                &owner,
                expected,
                replacement,
            )
            .expect("owned cleanup");

        assert!(!owned.exists());
        assert!(foreign.exists(), "unowned artifacts are never reclaimed");
        assert_eq!(fs::read(manifest).expect("manifest"), expected);

        fs::write(&owned, b"unsealed bytes").expect("mismatched owned name");
        assert!(
            state
                .recover_owned_exchange_artifacts(
                    Path::new(".folderbase/manifest.json"),
                    &owner,
                    expected,
                    replacement,
                )
                .is_err(),
            "an owned name alone never authorizes deletion"
        );
        assert!(
            owned.exists(),
            "mismatched recovery evidence remains for inspection"
        );
    }

    #[cfg(windows)]
    #[test]
    fn interrupted_windows_exchange_reclaims_only_its_owned_artifacts() {
        let fixture = tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        let manifest = fixture.path().join(".folderbase/manifest.json");
        let expected = b"legacy manifest\n";
        let replacement = b"ordinary manifest\n";
        fs::write(&manifest, expected).expect("manifest");
        let state = FolderbaseState::open_existing(fixture.path()).expect("state capability");
        let owner = Uuid::now_v7().to_string();
        let foreign = fixture
            .path()
            .join(".folderbase/.exchange-backup-foreign.tmp");
        fs::write(&foreign, expected).expect("foreign artifact");

        state
            .compare_exchange_exact_owned_with_hooks(
                Path::new(".folderbase/manifest.json"),
                expected,
                replacement,
                &owner,
                || {},
                || Err(io::Error::other("simulated crash after ReplaceFileW")),
            )
            .expect_err("interrupted exchange");
        let owned = fixture
            .path()
            .join(format!(".folderbase/.exchange-backup-{owner}.tmp"));
        assert!(owned.exists(), "fault leaves the exact owned backup");

        state
            .recover_owned_exchange_artifacts(
                Path::new(".folderbase/manifest.json"),
                &owner,
                expected,
                replacement,
            )
            .expect("owned cleanup");
        assert!(!owned.exists());
        assert!(foreign.exists(), "unowned artifacts are never reclaimed");
        assert_eq!(fs::read(manifest).expect("target manifest"), replacement);
    }
}
