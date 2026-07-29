//! Capability-confined publication for mutable and append-only `.folderbase` state.
//!
//! Display paths are retained only for diagnostics. Every filesystem operation
//! is relative to a retained, no-follow directory capability.

use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use same_file::Handle;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{FolderbaseError, Result};

const STATE_COMPONENT: &str = ".folderbase";
const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) struct PublishedBlob {
    pub(crate) digest: String,
    pub(crate) bytes: u64,
}

pub(crate) struct FolderbaseState {
    root: Dir,
    state: Dir,
    state_identity: Handle,
    display_root: PathBuf,
}

impl FolderbaseState {
    pub(crate) fn open(root: &Path) -> Result<Self> {
        let root_cap = open_root_nofollow(root)?;
        let state = match root_cap.open_dir_nofollow(STATE_COMPONENT) {
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
                root_cap
                    .open_dir_nofollow(STATE_COMPONENT)
                    .map_err(|source| FolderbaseError::io(root.join(STATE_COMPONENT), source))?
            }
            Err(source) => {
                return Err(FolderbaseError::io(root.join(STATE_COMPONENT), source));
            }
        };
        let state_identity = directory_identity(&state, &root.join(STATE_COMPONENT))?;
        Ok(Self {
            root: root_cap,
            state,
            state_identity,
            display_root: root.to_path_buf(),
        })
    }

    pub(crate) fn ensure_private_dir(&self, relative: &Path) -> Result<()> {
        let relative = state_relative(relative)?;
        let mut directory = self.state.try_clone().map_err(|source| {
            FolderbaseError::io(self.display_root.join(STATE_COMPONENT), source)
        })?;
        let mut display = self.display_root.join(STATE_COMPONENT);
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
            };
            display.push(name);
            directory = match directory.open_dir_nofollow(name) {
                Ok(child) => child,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    let builder = private_directory_builder();
                    match directory.create_dir_with(name, &builder) {
                        Ok(()) => sync_directory(&directory, &display)?,
                        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(source) => return Err(FolderbaseError::io(&display, source)),
                    }
                    directory
                        .open_dir_nofollow(name)
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
    ) -> Result<PublishedBlob> {
        let relative = state_relative(directory)?;
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
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|source| FolderbaseError::io(source_label, source))?;
                if read == 0 {
                    break;
                }
                staged
                    .write_all(&buffer[..read])
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                hasher.update(&buffer[..read]);
                bytes = bytes.checked_add(read as u64).ok_or_else(|| {
                    FolderbaseError::InvalidRecord {
                        path: source_label.to_path_buf(),
                        message: "content length exceeds supported range".to_owned(),
                    }
                })?;
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

    fn publish_new_with_hook(
        &self,
        relative: &Path,
        bytes: &[u8],
        after_parent_open: impl FnOnce(),
    ) -> Result<()> {
        let relative = state_relative(relative)?;
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
        let (parent, name) = self.open_parent(&relative)?;
        let display = self.display_path(&relative);
        match parent.remove_file(&name) {
            Ok(()) => sync_directory(&parent, &display),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(FolderbaseError::io(display, source)),
        }
    }

    pub(crate) fn verify_still_attached(&self) -> Result<()> {
        let visible = self
            .root
            .open_dir_nofollow(STATE_COMPONENT)
            .map_err(|source| {
                FolderbaseError::io(self.display_root.join(STATE_COMPONENT), source)
            })?;
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
                directory = directory
                    .open_dir_nofollow(component)
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
            directory = directory
                .open_dir_nofollow(component)
                .map_err(|source| FolderbaseError::io(&display, source))?;
        }
        Ok(directory)
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
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| FolderbaseError::io(display, source))?;
        if read == 0 {
            break;
        }
        observed += read as u64;
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
    let mut observed = Vec::with_capacity(expected.len());
    file.read_to_end(&mut observed)
        .map_err(|source| FolderbaseError::io(display, source))?;
    if observed != expected {
        return Err(FolderbaseError::InvalidRecord {
            path: display.to_path_buf(),
            message: "published state record bytes changed".to_owned(),
        });
    }
    Ok(())
}

fn open_root_nofollow(root: &Path) -> Result<Dir> {
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
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        options
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options
        .open(root)
        .map_err(|source| FolderbaseError::io(root, source))?;
    if !file
        .metadata()
        .map_err(|source| FolderbaseError::io(root, source))?
        .is_dir()
    {
        return Err(FolderbaseError::UnsafePath(root.to_path_buf()));
    }
    Ok(Dir::from_std_file(file))
}

fn directory_identity(directory: &Dir, display: &Path) -> Result<Handle> {
    let file = directory
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std_file();
    Handle::from_file(file).map_err(|source| FolderbaseError::io(display, source))
}

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
    use std::fs;

    use tempfile::tempdir;

    use super::*;

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
}
