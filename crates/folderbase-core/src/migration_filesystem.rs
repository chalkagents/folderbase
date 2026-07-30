//! Exact-root filesystem authority for migration apply, recovery, and rollback.
//!
//! A migration's display path is mutable ambient namespace. This module keeps
//! that path diagnostic-only after transaction coordination and performs every
//! durable read or mutation relative to one retained, no-follow root handle.

use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use cap_fs_ext::DirExt;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(windows)]
use crate::root_attestation::metadata_is_link_or_reparse;
use crate::{FolderbaseError, Result, folderbase_state::FolderbaseState};

pub(crate) struct MigrationFilesystem {
    root: Dir,
    display_root: PathBuf,
}

impl MigrationFilesystem {
    pub(crate) fn from_state(state: &FolderbaseState, display_root: &Path) -> Result<Self> {
        Ok(Self {
            root: state.clone_root_capability()?,
            display_root: display_root.to_path_buf(),
        })
    }

    pub(crate) fn display_root(&self) -> &Path {
        &self.display_root
    }

    pub(crate) fn display(&self, relative: &Path) -> PathBuf {
        self.display_root.join(relative)
    }

    pub(crate) fn metadata(&self, relative: &Path) -> Result<Option<Metadata>> {
        let (parent, name) = match self.open_parent(relative) {
            Ok(parent) => parent,
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let display = self.display(relative);
        match parent.symlink_metadata(&name) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(FolderbaseError::io(display, source)),
        }
    }

    pub(crate) fn read_regular_bounded(
        &self,
        relative: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > maximum_bytes
        {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "migration file is unsafe or exceeds its bounded size".to_owned(),
            });
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| FolderbaseError::io(self.display(relative), source))?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: self.display(relative),
                message: "migration file exceeds its bounded size".to_owned(),
            });
        }
        Ok(bytes)
    }

    pub(crate) fn sha256_regular(&self, relative: &Path) -> Result<String> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(display));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|source| FolderbaseError::io(self.display(relative), source))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub(crate) fn sha256_regular_if_present(&self, relative: &Path) -> Result<Option<String>> {
        match self.metadata(relative)? {
            None => Ok(None),
            Some(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                self.sha256_regular(relative).map(Some)
            }
            Some(_) => Ok(None),
        }
    }

    pub(crate) fn physical_identity_sha256(&self, relative: &Path) -> Result<String> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std();
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(display));
        }
        crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map(crate::physical_identity::PhysicalIdentity::stable_sha256)
            .map_err(|source| FolderbaseError::io(self.display(relative), source))
    }

    pub(crate) fn ensure_directory(&self, relative: &Path) -> Result<()> {
        validate_relative(relative, true)?;
        let mut directory = self
            .root
            .try_clone()
            .map_err(|source| FolderbaseError::io(&self.display_root, source))?;
        let mut walked = PathBuf::new();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
            };
            walked.push(name);
            let display = self.display(&walked);
            directory = match open_directory_nofollow(&directory, name, &display) {
                Ok(child) => child,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    match directory.create_dir(name) {
                        Ok(()) => sync_directory(&directory, &display)?,
                        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(source) => return Err(FolderbaseError::io(&display, source)),
                    }
                    open_directory_nofollow(&directory, name, &display)
                        .map_err(|source| FolderbaseError::io(&display, source))?
                }
                Err(source) => return Err(FolderbaseError::io(&display, source)),
            };
        }
        Ok(())
    }

    pub(crate) fn create_directory(&self, relative: &Path) -> Result<()> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        parent.create_dir(&name).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                FolderbaseError::WouldOverwrite(display.clone())
            } else {
                FolderbaseError::io(&display, source)
            }
        })?;
        sync_directory(&parent, &display)
    }

    pub(crate) fn ensure_private_directory(&self, relative: &Path) -> Result<()> {
        self.ensure_directory(relative)?;
        #[cfg(unix)]
        {
            use cap_std::fs::{Permissions, PermissionsExt};

            let (parent, name) = self.open_parent(relative)?;
            let display = self.display(relative);
            parent
                .set_permissions(&name, Permissions::from_mode(0o700))
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let mode = parent
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o700 {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: "private migration directory is not owner-only".to_owned(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn set_private_regular_mode(&self, relative: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use cap_std::fs::{Permissions, PermissionsExt};

            let (parent, name) = self.open_parent(relative)?;
            let display = self.display(relative);
            let metadata = parent
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(FolderbaseError::UnsafePath(display));
            }
            parent
                .set_permissions(&name, Permissions::from_mode(0o600))
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let mode = parent
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o600 {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: "private migration file is not owner-only".to_owned(),
                });
            }
        }
        #[cfg(not(unix))]
        {
            let _ = relative;
        }
        Ok(())
    }

    pub(crate) fn publish_new(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        self.publish_new_with_hook(relative, bytes, || {})
    }

    pub(crate) fn publish_private_new(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        self.publish_new(relative, bytes)?;
        self.set_private_regular_mode(relative)
    }

    pub(crate) fn publish_new_with_hook(
        &self,
        relative: &Path,
        bytes: &[u8],
        after_stage: impl FnOnce(),
    ) -> Result<()> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let temporary = OsString::from(format!(".migration-{}.tmp", Uuid::now_v7()));
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| -> Result<()> {
            let mut file = parent
                .open_with(&temporary, &options)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| FolderbaseError::io(&display, source))?;
            drop(file);
            after_stage();
            parent
                .hard_link(&temporary, &parent, &name)
                .map_err(|source| {
                    if source.kind() == std::io::ErrorKind::AlreadyExists {
                        FolderbaseError::WouldOverwrite(display.clone())
                    } else {
                        FolderbaseError::io(&display, source)
                    }
                })?;
            parent
                .remove_file(&temporary)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            sync_directory(&parent, &display)
        })();
        if result.is_err() {
            let _ = parent.remove_file(&temporary);
        }
        result
    }

    pub(crate) fn replace(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let metadata = parent
            .symlink_metadata(&name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(display));
        }
        let temporary = OsString::from(format!(".migration-{}.tmp", Uuid::now_v7()));
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let result = (|| -> Result<()> {
            let mut file = parent
                .open_with(&temporary, &options)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            file.set_permissions(metadata.permissions())
                .map_err(|source| FolderbaseError::io(&display, source))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| FolderbaseError::io(&display, source))?;
            drop(file);
            parent
                .rename(&temporary, &parent, &name)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            sync_directory(&parent, &display)
        })();
        if result.is_err() {
            let _ = parent.remove_file(&temporary);
        }
        result
    }

    pub(crate) fn copy_regular_new(&self, source: &Path, destination: &Path) -> Result<()> {
        let (source_parent, source_name) = self.open_parent(source)?;
        let source_display = self.display(source);
        let mut read_options = OpenOptions::new();
        read_options.read(true).follow(FollowSymlinks::No);
        let mut source_file = source_parent
            .open_with(&source_name, &read_options)
            .map_err(|error| FolderbaseError::io(&source_display, error))?;
        let source_metadata = source_file
            .metadata()
            .map_err(|error| FolderbaseError::io(&source_display, error))?;
        if !source_metadata.is_file() || source_metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(source_display));
        }

        let (destination_parent, destination_name) = self.open_parent(destination)?;
        let destination_display = self.display(destination);
        let mut write_options = OpenOptions::new();
        write_options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let mut destination_file = destination_parent
            .open_with(&destination_name, &write_options)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    FolderbaseError::WouldOverwrite(destination_display.clone())
                } else {
                    FolderbaseError::io(&destination_display, error)
                }
            })?;
        let result = (|| -> Result<()> {
            destination_file
                .set_permissions(source_metadata.permissions())
                .map_err(|error| FolderbaseError::io(&destination_display, error))?;
            std::io::copy(&mut source_file, &mut destination_file)
                .and_then(|_| destination_file.sync_all())
                .map_err(|error| FolderbaseError::io(&destination_display, error))?;
            sync_directory(&destination_parent, &destination_display)
        })();
        if result.is_err() {
            let _ = destination_parent.remove_file(&destination_name);
        }
        result
    }

    pub(crate) fn hard_link(&self, source: &Path, destination: &Path) -> Result<()> {
        let (source_parent, source_name) = self.open_parent(source)?;
        let (destination_parent, destination_name) = self.open_parent(destination)?;
        let display = self.display(destination);
        source_parent
            .hard_link(&source_name, &destination_parent, &destination_name)
            .map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    FolderbaseError::WouldOverwrite(display.clone())
                } else {
                    FolderbaseError::io(&display, source)
                }
            })?;
        sync_directory(&destination_parent, &display)
    }

    pub(crate) fn remove_file(&self, relative: &Path) -> Result<()> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        parent
            .remove_file(&name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        sync_directory(&parent, &display)
    }

    pub(crate) fn remove_file_if_present(&self, relative: &Path) -> Result<()> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        match parent.remove_file(&name) {
            Ok(()) => sync_directory(&parent, &display),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(FolderbaseError::io(display, source)),
        }
    }

    pub(crate) fn remove_empty_directory_if_present(&self, relative: &Path) -> Result<bool> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let directory = match open_directory_nofollow(&parent, &name, &display) {
            Ok(directory) => directory,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => return Err(FolderbaseError::io(display, source)),
        };
        if directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&display, source))?
            .next()
            .is_some()
        {
            return Ok(false);
        }
        drop(directory);
        parent
            .remove_dir(&name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        sync_directory(&parent, &display)?;
        Ok(true)
    }

    pub(crate) fn directory_file_names(&self, relative: &Path) -> Result<Vec<OsString>> {
        let directory = self.open_directory(relative)?;
        let display = self.display(relative);
        let mut names = Vec::new();
        for entry in directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&display, source))?
        {
            let entry = entry.map_err(|source| FolderbaseError::io(&display, source))?;
            if entry
                .file_type()
                .map_err(|source| FolderbaseError::io(&display, source))?
                .is_file()
            {
                names.push(entry.file_name());
            }
        }
        Ok(names)
    }

    pub(crate) fn open_directory(&self, relative: &Path) -> Result<Dir> {
        validate_relative(relative, true)?;
        let mut directory = self
            .root
            .try_clone()
            .map_err(|source| FolderbaseError::io(&self.display_root, source))?;
        let mut walked = PathBuf::new();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
            };
            walked.push(name);
            let display = self.display(&walked);
            directory = open_directory_nofollow(&directory, name, &display)
                .map_err(|source| FolderbaseError::io(&display, source))?;
        }
        Ok(directory)
    }

    pub(crate) fn open_parent(&self, relative: &Path) -> Result<(Dir, OsString)> {
        validate_relative(relative, false)?;
        let name = relative
            .file_name()
            .ok_or_else(|| FolderbaseError::UnsafePath(relative.to_path_buf()))?
            .to_os_string();
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        Ok((self.open_directory(parent)?, name))
    }
}

fn validate_relative(path: &Path, allow_empty: bool) -> Result<()> {
    if path.as_os_str().is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(FolderbaseError::UnsafePath(path.to_path_buf()))
        };
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(windows))]
fn open_directory_nofollow(parent: &Dir, name: &OsStr, _display: &Path) -> std::io::Result<Dir> {
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
fn open_directory_nofollow(parent: &Dir, name: &OsStr, display: &Path) -> std::io::Result<Dir> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    options
        .access_mode(GENERIC_READ | GENERIC_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let file = parent.open_with(name, &options)?.into_std();
    let metadata = file.metadata()?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::other(format!(
            "unsafe migration directory capability: {}",
            display.display()
        )));
    }
    Ok(Dir::from_std_file(file))
}

#[cfg(unix)]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(Path::new("."), &options)
        .and_then(|file| file.into_std().sync_all())
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(windows)]
fn sync_directory(_directory: &Dir, _display: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().sync_all())
        .map_err(|source| FolderbaseError::io(display, source))
}
