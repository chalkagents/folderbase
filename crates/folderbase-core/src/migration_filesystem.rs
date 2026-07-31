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

use crate::root_attestation::metadata_is_link_or_reparse;
use crate::traversal_policy::{NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary};
use crate::{
    FolderbaseError, Result,
    folder_analysis::{FolderAnalysis, analyze_folder_from_retained},
    folderbase_state::FolderbaseState,
};

#[derive(Debug, Clone)]
pub(crate) struct MigrationRegularFact {
    pub(crate) physical_identity_sha256: String,
    pub(crate) device_sha256: String,
    pub(crate) bytes: u64,
    pub(crate) read_only: bool,
    pub(crate) unix_mode: Option<u32>,
    pub(crate) link_count: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct MigrationDirectoryFact {
    pub(crate) physical_identity_sha256: String,
    pub(crate) device_sha256: String,
    pub(crate) read_only: bool,
    pub(crate) unix_mode: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExactRegularLeaf<'a> {
    pub(crate) physical_identity_sha256: &'a str,
    pub(crate) device_sha256: &'a str,
    pub(crate) bytes: u64,
    pub(crate) sha256: &'a str,
    pub(crate) read_only: bool,
    pub(crate) executable: bool,
    pub(crate) link_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExactDirectoryLeaf<'a> {
    pub(crate) physical_identity_sha256: &'a str,
    pub(crate) device_sha256: &'a str,
    pub(crate) read_only: bool,
    pub(crate) executable: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ExactLeafClaimExpectation<'a> {
    Regular(ExactRegularLeaf<'a>),
    EmptyDirectory(ExactDirectoryLeaf<'a>),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ExactExistingClaimSource<'a> {
    Absent,
    Regular(ExactRegularLeaf<'a>),
}

pub(crate) struct ExactLeafClaimRequest<'a> {
    pub(crate) source_parent: &'a VerifiedVisibleDirectory,
    pub(crate) source_name: &'a OsStr,
    pub(crate) destination: &'a VerifiedPrivateDirectory,
    pub(crate) destination_name: &'a str,
    pub(crate) expectation: ExactLeafClaimExpectation<'a>,
    pub(crate) existing_source: ExactExistingClaimSource<'a>,
}

pub(crate) enum ExactLeafClaimResult {
    Regular(MigrationRegularFact),
    Directory(MigrationDirectoryFact),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ExactNestedBoundaryExpectation<'a> {
    None,
    StateOnly {
        state: ExactDirectoryLeaf<'a>,
    },
    Exact {
        state: ExactDirectoryLeaf<'a>,
        manifest: ExactRegularLeaf<'a>,
    },
}

pub(crate) struct MigrationFilesystem {
    root: Dir,
    display_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegularContentVersion {
    #[cfg(unix)]
    Unix {
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    },
    #[cfg(windows)]
    Windows {
        last_write_time: i64,
        change_time: i64,
    },
    #[cfg(not(any(unix, windows)))]
    Portable {
        modified: Option<std::time::SystemTime>,
        bytes: u64,
    },
}

pub(crate) struct VerifiedPrivateDirectory {
    directory: Dir,
    display: PathBuf,
}

pub(crate) struct VerifiedVisibleDirectory {
    directory: Dir,
    display: PathBuf,
    expected_identity_sha256: String,
    expected_device_sha256: String,
    read_only: bool,
    executable: bool,
}

struct VerifiedVisibleRegular {
    file: cap_std::fs::File,
    std_file: std::fs::File,
    metadata: std::fs::Metadata,
    identity: crate::physical_identity::PhysicalIdentity,
    display: PathBuf,
}

impl VerifiedVisibleDirectory {
    pub(crate) fn reverify(&self) -> Result<()> {
        let fact = directory_fact_from_handle(&self.directory, &self.display)?;
        validate_directory_fidelity(&fact, self.read_only, self.executable, &self.display)?;
        if fact.physical_identity_sha256 != self.expected_identity_sha256
            || fact.device_sha256 != self.expected_device_sha256
        {
            return Err(FolderbaseError::MigrationSourceChanged(
                self.display.clone(),
            ));
        }
        Ok(())
    }

    pub(crate) fn nested_boundary_kind(&self) -> Result<NestedFolderbaseBoundaryKind> {
        classify_nested_folderbase_boundary(&self.directory, &self.display)
    }

    pub(crate) fn require_exact_nested_boundary(
        &self,
        expectation: ExactNestedBoundaryExpectation<'_>,
    ) -> Result<()> {
        self.reverify()?;
        let observed = self.nested_boundary_kind()?;
        match expectation {
            ExactNestedBoundaryExpectation::None => {
                if observed != NestedFolderbaseBoundaryKind::None {
                    return Err(FolderbaseError::MigrationSourceChanged(
                        self.display.clone(),
                    ));
                }
                require_absent_from_retained_parent(self, OsStr::new(".folderbase"))?;
            }
            ExactNestedBoundaryExpectation::StateOnly { state } => {
                if observed != NestedFolderbaseBoundaryKind::None {
                    return Err(FolderbaseError::MigrationSourceChanged(
                        self.display.clone(),
                    ));
                }
                let state_display = self.display.join(".folderbase");
                let state_directory = open_directory_nofollow(
                    &self.directory,
                    OsStr::new(".folderbase"),
                    &state_display,
                )
                .map_err(|source| FolderbaseError::io(&state_display, source))?;
                let state_fact = directory_fact_from_handle(&state_directory, &state_display)?;
                require_exact_directory_fact(
                    &state_fact,
                    state,
                    &state_display,
                    ExactFactLocation::Visible,
                )?;
                let state_parent = VerifiedVisibleDirectory {
                    directory: state_directory,
                    display: state_display,
                    expected_identity_sha256: state.physical_identity_sha256.to_owned(),
                    expected_device_sha256: state.device_sha256.to_owned(),
                    read_only: state.read_only,
                    executable: state.executable,
                };
                require_absent_from_retained_parent(&state_parent, OsStr::new("manifest.json"))?;
                state_parent.reverify()?;
            }
            ExactNestedBoundaryExpectation::Exact { state, manifest } => {
                if observed != NestedFolderbaseBoundaryKind::ExactBoundary {
                    return Err(FolderbaseError::MigrationSourceChanged(
                        self.display.clone(),
                    ));
                }
                let state_display = self.display.join(".folderbase");
                let state_directory = open_directory_nofollow(
                    &self.directory,
                    OsStr::new(".folderbase"),
                    &state_display,
                )
                .map_err(|source| FolderbaseError::io(&state_display, source))?;
                let state_fact = directory_fact_from_handle(&state_directory, &state_display)?;
                require_exact_directory_fact(
                    &state_fact,
                    state,
                    &state_display,
                    ExactFactLocation::Visible,
                )?;
                let state_parent = VerifiedVisibleDirectory {
                    directory: state_directory,
                    display: state_display,
                    expected_identity_sha256: state.physical_identity_sha256.to_owned(),
                    expected_device_sha256: state.device_sha256.to_owned(),
                    read_only: state.read_only,
                    executable: state.executable,
                };
                require_exact_visible_claim_source(
                    &state_parent,
                    OsStr::new("manifest.json"),
                    ExactLeafClaimExpectation::Regular(manifest),
                )?;
                state_parent.reverify()?;
            }
        }
        self.reverify()
    }
}

impl VerifiedPrivateDirectory {
    pub(crate) fn display_path(&self, name: &OsStr) -> PathBuf {
        self.display.join(name)
    }

    pub(crate) fn open_directory(&self, name: &str) -> Result<Self> {
        validate_private_name(name)?;
        let display = self.display.join(name);
        let directory = open_directory_nofollow(&self.directory, OsStr::new(name), &display)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        validate_private_directory_metadata(&directory, &display)?;
        Ok(Self { directory, display })
    }

    pub(crate) fn open_relaxed_directory(&self, name: &OsStr) -> Result<Self> {
        let display = self.display.join(name);
        let directory = open_directory_nofollow(&self.directory, name, &display)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let _ = directory_fact_from_handle(&directory, &display)?;
        Ok(Self { directory, display })
    }

    pub(crate) fn relaxed_directory_fact(&self, name: &OsStr) -> Result<MigrationDirectoryFact> {
        let display = self.display.join(name);
        let directory = open_directory_nofollow(&self.directory, name, &display)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        directory_fact_from_handle(&directory, &display)
    }

    pub(crate) fn prepare_directory_claim(
        &self,
        name: &str,
        read_only: bool,
        executable: bool,
    ) -> Result<MigrationDirectoryFact> {
        validate_private_name(name)?;
        let name = OsStr::new(name);
        let display = self.display.join(name);
        match self.relaxed_directory_fact(name) {
            Ok(fact) => {
                validate_directory_fidelity(&fact, read_only, executable, &display)?;
                return Ok(fact);
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.directory
            .create_dir(name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let directory = open_directory_nofollow(&self.directory, name, &display)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        set_directory_fidelity(&directory, read_only, executable, &display)?;
        sync_directory(&directory, &display)?;
        sync_directory(&self.directory, &display)?;
        let fact = directory_fact_from_handle(&directory, &display)?;
        validate_directory_fidelity(&fact, read_only, executable, &display)?;
        Ok(fact)
    }

    pub(crate) fn closed_entries(&self, maximum_entries: usize) -> Result<Vec<(OsString, bool)>> {
        let mut entries = Vec::new();
        for entry in self
            .directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&self.display, source))?
        {
            let entry = entry.map_err(|source| FolderbaseError::io(&self.display, source))?;
            if entries.len() == maximum_entries {
                return Err(FolderbaseError::InvalidRecord {
                    path: self.display.clone(),
                    message: "private migration directory exceeds its entry bound".to_owned(),
                });
            }
            let file_type = entry
                .file_type()
                .map_err(|source| FolderbaseError::io(&self.display, source))?;
            if !file_type.is_file() && !file_type.is_dir() {
                return Err(FolderbaseError::UnsafePath(
                    self.display.join(entry.file_name()),
                ));
            }
            entries.push((entry.file_name(), file_type.is_dir()));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries)
    }

    pub(crate) fn closed_regular_file_names(
        &self,
        maximum_entries: usize,
    ) -> Result<Vec<OsString>> {
        self.closed_entries(maximum_entries)?
            .into_iter()
            .map(|(name, is_directory)| {
                if is_directory {
                    Err(FolderbaseError::InvalidRecord {
                        path: self.display.join(&name),
                        message: "private migration file directory contains a nested directory"
                            .to_owned(),
                    })
                } else {
                    Ok(name)
                }
            })
            .collect()
    }

    pub(crate) fn verify_regular(&self, name: &OsStr) -> Result<()> {
        let _ = self.open_regular(name)?;
        Ok(())
    }

    pub(crate) fn verify_relaxed_regular(&self, name: &OsStr) -> Result<()> {
        let _ = self.open_regular_relaxed(name)?;
        Ok(())
    }

    pub(crate) fn relaxed_regular_fact(
        &self,
        name: &OsStr,
        expected_sha256: &str,
    ) -> Result<MigrationRegularFact> {
        let (fact, observed_sha256) = self.relaxed_regular_fact_observed(name)?;
        if observed_sha256 != expected_sha256 {
            return Err(FolderbaseError::MigrationVerificationFailed(
                self.display.join(name),
            ));
        }
        Ok(fact)
    }

    pub(crate) fn relaxed_regular_fact_observed(
        &self,
        name: &OsStr,
    ) -> Result<(MigrationRegularFact, String)> {
        let (mut file, metadata, display) = self.open_regular_relaxed(name)?;
        let identity = crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let link_count = private_regular_link_count(&file, &metadata, &display)?;
        let mut digest = Sha256::new();
        let mut observed = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
            observed = observed
                .checked_add(read as u64)
                .ok_or_else(|| FolderbaseError::MigrationVerificationFailed(display.clone()))?;
        }
        let final_metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let observed_sha256 = format!("{:x}", digest.finalize());
        if observed != metadata.len()
            || final_metadata.len() != metadata.len()
            || crate::physical_identity::PhysicalIdentity::from_file(&file)
                .map_err(|source| FolderbaseError::io(&display, source))?
                != identity
        {
            return Err(FolderbaseError::MigrationVerificationFailed(display));
        }
        Ok((
            MigrationRegularFact {
                physical_identity_sha256: identity.stable_sha256(),
                device_sha256: identity.device_sha256(),
                bytes: metadata.len(),
                read_only: portable_read_only(&metadata),
                unix_mode: private_unix_mode(&metadata),
                link_count,
            },
            observed_sha256,
        ))
    }

    pub(crate) fn exact_regular_fact(
        &self,
        name: &OsStr,
        expected: ExactRegularLeaf<'_>,
    ) -> Result<MigrationRegularFact> {
        let (fact, observed_sha256) = self.relaxed_regular_fact_observed(name)?;
        require_exact_regular_fact(
            &fact,
            &observed_sha256,
            expected,
            &self.display.join(name),
            ExactFactLocation::Private,
        )?;
        Ok(fact)
    }

    pub(crate) fn exact_empty_directory_fact(
        &self,
        name: &OsStr,
        expected: ExactDirectoryLeaf<'_>,
    ) -> Result<MigrationDirectoryFact> {
        let fact = self.relaxed_directory_fact(name)?;
        require_exact_directory_fact(
            &fact,
            expected,
            &self.display.join(name),
            ExactFactLocation::Private,
        )?;
        let directory = self.open_relaxed_directory(name)?;
        if !directory.closed_entries(1)?.is_empty() {
            return Err(FolderbaseError::MigrationVerificationFailed(
                self.display.join(name),
            ));
        }
        Ok(fact)
    }

    pub(crate) fn remove_exact_regular(
        &self,
        name: &OsStr,
        expected: ExactRegularLeaf<'_>,
    ) -> Result<()> {
        let display = self.display.join(name);
        self.exact_regular_fact(name, expected)?;
        reject_windows_reparse(&self.directory, name, &display)?;
        self.directory
            .remove_file(name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        sync_directory(&self.directory, &display)?;
        match self.relaxed_regular_fact_observed(name) {
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Ok(_) => Err(FolderbaseError::MigrationVerificationFailed(display)),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn remove_exact_empty_directory(
        &self,
        name: &OsStr,
        expected: ExactDirectoryLeaf<'_>,
    ) -> Result<()> {
        let display = self.display.join(name);
        self.exact_empty_directory_fact(name, expected)?;
        self.directory
            .remove_dir(name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        sync_directory(&self.directory, &display)?;
        match self.relaxed_directory_fact(name) {
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Ok(_) => Err(FolderbaseError::MigrationVerificationFailed(display)),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn restore_exact_regular_through(
        &self,
        source_name: &OsStr,
        destination_parent: &VerifiedVisibleDirectory,
        destination_name: &OsStr,
        expected: ExactRegularLeaf<'_>,
    ) -> Result<MigrationRegularFact> {
        self.exact_regular_fact(source_name, expected)?;
        destination_parent.reverify()?;
        require_absent_from_retained_parent(destination_parent, destination_name)?;
        self.exact_regular_fact(source_name, expected)?;
        rename_noreplace(
            &self.directory,
            source_name,
            &destination_parent.directory,
            destination_name,
        )
        .map_err(|error| {
            map_rename_noreplace_error(destination_parent.display.join(destination_name), error)
        })?;
        sync_directory(&self.directory, &self.display.join(source_name))?;
        sync_directory(
            &destination_parent.directory,
            &destination_parent.display.join(destination_name),
        )?;
        destination_parent.reverify()?;
        match self.relaxed_regular_fact_observed(source_name) {
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    self.display.join(source_name),
                ));
            }
            Err(error) => return Err(error),
        }
        require_exact_visible_claim_source(
            destination_parent,
            destination_name,
            ExactLeafClaimExpectation::Regular(expected),
        )?;
        visible_regular_fact_from_parent(
            &destination_parent.directory,
            &destination_parent.display,
            destination_name,
            expected.sha256,
        )
    }

    pub(crate) fn regular_fact(
        &self,
        name: &OsStr,
        expected_sha256: &str,
    ) -> Result<MigrationRegularFact> {
        let (mut file, metadata, display) = self.open_regular(name)?;
        let identity = crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut observed_bytes = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
            observed_bytes = observed_bytes
                .checked_add(read as u64)
                .ok_or_else(|| FolderbaseError::MigrationVerificationFailed(display.clone()))?;
        }
        let final_metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let final_identity = crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if format!("{:x}", digest.finalize()) != expected_sha256
            || observed_bytes != metadata.len()
            || final_metadata.len() != metadata.len()
            || final_identity != identity
            || private_regular_link_count(&file, &final_metadata, &display)? != 1
            || portable_read_only(&final_metadata) != portable_read_only(&metadata)
            || private_unix_mode(&final_metadata) != private_unix_mode(&metadata)
        {
            return Err(FolderbaseError::MigrationVerificationFailed(display));
        }
        Ok(MigrationRegularFact {
            physical_identity_sha256: identity.stable_sha256(),
            device_sha256: identity.device_sha256(),
            bytes: metadata.len(),
            read_only: portable_read_only(&metadata),
            unix_mode: private_unix_mode(&metadata),
            link_count: 1,
        })
    }

    pub(crate) fn read_regular_bounded(&self, name: &OsStr, maximum_bytes: u64) -> Result<Vec<u8>> {
        self.read_regular_bounded_with(name, maximum_bytes, || {})
    }

    pub(crate) fn read_relaxed_regular_bounded(
        &self,
        name: &OsStr,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>> {
        let (mut file, metadata, display) = self.open_regular_relaxed(name)?;
        let identity = crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if metadata.len() > maximum_bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "private migration file exceeds its byte bound".to_owned(),
            });
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let final_metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if bytes.len() as u64 > maximum_bytes
            || bytes.len() as u64 != metadata.len()
            || final_metadata.len() != metadata.len()
            || crate::physical_identity::PhysicalIdentity::from_file(&file)
                .map_err(|source| FolderbaseError::io(&display, source))?
                != identity
            || portable_read_only(&final_metadata) != portable_read_only(&metadata)
            || private_unix_mode(&final_metadata) != private_unix_mode(&metadata)
        {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "private migration file changed while it was read".to_owned(),
            });
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub(crate) fn read_regular_bounded_with_hook(
        &self,
        name: &OsStr,
        maximum_bytes: u64,
        after_verified_open: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        self.read_regular_bounded_with(name, maximum_bytes, after_verified_open)
    }

    fn read_regular_bounded_with(
        &self,
        name: &OsStr,
        maximum_bytes: u64,
        after_verified_open: impl FnOnce(),
    ) -> Result<Vec<u8>> {
        let (mut file, metadata, display) = self.open_regular(name)?;
        let identity = crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if metadata.len() > maximum_bytes {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "private migration file exceeds its byte bound".to_owned(),
            });
        }
        after_verified_open();
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let final_metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if bytes.len() as u64 > maximum_bytes
            || bytes.len() as u64 != metadata.len()
            || final_metadata.len() != metadata.len()
            || crate::physical_identity::PhysicalIdentity::from_file(&file)
                .map_err(|source| FolderbaseError::io(&display, source))?
                != identity
            || private_regular_link_count(&file, &final_metadata, &display)? != 1
            || portable_read_only(&final_metadata) != portable_read_only(&metadata)
            || private_unix_mode(&final_metadata) != private_unix_mode(&metadata)
        {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "private migration file changed while it was read".to_owned(),
            });
        }
        Ok(bytes)
    }

    pub(crate) fn publish_recoverable_new(
        &self,
        name: &str,
        staging_name: &str,
        bytes: &[u8],
    ) -> Result<()> {
        validate_private_name(name)?;
        validate_private_name(staging_name)?;
        let name = OsStr::new(name);
        let staging_name = OsStr::new(staging_name);
        let expected_sha256 = format!("{:x}", Sha256::digest(bytes));
        let expected_bytes = bytes.len() as u64;

        match self.relaxed_regular_fact(name, &expected_sha256) {
            Ok(fact) if fact.bytes == expected_bytes => {
                remove_private_regular_if_present(
                    self,
                    staging_name,
                    &self.display.join(staging_name),
                )?;
                return Ok(());
            }
            Ok(_) => {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    self.display.join(name),
                ));
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let staging_ready = match self.relaxed_regular_fact(staging_name, &expected_sha256) {
            Ok(fact) if fact.bytes == expected_bytes => true,
            Ok(_) | Err(FolderbaseError::MigrationVerificationFailed(_)) => {
                remove_private_regular_if_present(
                    self,
                    staging_name,
                    &self.display.join(staging_name),
                )?;
                false
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                false
            }
            Err(error) => return Err(error),
        };
        if !staging_ready {
            let staging_display = self.display.join(staging_name);
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
            let mut file = self
                .directory
                .open_with(staging_name, &options)
                .map_err(|source| FolderbaseError::io(&staging_display, source))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| FolderbaseError::io(&staging_display, source))?;
            drop(file);
            sync_directory(&self.directory, &self.display)?;
        }
        install_prepared_private_claim(self, staging_name, name, &expected_sha256, expected_bytes)
            .map(|_| ())
    }

    pub(crate) fn retire_recoverable_regular(&self, name: &OsStr) -> Result<()> {
        remove_private_regular_if_present(self, name, &self.display.join(name))
    }

    pub(crate) fn install_recoverable_regular(
        &self,
        staging_name: &OsStr,
        destination_name: &OsStr,
        expected_sha256: &str,
        expected_bytes: u64,
    ) -> Result<()> {
        install_prepared_private_claim(
            self,
            staging_name,
            destination_name,
            expected_sha256,
            expected_bytes,
        )
        .map(|_| ())
    }

    fn open_regular(&self, name: &OsStr) -> Result<(std::fs::File, std::fs::Metadata, PathBuf)> {
        let (file, metadata, display) = self.open_regular_relaxed(name)?;
        if private_regular_link_count(&file, &metadata, &display)? != 1 {
            return Err(FolderbaseError::InvalidRecord {
                path: display,
                message: "private migration file has a hard-link alias".to_owned(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: "private migration file is not owner-only".to_owned(),
                });
            }
        }
        Ok((file, metadata, display))
    }

    fn open_regular_relaxed(
        &self,
        name: &OsStr,
    ) -> Result<(std::fs::File, std::fs::Metadata, PathBuf)> {
        validate_private_name_os(name)?;
        let display = self.display.join(name);
        let options = nofollow_regular_read_options();
        let file = self
            .directory
            .open_with(name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std();
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
            return Err(FolderbaseError::UnsafePath(display));
        }
        Ok((file, metadata, display))
    }
}

impl MigrationFilesystem {
    pub(crate) fn require_atomic_noreplace(&self) -> Result<()> {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        ))]
        {
            Ok(())
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        )))]
        {
            Err(FolderbaseError::UnsupportedMigrationFilesystem {
                path: self.display_root.clone(),
                reason: "atomic retained-handle no-replace rename is unavailable on this platform"
                    .to_owned(),
            })
        }
    }

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

    pub(crate) fn analyze_retained_root(&self) -> Result<FolderAnalysis> {
        analyze_folder_from_retained(&self.root, &self.display_root, true, true)
    }

    pub(crate) fn expand_retained_tree(&self, relative: &Path) -> Result<FolderAnalysis> {
        let directory = self.open_directory(relative)?;
        analyze_folder_from_retained(&directory, &self.display(relative), false, true)
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
            Ok(metadata) => {
                reject_windows_reparse(&parent, &name, &display)?;
                Ok(Some(metadata))
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(FolderbaseError::io(display, source)),
        }
    }

    pub(crate) fn retained_nofollow_leaf_fingerprint(
        &self,
        relative: &Path,
    ) -> Result<Option<String>> {
        self.retained_nofollow_leaf_fingerprint_inner(relative, || {})
    }

    #[cfg(test)]
    pub(crate) fn retained_nofollow_leaf_fingerprint_with_regular_open_hook(
        &self,
        relative: &Path,
        after_regular_open: impl FnOnce(),
    ) -> Result<Option<String>> {
        self.retained_nofollow_leaf_fingerprint_inner(relative, after_regular_open)
    }

    fn retained_nofollow_leaf_fingerprint_inner(
        &self,
        relative: &Path,
        after_regular_open: impl FnOnce(),
    ) -> Result<Option<String>> {
        let (parent, name) = match self.open_parent(relative) {
            Ok(parent) => parent,
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(Some("absent".to_owned()));
            }
            Err(error) => return Err(error),
        };
        let display = self.display(relative);
        let metadata = match parent.symlink_metadata(&name) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Some("absent".to_owned()));
            }
            Err(source) => return Err(FolderbaseError::io(&display, source)),
        };
        #[cfg(windows)]
        if windows_entry_is_reparse(&parent, &name, &display)? {
            return Err(FolderbaseError::UnsafePath(display));
        }
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            let options = nofollow_regular_read_options();
            let mut file = parent
                .open_with(&name, &options)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let std_file = file
                .try_clone()
                .map_err(|source| FolderbaseError::io(&display, source))?
                .into_std();
            let opened_metadata = std_file
                .metadata()
                .map_err(|source| FolderbaseError::io(&display, source))?;
            if !opened_metadata.is_file() || metadata_is_link_or_reparse(&opened_metadata) {
                return Err(FolderbaseError::MigrationSourceChanged(display));
            }
            let identity = crate::physical_identity::PhysicalIdentity::from_file(&std_file)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let link_count = private_regular_link_count(&std_file, &opened_metadata, &display)?;
            let content_version = regular_content_version(&std_file, &opened_metadata, &display)?;
            after_regular_open();
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut observed_bytes = 0_u64;
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
                observed_bytes = observed_bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| FolderbaseError::MigrationSourceChanged(display.clone()))?;
            }
            verify_fingerprinted_regular_after_read(
                &std_file,
                &opened_metadata,
                identity,
                link_count,
                &content_version,
                observed_bytes,
                &display,
            )?;

            let mut reopened_options = OpenOptions::new();
            reopened_options.read(true).follow(FollowSymlinks::No);
            #[cfg(windows)]
            {
                use cap_std::fs::OpenOptionsExt;
                use windows_sys::Win32::Storage::FileSystem::{
                    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
                    FILE_SHARE_WRITE,
                };

                reopened_options
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
            }
            let reopened = parent
                .open_with(&name, &reopened_options)
                .map_err(|_| FolderbaseError::MigrationSourceChanged(display.clone()))?;
            let reopened_std = reopened
                .try_clone()
                .map_err(|source| FolderbaseError::io(&display, source))?
                .into_std();
            let reopened_metadata = reopened_std
                .metadata()
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let reopened_identity =
                crate::physical_identity::PhysicalIdentity::from_file(&reopened_std)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
            if !reopened_metadata.is_file()
                || metadata_is_link_or_reparse(&reopened_metadata)
                || reopened_identity != identity
                || reopened_metadata.len() != opened_metadata.len()
                || portable_read_only(&reopened_metadata) != portable_read_only(&opened_metadata)
                || private_unix_mode(&reopened_metadata) != private_unix_mode(&opened_metadata)
                || private_regular_link_count(&reopened_std, &reopened_metadata, &display)?
                    != link_count
                || regular_content_version(&reopened_std, &reopened_metadata, &display)?
                    != content_version
            {
                return Err(FolderbaseError::MigrationSourceChanged(display));
            }
            return Ok(Some(format!(
                "regular:{}:{}:{}:{:x}:{}:{:?}:{}",
                identity.stable_sha256(),
                identity.device_sha256(),
                opened_metadata.len(),
                digest.finalize(),
                portable_read_only(&opened_metadata),
                private_unix_mode(&opened_metadata),
                link_count
            )));
        }
        if metadata.file_type().is_symlink() {
            let link_target = parent
                .read_link(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let initial = retained_link_fingerprint(&metadata, &link_target);
            let final_metadata = parent
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let final_target = parent
                .read_link(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            if initial != retained_link_fingerprint(&final_metadata, &final_target) {
                return Err(FolderbaseError::MigrationSourceChanged(display));
            }
            return Ok(Some(initial));
        }
        if metadata.is_dir() {
            let directory = open_directory_nofollow(&parent, &name, &display)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let initial_fact = directory_fact_from_handle(&directory, &display)?;
            let initial_metadata_fingerprint =
                retained_nonregular_fingerprint(&metadata, "directory");
            let final_metadata = parent
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let reopened = open_directory_nofollow(&parent, &name, &display)
                .map_err(|_| FolderbaseError::MigrationSourceChanged(display.clone()))?;
            let final_fact = directory_fact_from_handle(&reopened, &display)?;
            if retained_nonregular_fingerprint(&final_metadata, "directory")
                != initial_metadata_fingerprint
                || final_fact.physical_identity_sha256 != initial_fact.physical_identity_sha256
                || final_fact.device_sha256 != initial_fact.device_sha256
                || final_fact.read_only != initial_fact.read_only
                || final_fact.unix_mode != initial_fact.unix_mode
            {
                return Err(FolderbaseError::MigrationSourceChanged(display));
            }
            return Ok(Some(format!(
                "directory:{}:{}:{}:{:?}:{}",
                initial_fact.physical_identity_sha256,
                initial_fact.device_sha256,
                initial_fact.read_only,
                initial_fact.unix_mode,
                initial_metadata_fingerprint
            )));
        }

        let initial = retained_nonregular_fingerprint(&metadata, "special");
        let final_metadata = parent
            .symlink_metadata(&name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if retained_nonregular_fingerprint(&final_metadata, "special") != initial {
            return Err(FolderbaseError::MigrationSourceChanged(display));
        }
        Ok(Some(initial))
    }

    fn open_visible_regular(&self, relative: &Path) -> Result<VerifiedVisibleRegular> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let options = nofollow_regular_read_options();
        let file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let std_file = file
            .try_clone()
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std();
        let metadata = std_file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
            return Err(FolderbaseError::UnsafePath(display));
        }
        let identity = crate::physical_identity::PhysicalIdentity::from_file(&std_file)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        Ok(VerifiedVisibleRegular {
            file,
            std_file,
            metadata,
            identity,
            display,
        })
    }

    pub(crate) fn read_regular_bounded(
        &self,
        relative: &Path,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let options = nofollow_regular_read_options();
        let mut file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std();
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file()
            || metadata_is_link_or_reparse(&metadata)
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
        let options = nofollow_regular_read_options();
        let mut file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std();
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
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
        let options = nofollow_regular_read_options();
        let file = parent
            .open_with(&name, &options)
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std();
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
            return Err(FolderbaseError::UnsafePath(display));
        }
        crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map(crate::physical_identity::PhysicalIdentity::stable_sha256)
            .map_err(|source| FolderbaseError::io(self.display(relative), source))
    }

    pub(crate) fn regular_fact_with_sha256(
        &self,
        relative: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<MigrationRegularFact> {
        let VerifiedVisibleRegular {
            mut file,
            std_file,
            metadata,
            identity,
            display,
        } = self.open_visible_regular(relative)?;
        let link_count = private_regular_link_count(&std_file, &metadata, &display)?;
        if let Some(expected_sha256) = expected_sha256 {
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut observed_bytes = 0_u64;
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
                observed_bytes = observed_bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| FolderbaseError::MigrationSourceChanged(display.clone()))?;
            }
            if format!("{:x}", digest.finalize()) != expected_sha256
                || observed_bytes != metadata.len()
            {
                return Err(FolderbaseError::MigrationSourceChanged(display));
            }
            verify_visible_regular_after_read(
                &std_file,
                &metadata,
                identity,
                link_count,
                observed_bytes,
                &display,
            )?;
        }
        #[cfg(unix)]
        let unix_mode = {
            use std::os::unix::fs::MetadataExt;

            Some(metadata.mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let unix_mode = None;
        Ok(MigrationRegularFact {
            physical_identity_sha256: identity.stable_sha256(),
            device_sha256: identity.device_sha256(),
            bytes: metadata.len(),
            read_only: portable_read_only(&metadata),
            unix_mode,
            link_count,
        })
    }

    pub(crate) fn exact_regular_fact(
        &self,
        relative: &Path,
        expected: ExactRegularLeaf<'_>,
    ) -> Result<MigrationRegularFact> {
        let fact = self.regular_fact_with_sha256(relative, Some(expected.sha256))?;
        require_exact_regular_fact(
            &fact,
            expected.sha256,
            expected,
            &self.display(relative),
            ExactFactLocation::Visible,
        )?;
        Ok(fact)
    }

    pub(crate) fn exact_directory_fact(
        &self,
        relative: &Path,
        expected: ExactDirectoryLeaf<'_>,
        require_empty: bool,
    ) -> Result<MigrationDirectoryFact> {
        let fact = self.directory_fact(relative)?;
        require_exact_directory_fact(
            &fact,
            expected,
            &self.display(relative),
            ExactFactLocation::Visible,
        )?;
        if require_empty {
            let directory = self.open_directory(relative)?;
            if directory
                .entries()
                .map_err(|source| FolderbaseError::io(self.display(relative), source))?
                .next()
                .transpose()
                .map_err(|source| FolderbaseError::io(self.display(relative), source))?
                .is_some()
            {
                return Err(FolderbaseError::MigrationSourceChanged(
                    self.display(relative),
                ));
            }
        }
        Ok(fact)
    }

    pub(crate) fn regular_fact_and_bytes_bounded(
        &self,
        relative: &Path,
        expected_sha256: &str,
        maximum_bytes: u64,
    ) -> Result<(MigrationRegularFact, Vec<u8>)> {
        let VerifiedVisibleRegular {
            mut file,
            std_file,
            metadata,
            identity,
            display,
        } = self.open_visible_regular(relative)?;
        if metadata.len() > maximum_bytes {
            return Err(FolderbaseError::UnsafePath(display));
        }
        let link_count = private_regular_link_count(&std_file, &metadata, &display)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if bytes.len() as u64 > maximum_bytes
            || bytes.len() as u64 != metadata.len()
            || format!("{:x}", Sha256::digest(&bytes)) != expected_sha256
        {
            return Err(FolderbaseError::MigrationSourceChanged(display));
        }
        verify_visible_regular_after_read(
            &std_file,
            &metadata,
            identity,
            link_count,
            bytes.len() as u64,
            &display,
        )?;
        #[cfg(unix)]
        let unix_mode = {
            use std::os::unix::fs::MetadataExt;

            Some(metadata.mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let unix_mode = None;
        Ok((
            MigrationRegularFact {
                physical_identity_sha256: identity.stable_sha256(),
                device_sha256: identity.device_sha256(),
                bytes: metadata.len(),
                read_only: portable_read_only(&metadata),
                unix_mode,
                link_count,
            },
            bytes,
        ))
    }

    pub(crate) fn directory_fact(&self, relative: &Path) -> Result<MigrationDirectoryFact> {
        let directory = self.open_directory(relative)?;
        let display = self.display(relative);
        let file = directory
            .try_clone()
            .map_err(|source| FolderbaseError::io(&display, source))?
            .into_std_file();
        let metadata = file
            .metadata()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(display));
        }
        let identity = crate::physical_identity::PhysicalIdentity::from_file(&file)
            .map_err(|source| FolderbaseError::io(self.display(relative), source))?;
        #[cfg(unix)]
        let unix_mode = {
            use std::os::unix::fs::MetadataExt;

            Some(metadata.mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let unix_mode = None;
        Ok(MigrationDirectoryFact {
            physical_identity_sha256: identity.stable_sha256(),
            device_sha256: identity.device_sha256(),
            read_only: portable_read_only(&metadata),
            unix_mode,
        })
    }

    pub(crate) fn retain_verified_directory(
        &self,
        relative: &Path,
        expected_identity_sha256: &str,
        expected_device_sha256: &str,
        read_only: bool,
        executable: bool,
    ) -> Result<VerifiedVisibleDirectory> {
        let directory = self.open_directory(relative)?;
        let retained = VerifiedVisibleDirectory {
            directory,
            display: self.display(relative),
            expected_identity_sha256: expected_identity_sha256.to_owned(),
            expected_device_sha256: expected_device_sha256.to_owned(),
            read_only,
            executable,
        };
        retained.reverify()?;
        Ok(retained)
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

    pub(crate) fn ensure_private_directory(&self, relative: &Path) -> Result<()> {
        validate_relative(relative, false)?;
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        let directory = match open_directory_nofollow(&parent, &name, &display) {
            Ok(directory) => directory,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let builder = cap_std::fs::DirBuilder::new();
                #[cfg(unix)]
                let builder = {
                    use cap_std::fs::DirBuilderExt;

                    let mut builder = builder;
                    builder.mode(0o700);
                    builder
                };
                parent
                    .create_dir_with(&name, &builder)
                    .map_err(|source| FolderbaseError::io(&display, source))?;
                sync_directory(&parent, &display)?;
                open_directory_nofollow(&parent, &name, &display)
                    .map_err(|source| FolderbaseError::io(&display, source))?
            }
            Err(source) => return Err(FolderbaseError::io(&display, source)),
        };
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt;

            let mode = directory
                .dir_metadata()
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
        #[cfg(not(unix))]
        let _ = directory;
        Ok(())
    }

    pub(crate) fn open_private_directory(
        &self,
        relative: &Path,
    ) -> Result<VerifiedPrivateDirectory> {
        let directory = self.open_directory(relative)?;
        let display = self.display(relative);
        validate_private_directory_metadata(&directory, &display)?;
        Ok(VerifiedPrivateDirectory { directory, display })
    }

    pub(crate) fn stage_regular_private(
        &self,
        source: &Path,
        destination: &VerifiedPrivateDirectory,
        destination_name: &str,
        expected_sha256: &str,
    ) -> Result<MigrationRegularFact> {
        validate_private_name(destination_name)?;
        let destination_name = OsStr::new(destination_name);
        let temporary =
            OsString::from(format!(".{}.preparing", destination_name.to_string_lossy()));
        validate_private_name_os(&temporary)?;
        let VerifiedVisibleRegular {
            file: mut source_file,
            std_file: source_std,
            metadata: source_std_metadata,
            identity: source_identity,
            display: source_display,
        } = self.open_visible_regular(source)?;
        #[cfg(unix)]
        let source_unix_mode = {
            use std::os::unix::fs::MetadataExt;

            Some(source_std_metadata.mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let source_unix_mode = None;
        let source_link_count =
            private_regular_link_count(&source_std, &source_std_metadata, &source_display)?;
        let source_fact = MigrationRegularFact {
            physical_identity_sha256: source_identity.stable_sha256(),
            device_sha256: source_identity.device_sha256(),
            bytes: source_std_metadata.len(),
            read_only: portable_read_only(&source_std_metadata),
            unix_mode: source_unix_mode,
            link_count: source_link_count,
        };
        match destination.relaxed_regular_fact(destination_name, expected_sha256) {
            Ok(destination_fact) if destination_fact.bytes == source_fact.bytes => {
                match destination.relaxed_regular_fact(&temporary, expected_sha256) {
                    Ok(staging_fact)
                        if destination_fact.link_count == 2
                            && staging_fact.link_count == 2
                            && destination_fact.physical_identity_sha256
                                == staging_fact.physical_identity_sha256
                            && destination_fact.device_sha256 == staging_fact.device_sha256
                            && destination_fact.bytes == staging_fact.bytes =>
                    {
                        remove_private_regular_if_present(
                            destination,
                            &temporary,
                            &destination.display.join(&temporary),
                        )?;
                        destination.regular_fact(destination_name, expected_sha256)?;
                    }
                    Err(FolderbaseError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound
                            && destination_fact.link_count == 1 => {}
                    Ok(_) | Err(FolderbaseError::MigrationVerificationFailed(_)) => {
                        return Err(FolderbaseError::InvalidRecord {
                            path: destination.display.join(&temporary),
                            message: "private blob final and staging are not one exact publication"
                                .to_owned(),
                        });
                    }
                    Err(error) => return Err(error),
                }
                let mut digest = Sha256::new();
                let mut buffer = [0_u8; 64 * 1024];
                let mut copied_bytes = 0_u64;
                loop {
                    let read = source_file
                        .read(&mut buffer)
                        .map_err(|error| FolderbaseError::io(&source_display, error))?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                    copied_bytes = copied_bytes.checked_add(read as u64).ok_or_else(|| {
                        FolderbaseError::MigrationSourceChanged(source_display.clone())
                    })?;
                }
                if format!("{:x}", digest.finalize()) != expected_sha256
                    || copied_bytes != source_fact.bytes
                {
                    return Err(FolderbaseError::MigrationSourceChanged(source_display));
                }
                verify_visible_regular_after_read(
                    &source_std,
                    &source_std_metadata,
                    source_identity,
                    source_link_count,
                    copied_bytes,
                    &source_display,
                )?;
                return Ok(source_fact);
            }
            Ok(_) => {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    destination.display.join(destination_name),
                ));
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                remove_private_regular_if_present(
                    destination,
                    &temporary,
                    &destination.display.join(&temporary),
                )?;
            }
            Err(error) => return Err(error),
        }

        let destination_display = destination.display.join(destination_name);
        let mut destination_options = OpenOptions::new();
        destination_options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            destination_options.mode(0o600);
        }
        let result = (|| -> Result<()> {
            let mut destination_file = destination
                .directory
                .open_with(&temporary, &destination_options)
                .map_err(|error| FolderbaseError::io(&destination_display, error))?;
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut copied_bytes = 0_u64;
            loop {
                let read = source_file
                    .read(&mut buffer)
                    .map_err(|error| FolderbaseError::io(&source_display, error))?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
                copied_bytes = copied_bytes.checked_add(read as u64).ok_or_else(|| {
                    FolderbaseError::MigrationSourceChanged(source_display.clone())
                })?;
                destination_file
                    .write_all(&buffer[..read])
                    .map_err(|error| FolderbaseError::io(&destination_display, error))?;
            }
            destination_file
                .sync_all()
                .map_err(|error| FolderbaseError::io(&destination_display, error))?;
            let observed_sha256 = format!("{:x}", digest.finalize());
            if observed_sha256 != expected_sha256 || copied_bytes != source_fact.bytes {
                return Err(FolderbaseError::MigrationSourceChanged(source_display));
            }
            verify_visible_regular_after_read(
                &source_std,
                &source_std_metadata,
                source_identity,
                source_link_count,
                copied_bytes,
                &source_display,
            )?;
            drop(destination_file);
            destination
                .directory
                .hard_link(&temporary, &destination.directory, destination_name)
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        FolderbaseError::WouldOverwrite(destination_display.clone())
                    } else {
                        FolderbaseError::io(&destination_display, error)
                    }
                })?;
            reject_windows_reparse(&destination.directory, &temporary, &destination_display)?;
            destination
                .directory
                .remove_file(&temporary)
                .map_err(|error| FolderbaseError::io(&destination_display, error))?;
            sync_directory(&destination.directory, &destination_display)?;
            destination
                .regular_fact(destination_name, expected_sha256)
                .map(|_| ())
        })();
        if result.is_err()
            && reject_windows_reparse(&destination.directory, &temporary, &destination_display)
                .is_ok()
        {
            let _ = destination.directory.remove_file(&temporary);
        }
        result.map(|()| source_fact)
    }

    // Every argument is an independently verified security fact. Keeping them
    // explicit avoids hiding which identity, content, and mode constraints are
    // checked at this mutation boundary.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_private_publish_claim(
        &self,
        source: &VerifiedPrivateDirectory,
        source_name: &OsStr,
        destination: &VerifiedPrivateDirectory,
        destination_name: &str,
        expected_sha256: &str,
        expected_bytes: u64,
        read_only: bool,
        executable: bool,
        after_staged_sync: impl FnOnce(),
    ) -> Result<MigrationRegularFact> {
        validate_private_name(destination_name)?;
        let destination_name = OsStr::new(destination_name);
        let preparing_name =
            OsString::from(format!(".{}.preparing", destination_name.to_string_lossy()));
        validate_private_name_os(&preparing_name)?;
        match destination.relaxed_regular_fact(destination_name, expected_sha256) {
            Ok(fact) if fact.bytes == expected_bytes => {
                remove_private_regular_if_present(
                    destination,
                    &preparing_name,
                    &destination.display.join(&preparing_name),
                )?;
                return Ok(fact);
            }
            Ok(_) => {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    destination.display.join(destination_name),
                ));
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let preparing_display = destination.display.join(&preparing_name);
        let preparing_ready =
            match destination.relaxed_regular_fact(&preparing_name, expected_sha256) {
                Ok(fact) if fact.bytes == expected_bytes => true,
                Ok(_) | Err(FolderbaseError::MigrationVerificationFailed(_)) => {
                    remove_private_regular_if_present(
                        destination,
                        &preparing_name,
                        &preparing_display,
                    )?;
                    false
                }
                Err(FolderbaseError::Io { source, .. })
                    if matches!(
                        source.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::InvalidData
                    ) =>
                {
                    remove_private_regular_if_present(
                        destination,
                        &preparing_name,
                        &preparing_display,
                    )?;
                    false
                }
                Err(error) => return Err(error),
            };
        if preparing_ready {
            after_staged_sync();
            return install_prepared_private_claim(
                destination,
                &preparing_name,
                destination_name,
                expected_sha256,
                expected_bytes,
            );
        }
        let (mut source_file, source_metadata, source_display) =
            source.open_regular(source_name)?;
        if source_metadata.len() != expected_bytes {
            return Err(FolderbaseError::MigrationVerificationFailed(source_display));
        }
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
        let mut destination_file = destination
            .directory
            .open_with(&preparing_name, &options)
            .map_err(|source| FolderbaseError::io(&preparing_display, source))?;
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(|source| FolderbaseError::io(&source_display, source))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
            copied = copied.checked_add(read as u64).ok_or_else(|| {
                FolderbaseError::MigrationVerificationFailed(source_display.clone())
            })?;
            destination_file
                .write_all(&buffer[..read])
                .map_err(|source| FolderbaseError::io(&preparing_display, source))?;
        }
        if copied != expected_bytes || format!("{:x}", digest.finalize()) != expected_sha256 {
            return Err(FolderbaseError::MigrationVerificationFailed(source_display));
        }
        set_visible_fidelity(&destination_file, read_only, executable, &preparing_display)?;
        destination_file
            .sync_all()
            .map_err(|source| FolderbaseError::io(&preparing_display, source))?;
        drop(destination_file);
        sync_directory(&destination.directory, &destination.display)?;
        after_staged_sync();
        install_prepared_private_claim(
            destination,
            &preparing_name,
            destination_name,
            expected_sha256,
            expected_bytes,
        )
    }

    pub(crate) fn claim_exact_leaf_through(
        &self,
        request: ExactLeafClaimRequest<'_>,
    ) -> Result<ExactLeafClaimResult> {
        validate_private_name(request.destination_name)?;
        let destination_name = OsStr::new(request.destination_name);
        request.source_parent.reverify()?;

        let existing = match request.expectation {
            ExactLeafClaimExpectation::Regular(expected) => {
                match request
                    .destination
                    .exact_regular_fact(destination_name, expected)
                {
                    Ok(fact) => Some(ExactLeafClaimResult::Regular(fact)),
                    Err(FolderbaseError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound =>
                    {
                        None
                    }
                    Err(error) => return Err(error),
                }
            }
            ExactLeafClaimExpectation::EmptyDirectory(expected) => {
                match request
                    .destination
                    .exact_empty_directory_fact(destination_name, expected)
                {
                    Ok(fact) => Some(ExactLeafClaimResult::Directory(fact)),
                    Err(FolderbaseError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound =>
                    {
                        None
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        if let Some(existing) = existing {
            match request.existing_source {
                ExactExistingClaimSource::Absent => {
                    require_absent_from_retained_parent(
                        request.source_parent,
                        request.source_name,
                    )?;
                }
                ExactExistingClaimSource::Regular(expected) => {
                    require_exact_visible_claim_source(
                        request.source_parent,
                        request.source_name,
                        ExactLeafClaimExpectation::Regular(expected),
                    )?;
                }
            }
            request.source_parent.reverify()?;
            return Ok(existing);
        }

        require_exact_visible_claim_source(
            request.source_parent,
            request.source_name,
            request.expectation,
        )?;
        request.source_parent.reverify()?;
        require_exact_visible_claim_source(
            request.source_parent,
            request.source_name,
            request.expectation,
        )?;
        rename_noreplace(
            &request.source_parent.directory,
            request.source_name,
            &request.destination.directory,
            destination_name,
        )
        .map_err(|error| {
            map_rename_noreplace_error(request.destination.display.join(destination_name), error)
        })?;
        sync_directory(
            &request.source_parent.directory,
            &request.source_parent.display.join(request.source_name),
        )?;
        sync_directory(&request.destination.directory, &request.destination.display)?;

        // A post-rename verification failure deliberately leaves the captured
        // inode or directory in the private claim slot. That is the only exact
        // evidence available for deterministic recovery or conflict review.
        request.source_parent.reverify()?;
        require_absent_from_retained_parent(request.source_parent, request.source_name)?;
        match request.expectation {
            ExactLeafClaimExpectation::Regular(expected) => request
                .destination
                .exact_regular_fact(destination_name, expected)
                .map(ExactLeafClaimResult::Regular),
            ExactLeafClaimExpectation::EmptyDirectory(expected) => request
                .destination
                .exact_empty_directory_fact(destination_name, expected)
                .map(ExactLeafClaimResult::Directory),
        }
    }

    // Every argument is an independently verified security fact. Keeping them
    // explicit avoids weakening the retained-parent publication contract.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_private_claim_new_through(
        &self,
        source: &VerifiedPrivateDirectory,
        source_name: &OsStr,
        destination_parent: &VerifiedVisibleDirectory,
        destination_name: &OsStr,
        expected_identity: &str,
        expected_sha256: &str,
        expected_bytes: u64,
    ) -> Result<MigrationRegularFact> {
        destination_parent.reverify()?;
        let claim = source.relaxed_regular_fact(source_name, expected_sha256)?;
        if claim.physical_identity_sha256 != expected_identity || claim.bytes != expected_bytes {
            return Err(FolderbaseError::MigrationVerificationFailed(
                source.display.join(source_name),
            ));
        }
        match visible_regular_fact_from_parent(
            &destination_parent.directory,
            &destination_parent.display,
            destination_name,
            expected_sha256,
        ) {
            Ok(current)
                if current.physical_identity_sha256 == expected_identity
                    && current.bytes == expected_bytes =>
            {
                return Ok(current);
            }
            Ok(_) => {
                return Err(FolderbaseError::WouldOverwrite(
                    destination_parent.display.join(destination_name),
                ));
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        source
            .directory
            .hard_link(source_name, &destination_parent.directory, destination_name)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    FolderbaseError::WouldOverwrite(
                        destination_parent.display.join(destination_name),
                    )
                } else {
                    FolderbaseError::io(destination_parent.display.join(destination_name), error)
                }
            })?;
        sync_directory(
            &destination_parent.directory,
            &destination_parent.display.join(destination_name),
        )?;
        destination_parent.reverify()?;
        let current = visible_regular_fact_from_parent(
            &destination_parent.directory,
            &destination_parent.display,
            destination_name,
            expected_sha256,
        )?;
        if current.physical_identity_sha256 != expected_identity || current.bytes != expected_bytes
        {
            return Err(FolderbaseError::MigrationVerificationFailed(
                destination_parent.display.join(destination_name),
            ));
        }
        Ok(current)
    }

    pub(crate) fn publish_private_directory_claim_new_through(
        &self,
        source: &VerifiedPrivateDirectory,
        source_name: &OsStr,
        destination_parent: &VerifiedVisibleDirectory,
        destination_name: &OsStr,
        expected_identity: &str,
    ) -> Result<MigrationDirectoryFact> {
        destination_parent.reverify()?;
        match visible_directory_fact_from_parent(
            &destination_parent.directory,
            &destination_parent.display,
            destination_name,
        ) {
            Ok(current) if current.physical_identity_sha256 == expected_identity => {
                return Ok(current);
            }
            Ok(_) => {
                return Err(FolderbaseError::WouldOverwrite(
                    destination_parent.display.join(destination_name),
                ));
            }
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let claim = source.relaxed_directory_fact(source_name)?;
        if claim.physical_identity_sha256 != expected_identity {
            return Err(FolderbaseError::MigrationVerificationFailed(
                source.display.join(source_name),
            ));
        }
        rename_noreplace(
            &source.directory,
            source_name,
            &destination_parent.directory,
            destination_name,
        )
        .map_err(|error| {
            map_rename_noreplace_error(destination_parent.display.join(destination_name), error)
        })?;
        sync_directory(&source.directory, &source.display)?;
        sync_directory(
            &destination_parent.directory,
            &destination_parent.display.join(destination_name),
        )?;
        destination_parent.reverify()?;
        let current = visible_directory_fact_from_parent(
            &destination_parent.directory,
            &destination_parent.display,
            destination_name,
        )?;
        if current.physical_identity_sha256 != expected_identity {
            return Err(FolderbaseError::MigrationVerificationFailed(
                destination_parent.display.join(destination_name),
            ));
        }
        Ok(current)
    }

    pub(crate) fn publish_new(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        self.publish_new_with_hook(relative, bytes, || {})
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
            reject_windows_reparse(&parent, &temporary, &display)?;
            parent
                .remove_file(&temporary)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            sync_directory(&parent, &display)
        })();
        if result.is_err() && reject_windows_reparse(&parent, &temporary, &display).is_ok() {
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
        reject_windows_reparse(&parent, &name, &display)?;
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
        if result.is_err() && reject_windows_reparse(&parent, &temporary, &display).is_ok() {
            let _ = parent.remove_file(&temporary);
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
        reject_windows_reparse(&parent, &name, &display)?;
        parent
            .remove_file(&name)
            .map_err(|source| FolderbaseError::io(&display, source))?;
        sync_directory(&parent, &display)
    }

    pub(crate) fn remove_file_if_present(&self, relative: &Path) -> Result<()> {
        let (parent, name) = self.open_parent(relative)?;
        let display = self.display(relative);
        match reject_windows_reparse(&parent, &name, &display) {
            Ok(()) => {}
            Err(FolderbaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
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

    pub(crate) fn closed_directory_entries(
        &self,
        relative: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<(OsString, bool)>> {
        let directory = self.open_directory(relative)?;
        let display = self.display(relative);
        let mut entries = Vec::new();
        for entry in directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&display, source))?
        {
            let entry = entry.map_err(|source| FolderbaseError::io(&display, source))?;
            if entries.len() == maximum_entries {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: "private migration directory exceeds its entry bound".to_owned(),
                });
            }
            let file_type = entry
                .file_type()
                .map_err(|source| FolderbaseError::io(&display, source))?;
            if !file_type.is_file() && !file_type.is_dir() {
                return Err(FolderbaseError::UnsafePath(
                    self.display(&relative.join(entry.file_name())),
                ));
            }
            entries.push((entry.file_name(), file_type.is_dir()));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries)
    }

    pub(crate) fn directory_entry_names(
        &self,
        relative: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<OsString>> {
        let directory = self.open_directory(relative)?;
        let display = self.display(relative);
        let mut names = Vec::new();
        for entry in directory
            .read_dir(".")
            .map_err(|source| FolderbaseError::io(&display, source))?
        {
            let entry = entry.map_err(|source| FolderbaseError::io(&display, source))?;
            if names.len() == maximum_entries {
                return Err(FolderbaseError::InvalidRecord {
                    path: display,
                    message: "migration parent directory exceeds its entry bound".to_owned(),
                });
            }
            names.push(entry.file_name());
        }
        names.sort();
        Ok(names)
    }

    pub(crate) fn closed_regular_file_names(
        &self,
        relative: &Path,
        maximum_entries: usize,
    ) -> Result<Vec<OsString>> {
        self.closed_directory_entries(relative, maximum_entries)?
            .into_iter()
            .map(|(name, is_directory)| {
                if is_directory {
                    Err(FolderbaseError::InvalidRecord {
                        path: self.display(&relative.join(&name)),
                        message: "private migration file directory contains a nested directory"
                            .to_owned(),
                    })
                } else {
                    Ok(name)
                }
            })
            .collect()
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

fn validate_private_name(name: &str) -> Result<()> {
    validate_private_name_os(OsStr::new(name))
}

fn validate_private_name_os(name: &OsStr) -> Result<()> {
    let path = Path::new(name);
    let mut components = path.components();
    if name.is_empty()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_private_directory_metadata(directory: &Dir, display: &Path) -> Result<()> {
    let file = directory
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std_file();
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if !metadata.is_dir() || metadata_is_link_or_reparse(&metadata) {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(FolderbaseError::InvalidRecord {
                path: display.to_path_buf(),
                message: "private migration directory is not owner-only".to_owned(),
            });
        }
    }
    Ok(())
}

fn remove_private_regular_if_present(
    directory: &VerifiedPrivateDirectory,
    name: &OsStr,
    display: &Path,
) -> Result<()> {
    match directory.directory.symlink_metadata(name) {
        Ok(metadata) => {
            reject_windows_reparse(&directory.directory, name, display)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
            }
            directory
                .directory
                .remove_file(name)
                .map_err(|source| FolderbaseError::io(display, source))?;
            sync_directory(&directory.directory, &directory.display)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(FolderbaseError::io(display, source)),
    }
}

fn install_prepared_private_claim(
    destination: &VerifiedPrivateDirectory,
    preparing_name: &OsStr,
    destination_name: &OsStr,
    expected_sha256: &str,
    expected_bytes: u64,
) -> Result<MigrationRegularFact> {
    let destination_display = destination.display.join(destination_name);
    match destination
        .directory
        .hard_link(preparing_name, &destination.directory, destination_name)
    {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            let fact = destination.relaxed_regular_fact(destination_name, expected_sha256)?;
            if fact.bytes != expected_bytes {
                return Err(FolderbaseError::MigrationVerificationFailed(
                    destination_display,
                ));
            }
        }
        Err(source) => return Err(FolderbaseError::io(&destination_display, source)),
    }
    remove_private_regular_if_present(
        destination,
        preparing_name,
        &destination.display.join(preparing_name),
    )?;
    let fact = destination.relaxed_regular_fact(destination_name, expected_sha256)?;
    if fact.bytes != expected_bytes {
        return Err(FolderbaseError::MigrationVerificationFailed(
            destination_display,
        ));
    }
    Ok(fact)
}

fn directory_fact_from_handle(directory: &Dir, display: &Path) -> Result<MigrationDirectoryFact> {
    let file = directory
        .try_clone()
        .map_err(|source| FolderbaseError::io(display, source))?
        .into_std_file();
    let metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    if !metadata.is_dir() || metadata_is_link_or_reparse(&metadata) {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    let identity = crate::physical_identity::PhysicalIdentity::from_file(&file)
        .map_err(|source| FolderbaseError::io(display, source))?;
    #[cfg(unix)]
    let unix_mode = {
        use std::os::unix::fs::MetadataExt;

        Some(metadata.mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let unix_mode = None;
    Ok(MigrationDirectoryFact {
        physical_identity_sha256: identity.stable_sha256(),
        device_sha256: identity.device_sha256(),
        read_only: portable_read_only(&metadata),
        unix_mode,
    })
}

#[derive(Debug, Clone, Copy)]
enum ExactFactLocation {
    Visible,
    Private,
}

fn exact_fact_mismatch(location: ExactFactLocation, display: &Path) -> FolderbaseError {
    match location {
        ExactFactLocation::Visible => {
            FolderbaseError::MigrationSourceChanged(display.to_path_buf())
        }
        ExactFactLocation::Private => {
            FolderbaseError::MigrationVerificationFailed(display.to_path_buf())
        }
    }
}

fn require_exact_regular_fact(
    fact: &MigrationRegularFact,
    observed_sha256: &str,
    expected: ExactRegularLeaf<'_>,
    display: &Path,
    location: ExactFactLocation,
) -> Result<()> {
    let executable = fact.unix_mode.is_some_and(|mode| mode & 0o111 != 0);
    if fact.physical_identity_sha256 != expected.physical_identity_sha256
        || fact.device_sha256 != expected.device_sha256
        || fact.bytes != expected.bytes
        || observed_sha256 != expected.sha256
        || fact.read_only != expected.read_only
        || executable != expected.executable
        || fact.link_count != expected.link_count
    {
        return Err(exact_fact_mismatch(location, display));
    }
    Ok(())
}

fn require_exact_directory_fact(
    fact: &MigrationDirectoryFact,
    expected: ExactDirectoryLeaf<'_>,
    display: &Path,
    location: ExactFactLocation,
) -> Result<()> {
    let executable = fact.unix_mode.is_none_or(|mode| mode & 0o111 != 0);
    if fact.physical_identity_sha256 != expected.physical_identity_sha256
        || fact.device_sha256 != expected.device_sha256
        || fact.read_only != expected.read_only
        || executable != expected.executable
    {
        return Err(exact_fact_mismatch(location, display));
    }
    Ok(())
}

fn require_absent_from_retained_parent(
    parent: &VerifiedVisibleDirectory,
    name: &OsStr,
) -> Result<()> {
    match parent.directory.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(FolderbaseError::MigrationSourceChanged(
            parent.display.join(name),
        )),
        Err(error) => Err(FolderbaseError::io(parent.display.join(name), error)),
    }
}

fn require_exact_visible_claim_source(
    parent: &VerifiedVisibleDirectory,
    name: &OsStr,
    expectation: ExactLeafClaimExpectation<'_>,
) -> Result<()> {
    let display = parent.display.join(name);
    match expectation {
        ExactLeafClaimExpectation::Regular(expected) => {
            let fact = visible_regular_fact_from_parent(
                &parent.directory,
                &parent.display,
                name,
                expected.sha256,
            )?;
            require_exact_regular_fact(
                &fact,
                expected.sha256,
                expected,
                &display,
                ExactFactLocation::Visible,
            )
        }
        ExactLeafClaimExpectation::EmptyDirectory(expected) => {
            let fact =
                visible_directory_fact_from_parent(&parent.directory, &parent.display, name)?;
            require_exact_directory_fact(&fact, expected, &display, ExactFactLocation::Visible)?;
            let directory = open_directory_nofollow(&parent.directory, name, &display)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            let private_view = VerifiedPrivateDirectory {
                directory,
                display: display.clone(),
            };
            if !private_view.closed_entries(1)?.is_empty() {
                return Err(FolderbaseError::MigrationSourceChanged(display));
            }
            Ok(())
        }
    }
}

fn visible_regular_fact_from_parent(
    parent: &Dir,
    parent_display: &Path,
    name: &OsStr,
    expected_sha256: &str,
) -> Result<MigrationRegularFact> {
    let view = VerifiedPrivateDirectory {
        directory: parent
            .try_clone()
            .map_err(|source| FolderbaseError::io(parent_display, source))?,
        display: parent_display.to_path_buf(),
    };
    view.relaxed_regular_fact(name, expected_sha256)
}

fn visible_directory_fact_from_parent(
    parent: &Dir,
    parent_display: &Path,
    name: &OsStr,
) -> Result<MigrationDirectoryFact> {
    let display = parent_display.join(name);
    let directory = open_directory_nofollow(parent, name, &display)
        .map_err(|source| FolderbaseError::io(&display, source))?;
    directory_fact_from_handle(&directory, &display)
}

fn nofollow_regular_read_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    options
}

fn reject_windows_reparse(parent: &Dir, name: &OsStr, display: &Path) -> Result<()> {
    #[cfg(windows)]
    if windows_entry_is_reparse(parent, name, display)? {
        return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
    }
    #[cfg(not(windows))]
    {
        let _ = (parent, name, display);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_entry_is_reparse(parent: &Dir, name: &OsStr, display: &Path) -> Result<bool> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
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
    Ok(metadata_is_link_or_reparse(&metadata))
}

fn validate_directory_fidelity(
    fact: &MigrationDirectoryFact,
    read_only: bool,
    executable: bool,
    display: &Path,
) -> Result<()> {
    let observed_executable = fact.unix_mode.is_none_or(|mode| mode & 0o111 != 0);
    if fact.read_only != read_only || observed_executable != executable {
        return Err(FolderbaseError::MigrationVerificationFailed(
            display.to_path_buf(),
        ));
    }
    Ok(())
}

fn set_directory_fidelity(
    directory: &Dir,
    read_only: bool,
    executable: bool,
    display: &Path,
) -> Result<()> {
    let file = reopen_directory_file(directory, display)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut mode = if read_only { 0o555 } else { 0o755 };
        if !executable {
            mode &= !0o111;
        }
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|source| FolderbaseError::io(display, source))?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = file
            .metadata()
            .map_err(|source| FolderbaseError::io(display, source))?
            .permissions();
        permissions.set_readonly(read_only);
        file.set_permissions(permissions)
            .map_err(|source| FolderbaseError::io(display, source))?;
        let _ = executable;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reopen_directory_file(directory: &Dir, display: &Path) -> Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    // cap-std intentionally retains Linux directories with O_PATH. That is
    // sufficient for capability-relative traversal, but descriptor operations
    // such as fchmod and fsync fail with EBADF. Reopen only the fixed "."
    // component through the retained capability, preserving the no-ambient-path
    // security boundary while obtaining an operable directory descriptor.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(FolderbaseError::io(
            display,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn reopen_directory_file(directory: &Dir, display: &Path) -> Result<std::fs::File> {
    directory
        .try_clone()
        .map(Dir::into_std_file)
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(windows)]
fn reopen_directory_file(directory: &Dir, display: &Path) -> Result<std::fs::File> {
    use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;

    reopen_windows_directory_with_access(directory, FILE_WRITE_ATTRIBUTES)
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(windows)]
fn reopen_windows_directory_with_access(
    directory: &Dir,
    desired_access: u32,
) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
        },
    };

    let original = directory.try_clone()?.into_std_file();
    let reopened = unsafe {
        ReOpenFile(
            original.as_raw_handle() as HANDLE,
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if reopened == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_handle(reopened as _) };
    let metadata = file.metadata()?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(file)
}

#[cfg(unix)]
fn private_unix_mode(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.mode() & 0o7777)
}

#[cfg(not(unix))]
fn private_unix_mode(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

fn portable_read_only(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        private_unix_mode(metadata).is_some_and(|mode| mode & 0o222 == 0)
    }
    #[cfg(not(unix))]
    {
        metadata.permissions().readonly()
    }
}

#[cfg(unix)]
fn regular_content_version(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
    _display: &Path,
) -> Result<RegularContentVersion> {
    use std::os::unix::fs::MetadataExt;

    Ok(RegularContentVersion::Unix {
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(windows)]
fn regular_content_version(
    file: &std::fs::File,
    _metadata: &std::fs::Metadata,
    display: &Path,
) -> Result<RegularContentVersion> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx},
    };

    let mut information = FILE_BASIC_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileBasicInfo,
            (&raw mut information).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(FolderbaseError::io(
            display,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(RegularContentVersion::Windows {
        last_write_time: information.LastWriteTime,
        change_time: information.ChangeTime,
    })
}

#[cfg(not(any(unix, windows)))]
fn regular_content_version(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
    _display: &Path,
) -> Result<RegularContentVersion> {
    Ok(RegularContentVersion::Portable {
        modified: metadata.modified().ok(),
        bytes: metadata.len(),
    })
}

#[cfg(unix)]
fn retained_link_fingerprint(metadata: &Metadata, target: &Path) -> String {
    use cap_fs_ext::OsMetadataExt;

    format!(
        "other:{}:{}:{}:{}:{}:{}:{:?}",
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime_nsec(),
        Some(target)
    )
}

#[cfg(not(unix))]
fn retained_link_fingerprint(metadata: &Metadata, target: &Path) -> String {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.into_std().duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| (value.as_secs(), value.subsec_nanos()));
    format!(
        "other:{}:{}:{modified:?}:{:?}",
        metadata.len(),
        metadata.permissions().readonly(),
        Some(target)
    )
}

#[cfg(unix)]
fn retained_nonregular_fingerprint(metadata: &Metadata, kind: &str) -> String {
    use cap_fs_ext::OsMetadataExt;

    format!(
        "{kind}:{}:{}:{}:{}:{}:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec()
    )
}

#[cfg(not(unix))]
fn retained_nonregular_fingerprint(metadata: &Metadata, kind: &str) -> String {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.into_std().duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| (value.as_secs(), value.subsec_nanos()));
    format!(
        "{kind}:{}:{}:{modified:?}",
        metadata.len(),
        metadata.permissions().readonly()
    )
}

fn verify_visible_regular_after_read(
    file: &std::fs::File,
    initial_metadata: &std::fs::Metadata,
    initial_identity: crate::physical_identity::PhysicalIdentity,
    initial_link_count: u64,
    observed_bytes: u64,
    display: &Path,
) -> Result<()> {
    let final_metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    let final_identity = crate::physical_identity::PhysicalIdentity::from_file(file)
        .map_err(|source| FolderbaseError::io(display, source))?;
    if observed_bytes != initial_metadata.len()
        || final_metadata.len() != initial_metadata.len()
        || metadata_is_link_or_reparse(&final_metadata)
        || final_identity != initial_identity
        || private_regular_link_count(file, &final_metadata, display)? != initial_link_count
        || portable_read_only(&final_metadata) != portable_read_only(initial_metadata)
        || private_unix_mode(&final_metadata) != private_unix_mode(initial_metadata)
    {
        return Err(FolderbaseError::MigrationSourceChanged(
            display.to_path_buf(),
        ));
    }
    Ok(())
}

fn verify_fingerprinted_regular_after_read(
    file: &std::fs::File,
    initial_metadata: &std::fs::Metadata,
    initial_identity: crate::physical_identity::PhysicalIdentity,
    initial_link_count: u64,
    initial_content_version: &RegularContentVersion,
    observed_bytes: u64,
    display: &Path,
) -> Result<()> {
    let final_metadata = file
        .metadata()
        .map_err(|source| FolderbaseError::io(display, source))?;
    let final_identity = crate::physical_identity::PhysicalIdentity::from_file(file)
        .map_err(|source| FolderbaseError::io(display, source))?;
    if observed_bytes != initial_metadata.len()
        || final_metadata.len() != initial_metadata.len()
        || metadata_is_link_or_reparse(&final_metadata)
        || final_identity != initial_identity
        || private_regular_link_count(file, &final_metadata, display)? != initial_link_count
        || portable_read_only(&final_metadata) != portable_read_only(initial_metadata)
        || private_unix_mode(&final_metadata) != private_unix_mode(initial_metadata)
        || regular_content_version(file, &final_metadata, display)? != *initial_content_version
    {
        return Err(FolderbaseError::MigrationSourceChanged(
            display.to_path_buf(),
        ));
    }
    Ok(())
}

fn set_visible_fidelity(
    file: &cap_std::fs::File,
    read_only: bool,
    executable: bool,
    display: &Path,
) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;

        let mut mode = if read_only { 0o444 } else { 0o644 };
        if executable {
            mode |= 0o111;
        }
        file.set_permissions(cap_std::fs::Permissions::from_mode(mode))
            .map_err(|source| FolderbaseError::io(display, source))?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = file
            .metadata()
            .map_err(|source| FolderbaseError::io(display, source))?
            .permissions();
        permissions.set_readonly(read_only);
        file.set_permissions(permissions)
            .map_err(|source| FolderbaseError::io(display, source))?;
        let _ = executable;
    }
    Ok(())
}

#[cfg(unix)]
fn private_regular_link_count(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
    _display: &Path,
) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.nlink())
}

#[cfg(windows)]
fn private_regular_link_count(
    file: &std::fs::File,
    _metadata: &std::fs::Metadata,
    display: &Path,
) -> Result<u64> {
    winapi_util::file::information(file)
        .map(|information| information.number_of_links())
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(not(any(unix, windows)))]
fn private_regular_link_count(
    _file: &std::fs::File,
    _metadata: &std::fs::Metadata,
    _display: &Path,
) -> Result<u64> {
    Ok(1)
}

fn map_rename_noreplace_error(path: impl Into<PathBuf>, error: std::io::Error) -> FolderbaseError {
    let path = path.into();
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => FolderbaseError::WouldOverwrite(path),
        std::io::ErrorKind::Unsupported => FolderbaseError::UnsupportedMigrationFilesystem {
            path,
            reason: error.to_string(),
        },
        _ => FolderbaseError::io(path, error),
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_noreplace(
    source_parent: &Dir,
    source_name: &OsStr,
    destination_parent: &Dir,
    destination_name: &OsStr,
) -> std::io::Result<()> {
    use std::{
        ffi::CString,
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
    };

    let source_name = CString::new(source_name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let destination_name = CString::new(destination_name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    #[cfg(target_vendor = "apple")]
    let result = unsafe {
        libc::renameatx_np(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = unsafe {
        libc::renameat2(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_noreplace(
    source_parent: &Dir,
    source_name: &OsStr,
    destination_parent: &Dir,
    destination_name: &OsStr,
) -> std::io::Result<()> {
    use cap_std::fs::OpenOptionsExt;
    use std::{
        mem::size_of,
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
            FileRenameInfo, SYNCHRONIZE, SetFileInformationByHandle,
        },
    };

    const MAX_RENAME_UTF16_UNITS: usize = 32_767;

    let destination_utf16 = destination_name.encode_wide().collect::<Vec<_>>();
    if destination_utf16.is_empty()
        || destination_utf16.len() > MAX_RENAME_UTF16_UNITS
        || destination_utf16.contains(&0)
    {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }

    let mut source_options = OpenOptions::new();
    source_options
        .access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .follow(FollowSymlinks::No);
    let source = source_parent
        .open_with(source_name, &source_options)
        .map_err(|source| {
            std::io::Error::new(
                source.kind(),
                format!("open source for no-replace rename: {source}"),
            )
        })?
        .into_std();
    let source_metadata = source.metadata()?;
    if metadata_is_link_or_reparse(&source_metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to rename a reparse-point leaf",
        ));
    }
    let destination_directory = reopen_windows_directory_with_access(
        destination_parent,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
    )
    .map_err(|source| {
        std::io::Error::new(
            source.kind(),
            format!("ReOpenFile(destination directory for no-replace rename): {source}"),
        )
    })?;

    let file_name_bytes = destination_utf16
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // The Win32 contract requires the complete structure size plus the
    // filename bytes. The FileName field offset is smaller on 64-bit Windows
    // because FILE_RENAME_INFO has trailing alignment padding.
    let total_bytes = size_of::<FILE_RENAME_INFO>()
        .checked_add(file_name_bytes)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let words = total_bytes.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        (*information).RootDirectory = destination_directory.as_raw_handle() as HANDLE;
        (*information).FileNameLength = u32::try_from(file_name_bytes)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        ptr::copy_nonoverlapping(
            destination_utf16.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            destination_utf16.len(),
        );
        if SetFileInformationByHandle(
            source.as_raw_handle() as HANDLE,
            FileRenameInfo,
            information.cast(),
            u32::try_from(total_bytes)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
        ) == 0
        {
            let source = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                source.kind(),
                format!("SetFileInformationByHandle(FileRenameInfo): {source}"),
            ));
        }
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
fn rename_noreplace(
    _source_parent: &Dir,
    _source_name: &OsStr,
    _destination_parent: &Dir,
    _destination_name: &OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace rename is unavailable on this platform",
    ))
}

#[cfg(not(windows))]
fn open_directory_nofollow(parent: &Dir, name: &OsStr, _display: &Path) -> std::io::Result<Dir> {
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
fn open_directory_nofollow(parent: &Dir, name: &OsStr, display: &Path) -> std::io::Result<Dir> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .follow(FollowSymlinks::No)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
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

#[cfg(target_os = "linux")]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    let file = reopen_directory_file(directory, display)?;
    file.sync_all()
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().sync_all())
        .map_err(|source| FolderbaseError::io(display, source))
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod linux_directory_sync_tests {
    use std::fs;

    use cap_fs_ext::DirExt;
    use cap_std::{ambient_authority, fs::Dir};

    use super::{set_directory_fidelity, sync_directory};

    #[test]
    fn retained_o_path_directory_is_reopened_before_fsync() {
        let root = tempfile::tempdir().expect("temporary root");
        fs::create_dir(root.path().join("private")).expect("private directory");
        let ambient = Dir::open_ambient_dir(root.path(), ambient_authority()).expect("root");
        let retained = ambient
            .open_dir_nofollow("private")
            .expect("retained no-follow directory");

        sync_directory(&retained, &root.path().join("private"))
            .expect("O_PATH authority must be reopened as an fsyncable descriptor");
    }

    #[test]
    fn retained_o_path_directory_is_reopened_before_setting_fidelity() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary root");
        let private_path = root.path().join("private");
        fs::create_dir(&private_path).expect("private directory");
        let ambient = Dir::open_ambient_dir(root.path(), ambient_authority()).expect("root");
        let retained = ambient
            .open_dir_nofollow("private")
            .expect("retained no-follow directory");

        set_directory_fidelity(&retained, true, true, &private_path)
            .expect("O_PATH authority must be reopened as a chmod-capable descriptor");

        let mode = fs::metadata(&private_path)
            .expect("private metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o555);
    }
}

#[cfg(windows)]
fn sync_directory(_directory: &Dir, _display: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, windows))]
mod windows_directory_fidelity_tests {
    use std::{ffi::OsStr, fs, path::Path};

    use cap_std::{ambient_authority, fs::Dir};

    use super::{
        MigrationFilesystem, VerifiedPrivateDirectory, open_directory_nofollow,
        remove_private_regular_if_present, set_directory_fidelity,
    };
    use crate::FolderbaseError;

    #[test]
    fn full_private_directory_claim_applies_and_validates_windows_fidelity() {
        let root = tempfile::tempdir().expect("temporary root");
        let private = VerifiedPrivateDirectory {
            directory: Dir::open_ambient_dir(root.path(), ambient_authority())
                .expect("retained private root"),
            display: root.path().to_path_buf(),
        };

        let writable = private
            .prepare_directory_claim("writable.claim", false, true)
            .expect("writable transaction directory claim");
        assert!(!writable.read_only);
        assert!(writable.unix_mode.is_none());

        let readonly = private
            .prepare_directory_claim("readonly.claim", true, true)
            .expect("readonly transaction directory claim");
        assert!(readonly.read_only);
        assert!(readonly.unix_mode.is_none());
    }

    #[test]
    fn private_cleanup_rejects_a_reparse_leaf_without_removing_it() {
        use std::os::windows::fs::symlink_file;

        let root = tempfile::tempdir().expect("temporary private root");
        let foreign = tempfile::NamedTempFile::new().expect("foreign regular file");
        fs::write(foreign.path(), b"foreign bytes\n").expect("foreign bytes");
        let link = root.path().join("staged.claim");
        symlink_file(foreign.path(), &link).expect("GitHub Windows runners permit file symlinks");
        let private = VerifiedPrivateDirectory {
            directory: Dir::open_ambient_dir(root.path(), ambient_authority())
                .expect("retained private root"),
            display: root.path().to_path_buf(),
        };

        assert!(matches!(
            remove_private_regular_if_present(
                &private,
                OsStr::new("staged.claim"),
                &link,
            ),
            Err(FolderbaseError::UnsafePath(path)) if path == link
        ));
        assert!(
            fs::symlink_metadata(&link)
                .expect("reparse leaf remains")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(foreign.path()).expect("foreign target remains"),
            b"foreign bytes\n"
        );
    }

    #[test]
    fn raw_state_replace_and_remove_helpers_reject_reparse_leaves() {
        use std::os::windows::fs::symlink_file;

        let root = tempfile::tempdir().expect("temporary retained root");
        let foreign = tempfile::NamedTempFile::new().expect("foreign regular file");
        fs::write(foreign.path(), b"foreign bytes\n").expect("foreign bytes");
        let filesystem = MigrationFilesystem {
            root: Dir::open_ambient_dir(root.path(), ambient_authority())
                .expect("retained migration root"),
            display_root: root.path().to_path_buf(),
        };

        for (name, operation) in [
            ("replace.link", 0_u8),
            ("remove.link", 1_u8),
            ("remove-if-present.link", 2_u8),
        ] {
            let link = root.path().join(name);
            symlink_file(foreign.path(), &link)
                .expect("GitHub Windows runners permit file symlinks");
            let result = match operation {
                0 => filesystem.replace(Path::new(name), b"replacement\n"),
                1 => filesystem.remove_file(Path::new(name)),
                2 => filesystem.remove_file_if_present(Path::new(name)),
                _ => unreachable!("closed operation fixture"),
            };
            assert!(matches!(
                result,
                Err(FolderbaseError::UnsafePath(path)) if path == link
            ));
            assert!(
                fs::symlink_metadata(&link)
                    .expect("reparse leaf remains")
                    .file_type()
                    .is_symlink()
            );
        }
        assert_eq!(
            fs::read(foreign.path()).expect("foreign target remains"),
            b"foreign bytes\n"
        );
    }

    #[test]
    fn retained_directory_reopens_with_write_attributes_for_fidelity() {
        let root = tempfile::tempdir().expect("temporary root");
        let private_path = root.path().join("private");
        fs::create_dir(&private_path).expect("private directory");
        let ambient = Dir::open_ambient_dir(root.path(), ambient_authority()).expect("root");
        let retained =
            open_directory_nofollow(&ambient, OsStr::new("private"), &private_path).expect("child");

        set_directory_fidelity(&retained, true, false, &private_path)
            .expect("set readonly fidelity");
        assert!(
            fs::metadata(&private_path)
                .expect("readonly metadata")
                .permissions()
                .readonly()
        );

        set_directory_fidelity(&retained, false, false, &private_path)
            .expect("clear readonly fidelity");
        assert!(
            !fs::metadata(&private_path)
                .expect("writable metadata")
                .permissions()
                .readonly()
        );
    }
}

#[cfg(test)]
mod rename_noreplace_error_tests {
    use std::{
        ffi::OsStr,
        fs,
        io::{Error, ErrorKind},
        path::Path,
    };

    use cap_std::fs::Dir;

    use super::{map_rename_noreplace_error, rename_noreplace};
    use crate::FolderbaseError;

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    )))]
    use super::MigrationFilesystem;

    #[test]
    fn unsupported_no_replace_is_a_typed_migration_filesystem_error() {
        let path = Path::new("Folderbase/target.bin");
        let error = map_rename_noreplace_error(
            path,
            Error::new(ErrorKind::Unsupported, "native no-replace is unavailable"),
        );

        assert!(matches!(
            error,
            FolderbaseError::UnsupportedMigrationFilesystem {
                path: observed_path,
                reason,
            } if observed_path == path
                && reason == "native no-replace is unavailable"
        ));
    }

    #[test]
    fn no_replace_collision_remains_would_overwrite() {
        let path = Path::new("Folderbase/target.bin");
        let error = map_rename_noreplace_error(path, Error::from(ErrorKind::AlreadyExists));

        assert!(
            matches!(error, FolderbaseError::WouldOverwrite(observed_path) if observed_path == path)
        );
    }

    #[test]
    fn ordinary_no_replace_failure_remains_io_with_its_kind() {
        let path = Path::new("Folderbase/target.bin");
        let error = map_rename_noreplace_error(path, Error::from(ErrorKind::PermissionDenied));

        assert!(matches!(
            error,
            FolderbaseError::Io {
                path: observed_path,
                source,
            } if observed_path == path && source.kind() == ErrorKind::PermissionDenied
        ));
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    )))]
    #[test]
    fn unsupported_platform_preflight_is_typed_before_transaction_work() {
        let root = tempfile::tempdir().expect("unsupported-platform fixture");
        let filesystem = MigrationFilesystem {
            root: Dir::open_ambient_dir(root.path(), cap_std::ambient_authority())
                .expect("retained root"),
            display_root: root.path().to_path_buf(),
        };

        assert!(matches!(
            filesystem.require_atomic_noreplace(),
            Err(FolderbaseError::UnsupportedMigrationFilesystem { path, reason })
                if path == root.path() && reason.contains("no-replace rename")
        ));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_no_replace_moves_an_unoccupied_leaf() {
        let root = tempfile::tempdir().expect("retained no-replace fixture");
        fs::write(root.path().join("source.bin"), b"source bytes").expect("source");
        let directory = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority())
            .expect("retained directory");

        rename_noreplace(
            &directory,
            OsStr::new("source.bin"),
            &directory,
            OsStr::new("destination.bin"),
        )
        .expect("native no-replace move");

        assert!(!root.path().join("source.bin").exists());
        assert_eq!(
            fs::read(root.path().join("destination.bin")).expect("destination bytes"),
            b"source bytes"
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_no_replace_moves_across_retained_parent_directories() {
        let root = tempfile::tempdir().expect("retained no-replace fixture");
        let source_path = root.path().join("source");
        let destination_path = root.path().join("destination");
        fs::create_dir(&source_path).expect("source parent");
        fs::create_dir(&destination_path).expect("destination parent");
        fs::write(source_path.join("source.bin"), b"source bytes").expect("source");
        let root_directory = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority())
            .expect("retained root");
        let source_directory = root_directory
            .open_dir("source")
            .expect("source capability");
        let destination_directory = root_directory
            .open_dir("destination")
            .expect("destination capability");

        rename_noreplace(
            &source_directory,
            OsStr::new("source.bin"),
            &destination_directory,
            OsStr::new("destination.bin"),
        )
        .expect("native cross-parent no-replace move");

        assert!(!source_path.join("source.bin").exists());
        assert_eq!(
            fs::read(destination_path.join("destination.bin")).expect("destination bytes"),
            b"source bytes"
        );
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    ))]
    #[test]
    fn native_no_replace_collision_preserves_both_files_and_maps_to_would_overwrite() {
        let root = tempfile::tempdir().expect("retained no-replace fixture");
        fs::write(root.path().join("source.bin"), b"source bytes").expect("source");
        fs::write(root.path().join("destination.bin"), b"destination bytes").expect("destination");
        let directory = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority())
            .expect("retained directory");

        let error = rename_noreplace(
            &directory,
            OsStr::new("source.bin"),
            &directory,
            OsStr::new("destination.bin"),
        )
        .expect_err("native no-replace must refuse the occupied destination");
        let error = map_rename_noreplace_error(root.path().join("destination.bin"), error);

        assert!(matches!(
            error,
            FolderbaseError::WouldOverwrite(path)
                if path == root.path().join("destination.bin")
        ));
        assert_eq!(
            fs::read(root.path().join("source.bin")).expect("preserved source"),
            b"source bytes"
        );
        assert_eq!(
            fs::read(root.path().join("destination.bin")).expect("preserved destination"),
            b"destination bytes"
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{ffi::OsStr, fs, os::unix::fs::PermissionsExt};

    use cap_fs_ext::DirExt;
    use cap_std::fs::Dir;

    use super::{VerifiedPrivateDirectory, validate_private_directory_metadata};
    use crate::FolderbaseError;

    fn private_fixture() -> (tempfile::TempDir, VerifiedPrivateDirectory) {
        let root = tempfile::tempdir().expect("fixture");
        let private = root.path().join("private");
        fs::create_dir(&private).expect("private");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("private mode");
        let ambient =
            Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).expect("root cap");
        let directory = ambient
            .open_dir_nofollow("private")
            .expect("private capability");
        validate_private_directory_metadata(&directory, &private).expect("private verification");
        (
            root,
            VerifiedPrivateDirectory {
                directory,
                display: private,
            },
        )
    }

    #[test]
    fn retained_private_file_read_is_not_redirected_by_a_path_replacement() {
        let (root, private) = private_fixture();
        let path = root.path().join("private/program.json");
        fs::write(&path, b"original admitted bytes").expect("program");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("program mode");

        let bytes = private
            .read_regular_bounded_with_hook(OsStr::new("program.json"), 1024, || {
                fs::rename(&path, root.path().join("detached-program.json"))
                    .expect("detach admitted file");
                fs::write(&path, b"replacement bytes").expect("replacement");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("replacement mode");
            })
            .expect("retained read");

        assert_eq!(bytes, b"original admitted bytes");
        assert_eq!(
            fs::read(path).expect("visible replacement"),
            b"replacement bytes"
        );
    }

    #[test]
    fn private_file_hardlink_alias_is_rejected_before_read() {
        let (root, private) = private_fixture();
        let path = root.path().join("private/program.json");
        fs::write(&path, b"admitted bytes").expect("program");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("program mode");
        fs::hard_link(&path, root.path().join("alias")).expect("hardlink alias");

        let error = private
            .read_regular_bounded(OsStr::new("program.json"), 1024)
            .expect_err("aliased private state must fail closed");
        assert!(matches!(error, FolderbaseError::InvalidRecord { .. }));
    }
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(directory: &Dir, display: &Path) -> Result<()> {
    directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().sync_all())
        .map_err(|source| FolderbaseError::io(display, source))
}
