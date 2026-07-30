use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

use crate::physical_identity::PhysicalIdentity;
use serde::{Deserialize, Serialize};

pub(crate) const RESTORE_AUTHORITIES_DIRECTORY: &str =
    ".folderbase/transactions/folderbase-version-restores";
pub(crate) const RESTORE_AUTHORITY_FILENAME: &str = "authority.json";
pub(crate) const RESTORE_AUTHORITY_FORMAT_V1: &str = "folderbase-restore-authority-v1";
pub(crate) const MAX_RESTORE_AUTHORITIES: usize = 4096;
pub(crate) const MAX_RESTORE_AUTHORITY_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreAuthorityRecord {
    pub(crate) format: String,
    pub(crate) folderbase_id: String,
    pub(crate) root_instance_sha256: String,
    pub(crate) transaction_id: String,
    pub(crate) workspace_path: String,
    pub(crate) private_stage_path: String,
    pub(crate) published_identity_sha256: String,
}

pub(crate) fn restore_transaction_directory(transaction_id: &str) -> PathBuf {
    Path::new(RESTORE_AUTHORITIES_DIRECTORY).join(transaction_id)
}

pub(crate) fn restore_stage_path(transaction_id: &str) -> PathBuf {
    restore_transaction_directory(transaction_id).join("content")
}

pub(crate) fn restore_authority_record_path(transaction_id: &str) -> PathBuf {
    restore_transaction_directory(transaction_id).join(RESTORE_AUTHORITY_FILENAME)
}

pub(crate) fn stable_file_identity_sha256(file: &File) -> io::Result<String> {
    Ok(PhysicalIdentity::from_file(file)?.stable_sha256())
}

#[cfg(unix)]
pub(crate) fn stable_unix_file_identity_sha256(device: u64, inode: u64) -> String {
    PhysicalIdentity::Unix { device, inode }.stable_sha256()
}

pub(crate) fn stable_file_link_count(file: &File) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Ok(file.metadata()?.nlink())
    }

    #[cfg(windows)]
    {
        let information = winapi_util::file::information(file.try_clone()?)?;
        Ok(u64::from(information.number_of_links()))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stable file link count is unavailable on this platform",
        ))
    }
}
