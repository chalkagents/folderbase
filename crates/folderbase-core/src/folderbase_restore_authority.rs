use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata()?;
        return Ok(stable_unix_file_identity_sha256(
            metadata.dev(),
            metadata.ino(),
        ));
    }

    #[cfg(windows)]
    {
        use std::{mem::size_of, os::windows::io::AsRawHandle};
        use windows_sys::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
        };

        let mut information = FILE_ID_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileIdInfo,
                (&raw mut information).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut digest = Sha256::new();
        digest.update(b"folderbase-workspace-file-identity-v1");
        digest.update([0]);
        digest.update(b"windows");
        digest.update([0]);
        digest.update(information.VolumeSerialNumber.to_be_bytes());
        digest.update(information.FileId.Identifier);
        return Ok(format!("{:x}", digest.finalize()));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stable file identity is unavailable on this platform",
        ))
    }
}

#[cfg(unix)]
pub(crate) fn stable_unix_file_identity_sha256(device: u64, inode: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"folderbase-workspace-file-identity-v1");
    digest.update([0]);
    digest.update(b"unix");
    digest.update([0]);
    digest.update(device.to_be_bytes());
    digest.update(inode.to_be_bytes());
    format!("{:x}", digest.finalize())
}

pub(crate) fn stable_file_link_count(file: &File) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        return Ok(file.metadata()?.nlink());
    }

    #[cfg(windows)]
    {
        let information = winapi_util::file::information(file.try_clone()?)?;
        return Ok(u64::from(information.number_of_links()));
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
