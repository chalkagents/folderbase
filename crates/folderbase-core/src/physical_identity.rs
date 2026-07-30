use std::{fs::File, io};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PhysicalIdentity {
    Unix {
        device: u64,
        inode: u64,
    },
    Windows {
        volume_serial: u64,
        file_id: [u8; 16],
    },
}

impl PhysicalIdentity {
    #[cfg(unix)]
    pub(crate) fn from_file(file: &File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata()?;
        Ok(Self::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    pub(crate) fn from_file(file: &File) -> io::Result<Self> {
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
        Ok(Self::Windows {
            volume_serial: information.VolumeSerialNumber,
            file_id: information.FileId.Identifier,
        })
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn from_file(_file: &File) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stable physical identity is unavailable on this platform",
        ))
    }

    pub(crate) fn stable_sha256(self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"folderbase-workspace-file-identity-v1");
        digest.update([0]);
        match self {
            Self::Unix { device, inode } => {
                digest.update(b"unix");
                digest.update([0]);
                digest.update(device.to_be_bytes());
                digest.update(inode.to_be_bytes());
            }
            Self::Windows {
                volume_serial,
                file_id,
            } => {
                digest.update(b"windows");
                digest.update([0]);
                digest.update(volume_serial.to_be_bytes());
                digest.update(file_id);
            }
        }
        format!("{:x}", digest.finalize())
    }

    #[cfg(test)]
    fn windows(volume_serial: u64, file_id: [u8; 16]) -> Self {
        Self::Windows {
            volume_serial,
            file_id,
        }
    }

    #[cfg(test)]
    fn unix(device: u64, inode: u64) -> Self {
        Self::Unix { device, inode }
    }
}

#[cfg(test)]
mod tests {
    use super::PhysicalIdentity;

    #[test]
    fn windows_identity_uses_all_128_file_id_bits() {
        let legacy_collision_a = PhysicalIdentity::windows(
            0x1020_3040_5060_7080,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
                0xf0, 0x01,
            ],
        );
        let legacy_collision_b = PhysicalIdentity::windows(
            0x1020_3040_5060_7080,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
        );

        assert_ne!(
            legacy_collision_a, legacy_collision_b,
            "equal volume and legacy low 64-bit file index cannot authorize a foreign ReFS file"
        );
    }

    #[test]
    fn identity_domains_and_unix_fields_are_distinct() {
        assert_ne!(PhysicalIdentity::unix(1, 2), PhysicalIdentity::unix(1, 3));
        assert_ne!(
            PhysicalIdentity::unix(1, 2),
            PhysicalIdentity::windows(1, [2; 16])
        );
    }
}
