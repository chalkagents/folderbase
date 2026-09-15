//! Amortize repeated sibling enumeration within one complete Object lookup.
//!
//! Only a directory with no `.folderbase` entry and a retained parent chain is
//! reusable. Observations retain their original handle and change metadata; a
//! changed observation is never replaced. Before returning a lookup result,
//! every retained boundary is classified again. This is local work reuse, not a
//! persistent identity index.

use std::path::{Path, PathBuf};

#[cfg(not(unix))]
use cap_std::ambient_authority;
use cap_std::fs::Dir;
#[cfg(unix)]
use {
    cap_std::fs::{Metadata, MetadataExt},
    std::{collections::BTreeMap, fs, io, os::unix::fs::OpenOptionsExt},
};

use crate::{
    FolderbaseError, Result,
    traversal_policy::{
        NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary_with_observer,
    },
    workspace::resolve_existing_workspace_file_with_boundary_check,
};

pub(crate) struct WorkspacePathLookup<'a> {
    root: &'a Path,
    #[cfg(unix)]
    root_directory: Dir,
    #[cfg(unix)]
    root_identity: (u64, u64),
    #[cfg(unix)]
    observations: BTreeMap<PathBuf, BoundaryObservation>,
    #[cfg(test)]
    examined_entries: usize,
}

impl<'a> WorkspacePathLookup<'a> {
    pub(crate) fn new(root: &'a Path) -> Result<Self> {
        #[cfg(unix)]
        let root_directory = open_directory_nofollow(root)?;
        #[cfg(unix)]
        let root_identity = directory_identity(&root_directory, root)?;
        Ok(Self {
            root,
            #[cfg(unix)]
            root_directory,
            #[cfg(unix)]
            root_identity,
            #[cfg(unix)]
            observations: BTreeMap::new(),
            #[cfg(test)]
            examined_entries: 0,
        })
    }

    pub(crate) fn resolve(&mut self, relative: &Path) -> Result<(PathBuf, PathBuf)> {
        #[cfg(unix)]
        self.verify_root()?;
        let root = self.root;
        resolve_existing_workspace_file_with_boundary_check(root, relative, |path| {
            #[cfg(unix)]
            if let Some(observation) = self.observations.get(path) {
                observation.verify(path)?;
                return Ok(false);
            }

            // Keep the existing resolver on platforms without the exact Unix
            // identity/change metadata checked by the scoped reuse below.
            #[cfg(not(unix))]
            let directory = Dir::open_ambient_dir(path, ambient_authority())
                .map_err(|source| FolderbaseError::io(path, source))?;
            #[cfg(unix)]
            let directory = open_directory_nofollow(path)?;
            #[cfg(unix)]
            let before = directory_fingerprint(&directory, path)?;
            let boundary = self.classify(&directory, path)?;
            let result = boundary_result(boundary, path)?;
            #[cfg(unix)]
            if boundary == NestedFolderbaseBoundaryKind::None
                && self.observations.len() < MAX_RETAINED_BOUNDARIES
                // Final validation must retain the entire chain back to root;
                // an uncached ancestor may change without changing this leaf.
                && path.parent().is_some_and(|parent| {
                    parent == self.root || self.observations.contains_key(parent)
                })
                && state_entry_absent(&directory, path)?
            {
                let observation = BoundaryObservation {
                    directory,
                    fingerprint: before,
                };
                observation.verify(path)?;
                self.observations.insert(path.to_path_buf(), observation);
            }
            Ok(result)
        })
    }

    fn classify(&mut self, directory: &Dir, path: &Path) -> Result<NestedFolderbaseBoundaryKind> {
        classify_nested_folderbase_boundary_with_observer(directory, path, || {
            #[cfg(test)]
            {
                self.examined_entries += 1;
            }
            Ok(())
        })
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            self.verify_root()?;
            // Keep every handle alive until the complete final check finishes.
            let observations = std::mem::take(&mut self.observations);
            for (path, observation) in &observations {
                observation.verify(path)?;
                if self.classify(&observation.directory, path)?
                    != NestedFolderbaseBoundaryKind::None
                    || !state_entry_absent(&observation.directory, path)?
                {
                    return Err(changed_during_lookup(path));
                }
                observation.verify(path)?;
            }
            self.verify_root()?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn verify_root(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(self.root)
            .map_err(|source| FolderbaseError::io(self.root, source))?;
        let metadata = Metadata::from_just_metadata(metadata);
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.dev(), metadata.ino()) != self.root_identity
            || directory_identity(&self.root_directory, self.root)? != self.root_identity
        {
            return Err(changed_during_lookup(self.root));
        }
        Ok(())
    }
}

// A wide/deep workspace must not retain one descriptor for every directory.
// Beyond this bound, resolve through the unchanged classifier without reuse.
#[cfg(unix)]
const MAX_RETAINED_BOUNDARIES: usize = 64;

#[cfg(unix)]
struct BoundaryObservation {
    directory: Dir,
    fingerprint: DirectoryFingerprint,
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct DirectoryFingerprint {
    identity: (u64, u64),
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    bytes: u64,
}

#[cfg(unix)]
impl DirectoryFingerprint {
    fn new(metadata: &Metadata) -> Self {
        Self {
            identity: (metadata.dev(), metadata.ino()),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
            bytes: metadata.len(),
        }
    }
}

#[cfg(unix)]
impl BoundaryObservation {
    fn verify(&self, path: &Path) -> Result<()> {
        let metadata =
            fs::symlink_metadata(path).map_err(|source| FolderbaseError::io(path, source))?;
        let metadata = Metadata::from_just_metadata(metadata);
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || DirectoryFingerprint::new(&metadata) != self.fingerprint
            || directory_fingerprint(&self.directory, path)? != self.fingerprint
            || !state_entry_absent(&self.directory, path)?
        {
            return Err(changed_during_lookup(path));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn directory_fingerprint(directory: &Dir, path: &Path) -> Result<DirectoryFingerprint> {
    directory
        .dir_metadata()
        .map(|metadata| DirectoryFingerprint::new(&metadata))
        .map_err(|source| FolderbaseError::io(path, source))
}

#[cfg(unix)]
fn directory_identity(directory: &Dir, path: &Path) -> Result<(u64, u64)> {
    directory
        .dir_metadata()
        .map(|metadata| (metadata.dev(), metadata.ino()))
        .map_err(|source| FolderbaseError::io(path, source))
}

#[cfg(unix)]
fn state_entry_absent(directory: &Dir, path: &Path) -> Result<bool> {
    match directory.symlink_metadata(".folderbase") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(source) => Err(FolderbaseError::io(path.join(".folderbase"), source)),
    }
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> Result<Dir> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map(Dir::from_std_file)
        .map_err(|source| FolderbaseError::io(path, source))
}

#[cfg(unix)]
fn changed_during_lookup(path: &Path) -> FolderbaseError {
    // Unlike UnsafePath on an unrelated stored path, this invalidates all
    // earlier resolutions in this scope and must never be swallowed.
    FolderbaseError::InvalidRecord {
        path: path.to_path_buf(),
        message: "directory changed during Object path lookup".to_owned(),
    }
}

fn boundary_result(boundary: NestedFolderbaseBoundaryKind, path: &Path) -> Result<bool> {
    match boundary {
        NestedFolderbaseBoundaryKind::ExactBoundary => Ok(true),
        NestedFolderbaseBoundaryKind::None => Ok(false),
        NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
            Err(FolderbaseError::UnsafePath(path.to_path_buf()))
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn repeated_paths_do_not_repeat_wide_sibling_scans() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        fs::create_dir(root.join("records")).unwrap();
        for index in 0..100 {
            fs::write(root.join(format!("records/{index}.json")), "{}\n").unwrap();
        }
        let mut lookup = WorkspacePathLookup::new(&root).unwrap();
        for index in 0..100 {
            lookup
                .resolve(Path::new(&format!("records/{index}.json")))
                .unwrap();
        }
        lookup.finish().unwrap();
        assert!(
            lookup.examined_entries <= 400,
            "repeated sibling enumeration: {} entries for 100 files",
            lookup.examined_entries
        );
    }

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap().join("root");
        fs::create_dir_all(root.join("records")).unwrap();
        fs::write(root.join("records/a.json"), "{}\n").unwrap();
        (fixture, root)
    }

    #[test]
    fn markerless_state_is_never_reused_when_its_manifest_appears() {
        let (_fixture, root) = fixture();
        fs::create_dir(root.join("records/.folderbase")).unwrap();
        let mut lookup = WorkspacePathLookup::new(&root).unwrap();
        lookup.resolve(Path::new("records/a.json")).unwrap();
        assert!(lookup.observations.is_empty());
        fs::write(root.join("records/.folderbase/manifest.json"), "opaque").unwrap();
        assert!(matches!(
            lookup.resolve(Path::new("records/a.json")),
            Err(FolderbaseError::UnsafePath(_))
        ));
    }

    #[test]
    fn markerless_ancestor_also_excludes_descendants_from_reuse() {
        let (_fixture, root) = fixture();
        fs::create_dir(root.join("records/.folderbase")).unwrap();
        fs::create_dir(root.join("records/child")).unwrap();
        fs::write(root.join("records/child/a.json"), "{}\n").unwrap();
        let mut lookup = WorkspacePathLookup::new(&root).unwrap();
        lookup.resolve(Path::new("records/child/a.json")).unwrap();
        assert!(lookup.observations.is_empty());
        fs::write(root.join("records/.folderbase/manifest.json"), "opaque").unwrap();
        assert!(matches!(
            lookup.resolve(Path::new("records/child/a.json")),
            Err(FolderbaseError::UnsafePath(_))
        ));
    }

    #[test]
    fn newly_created_state_invalidates_reuse_and_final_validation() {
        for reuse in [false, true] {
            let (_fixture, root) = fixture();
            let mut lookup = WorkspacePathLookup::new(&root).unwrap();
            lookup.resolve(Path::new("records/a.json")).unwrap();
            fs::create_dir(root.join("records/.folderbase")).unwrap();
            if reuse {
                assert!(matches!(
                    lookup.resolve(Path::new("records/a.json")),
                    Err(FolderbaseError::InvalidRecord { .. })
                ));
            }
            assert!(lookup.finish().is_err());
        }
    }

    #[test]
    fn marker_alias_and_symlink_invalidate_the_original_observation() {
        for alias in [false, true] {
            let (_fixture, root) = fixture();
            let mut lookup = WorkspacePathLookup::new(&root).unwrap();
            lookup.resolve(Path::new("records/a.json")).unwrap();
            if alias {
                fs::create_dir(root.join("records/.FolderBase")).unwrap();
            } else {
                std::os::unix::fs::symlink("missing", root.join("records/.folderbase")).unwrap();
            }
            assert!(lookup.resolve(Path::new("records/a.json")).is_err());
            assert!(lookup.finish().is_err());
        }
    }

    #[test]
    fn directory_and_root_replacement_never_reuse_retained_authority() {
        for replace_root in [false, true] {
            let (_fixture, root) = fixture();
            let mut lookup = WorkspacePathLookup::new(&root).unwrap();
            lookup.resolve(Path::new("records/a.json")).unwrap();
            if replace_root {
                fs::rename(&root, root.with_file_name("detached")).unwrap();
                fs::create_dir_all(root.join("records")).unwrap();
            } else {
                fs::rename(root.join("records"), root.join("detached")).unwrap();
                fs::create_dir(root.join("records")).unwrap();
            }
            fs::write(root.join("records/a.json"), "replacement\n").unwrap();
            assert!(lookup.resolve(Path::new("records/a.json")).is_err());
            assert!(lookup.finish().is_err());
        }
    }

    #[test]
    fn state_observations_do_not_survive_a_new_lookup() {
        let (_fixture, root) = fixture();
        let mut first = WorkspacePathLookup::new(&root).unwrap();
        first.resolve(Path::new("records/a.json")).unwrap();
        first.finish().unwrap();
        fs::create_dir(root.join("records/.folderbase")).unwrap();
        fs::write(root.join("records/.folderbase/manifest.json"), "opaque").unwrap();
        let mut second = WorkspacePathLookup::new(&root).unwrap();
        assert!(matches!(
            second.resolve(Path::new("records/a.json")),
            Err(FolderbaseError::UnsafePath(_))
        ));
    }

    #[test]
    fn handle_bound_preserves_uncached_boundary_validation() {
        let (_fixture, root) = fixture();
        for index in 0..MAX_RETAINED_BOUNDARIES + 8 {
            fs::create_dir(root.join(format!("d{index}"))).unwrap();
            fs::write(root.join(format!("d{index}/a.json")), "{}\n").unwrap();
        }
        let mut lookup = WorkspacePathLookup::new(&root).unwrap();
        for index in 0..MAX_RETAINED_BOUNDARIES + 8 {
            lookup
                .resolve(Path::new(&format!("d{index}/a.json")))
                .unwrap();
        }
        assert_eq!(lookup.observations.len(), MAX_RETAINED_BOUNDARIES);
        let uncached = format!("d{}", MAX_RETAINED_BOUNDARIES + 7);
        fs::create_dir(root.join(&uncached).join(".folderbase")).unwrap();
        fs::write(
            root.join(&uncached).join(".folderbase/manifest.json"),
            "opaque",
        )
        .unwrap();
        assert!(matches!(
            lookup.resolve(Path::new(&format!("{uncached}/a.json"))),
            Err(FolderbaseError::UnsafePath(_))
        ));
        lookup.finish().unwrap();
    }
}
