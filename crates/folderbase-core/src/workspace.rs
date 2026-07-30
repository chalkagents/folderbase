//! Workspace navigation and optimistic text editing over an ordinary folderbase folder.

use std::{
    ffi::OsStr,
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use cap_std::{ambient_authority, fs::Dir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{
    ContentDigest, FolderbaseError, LocalVersionStore, ObjectId, Result, VersionId,
    root_attestation::metadata_is_link_or_reparse,
    traversal_policy::{
        NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary,
        is_reconstructable_directory, is_reserved_workspace_component as is_reserved_component,
    },
};

pub const MAX_WORKSPACE_TEXT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_WORKSPACE_ENTRIES: usize = 50_000;
const MAX_WORKSPACE_DEPTH: usize = 64;
const ROOT_IGNORE_POLICY_PATH: &str = ".folderbaseignore";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceEntryKind {
    Folderbase,
    Directory,
    File,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    pub path: String,
    pub name: String,
    pub kind: WorkspaceEntryKind,
    pub bytes: u64,
    pub editable: bool,
    pub reconstructable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceListing {
    pub root: PathBuf,
    pub entries: Vec<WorkspaceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceTextDocument {
    pub path: String,
    pub content: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceSaveResult {
    pub path: String,
    pub previous_sha256: String,
    pub document: WorkspaceDocumentState,
    pub object_id: ObjectId,
    pub version_id: VersionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceDocumentState {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Return a deterministic flat projection of an ordinary folderbase folder.
///
/// Protocol and Git metadata are hidden. Default reconstructable directories
/// remain visible as collapsed entries. Symbolic links are represented but
/// never followed.
pub fn list_workspace(root: impl AsRef<Path>) -> Result<WorkspaceListing> {
    let root = canonical_folderbase_root(root.as_ref())?;
    let mut entries = Vec::new();
    let mut walker = WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    while let Some(next) = walker.next() {
        let entry = next.map_err(|error| {
            let path = error
                .path()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.clone());
            FolderbaseError::io(
                path,
                error
                    .into_io_error()
                    .unwrap_or_else(|| io::Error::other("workspace traversal failed")),
            )
        })?;
        if entry.depth() == 0 {
            continue;
        }
        if entry.depth() > MAX_WORKSPACE_DEPTH {
            return Err(invalid_workspace_record(
                &root,
                format!("workspace traversal exceeds the {MAX_WORKSPACE_DEPTH} level depth limit"),
            ));
        }

        let file_type = entry.file_type();
        let name = entry.file_name();
        if is_reserved_workspace_component(name) {
            if file_type.is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        let is_collapsed_reconstructable = file_type.is_dir() && is_reconstructable_directory(name);
        let is_nested_folderbase_boundary =
            file_type.is_dir() && has_nested_folderbase_marker(entry.path())?;

        if entries.len() == MAX_WORKSPACE_ENTRIES {
            return Err(invalid_workspace_record(
                &root,
                format!("workspace traversal exceeds {MAX_WORKSPACE_ENTRIES} entries"),
            ));
        }

        let relative = entry
            .path()
            .strip_prefix(&root)
            .map_err(|_| FolderbaseError::UnsafePath(entry.path().to_path_buf()))?;
        let path = displayable_path(relative)?;
        let name = name
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| FolderbaseError::UnsafePath(relative.to_path_buf()))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| FolderbaseError::io(entry.path(), source))?;

        let (kind, bytes, editable) = if is_nested_folderbase_boundary {
            (WorkspaceEntryKind::Folderbase, 0, false)
        } else if file_type.is_symlink() {
            (WorkspaceEntryKind::Symlink, 0, false)
        } else if file_type.is_dir() {
            (WorkspaceEntryKind::Directory, 0, false)
        } else if file_type.is_file() {
            let bytes = metadata.len();
            (
                WorkspaceEntryKind::File,
                bytes,
                relative != Path::new(ROOT_IGNORE_POLICY_PATH)
                    && file_is_editable(entry.path(), bytes)?,
            )
        } else {
            continue;
        };

        entries.push(WorkspaceEntry {
            path,
            name,
            kind,
            bytes,
            editable,
            reconstructable: is_collapsed_reconstructable && !is_nested_folderbase_boundary,
        });
        if is_collapsed_reconstructable || is_nested_folderbase_boundary {
            walker.skip_current_dir();
        }
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(WorkspaceListing { root, entries })
}

/// Read one existing, regular UTF-8 document without changing the folderbase.
pub fn read_workspace_text(
    root: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> Result<WorkspaceTextDocument> {
    let root = canonical_folderbase_root(root.as_ref())?;
    let relative_path = safe_workspace_path(relative_path.as_ref())?;
    let (file_path, relative_path) = resolve_existing_workspace_file(&root, &relative_path)?;
    let metadata =
        fs::metadata(&file_path).map_err(|source| FolderbaseError::io(&file_path, source))?;
    if metadata.len() > MAX_WORKSPACE_TEXT_BYTES {
        return Err(workspace_text_too_large(&relative_path));
    }

    let bytes = read_limited(&file_path)?;
    if bytes.contains(&0) {
        return Err(invalid_workspace_record(
            &relative_path,
            "workspace text contains a NUL byte",
        ));
    }
    let content = String::from_utf8(bytes.clone())
        .map_err(|_| invalid_workspace_record(&relative_path, "workspace file is not UTF-8"))?;

    Ok(WorkspaceTextDocument {
        path: displayable_path(&relative_path)?,
        content,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        bytes: bytes.len() as u64,
    })
}

/// Optimistically replace one existing UTF-8 file and durably version both
/// sides of the accepted save.
pub fn save_workspace_text(
    root: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
    expected_sha256: &str,
    content: &str,
) -> Result<WorkspaceSaveResult> {
    let root = canonical_folderbase_root(root.as_ref())?;
    let relative_path = safe_workspace_path(relative_path.as_ref())?;
    refuse_generic_workspace_mutation_path(&relative_path)?;
    validate_sha256(expected_sha256, &relative_path)?;
    if content.len() as u64 > MAX_WORKSPACE_TEXT_BYTES {
        return Err(workspace_text_too_large(&relative_path));
    }
    if content.contains('\0') {
        return Err(invalid_workspace_record(
            &relative_path,
            "workspace text contains a NUL byte",
        ));
    }

    // Reject an already-stale editor before creating protocol storage. The
    // version store checks the same precondition again immediately before
    // accepting its durable transaction.
    let (_, relative_path) = resolve_existing_workspace_file(&root, &relative_path)?;
    refuse_generic_workspace_mutation_path(&relative_path)?;
    let current = read_workspace_text(&root, &relative_path)?;
    if current.sha256 != expected_sha256 {
        return Err(FolderbaseError::WorkspaceContentChanged(relative_path));
    }

    let expected = ContentDigest {
        algorithm: "sha256".to_owned(),
        digest: expected_sha256.to_owned(),
        bytes: current.bytes,
    };
    let versioned = LocalVersionStore::open(&root)?.replace_file_versioned(
        &relative_path,
        &expected,
        content.as_bytes(),
    )?;
    let path = displayable_path(&relative_path)?;
    let document = WorkspaceDocumentState {
        path: path.clone(),
        sha256: versioned.content.digest.clone(),
        bytes: versioned.content.bytes,
    };
    Ok(WorkspaceSaveResult {
        path,
        previous_sha256: versioned.previous_content.digest,
        document,
        object_id: versioned.object_id,
        version_id: versioned.version_id,
    })
}

pub(crate) fn canonical_folderbase_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => FolderbaseError::InvalidRoot(root.to_path_buf()),
        _ => FolderbaseError::io(root, source),
    })?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(root.to_path_buf()));
    }
    root.canonicalize()
        .map_err(|source| FolderbaseError::io(root, source))
}

pub(crate) fn safe_workspace_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() || path.to_str().is_none() {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
        };
        if is_reserved_workspace_component(name) {
            return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
        }
        normalized.push(name);
    }
    if normalized.as_os_str().is_empty() {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(normalized)
}

pub(crate) fn resolve_existing_workspace_file(
    root: &Path,
    relative: &Path,
) -> Result<(PathBuf, PathBuf)> {
    let relative = safe_workspace_path(relative)?;
    let mut resolved = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(FolderbaseError::UnsafePath(relative));
        };
        resolved.push(name);
        let metadata = fs::symlink_metadata(&resolved)
            .map_err(|source| FolderbaseError::io(&resolved, source))?;
        if metadata.file_type().is_symlink() {
            return Err(FolderbaseError::UnsafePath(resolved));
        }
        if metadata.is_dir() && has_nested_folderbase_marker(&resolved)? {
            return Err(FolderbaseError::UnsafePath(relative.to_path_buf()));
        }
    }
    let metadata =
        fs::symlink_metadata(&resolved).map_err(|source| FolderbaseError::io(&resolved, source))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_workspace_record(
            resolved,
            "workspace path is not a regular file",
        ));
    }
    let resolved = resolved
        .canonicalize()
        .map_err(|source| FolderbaseError::io(&resolved, source))?;
    let canonical_relative = resolved
        .strip_prefix(root)
        .map_err(|_| FolderbaseError::UnsafePath(resolved.clone()))?
        .to_path_buf();
    Ok((resolved, canonical_relative))
}

pub(crate) fn is_reserved_workspace_component(name: &OsStr) -> bool {
    is_reserved_component(name)
}

pub(crate) fn refuse_generic_workspace_mutation_path(path: &Path) -> Result<()> {
    if path == Path::new(ROOT_IGNORE_POLICY_PATH) {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

pub(crate) fn has_nested_folderbase_marker(path: &Path) -> Result<bool> {
    let directory = Dir::open_ambient_dir(path, ambient_authority())
        .map_err(|source| FolderbaseError::io(path, source))?;
    match classify_nested_folderbase_boundary(&directory, path)? {
        NestedFolderbaseBoundaryKind::ExactBoundary => Ok(true),
        NestedFolderbaseBoundaryKind::None => Ok(false),
        NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
            Err(FolderbaseError::UnsafePath(path.to_path_buf()))
        }
    }
}

fn displayable_path(path: &Path) -> Result<String> {
    path.to_str()
        .map(|value| value.replace(std::path::MAIN_SEPARATOR, "/"))
        .ok_or_else(|| FolderbaseError::UnsafePath(path.to_path_buf()))
}

fn file_is_editable(path: &Path, bytes: u64) -> Result<bool> {
    if bytes > MAX_WORKSPACE_TEXT_BYTES {
        return Ok(false);
    }
    match read_limited(path) {
        Ok(contents) => Ok(!contents.contains(&0) && std::str::from_utf8(&contents).is_ok()),
        Err(FolderbaseError::InvalidRecord { message, .. })
            if message.contains("workspace text exceeds") =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|source| FolderbaseError::io(path, source))?;
    let mut contents = Vec::new();
    file.take(MAX_WORKSPACE_TEXT_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|source| FolderbaseError::io(path, source))?;
    if contents.len() as u64 > MAX_WORKSPACE_TEXT_BYTES {
        return Err(workspace_text_too_large(path));
    }
    Ok(contents)
}

fn workspace_text_too_large(path: &Path) -> FolderbaseError {
    invalid_workspace_record(
        path,
        format!(
            "workspace text exceeds the {} byte limit",
            MAX_WORKSPACE_TEXT_BYTES
        ),
    )
}

fn validate_sha256(value: &str, path: &Path) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_workspace_record(
            path,
            "expected SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn invalid_workspace_record(
    path: impl Into<PathBuf>,
    message: impl Into<String>,
) -> FolderbaseError {
    FolderbaseError::InvalidRecord {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_mutation_classifier_reserves_ascii_case_variants_only_at_the_root() {
        for root_policy in [
            ".folderbaseignore",
            ".FOLDERBASEIGNORE",
            ".FolderBaseIgnore",
        ] {
            assert!(matches!(
                refuse_generic_workspace_mutation_path(Path::new(root_policy)),
                Err(FolderbaseError::UnsafePath(path)) if path == Path::new(root_policy)
            ));
        }

        for ordinary_path in [
            "docs/.folderbaseignore",
            "docs/.FOLDERBASEIGNORE",
            ".folderbaseignore.txt",
        ] {
            assert!(
                refuse_generic_workspace_mutation_path(Path::new(ordinary_path)).is_ok(),
                "{ordinary_path} is not the root capture policy"
            );
        }
    }
}
