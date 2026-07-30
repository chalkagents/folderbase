//! Canonical traversal classification shared by every Core surface.

use std::{ffi::OsStr, path::Path};

use cap_fs_ext::DirExt;
use cap_std::fs::Dir;

use crate::{FolderbaseError, Result};

pub(crate) const RECONSTRUCTABLE_DIRECTORIES: &[&str] = &[
    "node_modules",
    ".next",
    ".nuxt",
    ".sites",
    ".svelte-kit",
    ".wrangler",
    "dist",
    "build",
    "coverage",
    ".build",
    ".swiftpm",
    ".venv",
    "__pycache__",
    ".dart_tool",
    "Pods",
    "DerivedData",
    "target",
];

pub(crate) fn is_reconstructable_directory(name: &OsStr) -> bool {
    RECONSTRUCTABLE_DIRECTORIES
        .iter()
        .any(|candidate| name == OsStr::new(candidate))
}

pub(crate) fn is_folderbase_state_component(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case(".folderbase"))
}

/// Git metadata is reserved and collapsed, but it is not reconstructable
/// application output. Keeping it explicit prevents lifecycle history from
/// being mislabeled as disposable generated state.
pub(crate) fn is_git_metadata_component(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
}

pub(crate) fn is_reserved_workspace_component(name: &OsStr) -> bool {
    is_folderbase_state_component(name) || is_git_metadata_component(name)
}

/// The only three outcomes recognized when a retained directory capability is
/// examined for a nested Folderbase boundary.
///
/// Authority is case-sensitive and exact. Any bytes behind an exact regular
/// no-follow marker form an opaque boundary. Case-folded aliases and unsafe
/// filesystem shapes are reported separately so every caller can fail closed
/// without granting them protocol authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NestedFolderbaseBoundaryKind {
    ExactBoundary,
    UnsafeAliasShape,
    None,
}

pub(crate) fn classify_nested_folderbase_boundary(
    directory: &Dir,
    display: &Path,
) -> Result<NestedFolderbaseBoundaryKind> {
    classify_nested_folderbase_boundary_with_observer(directory, display, || Ok(()))
}

pub(crate) fn classify_nested_folderbase_boundary_with_observer(
    directory: &Dir,
    display: &Path,
    mut observe_entry: impl FnMut() -> Result<()>,
) -> Result<NestedFolderbaseBoundaryKind> {
    let mut exact_state = false;
    for entry in directory
        .entries()
        .map_err(|source| FolderbaseError::io(display, source))?
    {
        let entry = entry.map_err(|source| FolderbaseError::io(display, source))?;
        observe_entry()?;
        let name = entry.file_name();
        if is_case_folded_alias(&name, ".folderbase") {
            return Ok(NestedFolderbaseBoundaryKind::UnsafeAliasShape);
        }
        if name != OsStr::new(".folderbase") {
            continue;
        }
        let state_display = display.join(&name);
        let metadata = directory
            .symlink_metadata(&name)
            .map_err(|source| FolderbaseError::io(&state_display, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(NestedFolderbaseBoundaryKind::UnsafeAliasShape);
        }
        exact_state = true;
    }
    if !exact_state {
        return Ok(NestedFolderbaseBoundaryKind::None);
    }

    let state_display = display.join(".folderbase");
    let state = directory
        .open_dir_nofollow(".folderbase")
        .map_err(|source| FolderbaseError::io(&state_display, source))?;
    let mut exact_manifest = false;
    for entry in state
        .entries()
        .map_err(|source| FolderbaseError::io(&state_display, source))?
    {
        let entry = entry.map_err(|source| FolderbaseError::io(&state_display, source))?;
        observe_entry()?;
        let name = entry.file_name();
        if is_case_folded_alias(&name, "manifest.json") {
            return Ok(NestedFolderbaseBoundaryKind::UnsafeAliasShape);
        }
        if name != OsStr::new("manifest.json") {
            continue;
        }
        let manifest_display = state_display.join(&name);
        let metadata = state
            .symlink_metadata(&name)
            .map_err(|source| FolderbaseError::io(&manifest_display, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(NestedFolderbaseBoundaryKind::UnsafeAliasShape);
        }
        exact_manifest = true;
    }

    Ok(if exact_manifest {
        NestedFolderbaseBoundaryKind::ExactBoundary
    } else {
        NestedFolderbaseBoundaryKind::None
    })
}

fn is_case_folded_alias(name: &OsStr, exact: &str) -> bool {
    name != OsStr::new(exact)
        && name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(exact))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;
    use std::fs;

    #[test]
    fn exact_boundary_and_case_folded_alias_are_distinct() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::create_dir(fixture.path().join(".folderbase")).expect("state");
        fs::write(
            fixture.path().join(".folderbase/manifest.json"),
            br#"{"protocol_version":"0.5.0"}"#,
        )
        .expect("manifest");
        let root =
            Dir::open_ambient_dir(fixture.path(), ambient_authority()).expect("root capability");
        assert_eq!(
            classify_nested_folderbase_boundary(&root, fixture.path()).expect("classification"),
            NestedFolderbaseBoundaryKind::ExactBoundary
        );

        fs::rename(
            fixture.path().join(".folderbase"),
            fixture.path().join(".FOLDERBASE"),
        )
        .expect("rename alias");
        assert_eq!(
            classify_nested_folderbase_boundary(&root, fixture.path()).expect("classification"),
            NestedFolderbaseBoundaryKind::UnsafeAliasShape
        );
    }

    #[test]
    fn default_classifier_has_a_hard_marker_directory_work_ceiling() {
        const EXPECTED_SHARED_WORK_CEILING: usize = 16_384;

        let fixture = tempfile::tempdir().expect("fixture");
        let state = fixture.path().join(".folderbase");
        fs::create_dir(&state).expect("state");
        for index in 0..=EXPECTED_SHARED_WORK_CEILING {
            fs::write(state.join(format!("entry-{index:05}")), b"").expect("state entry");
        }
        let root =
            Dir::open_ambient_dir(fixture.path(), ambient_authority()).expect("root capability");

        assert!(
            classify_nested_folderbase_boundary(&root, fixture.path()).is_err(),
            "the default observer must not make shared boundary classification unbounded"
        );
    }
}
