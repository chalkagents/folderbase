//! Canonical traversal classification shared by every Core surface.

use std::ffi::OsStr;

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
