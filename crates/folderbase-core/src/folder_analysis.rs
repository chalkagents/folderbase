use std::{
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
};

#[cfg(not(windows))]
use cap_fs_ext::DirExt;
#[cfg(windows)]
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
#[cfg(windows)]
use cap_std::fs::OpenOptions as CapOpenOptions;
use cap_std::{ambient_authority, fs::Dir};

use crate::{
    BoundaryHint, Classification, ClassifiedPath, FolderbaseError, InventorySummary,
    NestedFolderbaseBoundary, NestedFolderbaseState, ReconstructableTree, Result,
    root_attestation::metadata_is_link_or_reparse,
    traversal_policy::{
        NestedFolderbaseBoundaryKind, classify_nested_folderbase_boundary,
        is_folderbase_state_component, is_git_metadata_component, is_reconstructable_directory,
    },
};

const LARGE_FILE_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct FolderAnalysis {
    pub(crate) root: PathBuf,
    pub(crate) inventory: InventorySummary,
    pub(crate) classified_paths: Vec<ClassifiedPath>,
    pub(crate) git_repositories: Vec<PathBuf>,
    pub(crate) context_files: Vec<PathBuf>,
    pub(crate) boundary_hints: Vec<BoundaryHint>,
    pub(crate) reconstructable_trees: Vec<ReconstructableTree>,
    pub(crate) nested_folderbases: Vec<NestedFolderbaseBoundary>,
    pub(crate) warnings: Vec<String>,
    pub(crate) files: Vec<AnalyzedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnalyzedFile {
    pub(crate) path: PathBuf,
    pub(crate) bytes: u64,
    classifications: Vec<Classification>,
}

impl AnalyzedFile {
    pub(crate) fn is_generated(&self) -> bool {
        self.classifications.contains(&Classification::Generated)
    }

    pub(crate) fn is_secret_shaped(&self) -> bool {
        self.classifications.contains(&Classification::SecretShaped)
    }

    pub(crate) fn is_temporary(&self) -> bool {
        self.classifications.contains(&Classification::Temporary)
    }

    pub(crate) fn classification_bits(&self) -> u8 {
        self.classifications.iter().fold(0, |bits, classification| {
            bits | 1 << classification_rank(*classification)
        })
    }
}

pub(crate) fn analyze_folder(root: &Path) -> Result<FolderAnalysis> {
    analyze_folder_with(root, true)
}

pub(crate) fn expand_reconstructable_tree(root: &Path) -> Result<FolderAnalysis> {
    analyze_folder_with(root, false)
}

fn analyze_folder_with(root: &Path, collapse_reconstructable: bool) -> Result<FolderAnalysis> {
    let root_metadata = fs::symlink_metadata(root).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => FolderbaseError::InvalidRoot(root.to_path_buf()),
        _ => FolderbaseError::io(root, error),
    })?;
    if metadata_is_link_or_reparse(&root_metadata) || !root_metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(root.to_path_buf()));
    }

    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|source| FolderbaseError::io(root, source))?;
    analyze_folder_from_retained(&directory, root, collapse_reconstructable, false)
}

pub(crate) fn analyze_folder_from_retained(
    root: &Dir,
    display_root: &Path,
    collapse_reconstructable: bool,
    reject_windows_reparse: bool,
) -> Result<FolderAnalysis> {
    let root_file = root
        .try_clone()
        .map_err(|source| FolderbaseError::io(display_root, source))?
        .into_std_file();
    let root_metadata = root_file
        .metadata()
        .map_err(|source| FolderbaseError::io(display_root, source))?;
    if metadata_is_link_or_reparse(&root_metadata) || !root_metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(display_root.to_path_buf()));
    }

    let mut analysis = FolderAnalysis {
        root: display_root.to_path_buf(),
        inventory: InventorySummary::default(),
        classified_paths: Vec::new(),
        git_repositories: Vec::new(),
        context_files: Vec::new(),
        boundary_hints: Vec::new(),
        reconstructable_trees: Vec::new(),
        nested_folderbases: Vec::new(),
        warnings: Vec::new(),
        files: Vec::new(),
    };
    walk_retained_directory(
        root,
        display_root,
        Path::new(""),
        collapse_reconstructable,
        reject_windows_reparse,
        &mut analysis,
    )?;
    sort_analysis(&mut analysis);
    Ok(analysis)
}

fn walk_retained_directory(
    directory: &Dir,
    display_root: &Path,
    relative_directory: &Path,
    collapse_reconstructable: bool,
    reject_windows_reparse: bool,
    analysis: &mut FolderAnalysis,
) -> Result<()> {
    let display_directory = display_root.join(relative_directory);
    let mut entries = Vec::new();
    for entry in directory
        .entries()
        .map_err(|source| FolderbaseError::io(&display_directory, source))?
    {
        entries.push(entry.map_err(|source| FolderbaseError::io(&display_directory, source))?);
    }
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name();
        let relative = relative_directory.join(&name);
        let display = display_root.join(&relative);
        let advertised_file_type = entry
            .file_type()
            .map_err(|source| FolderbaseError::io(&display, source))?;
        let reconstructable = advertised_file_type.is_dir() && is_reconstructable_directory(&name);
        #[cfg(windows)]
        let (entry_metadata, child) = match open_windows_analysis_entry(directory, &name, &display)
        {
            Ok(Some(opened)) => opened,
            Ok(None) if reject_windows_reparse => {
                return Err(FolderbaseError::UnsafePath(display));
            }
            Ok(None) => {
                analysis.warnings.push(format!(
                    "Skipped Windows reparse point without following it: {}",
                    relative.display()
                ));
                continue;
            }
            Err(_) if reconstructable && collapse_reconstructable => {
                record_collapsed_reconstructable(analysis, relative);
                continue;
            }
            Err(error) => return Err(error),
        };
        #[cfg(windows)]
        let file_type = entry_metadata.file_type();
        #[cfg(not(windows))]
        let file_type = advertised_file_type;
        #[cfg(not(windows))]
        let child = if file_type.is_dir() {
            match directory.open_dir_nofollow(&name) {
                Ok(child) => Some(child),
                Err(_) if reconstructable && collapse_reconstructable => {
                    record_collapsed_reconstructable(analysis, relative);
                    continue;
                }
                Err(source) => return Err(FolderbaseError::io(display, source)),
            }
        } else {
            None
        };

        if let Some(child) = &child {
            match nested_folderbase_state_retained(child, &display, reject_windows_reparse) {
                Ok(Some(state)) => {
                    analysis.nested_folderbases.push(NestedFolderbaseBoundary {
                        path: relative,
                        state,
                    });
                    continue;
                }
                Ok(None) => {}
                Err(error @ FolderbaseError::UnsafePath(_)) if reject_windows_reparse => {
                    return Err(error);
                }
                Err(_) if reconstructable && collapse_reconstructable => {
                    record_collapsed_reconstructable(analysis, relative);
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        if is_folderbase_state_component(&name) {
            continue;
        }

        if collapse_reconstructable && reconstructable {
            analysis.inventory.reconstructable_tree_count += 1;
            analysis
                .reconstructable_trees
                .push(ReconstructableTree { path: relative });
            continue;
        }

        if is_git_metadata_component(&name) {
            if file_type.is_dir() || file_type.is_file() {
                let repository = relative
                    .parent()
                    .map(displayable_relative)
                    .unwrap_or_else(|| PathBuf::from("."));
                analysis.git_repositories.push(repository.clone());
                analysis.boundary_hints.push(BoundaryHint {
                    path: repository,
                    kind: "lifecycle".to_owned(),
                    reason: "Git repository has independent history and may be a project boundary."
                        .to_owned(),
                });
            } else if file_type.is_symlink() {
                analysis.warnings.push(format!(
                    "Skipped symbolic link without following it: {}",
                    relative.display()
                ));
            }
            continue;
        }

        if file_type.is_symlink() {
            analysis.warnings.push(format!(
                "Skipped symbolic link without following it: {}",
                relative.display()
            ));
            continue;
        }

        if let Some(child) = child {
            if let Some((kind, reason)) = boundary_reason(&relative) {
                analysis.boundary_hints.push(BoundaryHint {
                    path: relative.clone(),
                    kind: kind.to_owned(),
                    reason: reason.to_owned(),
                });
            }
            walk_retained_directory(
                &child,
                display_root,
                &relative,
                collapse_reconstructable,
                reject_windows_reparse,
                analysis,
            )?;
            continue;
        }

        #[cfg(not(windows))]
        let entry_bytes = {
            let metadata = directory
                .symlink_metadata(&name)
                .map_err(|source| FolderbaseError::io(&display, source))?;
            if metadata.file_type().is_symlink() {
                analysis.warnings.push(format!(
                    "Skipped symbolic link without following it: {}",
                    relative.display()
                ));
                continue;
            }
            if !metadata.is_file() {
                analysis
                    .warnings
                    .push(format!("Skipped non-regular file: {}", relative.display()));
                continue;
            }
            metadata.len()
        };
        #[cfg(windows)]
        let entry_bytes = if entry_metadata.is_file() {
            entry_metadata.len()
        } else {
            analysis
                .warnings
                .push(format!("Skipped non-regular file: {}", relative.display()));
            continue;
        };

        record_analyzed_file(analysis, relative, entry_bytes);
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_analysis_entry(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> Result<Option<(fs::Metadata, Option<Dir>)>> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = CapOpenOptions::new();
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
    if metadata_is_link_or_reparse(&metadata) {
        return Ok(None);
    }
    let child = metadata.is_dir().then(|| Dir::from_std_file(file));
    Ok(Some((metadata, child)))
}

fn nested_folderbase_state_retained(
    directory: &Dir,
    display: &Path,
    reject_unsafe_shapes: bool,
) -> Result<Option<NestedFolderbaseState>> {
    Ok(
        match classify_nested_folderbase_boundary(directory, display)? {
            NestedFolderbaseBoundaryKind::ExactBoundary => Some(NestedFolderbaseState::Unchecked),
            NestedFolderbaseBoundaryKind::UnsafeAliasShape if reject_unsafe_shapes => {
                return Err(FolderbaseError::UnsafePath(display.to_path_buf()));
            }
            NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
                Some(NestedFolderbaseState::Unchecked)
            }
            NestedFolderbaseBoundaryKind::None => None,
        },
    )
}

fn record_collapsed_reconstructable(analysis: &mut FolderAnalysis, relative: PathBuf) {
    analysis.inventory.reconstructable_tree_count += 1;
    let display = relative.display().to_string();
    analysis
        .reconstructable_trees
        .push(ReconstructableTree { path: relative });
    analysis.warnings.push(format!(
        "Collapsed unreadable reconstructable tree without entering it: {display}"
    ));
}

fn record_analyzed_file(analysis: &mut FolderAnalysis, relative: PathBuf, bytes: u64) {
    let mut classifications = Vec::new();
    classify(
        analysis,
        &mut classifications,
        &relative,
        bytes,
        Classification::Generated,
        is_generated(&relative),
        "Path is inside a known generated or reconstructable area.",
    );
    classify(
        analysis,
        &mut classifications,
        &relative,
        bytes,
        Classification::SecretShaped,
        is_secret_shaped(&relative),
        "Filename resembles a credential or secret; contents were not read.",
    );
    classify(
        analysis,
        &mut classifications,
        &relative,
        bytes,
        Classification::Temporary,
        is_temporary(&relative),
        "Path resembles temporary, cache, backup, or worktree content.",
    );
    classify(
        analysis,
        &mut classifications,
        &relative,
        bytes,
        Classification::Large,
        bytes >= LARGE_FILE_BYTES,
        "File is at least 100 MiB.",
    );
    classify(
        analysis,
        &mut classifications,
        &relative,
        bytes,
        Classification::Versioned,
        is_version_shaped(&relative),
        "Filename resembles a draft, revision, copy, or numbered version.",
    );

    analysis.inventory.file_count += 1;
    analysis.inventory.total_bytes = analysis.inventory.total_bytes.saturating_add(bytes);
    if is_context_file(&relative) {
        analysis.context_files.push(relative.clone());
    }
    if file_name_eq(&relative, ".gitmodules") {
        let repository = relative
            .parent()
            .map(displayable_relative)
            .unwrap_or_else(|| PathBuf::from("."));
        analysis.git_repositories.push(repository.clone());
        analysis.boundary_hints.push(BoundaryHint {
            path: repository,
            kind: "lifecycle".to_owned(),
            reason: "Git metadata indicates independent version history and a possible project boundary."
                .to_owned(),
        });
    }
    analysis.files.push(AnalyzedFile {
        path: relative,
        bytes,
        classifications,
    });
}

fn displayable_relative(path: &Path) -> PathBuf {
    if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path.to_path_buf()
    }
}

fn classify(
    analysis: &mut FolderAnalysis,
    classifications: &mut Vec<Classification>,
    path: &Path,
    bytes: u64,
    classification: Classification,
    matches: bool,
    reason: &str,
) {
    if !matches {
        return;
    }
    match classification {
        Classification::Generated => analysis.inventory.generated_file_count += 1,
        Classification::SecretShaped => analysis.inventory.secret_shaped_file_count += 1,
        Classification::Temporary => analysis.inventory.temporary_file_count += 1,
        Classification::Large => analysis.inventory.large_file_count += 1,
        Classification::Versioned => analysis.inventory.versioned_file_count += 1,
    }
    classifications.push(classification);
    analysis.classified_paths.push(ClassifiedPath {
        path: path.to_path_buf(),
        classification,
        reason: reason.to_owned(),
        bytes,
    });
}

fn is_generated(path: &Path) -> bool {
    const GENERATED_EXTENSIONS: &[&str] =
        &["class", "o", "obj", "pyc", "pyo", "wasm", "xcuserstate"];

    path.components().any(|component| {
        matches!(
            component,
            Component::Normal(name) if is_reconstructable_directory(name)
        )
    }) || path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            GENERATED_EXTENSIONS
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
        || file_name_eq(path, ".DS_Store")
}

fn is_secret_shaped(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".example")
        || lower.ends_with(".sample")
        || lower.ends_with(".template")
        || lower.contains("example.")
    {
        return false;
    }
    lower == ".env"
        || lower.starts_with(".env.")
        || matches!(
            lower.as_str(),
            "credentials"
                | "credentials.json"
                | "secrets.json"
                | "secrets.yaml"
                | "secrets.yml"
                | "id_rsa"
                | "id_dsa"
                | "id_ecdsa"
                | "id_ed25519"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
        )
        || [
            "secret",
            "credential",
            "password",
            "private_key",
            "private-key",
            "api_key",
            "api-key",
            "access_token",
            "access-token",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
        || path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| {
                ["key", "pem", "p12", "pfx"]
                    .iter()
                    .any(|candidate| extension.eq_ignore_ascii_case(candidate))
            })
}

fn is_temporary(path: &Path) -> bool {
    const TEMPORARY_DIRECTORIES: &[&str] = &[
        ".analysis",
        ".cache",
        ".codex-spreadsheet-work",
        "temp",
        "tmp",
        "worktrees",
    ];
    const TEMPORARY_EXTENSIONS: &[&str] = &["bak", "cache", "part", "swp", "swo", "temp", "tmp"];
    let file_name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();

    has_component_case_insensitive(path, TEMPORARY_DIRECTORIES)
        || file_name.starts_with("~$")
        || file_name.ends_with('~')
        || path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| {
                TEMPORARY_EXTENSIONS
                    .iter()
                    .any(|candidate| extension.eq_ignore_ascii_case(candidate))
            })
}

fn is_version_shaped(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
        return false;
    };
    let lower = stem.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();

    tokens.iter().any(|token| {
        matches!(
            *token,
            "draft" | "revised" | "revision" | "redline" | "final" | "copy"
        ) || token
            .strip_prefix('v')
            .is_some_and(|number| !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()))
            || token.strip_prefix("copy").is_some_and(|number| {
                !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
            })
    }) || lower.ends_with(')')
        && lower.rsplit_once('(').is_some_and(|(_, number)| {
            number[..number.len() - 1]
                .chars()
                .all(|c| c.is_ascii_digit())
        })
}

fn is_context_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let lower = file_name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "agents.md"
            | "folderbase.md"
            | "claude.md"
            | "context.md"
            | "gemini.md"
            | "hermes.md"
            | "memory.md"
            | "project.md"
            | ".cursorrules"
    ) || lower == "readme"
        || lower.starts_with("readme.")
}

fn boundary_reason(path: &Path) -> Option<(&'static str, &'static str)> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let normalized = name
        .trim_matches(|character: char| character == '_' || character == '-' || character == ' ');
    let tokens: Vec<&str> = normalized
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();

    if tokens.iter().any(|token| {
        [
            "agreement",
            "agreements",
            "client",
            "clients",
            "commercial",
            "company",
            "confidential",
            "contract",
            "contracts",
            "credential",
            "credentials",
            "customer",
            "customers",
            "email",
            "emails",
            "finance",
            "financial",
            "hr",
            "internal",
            "invoice",
            "invoices",
            "legal",
            "people",
            "personal",
            "private",
            "project",
            "restricted",
            "security",
            "secret",
            "secrets",
            "vapt",
        ]
        .contains(token)
    }) {
        return Some((
            "permission",
            "Directory name suggests content that may need a distinct access boundary.",
        ));
    }
    if tokens.iter().any(|token| {
        [
            "archive",
            "archives",
            "archived",
            "draft",
            "drafts",
            "evidence",
            "final",
            "finals",
            "output",
            "outputs",
            "raw",
            "temp",
            "tmp",
            "worktree",
            "worktrees",
        ]
        .contains(token)
    }) {
        return Some((
            "lifecycle",
            "Directory name suggests content with a distinct retention or activity lifecycle.",
        ));
    }
    None
}

fn has_component_case_insensitive(path: &Path, candidates: &[&str]) -> bool {
    path.components().any(|component| {
        let Component::Normal(part) = component else {
            return false;
        };
        let Some(part) = part.to_str() else {
            return false;
        };
        candidates
            .iter()
            .any(|candidate| part.eq_ignore_ascii_case(candidate))
    })
}

fn file_name_eq(path: &Path, candidate: &str) -> bool {
    path.file_name()
        .is_some_and(|name| name == OsStr::new(candidate))
}

fn sort_analysis(analysis: &mut FolderAnalysis) {
    analysis.classified_paths.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| {
                classification_rank(left.classification)
                    .cmp(&classification_rank(right.classification))
            })
            .then_with(|| left.reason.cmp(&right.reason))
    });
    analysis.classified_paths.dedup();
    analysis.git_repositories.sort();
    analysis.git_repositories.dedup();
    analysis.context_files.sort();
    analysis.context_files.dedup();
    analysis.boundary_hints.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    analysis.boundary_hints.dedup();
    analysis
        .reconstructable_trees
        .sort_by(|left, right| left.path.cmp(&right.path));
    analysis.reconstructable_trees.dedup();
    analysis
        .nested_folderbases
        .sort_by(|left, right| left.path.cmp(&right.path));
    analysis.nested_folderbases.dedup();
    analysis.warnings.sort();
    analysis.warnings.dedup();
    analysis
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
}

fn classification_rank(classification: Classification) -> u8 {
    match classification {
        Classification::Generated => 0,
        Classification::SecretShaped => 1,
        Classification::Temporary => 2,
        Classification::Large => 3,
        Classification::Versioned => 4,
    }
}

#[cfg(all(test, windows))]
mod windows_reparse_tests {
    use std::{fs, process::Command};

    use cap_std::{ambient_authority, fs::Dir};

    use super::{analyze_folder, analyze_folder_from_retained};
    use crate::FolderbaseError;

    #[test]
    fn public_analysis_skips_a_directory_junction_without_descent() {
        let root = tempfile::tempdir().expect("analysis root");
        let target = tempfile::tempdir().expect("junction target");
        fs::write(target.path().join("foreign.txt"), b"foreign\n").expect("foreign file");
        let junction = root.path().join("node_modules");
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(target.path())
            .output()
            .expect("run mklink");
        assert!(
            output.status.success(),
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let analysis = analyze_folder(root.path()).expect("tolerant public analysis");
        assert_eq!(analysis.inventory.file_count, 0);
        let junction_name = junction
            .file_name()
            .expect("junction filename")
            .to_string_lossy();
        assert!(analysis.warnings.iter().any(|warning| {
            warning.contains("Skipped Windows reparse point")
                && warning.contains(junction_name.as_ref())
        }));
    }

    #[test]
    fn retained_transaction_analysis_rejects_a_directory_junction_before_descent() {
        let root = tempfile::tempdir().expect("analysis root");
        let target = tempfile::tempdir().expect("junction target");
        fs::write(target.path().join("foreign.txt"), b"foreign\n").expect("foreign file");
        let junction = root.path().join("node_modules");
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(target.path())
            .output()
            .expect("run mklink");
        assert!(
            output.status.success(),
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let retained =
            Dir::open_ambient_dir(root.path(), ambient_authority()).expect("retained root");

        assert!(matches!(
            analyze_folder_from_retained(&retained, root.path(), true, true),
            Err(FolderbaseError::UnsafePath(path)) if path == junction
        ));
    }

    #[test]
    fn retained_transaction_analysis_rejects_a_nested_folderbase_junction() {
        let root = tempfile::tempdir().expect("analysis root");
        let project = root.path().join("project");
        fs::create_dir(&project).expect("project");
        let target = tempfile::tempdir().expect("junction target");
        fs::write(target.path().join("manifest.json"), b"{}\n").expect("foreign manifest");
        let junction = project.join(".folderbase");
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(target.path())
            .output()
            .expect("run mklink");
        assert!(
            output.status.success(),
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let retained =
            Dir::open_ambient_dir(root.path(), ambient_authority()).expect("retained root");

        assert!(matches!(
            analyze_folder_from_retained(&retained, root.path(), true, true),
            Err(FolderbaseError::UnsafePath(path)) if path == project
        ));
    }
}
