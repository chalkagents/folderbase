use std::{
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
};

use cap_std::{ambient_authority, fs::Dir};
use walkdir::WalkDir;

use crate::{
    BoundaryHint, Classification, ClassifiedPath, FolderbaseError, InventorySummary,
    NestedFolderbaseBoundary, NestedFolderbaseState, ReconstructableTree, Result,
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
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(root.to_path_buf()));
    }

    let mut analysis = FolderAnalysis {
        root: root.to_path_buf(),
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
    let mut entries = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    while let Some(next_entry) = entries.next() {
        let entry = next_entry.map_err(|error| {
            let path = error
                .path()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.to_path_buf());
            let source = error
                .into_io_error()
                .unwrap_or_else(|| io::Error::other("filesystem traversal failed"));
            FolderbaseError::io(path, source)
        })?;
        if entry.depth() == 0 {
            continue;
        }

        let relative = safe_relative(root, entry.path())?;
        let file_type = entry.file_type();
        let reconstructable = file_type.is_dir() && is_reconstructable_directory(entry.file_name());

        if file_type.is_dir() {
            match nested_folderbase_state(entry.path()) {
                Ok(Some(state)) => {
                    entries.skip_current_dir();
                    analysis.nested_folderbases.push(NestedFolderbaseBoundary {
                        path: relative,
                        state,
                    });
                    continue;
                }
                Ok(None) => {}
                Err(_) if reconstructable && collapse_reconstructable => {
                    entries.skip_current_dir();
                    analysis.inventory.reconstructable_tree_count += 1;
                    let display = relative.display().to_string();
                    analysis
                        .reconstructable_trees
                        .push(ReconstructableTree { path: relative });
                    analysis.warnings.push(format!(
                        "Collapsed unreadable reconstructable tree without entering it: {}",
                        display
                    ));
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        if is_folderbase_state_component(entry.file_name()) {
            if file_type.is_dir() {
                entries.skip_current_dir();
            }
            continue;
        }

        if collapse_reconstructable && reconstructable {
            entries.skip_current_dir();
            analysis.inventory.reconstructable_tree_count += 1;
            analysis
                .reconstructable_trees
                .push(ReconstructableTree { path: relative });
            continue;
        }

        if is_git_metadata_component(entry.file_name()) {
            if file_type.is_dir() {
                entries.skip_current_dir();
            }
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

        if file_type.is_dir() {
            if let Some((kind, reason)) = boundary_reason(&relative) {
                analysis.boundary_hints.push(BoundaryHint {
                    path: relative,
                    kind: kind.to_owned(),
                    reason: reason.to_owned(),
                });
            }
            continue;
        }

        if !file_type.is_file() {
            analysis
                .warnings
                .push(format!("Skipped non-regular file: {}", relative.display()));
            continue;
        }

        let bytes = entry
            .metadata()
            .map_err(|error| FolderbaseError::io(entry.path(), error.into()))?
            .len();
        let mut classifications = Vec::new();
        classify(
            &mut analysis,
            &mut classifications,
            &relative,
            bytes,
            Classification::Generated,
            is_generated(&relative),
            "Path is inside a known generated or reconstructable area.",
        );
        classify(
            &mut analysis,
            &mut classifications,
            &relative,
            bytes,
            Classification::SecretShaped,
            is_secret_shaped(&relative),
            "Filename resembles a credential or secret; contents were not read.",
        );
        classify(
            &mut analysis,
            &mut classifications,
            &relative,
            bytes,
            Classification::Temporary,
            is_temporary(&relative),
            "Path resembles temporary, cache, backup, or worktree content.",
        );
        classify(
            &mut analysis,
            &mut classifications,
            &relative,
            bytes,
            Classification::Large,
            bytes >= LARGE_FILE_BYTES,
            "File is at least 100 MiB.",
        );
        classify(
            &mut analysis,
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

    sort_analysis(&mut analysis);
    Ok(analysis)
}

fn nested_folderbase_state(root: &Path) -> Result<Option<NestedFolderbaseState>> {
    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|source| FolderbaseError::io(root, source))?;
    Ok(
        match classify_nested_folderbase_boundary(&directory, root)? {
            NestedFolderbaseBoundaryKind::ExactBoundary
            | NestedFolderbaseBoundaryKind::UnsafeAliasShape => {
                Some(NestedFolderbaseState::Unchecked)
            }
            NestedFolderbaseBoundaryKind::None => None,
        },
    )
}

fn safe_relative(root: &Path, child: &Path) -> Result<PathBuf> {
    let relative = child
        .strip_prefix(root)
        .map_err(|_| FolderbaseError::UnsafePath(child.to_path_buf()))?;
    let mut safe = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => safe.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FolderbaseError::UnsafePath(child.to_path_buf()));
            }
        }
    }
    Ok(safe)
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
