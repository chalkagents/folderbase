use std::path::Path;

use crate::{InspectionReport, Result, folder_analysis::analyze_folder};

/// Inspect an unmanaged folder without reading user file contents or changing it.
///
/// Classifications are conservative metadata hints. Nested folderbases are emitted
/// as opaque boundary records and none of their descendants are traversed.
pub fn inspect(root: impl AsRef<Path>) -> Result<InspectionReport> {
    let analysis = analyze_folder(root.as_ref())?;
    Ok(InspectionReport {
        root: analysis.root,
        inventory: analysis.inventory,
        classified_paths: analysis.classified_paths,
        git_repositories: analysis.git_repositories,
        context_files: analysis.context_files,
        boundary_hints: analysis.boundary_hints,
        reconstructable_trees: analysis.reconstructable_trees,
        nested_folderbases: analysis.nested_folderbases,
        warnings: analysis.warnings,
    })
}
