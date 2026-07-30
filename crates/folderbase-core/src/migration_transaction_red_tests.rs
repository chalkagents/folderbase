use std::{
    cell::RefCell,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
};

use tempfile::TempDir;
use uuid::Uuid;

use super::*;

#[derive(Clone, Copy, Debug)]
enum StructuralLeafKind {
    Replace,
    Move,
}

#[derive(Clone, Copy, Debug)]
enum ForeignBytes {
    Same,
    Different,
}

fn initialized_root() -> TempDir {
    let root = tempfile::tempdir().expect("fixture");
    let plan = crate::initialization::plan_initialization(
        root.path(),
        InitializationOptions {
            name: Some("Migration Execution Contract".to_owned()),
            kind: FolderbaseKind::Project,
            create_agent_adapters: true,
        },
    )
    .expect("initialization plan");
    crate::initialization::initialize(&plan).expect("initialize");
    root
}

fn typed_answers(analysis: &MigrationAnalysis) -> Vec<MigrationAnswer> {
    analysis
        .questions
        .iter()
        .map(|question| MigrationAnswer {
            question_id: question.id.clone(),
            answer: question.recommended_option_id.clone(),
            exceptions: Vec::new(),
        })
        .collect()
}

fn approved_structural_leaf(
    kind: StructuralLeafKind,
) -> (
    TempDir,
    String,
    ApprovedMigration,
    PathBuf,
    Option<PathBuf>,
    Vec<u8>,
) {
    let root = initialized_root();
    let (operation, contested, other) = match kind {
        StructuralLeafKind::Replace => (
            MigrationOperation::update_adapter(
                "AGENTS.md",
                "Use the exact claimed root for this migration.",
            ),
            root.path().join("AGENTS.md"),
            None,
        ),
        StructuralLeafKind::Move => {
            fs::create_dir(root.path().join("Archive")).expect("archive");
            fs::write(root.path().join("notes.md"), b"approved move bytes\n").expect("source");
            (
                MigrationOperation::move_object("notes.md", "Archive/notes.md"),
                root.path().join("notes.md"),
                Some(root.path().join("Archive/notes.md")),
            )
        }
    };
    let original = fs::read(&contested).expect("approved leaf");
    let plan = MigrationPlan::propose_structural(root.path(), vec![operation])
        .expect("structural proposal");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approval");
    (root, migration_id, approved, contested, other, original)
}

fn substitute_regular(path: &Path, bytes: &[u8]) -> PhysicalIdentity {
    fs::remove_file(path).expect("remove transaction-observed leaf");
    fs::write(path, bytes).expect("publish foreign leaf");
    PhysicalIdentity::from_path(path).expect("foreign identity")
}

fn bytes_for(case: ForeignBytes, same: &[u8]) -> Vec<u8> {
    match case {
        ForeignBytes::Same => same.to_vec(),
        ForeignBytes::Different => b"uncoordinated different bytes\n".to_vec(),
    }
}

#[cfg(unix)]
fn assert_additive_apply_uses_no_ambient_root_reads(install_replacement: bool) {
    let root = initialized_root();
    fs::write(root.path().join("README.md"), b"approved source\n").expect("source");
    let analysis = analyze_migration(root.path()).expect("analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("migration plan");
    let approved = approve_migration(plan).expect("approval");
    let visible_root = root.path().to_path_buf();
    let detached_root =
        visible_root.with_file_name(format!(".migration-claimed-{}", Uuid::now_v7()));

    let result = apply_migration_with_hook(approved, |checkpoint| {
        if checkpoint == ApplyCheckpoint::MutationAuthorityBound {
            fs::rename(&visible_root, &detached_root).expect("detach claimed root");
            if install_replacement {
                copy_tree(&detached_root, &visible_root);
                fs::write(
                    visible_root.join("ambient-only-after-claim.txt"),
                    b"must never be observed\n",
                )
                .expect("ambient replacement marker");
            }
        }
    });
    let claimed_manifest = detached_root.join("Organized/.folderbase/manifest.json");
    let claimed_template_artifact = detached_root.join("Organized/README.md");
    let claimed_manifest_exists = claimed_manifest.is_file();
    let claimed_template_exists = claimed_template_artifact.is_file();
    let replacement_was_untouched =
        !install_replacement || !visible_root.join("Organized").exists();

    if install_replacement {
        fs::remove_dir_all(&visible_root).expect("remove replacement root");
    }
    fs::rename(&detached_root, &visible_root).expect("restore fixture root");

    assert!(
        result.is_ok(),
        "post-claim ambient namespace must not influence additive topology or rendering \
         (replacement={install_replacement}): {result:?}"
    );
    assert!(
        claimed_manifest_exists && claimed_template_exists,
        "template rendering and publication must use the retained root"
    );
    assert!(
        replacement_was_untouched,
        "the visible replacement root must receive no migration writes"
    );
}

#[cfg(unix)]
#[test]
fn additive_apply_does_not_read_the_old_display_path_after_root_rename() {
    assert_additive_apply_uses_no_ambient_root_reads(false);
}

#[cfg(unix)]
#[test]
fn additive_apply_does_not_read_or_mutate_a_replacement_root_after_claim() {
    assert_additive_apply_uses_no_ambient_root_reads(true);
}

fn assert_apply_leaf_substitution_conflicts(kind: StructuralLeafKind, byte_case: ForeignBytes) {
    let (root, migration_id, approved, source, destination, original) =
        approved_structural_leaf(kind);
    let foreign = bytes_for(byte_case, &original);
    let foreign_identity = RefCell::new(None);

    let result = apply_migration_with_hook(approved, |checkpoint| {
        if checkpoint == ApplyCheckpoint::OperationPlanned(0) {
            *foreign_identity.borrow_mut() = Some(substitute_regular(&source, &foreign));
        }
    });

    assert!(
        result.is_err(),
        "{kind:?}/{byte_case:?} substitution must return an explicit conflict"
    );
    assert_eq!(
        fs::read(&source).expect("foreign leaf remains at the contested name"),
        foreign,
        "{kind:?}/{byte_case:?} foreign bytes must not be overwritten or retired"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&source).expect("foreign identity remains"),
        foreign_identity.into_inner().expect("fault installed"),
        "{kind:?}/{byte_case:?} same-byte identity substitution is still foreign"
    );
    if let Some(destination) = destination {
        assert!(
            !destination.exists(),
            "{kind:?}/{byte_case:?} move conflict must not publish a second name"
        );
    }
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .expect("durable conflicted plan")
            .state,
        MigrationState::Conflicted,
        "{kind:?}/{byte_case:?} conflict must be durable and explicit"
    );
}

fn assert_rollback_leaf_substitution_conflicts(kind: StructuralLeafKind, byte_case: ForeignBytes) {
    let (root, migration_id, approved, source, destination, _original) =
        approved_structural_leaf(kind);
    apply_migration(approved).expect("initial apply");
    let contested = destination.as_deref().unwrap_or(&source);
    let applied = fs::read(contested).expect("applied leaf");
    let foreign = bytes_for(byte_case, &applied);
    let canonical = canonical_root(root.path()).expect("canonical root");
    let (journal_path, mut journal) = load_journal(&canonical, &migration_id).expect("journal");
    let foreign_identity = RefCell::new(None);

    let result = rollback_structural_journal_with_hook(
        &canonical,
        &journal_path,
        &mut journal,
        |checkpoint| {
            if checkpoint == StructuralRollbackCheckpoint::OperationPlanned(0) {
                *foreign_identity.borrow_mut() = Some(substitute_regular(contested, &foreign));
            }
        },
    );

    assert!(
        result.is_err(),
        "{kind:?}/{byte_case:?} rollback substitution must return an explicit conflict"
    );
    assert_eq!(
        fs::read(contested).expect("foreign leaf remains"),
        foreign,
        "{kind:?}/{byte_case:?} rollback must not overwrite or retire foreign bytes"
    );
    assert_eq!(
        PhysicalIdentity::from_path(contested).expect("foreign identity remains"),
        foreign_identity.into_inner().expect("fault installed"),
        "{kind:?}/{byte_case:?} rollback must preserve foreign identity"
    );
    if matches!(kind, StructuralLeafKind::Move) {
        assert!(
            !source.exists(),
            "{kind:?}/{byte_case:?} conflicted rollback must not publish another name"
        );
    }
}
fn assert_recovery_leaf_substitution_conflicts(kind: StructuralLeafKind, byte_case: ForeignBytes) {
    let (root, migration_id, approved, source, destination, _original) =
        approved_structural_leaf(kind);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_hook(approved, |checkpoint| {
            if checkpoint == ApplyCheckpoint::OperationApplied(0) {
                panic!("leave a durable in-flight leaf mutation");
            }
        })
    }));
    assert!(interrupted.is_err(), "fault must interrupt apply");
    let contested = destination.as_deref().unwrap_or(&source);
    let applied = fs::read(contested).expect("applied leaf");
    let foreign = bytes_for(byte_case, &applied);
    let foreign_identity = substitute_regular(contested, &foreign);

    let result = MigrationResult::recover(root.path(), &migration_id);

    assert!(
        result.is_err(),
        "{kind:?}/{byte_case:?} recovery substitution must return an explicit conflict"
    );
    assert_eq!(
        fs::read(contested).expect("foreign leaf remains"),
        foreign,
        "{kind:?}/{byte_case:?} recovery must not overwrite or retire foreign bytes"
    );
    assert_eq!(
        PhysicalIdentity::from_path(contested).expect("foreign identity remains"),
        foreign_identity,
        "{kind:?}/{byte_case:?} recovery must preserve foreign identity"
    );
    if matches!(kind, StructuralLeafKind::Move) {
        assert!(
            !source.exists(),
            "{kind:?}/{byte_case:?} conflicted recovery must not publish another name"
        );
    }
}

macro_rules! leaf_conflict_case {
    ($name:ident, $assertion:ident, $kind:ident, $bytes:ident) => {
        #[test]
        fn $name() {
            $assertion(StructuralLeafKind::$kind, ForeignBytes::$bytes);
        }
    };
}

leaf_conflict_case!(
    apply_replace_same_byte_leaf_substitution_conflicts,
    assert_apply_leaf_substitution_conflicts,
    Replace,
    Same
);
leaf_conflict_case!(
    apply_replace_different_byte_leaf_substitution_conflicts,
    assert_apply_leaf_substitution_conflicts,
    Replace,
    Different
);
leaf_conflict_case!(
    apply_move_same_byte_leaf_substitution_conflicts,
    assert_apply_leaf_substitution_conflicts,
    Move,
    Same
);
leaf_conflict_case!(
    apply_move_different_byte_leaf_substitution_conflicts,
    assert_apply_leaf_substitution_conflicts,
    Move,
    Different
);
leaf_conflict_case!(
    rollback_replace_same_byte_leaf_substitution_conflicts,
    assert_rollback_leaf_substitution_conflicts,
    Replace,
    Same
);
leaf_conflict_case!(
    rollback_replace_different_byte_leaf_substitution_conflicts,
    assert_rollback_leaf_substitution_conflicts,
    Replace,
    Different
);
leaf_conflict_case!(
    rollback_move_same_byte_leaf_substitution_conflicts,
    assert_rollback_leaf_substitution_conflicts,
    Move,
    Same
);
leaf_conflict_case!(
    rollback_move_different_byte_leaf_substitution_conflicts,
    assert_rollback_leaf_substitution_conflicts,
    Move,
    Different
);
leaf_conflict_case!(
    recovery_replace_same_byte_leaf_substitution_conflicts,
    assert_recovery_leaf_substitution_conflicts,
    Replace,
    Same
);
leaf_conflict_case!(
    recovery_replace_different_byte_leaf_substitution_conflicts,
    assert_recovery_leaf_substitution_conflicts,
    Replace,
    Different
);
leaf_conflict_case!(
    recovery_move_same_byte_leaf_substitution_conflicts,
    assert_recovery_leaf_substitution_conflicts,
    Move,
    Same
);
leaf_conflict_case!(
    recovery_move_different_byte_leaf_substitution_conflicts,
    assert_recovery_leaf_substitution_conflicts,
    Move,
    Different
);

#[cfg(unix)]
fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("replacement root");
    for entry in fs::read_dir(source).expect("source directory") {
        let entry = entry.expect("source entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let kind = entry.file_type().expect("entry type");
        if kind.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else if kind.is_file() {
            fs::copy(&source_path, &destination_path).expect("copy replacement file");
        } else {
            panic!("unsupported replacement fixture entry");
        }
    }
}
