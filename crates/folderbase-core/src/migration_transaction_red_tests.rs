use std::{
    cell::RefCell,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Component, Path, PathBuf},
    sync::mpsc,
    thread,
};

use sha2::{Digest, Sha256};
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
    // Keep the displaced object alive under a test-only sibling name until
    // the replacement has been opened. Linux filesystems may immediately
    // recycle an unlinked inode, which can make a genuinely new object appear
    // to have the same (device, inode) identity and turn this adversarial
    // fixture into a no-op. A retained pathname works on Windows as well.
    let retained = path.with_file_name(format!(
        ".folderbase-substitution-retained-{}",
        Uuid::now_v7()
    ));
    fs::rename(path, &retained).expect("retain displaced physical leaf");
    fs::write(path, bytes).expect("publish foreign leaf");
    let identity = PhysicalIdentity::from_path(path).expect("foreign identity");
    fs::remove_file(retained).expect("retire displaced test leaf");
    identity
}

#[test]
fn substitution_fixture_forces_a_distinct_identity_without_retained_artifacts() {
    let root = tempfile::tempdir().expect("substitution fixture");
    let path = root.path().join("active.bin");
    fs::write(&path, b"generation 0").expect("initial leaf");
    let mut previous = PhysicalIdentity::from_path(&path).expect("initial identity");

    for generation in 1..=16 {
        let bytes = format!("generation {generation}");
        let current = substitute_regular(&path, bytes.as_bytes());
        assert_ne!(current, previous, "replacement must be a new object");
        assert_eq!(
            fs::read(&path).expect("replacement bytes"),
            bytes.as_bytes()
        );
        assert_eq!(
            fs::read_dir(root.path())
                .expect("fixture directory")
                .count(),
            1,
            "the displaced test object must be retired"
        );
        previous = current;
    }
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

#[cfg(unix)]
#[test]
fn additive_topology_validation_uses_retained_root_after_display_replacement() {
    let root = initialized_root();
    fs::write(root.path().join("README.md"), b"approved source\n").expect("source");
    let analysis = analyze_migration(root.path()).expect("analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("migration plan");
    let approved = approve_migration(plan).expect("approval");
    let state = FolderbaseState::open_existing(root.path()).expect("retained Folderbase state");
    let filesystem = MigrationFilesystem::from_state(&state, root.path())
        .expect("retained migration filesystem");
    let visible_root = root.path().to_path_buf();
    let detached_root =
        visible_root.with_file_name(format!(".topology-retained-{}", Uuid::now_v7()));

    fs::rename(&visible_root, &detached_root).expect("detach retained root");
    copy_tree(&detached_root, &visible_root);
    let replacement_marker = visible_root.join("ambient-only-before-apply.txt");
    fs::write(&replacement_marker, b"must never enter retained topology\n")
        .expect("ambient replacement marker");

    let validation = verify_additive_source_topology_in(&filesystem, &approved.plan)
        .and_then(|()| verify_expanded_reconstructable_trees_in(&filesystem, &approved.plan));
    let retained_source = fs::read(detached_root.join("README.md")).expect("retained source");
    let replacement_marker_bytes =
        fs::read(&replacement_marker).expect("replacement marker remains");
    let retained_was_not_mutated = !detached_root.join("Organized").exists();
    let replacement_was_not_mutated = !visible_root.join("Organized").exists();

    fs::remove_dir_all(&visible_root).expect("remove replacement root");
    fs::rename(&detached_root, &visible_root).expect("restore fixture root");

    assert!(
        validation.is_ok(),
        "additive topology validation must use the retained root rather than the replacement \
         display pathname: {validation:?}"
    );
    assert_eq!(retained_source, b"approved source\n");
    assert_eq!(
        replacement_marker_bytes,
        b"must never enter retained topology\n"
    );
    assert!(
        retained_was_not_mutated && replacement_was_not_mutated,
        "topology validation must not mutate either retained or replacement root"
    );
}

fn assert_apply_leaf_substitution_conflicts(kind: StructuralLeafKind, byte_case: ForeignBytes) {
    let (root, migration_id, approved, source, destination, original) =
        approved_structural_leaf(kind);
    let foreign = bytes_for(byte_case, &original);
    let foreign_identity = RefCell::new(None);
    let expected_kind = match kind {
        StructuralLeafKind::Replace => "replace_file",
        StructuralLeafKind::Move => "move_file",
    };
    let expected_source = source
        .strip_prefix(root.path())
        .expect("structural source beneath root")
        .to_string_lossy()
        .into_owned();

    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        let TransactionV1Checkpoint::ApplyIntentPersisted(index) = checkpoint else {
            return;
        };
        if foreign_identity.borrow().is_some() {
            return;
        }
        let program: serde_json::Value = serde_json::from_slice(
            &fs::read(program_path_for(root.path(), &migration_id))
                .expect("persisted mutation program"),
        )
        .expect("persisted mutation program JSON");
        let step = program["steps"]
            .as_array()
            .and_then(|steps| steps.get(index))
            .expect("persisted step for apply intent");
        let source_field = match kind {
            StructuralLeafKind::Replace => "target",
            StructuralLeafKind::Move => "source",
        };
        if step["kind"].as_str() == Some(expected_kind)
            && step[source_field]["path"].as_str() == Some(expected_source.as_str())
        {
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
    let fixture = apply_closed_leaf(match kind {
        StructuralLeafKind::Replace => ClosedLeafKind::ReplaceFile,
        StructuralLeafKind::Move => ClosedLeafKind::MoveFile,
    });
    let applied = fs::read(&fixture.target).expect("applied leaf");
    let foreign = bytes_for(byte_case, &applied);
    let foreign_identity = RefCell::new(None);

    let result = run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
        |checkpoint| {
            if checkpoint == TransactionV1Checkpoint::RollbackRequested
                && foreign_identity.borrow().is_none()
            {
                *foreign_identity.borrow_mut() =
                    Some(substitute_regular(&fixture.target, &foreign));
            }
        },
    );

    let (migration_id, conflicts) = expect_conflicted(
        result,
        &format!("{kind:?}/{byte_case:?} rollback substitution"),
    );
    assert_eq!(migration_id, fixture.migration_id);
    assert_eq!(
        fs::read(&fixture.target).expect("foreign leaf remains"),
        foreign,
        "{kind:?}/{byte_case:?} rollback must not overwrite or retire foreign bytes"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("foreign identity remains"),
        foreign_identity.into_inner().expect("fault installed"),
        "{kind:?}/{byte_case:?} rollback must preserve foreign identity"
    );
    if matches!(kind, StructuralLeafKind::Move) {
        assert!(
            !fixture.source.as_ref().expect("move source").exists(),
            "{kind:?}/{byte_case:?} conflicted rollback must not publish another name"
        );
    }
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .affected_paths
                .iter()
                .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))
        }),
        "{kind:?}/{byte_case:?} rollback conflict must name the foreign target"
    );
    let (_, latest) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(latest["direction"], "rollback");
    assert_eq!(latest["phase"], "conflicted");
    assert_eq!(
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id)
            .expect("durable conflicted plan")
            .state,
        MigrationState::Conflicted,
        "{kind:?}/{byte_case:?} rollback conflict must update the durable plan projection"
    );
}
fn assert_recovery_leaf_substitution_conflicts(kind: StructuralLeafKind, byte_case: ForeignBytes) {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(match kind {
            StructuralLeafKind::Replace => ClosedLeafKind::ReplaceFile,
            StructuralLeafKind::Move => ClosedLeafKind::MoveFile,
        }),
        LostAcknowledgement::Publish,
    );
    let applied = fs::read(&fixture.target).expect("published leaf");
    let foreign = bytes_for(byte_case, &applied);
    let foreign_identity = substitute_regular(&fixture.target, &foreign);
    let source_claim = source_claim_path(&fixture);
    let source_claim_identity =
        PhysicalIdentity::from_path(&source_claim).expect("private original identity");
    let source_claim_bytes = fs::read(&source_claim).expect("private original bytes");

    let (migration_id, conflicts) = expect_conflicted(
        public_recover(&fixture),
        &format!("{kind:?}/{byte_case:?} recovery substitution"),
    );

    assert_eq!(migration_id, fixture.migration_id);
    assert_eq!(
        fs::read(&fixture.target).expect("foreign leaf remains"),
        foreign,
        "{kind:?}/{byte_case:?} recovery must not overwrite or retire foreign bytes"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("foreign identity remains"),
        foreign_identity,
        "{kind:?}/{byte_case:?} recovery must preserve foreign identity"
    );
    if matches!(kind, StructuralLeafKind::Move) {
        assert!(
            !fixture.source.as_ref().expect("move source").exists(),
            "{kind:?}/{byte_case:?} conflicted recovery must not publish another name"
        );
    }
    assert_eq!(
        PhysicalIdentity::from_path(&source_claim).expect("private original remains"),
        source_claim_identity,
        "{kind:?}/{byte_case:?} recovery must preserve the exact private original"
    );
    assert_eq!(
        fs::read(&source_claim).expect("private original bytes remain"),
        source_claim_bytes,
        "{kind:?}/{byte_case:?} recovery must not rewrite private original bytes"
    );
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .affected_paths
                .iter()
                .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))
        }),
        "{kind:?}/{byte_case:?} recovery conflict must name the foreign target"
    );
    let (_, latest) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(latest["direction"], "apply");
    assert_eq!(latest["phase"], "conflicted");
    assert_eq!(
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id)
            .expect("durable conflicted plan")
            .state,
        MigrationState::Conflicted,
        "{kind:?}/{byte_case:?} recovery conflict must update the durable plan projection"
    );
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

struct PreparedV1Fixture {
    root: TempDir,
    migration_id: String,
    approval_digest: String,
    source: PathBuf,
    destination: PathBuf,
    source_bytes: Vec<u8>,
}

fn prepared_v1_fixture(interrupt_at: ApplyCheckpoint) -> PreparedV1Fixture {
    let root = initialized_root();
    let source = root.path().join("Inbox/notes.md");
    let destination = root.path().join("Archive/notes.md");
    fs::create_dir(root.path().join("Inbox")).expect("source parent");
    fs::create_dir(root.path().join("Archive")).expect("destination parent");
    fs::write(&source, b"approved move bytes\n").expect("source");
    let source_bytes = fs::read(&source).expect("approved source");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "Inbox/notes.md",
            "Archive/notes.md",
        )],
    )
    .expect("structural proposal");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approval");
    let approval_digest = approved.approval_digest.clone();
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_hook(approved, |checkpoint| {
            if checkpoint == interrupt_at {
                panic!("leave checkpoint-E transaction state");
            }
        })
    }));
    assert!(interrupted.is_err(), "checkpoint fixture must interrupt");
    assert!(transaction_v1_root(root.path(), &migration_id).is_dir());
    PreparedV1Fixture {
        root,
        migration_id,
        approval_digest,
        source,
        destination,
        source_bytes,
    }
}

fn transaction_v1_root(root: &Path, migration_id: &str) -> PathBuf {
    root.join(".folderbase/migrations")
        .join(migration_id)
        .join(TRANSACTION_DIRECTORY)
}

fn reopen_prepared_v1(fixture: &PreparedV1Fixture) -> Result<PreparedTransactionV1> {
    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("migration filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id);
    reopen_transaction_v1(&filesystem, &migration_root, None)
}

fn reopen_error(fixture: &PreparedV1Fixture, reason: &str) -> FolderbaseError {
    match reopen_prepared_v1(fixture) {
        Ok(_) => panic!("transaction-v1 reopen accepted {reason}"),
        Err(error) => error,
    }
}

fn program_path(fixture: &PreparedV1Fixture) -> PathBuf {
    transaction_v1_root(fixture.root.path(), &fixture.migration_id).join("program.json")
}

fn journal_root(fixture: &PreparedV1Fixture) -> PathBuf {
    transaction_v1_root(fixture.root.path(), &fixture.migration_id).join("journal")
}

#[test]
fn transaction_v1_rejects_a_semantically_equal_noncanonical_program_rewrite() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let path = program_path(&fixture);
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("program")).expect("program JSON");
    let rewritten = serde_json::to_vec_pretty(&value).expect("pretty program");
    assert_ne!(rewritten, fs::read(&path).expect("canonical program"));
    fs::write(&path, rewritten).expect("raw program rewrite");

    let _ = reopen_error(&fixture, "a semantically equal raw-byte rewrite");
}

#[test]
fn transaction_v1_rejects_unknown_fields_nested_inside_a_program_operation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let path = program_path(&fixture);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("program")).expect("program JSON");
    value["steps"][0]["x-checkpoint-e-unknown"] = serde_json::Value::Bool(true);
    let rewritten = serde_json::to_vec(&value).expect("rewritten program");
    assert!(
        MutationProgramV1::decode(Path::new("<checkpoint-e-program>"), &rewritten).is_err(),
        "the transaction schema must deny unknown fields in nested operation variants"
    );
    fs::write(&path, rewritten).expect("program rewrite");

    let _ = reopen_error(&fixture, "an unknown nested operation field");
}

#[test]
fn transaction_v1_rejects_an_unknown_root_file() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    fs::write(
        transaction_v1_root(fixture.root.path(), &fixture.migration_id).join("unexpected.bin"),
        b"unknown private state\n",
    )
    .expect("unknown root entry");

    let _ = reopen_error(&fixture, "an unknown transaction-root file");
}

#[test]
fn transaction_v1_rejects_an_unknown_journal_file() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    fs::write(
        journal_root(&fixture).join("unexpected.json"),
        b"unknown private state\n",
    )
    .expect("unknown journal entry");

    let _ = reopen_error(&fixture, "an unknown journal file");
}

#[test]
fn transaction_v1_rejects_a_nested_journal_directory() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    fs::create_dir(journal_root(&fixture).join("nested")).expect("nested journal directory");

    let _ = reopen_error(&fixture, "a nested journal directory");
}

#[cfg(any(unix, windows))]
#[test]
fn transaction_v1_rejects_unknown_symlink_entries() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let target = program_path(&fixture);
    let transaction_link =
        transaction_v1_root(fixture.root.path(), &fixture.migration_id).join("unexpected-link");
    let journal_link = journal_root(&fixture).join("unexpected-link");
    create_file_symlink(&target, &transaction_link);
    create_file_symlink(&target, &journal_link);

    let _ = reopen_error(&fixture, "unknown transaction symlink entries");
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("file symlink");
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) {
    std::os::windows::fs::symlink_file(target, link)
        .expect("GitHub Windows runners permit file symlinks");
}

#[test]
fn transaction_v1_rejects_a_partial_prepared_state() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    fs::remove_file(program_path(&fixture)).expect("remove immutable program");

    let _ = reopen_error(&fixture, "prepared state without program.json");
}

#[test]
fn transaction_v1_rejects_generation_count_above_the_operation_derived_bound() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(program_path(&fixture)).expect("immutable program"))
            .expect("program JSON");
    let operation_count = value["steps"].as_array().expect("program steps").len();
    // Eight phase records cover apply and rollback intent/completion plus each
    // direction's journal-bound publication and cleanup pair. Each retained
    // conflict reserves both its retry intent and exact evidence.
    let maximum_generation_count =
        6 + operation_count * 8 + transaction_v1::MAX_RETAINED_CONFLICTS * 2;
    let journal = journal_root(&fixture);
    let first = journal.join("00000000000000000000.json");
    for generation in 1..=maximum_generation_count {
        fs::hard_link(&first, journal.join(format!("{generation:020}.json")))
            .expect("bounded generation fixture");
    }

    let error = reopen_error(
        &fixture,
        "a journal generation count above the operation-derived bound",
    );
    let message = error.to_string();
    assert!(
        message.contains("count") || message.contains("bound"),
        "entry-count rejection must happen before allocating or decoding the chain: {message}"
    );
}

#[cfg(unix)]
#[test]
fn transaction_v1_reopen_rejects_insecure_directories_without_repair() {
    use std::os::unix::fs::PermissionsExt;

    for select in [
        |fixture: &PreparedV1Fixture| {
            transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        },
        journal_root,
    ] {
        let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
        let path = select(&fixture);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("insecure private directory");

        assert!(
            reopen_prepared_v1(&fixture).is_err(),
            "insecure reopened directory must fail closed"
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("private directory")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "reopen must not repair the directory {}",
            path.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn transaction_v1_reopen_rejects_insecure_files_without_repair() {
    use std::os::unix::fs::PermissionsExt;

    for select in [program_path, |fixture: &PreparedV1Fixture| {
        journal_root(fixture).join("00000000000000000000.json")
    }] {
        let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
        let path = select(&fixture);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("insecure private file");

        assert!(
            reopen_prepared_v1(&fixture).is_err(),
            "insecure reopened file must fail closed"
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("private file")
                .permissions()
                .mode()
                & 0o777,
            0o644,
            "reopen must not repair the file {}",
            path.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn transaction_v1_new_private_state_is_owner_only_under_a_permissive_umask() {
    const CHILD: &str = "FOLDERBASE_CHECKPOINT_E_MODE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "migration::migration_transaction_red_tests::transaction_v1_new_private_state_is_owner_only_under_a_permissive_umask",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("isolated mode test");
        assert!(
            output.status.success(),
            "isolated transaction-v1 mode test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    use std::os::unix::fs::PermissionsExt;

    struct Umask(libc::mode_t);
    impl Drop for Umask {
        fn drop(&mut self) {
            // SAFETY: restore the mask in the isolated child process.
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    // SAFETY: this test body runs alone in the subprocess above.
    let _umask = Umask(unsafe { libc::umask(0o000) });
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let transaction = transaction_v1_root(fixture.root.path(), &fixture.migration_id);
    let insecure = walkdir::WalkDir::new(&transaction)
        .into_iter()
        .map(|entry| entry.expect("private transaction entry"))
        .filter_map(|entry| {
            let mode = entry
                .metadata()
                .expect("private metadata")
                .permissions()
                .mode()
                & 0o777;
            let expected = if entry.file_type().is_dir() {
                0o700
            } else {
                0o600
            };
            (mode != expected).then(|| (entry.path().to_path_buf(), mode, expected))
        })
        .collect::<Vec<_>>();
    assert!(
        insecure.is_empty(),
        "new transaction-v1 state must be born private: {insecure:?}"
    );
}

fn migration_result_path(root: &Path, migration_id: &str) -> PathBuf {
    root.join(".folderbase/migrations")
        .join(migration_id)
        .join("result.json")
}

fn remove_transitional_legacy_result(fixture: &PreparedV1Fixture) {
    match fs::remove_file(migration_result_path(
        fixture.root.path(),
        &fixture.migration_id,
    )) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove transitional legacy result: {error}"),
    }
}

fn retry_prepared_apply(fixture: &PreparedV1Fixture) -> Result<MigrationOutcome> {
    remove_transitional_legacy_result(fixture);
    MigrationExecution::run(
        RootClaim::Current {
            display_root: fixture.root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &fixture.migration_id,
            approval_digest: &fixture.approval_digest,
        },
    )
}

#[derive(Clone, Copy, Debug)]
enum ClosedLeafKind {
    CreateDirectory,
    CreateFile,
    ReplaceFile,
    MoveFile,
}

#[derive(Clone, Copy, Debug)]
enum LostAcknowledgement {
    Intent,
    Claim,
    Publish,
    PrivateReceipt,
    JournalReceipt,
}

#[derive(Debug)]
enum ExpectedVisibleLeaf {
    Directory,
    Regular(Vec<u8>),
}

struct ClosedLeafFixture {
    root: TempDir,
    migration_id: String,
    approved: Option<ApprovedMigration>,
    kind: ClosedLeafKind,
    hook_operation_index: usize,
    operation: MigrationOperation,
    source: Option<PathBuf>,
    target: PathBuf,
    expected: ExpectedVisibleLeaf,
}

fn approved_closed_leaf(kind: ClosedLeafKind) -> ClosedLeafFixture {
    match kind {
        ClosedLeafKind::CreateDirectory | ClosedLeafKind::CreateFile => {
            let root = tempfile::tempdir().expect("ordinary source folder");
            match kind {
                ClosedLeafKind::CreateDirectory => {
                    fs::write(root.path().join("README.md"), b"ordinary project context\n")
                        .expect("ordinary project source");
                }
                ClosedLeafKind::CreateFile => {
                    fs::write(
                        root.path().join("payload.bin"),
                        b"\x00folderbase payload\xff\n",
                    )
                    .expect("ordinary source file");
                }
                ClosedLeafKind::ReplaceFile | ClosedLeafKind::MoveFile => unreachable!(),
            }
            let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
            let answers = typed_answers(&analysis);
            let plan =
                plan_migration(analysis, answers, "Organized").expect("additive migration plan");
            let (operation_index, operation, source, target, expected) = plan
                .operations
                .iter()
                .enumerate()
                .find_map(|(index, operation)| match (kind, operation) {
                    (
                        ClosedLeafKind::CreateDirectory,
                        MigrationOperation::CreateFolder { path },
                    ) if path == Path::new("Organized") => Some((
                        index,
                        operation.clone(),
                        None,
                        root.path().join(path),
                        ExpectedVisibleLeaf::Directory,
                    )),
                    (
                        ClosedLeafKind::CreateFile,
                        MigrationOperation::CopyFile {
                            source_path,
                            destination_path,
                            ..
                        },
                    ) if source_path == Path::new("payload.bin") => Some((
                        index,
                        operation.clone(),
                        Some(root.path().join(source_path)),
                        root.path().join(destination_path),
                        ExpectedVisibleLeaf::Regular(
                            fs::read(root.path().join(source_path)).expect("source bytes"),
                        ),
                    )),
                    _ => None,
                })
                .expect("closed additive leaf");
            let migration_id = plan.id.clone();
            let approved = approve_migration(plan).expect("approved additive migration");
            ClosedLeafFixture {
                root,
                migration_id,
                approved: Some(approved),
                kind,
                hook_operation_index: operation_index,
                operation,
                source,
                target,
                expected,
            }
        }
        ClosedLeafKind::ReplaceFile => {
            let root = initialized_root();
            let target = root.path().join("AGENTS.md");
            let plan = MigrationPlan::propose_structural(
                root.path(),
                vec![MigrationOperation::update_adapter(
                    "AGENTS.md",
                    "Use the exact claimed root for this migration.",
                )],
            )
            .expect("replace proposal");
            let migration_id = plan.id.clone();
            let approved = approve_migration(plan).expect("approved replace");
            let operation = approved.plan.operations[0].clone();
            let expected = structural_result_bytes(&target, &operation).expect("replacement bytes");
            ClosedLeafFixture {
                root,
                migration_id,
                approved: Some(approved),
                kind,
                hook_operation_index: 0,
                operation,
                source: Some(target.clone()),
                target,
                expected: ExpectedVisibleLeaf::Regular(expected),
            }
        }
        ClosedLeafKind::MoveFile => {
            let root = initialized_root();
            fs::create_dir(root.path().join("Inbox")).expect("source parent");
            fs::create_dir(root.path().join("Archive")).expect("destination parent");
            let source = root.path().join("Inbox/notes.md");
            let target = root.path().join("Archive/notes.md");
            fs::write(&source, b"approved move bytes\n").expect("move source");
            let expected = fs::read(&source).expect("move bytes");
            let plan = MigrationPlan::propose_structural(
                root.path(),
                vec![MigrationOperation::move_object(
                    "Inbox/notes.md",
                    "Archive/notes.md",
                )],
            )
            .expect("move proposal");
            let migration_id = plan.id.clone();
            let approved = approve_migration(plan).expect("approved move");
            let operation = approved.plan.operations[0].clone();
            ClosedLeafFixture {
                root,
                migration_id,
                approved: Some(approved),
                kind,
                hook_operation_index: 0,
                operation,
                source: Some(source),
                target,
                expected: ExpectedVisibleLeaf::Regular(expected),
            }
        }
    }
}

fn persisted_step_index(fixture: &ClosedLeafFixture) -> usize {
    let program: serde_json::Value = serde_json::from_slice(
        &fs::read(program_path_for(fixture.root.path(), &fixture.migration_id))
            .expect("persisted mutation program"),
    )
    .expect("persisted mutation program JSON");
    let Some(steps) = program.get("steps").and_then(serde_json::Value::as_array) else {
        // The released pre-E2 program indexes its operations exactly like the
        // legacy fault hook. E2's closed compiler has its own authoritative
        // step order and takes the branch below.
        return fixture.hook_operation_index;
    };
    let expected_kind = match fixture.kind {
        ClosedLeafKind::CreateDirectory => "create_directory",
        ClosedLeafKind::CreateFile => "create_file",
        ClosedLeafKind::ReplaceFile => "replace_file",
        ClosedLeafKind::MoveFile => "move_file",
    };
    let expected_target = fixture
        .target
        .strip_prefix(fixture.root.path())
        .expect("fixture target beneath root")
        .to_string_lossy();
    steps
        .iter()
        .position(|step| {
            step.get("kind").and_then(serde_json::Value::as_str) == Some(expected_kind)
                && step
                    .get(match fixture.kind {
                        ClosedLeafKind::MoveFile => "destination",
                        _ => "target",
                    })
                    .and_then(|target| target.get("path"))
                    .and_then(serde_json::Value::as_str)
                    == Some(expected_target.as_ref())
        })
        .expect("persisted closed-program step for fixture target")
}

fn program_path_for(root: &Path, migration_id: &str) -> PathBuf {
    transaction_v1_root(root, migration_id).join("program.json")
}

fn source_claim_path(fixture: &ClosedLeafFixture) -> PathBuf {
    let operation_index = persisted_step_index(fixture);
    transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        .join("claims")
        .join(format!("{operation_index:08}.source.claim"))
}

fn rollback_snapshot_path(fixture: &ClosedLeafFixture) -> PathBuf {
    let operation_index = persisted_step_index(fixture);
    transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        .join("snapshots")
        .join(format!("{operation_index:08}.snapshot"))
}

#[allow(dead_code)]
fn persist_apply_intent(fixture: &ClosedLeafFixture) {
    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("migration filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id);
    let mut transaction =
        reopen_transaction_v1(&filesystem, &migration_root, None).expect("prepared transaction-v1");
    let operation_index = persisted_step_index(fixture);
    let program_value: serde_json::Value = serde_json::from_slice(
        &fs::read(program_path_for(fixture.root.path(), &fixture.migration_id))
            .expect("persisted mutation program"),
    )
    .expect("persisted mutation program JSON");
    let released_plan = program_value.get("steps").is_none().then(|| {
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id)
            .expect("released operation order")
    });
    for predecessor in 0..operation_index {
        let intent = transaction
            .generations
            .last()
            .expect("previous apply generation")
            .next_apply_intent(&transaction.program, predecessor)
            .expect("predecessor apply intent");
        append_transaction_v1_generation(&filesystem, &mut transaction, intent)
            .expect("persist predecessor intent");
        let directory = if let Some(steps) = program_value
            .get("steps")
            .and_then(serde_json::Value::as_array)
        {
            let step = &steps[predecessor];
            assert_eq!(
                step.get("kind").and_then(serde_json::Value::as_str),
                Some("create_directory"),
                "a create-file tracer may advance only its parent-directory prefix"
            );
            PathBuf::from(
                step.get("target")
                    .and_then(|target| target.get("path"))
                    .and_then(serde_json::Value::as_str)
                    .expect("predecessor directory path"),
            )
        } else {
            match &released_plan.as_ref().expect("released plan").operations[predecessor] {
                MigrationOperation::CreateFolder { path } => path.clone(),
                operation => {
                    panic!(
                        "a create-file tracer may advance only its parent-directory prefix: \
                         {operation:?}"
                    )
                }
            }
        };
        fs::create_dir(fixture.root.path().join(&directory))
            .expect("materialize predecessor directory");
        let receipt = transaction
            .generations
            .last()
            .expect("predecessor intent generation")
            .next_apply_receipt(&transaction.program, predecessor, None)
            .expect("predecessor apply receipt");
        append_transaction_v1_generation(&filesystem, &mut transaction, receipt)
            .expect("persist predecessor receipt");
    }
    let intent = transaction
        .generations
        .last()
        .expect("prepared journal generation")
        .next_apply_intent(&transaction.program, operation_index)
        .expect("durable apply intent");
    append_transaction_v1_generation(&filesystem, &mut transaction, intent)
        .expect("persist apply intent");
}

#[allow(dead_code)]
fn install_claimed_crash_state(fixture: &ClosedLeafFixture) {
    let Some(source) = fixture.source.as_deref() else {
        // Creates claim an exact absence rather than moving an original leaf.
        return;
    };
    let claim = source_claim_path(fixture);
    fs::rename(source, claim)
        .expect("atomically retain the expected original in its private claim");
}

#[allow(dead_code)]
fn install_published_crash_state(fixture: &ClosedLeafFixture) {
    match fixture.expected {
        ExpectedVisibleLeaf::Directory => {
            fs::create_dir(&fixture.target).expect("publish created directory");
        }
        ExpectedVisibleLeaf::Regular(ref bytes) => match fixture.operation {
            MigrationOperation::CopyFile { .. } => {
                let source = fixture.source.as_deref().expect("copy source");
                fs::copy(source, &fixture.target).expect("publish created file");
            }
            MigrationOperation::MoveObject { .. } => {
                install_claimed_crash_state(fixture);
                fs::hard_link(source_claim_path(fixture), &fixture.target)
                    .expect("publish claimed move without replacing a competitor");
            }
            _ => {
                install_claimed_crash_state(fixture);
                fs::write(&fixture.target, bytes).expect("publish staged replacement bytes");
            }
        },
    }
}

fn interrupt_closed_leaf(
    mut fixture: ClosedLeafFixture,
    lost_acknowledgement: LostAcknowledgement,
) -> ClosedLeafFixture {
    let approved = fixture.approved.take().expect("approved migration");
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_transaction_hook(approved, |checkpoint| {
            let operation_index = persisted_step_index(&fixture);
            let at_operation = match (lost_acknowledgement, checkpoint) {
                (
                    LostAcknowledgement::Intent,
                    TransactionV1Checkpoint::ApplyIntentPersisted(index),
                )
                | (LostAcknowledgement::Claim, TransactionV1Checkpoint::ClaimComplete(index))
                | (
                    LostAcknowledgement::Publish,
                    TransactionV1Checkpoint::VisiblePublishComplete(index),
                )
                | (
                    LostAcknowledgement::PrivateReceipt,
                    TransactionV1Checkpoint::PrivateApplyReceiptPersisted(index),
                )
                | (
                    LostAcknowledgement::JournalReceipt,
                    TransactionV1Checkpoint::JournalApplyReceiptPersisted(index),
                ) => index == operation_index,
                _ => false,
            };
            if at_operation {
                panic!("simulate process loss at {lost_acknowledgement:?}");
            }
        })
    }));
    assert!(
        interrupted.is_err(),
        "{:?}/{lost_acknowledgement:?} fixture must interrupt",
        fixture.operation
    );
    match fs::remove_file(migration_result_path(
        fixture.root.path(),
        &fixture.migration_id,
    )) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove transitional result.json: {error}"),
    }
    fixture
}

fn assert_closed_leaf_recovery(kind: ClosedLeafKind, lost_acknowledgement: LostAcknowledgement) {
    let fixture = interrupt_closed_leaf(approved_closed_leaf(kind), lost_acknowledgement);
    let outcome = run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
        |_| {},
    )
    .expect("transaction-v1 recovery must classify and resume the durable leaf state");
    assert!(
        matches!(outcome, MigrationOutcome::Applied(_)),
        "{kind:?}/{lost_acknowledgement:?} must converge in the requested apply direction"
    );
    match fixture.expected {
        ExpectedVisibleLeaf::Directory => {
            assert!(fixture.target.is_dir(), "created directory must be visible");
        }
        ExpectedVisibleLeaf::Regular(expected) => {
            assert_eq!(
                fs::read(&fixture.target).expect("recovered visible file"),
                expected,
                "recovery must publish the exact approved bytes"
            );
        }
    }
    if matches!(kind, ClosedLeafKind::MoveFile) {
        assert!(
            !fixture.source.expect("move source").exists(),
            "recovered move must retire the source name"
        );
    }
    assert!(
        !migration_result_path(fixture.root.path(), &fixture.migration_id).exists(),
        "transaction-v1 recovery must not fall back to result.json"
    );
}

macro_rules! closed_leaf_recovery_case {
    ($name:ident, $kind:ident, $checkpoint:ident) => {
        #[test]
        fn $name() {
            assert_closed_leaf_recovery(ClosedLeafKind::$kind, LostAcknowledgement::$checkpoint);
        }
    };
}

closed_leaf_recovery_case!(
    create_directory_recovers_after_intent_loss,
    CreateDirectory,
    Intent
);
closed_leaf_recovery_case!(
    create_directory_recovers_after_absence_claim_loss,
    CreateDirectory,
    Claim
);
closed_leaf_recovery_case!(
    create_directory_recovers_after_publish_loss,
    CreateDirectory,
    Publish
);
closed_leaf_recovery_case!(
    create_directory_recovers_after_private_receipt_loss,
    CreateDirectory,
    PrivateReceipt
);
closed_leaf_recovery_case!(
    create_directory_recovers_after_journal_receipt_loss,
    CreateDirectory,
    JournalReceipt
);
closed_leaf_recovery_case!(create_file_recovers_after_intent_loss, CreateFile, Intent);
closed_leaf_recovery_case!(
    create_file_recovers_after_absence_claim_loss,
    CreateFile,
    Claim
);
closed_leaf_recovery_case!(create_file_recovers_after_publish_loss, CreateFile, Publish);
closed_leaf_recovery_case!(
    create_file_recovers_after_private_receipt_loss,
    CreateFile,
    PrivateReceipt
);
closed_leaf_recovery_case!(
    create_file_recovers_after_journal_receipt_loss,
    CreateFile,
    JournalReceipt
);
closed_leaf_recovery_case!(replace_file_recovers_after_intent_loss, ReplaceFile, Intent);
closed_leaf_recovery_case!(replace_file_recovers_after_claim_loss, ReplaceFile, Claim);
closed_leaf_recovery_case!(
    replace_file_recovers_after_publish_loss,
    ReplaceFile,
    Publish
);
closed_leaf_recovery_case!(
    replace_file_recovers_after_private_receipt_loss,
    ReplaceFile,
    PrivateReceipt
);
closed_leaf_recovery_case!(
    replace_file_recovers_after_journal_receipt_loss,
    ReplaceFile,
    JournalReceipt
);
closed_leaf_recovery_case!(move_file_recovers_after_intent_loss, MoveFile, Intent);
closed_leaf_recovery_case!(move_file_recovers_after_claim_loss, MoveFile, Claim);
closed_leaf_recovery_case!(move_file_recovers_after_publish_loss, MoveFile, Publish);
closed_leaf_recovery_case!(
    move_file_recovers_after_private_receipt_loss,
    MoveFile,
    PrivateReceipt
);
closed_leaf_recovery_case!(
    move_file_recovers_after_journal_receipt_loss,
    MoveFile,
    JournalReceipt
);

fn interrupt_create_directory_after_private_receipt_before_publication() -> ClosedLeafFixture {
    let mut fixture = approved_closed_leaf(ClosedLeafKind::CreateDirectory);
    let approved = fixture.approved.take().expect("approved migration");
    let observed_exact_boundary = RefCell::new(false);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_transaction_hook(approved, |checkpoint| {
            let TransactionV1Checkpoint::ParentsRevalidatedBeforePublish(index) = checkpoint else {
                return;
            };
            if index != persisted_step_index(&fixture) {
                return;
            }
            let claim = private_claim_path(&fixture, index, "publish");
            *observed_exact_boundary.borrow_mut() = private_receipt_path(&fixture).is_file()
                && claim.is_dir()
                && !fixture.target.exists();
            panic!("lose process after private receipt but before directory publication");
        })
    }));
    assert!(
        interrupted.is_err(),
        "fixture must interrupt after the private receipt but before publication"
    );
    assert!(
        *observed_exact_boundary.borrow(),
        "the prepublication checkpoint must expose the real receipt-before-publication state"
    );
    match fs::remove_file(migration_result_path(
        fixture.root.path(),
        &fixture.migration_id,
    )) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove transitional result.json: {error}"),
    }
    fixture
}

#[test]
fn create_directory_private_receipt_before_publication_crash_is_recoverable() {
    let fixture = interrupt_create_directory_after_private_receipt_before_publication();

    let outcome = public_recover(&fixture).expect("recover receipt-before-publication state");
    assert!(matches!(outcome, MigrationOutcome::Applied(_)));
    assert!(fixture.target.is_dir());
}

#[test]
fn rollback_direction_precedes_new_forward_work_for_unreceipted_apply_cells() {
    let mut violations = Vec::new();
    let kinds = [
        ClosedLeafKind::CreateDirectory,
        ClosedLeafKind::CreateFile,
        ClosedLeafKind::ReplaceFile,
        ClosedLeafKind::MoveFile,
    ];
    let cells = [
        ("intent", LostAcknowledgement::Intent),
        ("claim", LostAcknowledgement::Claim),
        ("visible", LostAcknowledgement::Publish),
    ];

    for kind in kinds {
        for (cell, lost_acknowledgement) in cells {
            if matches!(kind, ClosedLeafKind::CreateDirectory)
                && matches!(lost_acknowledgement, LostAcknowledgement::Publish)
            {
                // A created directory has a durable private receipt before
                // publication, so this is not an unreceipted matrix cell.
                continue;
            }
            let fixture = interrupt_closed_leaf(approved_closed_leaf(kind), lost_acknowledgement);
            let operation_index = persisted_step_index(&fixture);
            let checkpoints = RefCell::new(Vec::new());
            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                run_transaction_v1_with_hook(
                    fixture.root.path(),
                    MigrationCommand::Rollback {
                        migration_id: &fixture.migration_id,
                    },
                    |checkpoint| {
                        checkpoints.borrow_mut().push(checkpoint);
                        if checkpoint == TransactionV1Checkpoint::RollbackRequested {
                            panic!("lose acknowledgement of durable rollback direction");
                        }
                    },
                )
                .expect("rollback must reach its durable direction checkpoint");
            }));
            let checkpoints = checkpoints.into_inner();
            let Some(direction_index) = checkpoints
                .iter()
                .position(|checkpoint| *checkpoint == TransactionV1Checkpoint::RollbackRequested)
            else {
                violations.push(format!(
                    "{kind:?}/{cell}: no RollbackRequested checkpoint; trace={checkpoints:?}; \
                     interrupted={}",
                    interrupted.is_err()
                ));
                continue;
            };
            let forbidden = checkpoints[..direction_index]
                .iter()
                .copied()
                .filter(|checkpoint| {
                    matches!(
                        checkpoint,
                        TransactionV1Checkpoint::ClaimComplete(index)
                            | TransactionV1Checkpoint::VisiblePublishComplete(index)
                            if *index == operation_index
                    )
                })
                .collect::<Vec<_>>();
            let (_, durable) =
                latest_journal_generation(fixture.root.path(), &fixture.migration_id);
            if !forbidden.is_empty()
                || durable["direction"] != "rollback"
                || durable["phase"] != "rollback_requested"
            {
                violations.push(format!(
                    "{kind:?}/{cell}: forward={forbidden:?}; durable_direction={}; \
                     durable_phase={}; trace={checkpoints:?}",
                    durable["direction"], durable["phase"]
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Rollback must be durable before unreceipted forward work:\n{}",
        violations.join("\n")
    );
}

#[test]
fn rollback_after_regular_private_apply_receipt_only_journalizes_existing_evidence() {
    let mut violations = Vec::new();
    for kind in [
        ClosedLeafKind::CreateFile,
        ClosedLeafKind::ReplaceFile,
        ClosedLeafKind::MoveFile,
    ] {
        let fixture = interrupt_closed_leaf(
            approved_closed_leaf(kind),
            LostAcknowledgement::PrivateReceipt,
        );
        let operation_index = persisted_step_index(&fixture);
        let receipt = private_receipt_path(&fixture);
        let receipt_identity =
            PhysicalIdentity::from_path(&receipt).expect("private apply receipt identity");
        let receipt_bytes = fs::read(&receipt).expect("private apply receipt bytes");
        let checkpoints = RefCell::new(Vec::new());
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            run_transaction_v1_with_hook(
                fixture.root.path(),
                MigrationCommand::Rollback {
                    migration_id: &fixture.migration_id,
                },
                |checkpoint| {
                    checkpoints.borrow_mut().push(checkpoint);
                    if checkpoint == TransactionV1Checkpoint::RollbackRequested {
                        panic!("lose acknowledgement of durable rollback direction");
                    }
                },
            )
            .expect("rollback must reach its durable direction checkpoint");
        }));
        let checkpoints = checkpoints.into_inner();
        let mut expected = vec![TransactionV1Checkpoint::JournalApplyReceiptPersisted(
            operation_index,
        )];
        if !matches!(kind, ClosedLeafKind::MoveFile) {
            expected.push(TransactionV1Checkpoint::PrivatePublicationOwnershipRetired(
                operation_index,
            ));
        }
        expected.push(TransactionV1Checkpoint::RollbackRequested);
        let (_, durable) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
        if checkpoints != expected
            || interrupted.is_ok()
            || durable["direction"] != "rollback"
            || durable["phase"] != "rollback_requested"
            || PhysicalIdentity::from_path(&receipt).ok() != Some(receipt_identity)
            || fs::read(&receipt).ok().as_deref() != Some(receipt_bytes.as_slice())
        {
            violations.push(format!(
                "{kind:?}: expected={expected:?}; actual={checkpoints:?}; durable_direction={}; \
                 durable_phase={}",
                durable["direction"], durable["phase"]
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "a durable private apply receipt may only be verified and journalized before rollback:\n{}",
        violations.join("\n")
    );
}

#[test]
fn rollback_after_create_directory_prepublication_receipt_requests_direction_before_normalization()
{
    let fixture = interrupt_create_directory_after_private_receipt_before_publication();
    let operation_index = persisted_step_index(&fixture);
    let receipt = private_receipt_path(&fixture);
    let receipt_identity =
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt identity");
    let receipt_bytes = fs::read(&receipt).expect("private apply receipt bytes");
    let publish_claim = private_claim_path(&fixture, operation_index, "publish");
    let publish_claim_identity =
        PhysicalIdentity::from_path(&publish_claim).expect("private publish claim identity");
    let publish_claim_entries = fs::read_dir(&publish_claim)
        .expect("private publish claim")
        .map(|entry| entry.expect("private publish claim entry").file_name())
        .collect::<Vec<_>>();
    let (_, before) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    let before_cursor = before["operation_cursor"].clone();
    let before_in_flight = before["in_flight_operation"].clone();

    let checkpoints = RefCell::new(Vec::new());
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Rollback {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                checkpoints.borrow_mut().push(checkpoint);
                if checkpoint == TransactionV1Checkpoint::RollbackRequested {
                    panic!("lose acknowledgement of durable rollback direction");
                }
            },
        )
        .expect("rollback must reach its durable direction checkpoint");
    }));
    let checkpoints = checkpoints.into_inner();
    let (_, durable) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    let publish_claim_after = PhysicalIdentity::from_path(&publish_claim).ok();
    let publish_claim_entries_after = fs::read_dir(&publish_claim).ok().map(|entries| {
        entries
            .map(|entry| entry.expect("private publish claim entry").file_name())
            .collect::<Vec<_>>()
    });

    assert!(
        interrupted.is_err(),
        "the rollback-direction checkpoint must interrupt"
    );
    assert_eq!(
        checkpoints.first(),
        Some(&TransactionV1Checkpoint::RollbackRequested),
        "RollbackRequested must be the first durable transition after a prepublication receipt: \
         {checkpoints:?}"
    );
    assert!(
        !checkpoints.iter().any(|checkpoint| matches!(
            checkpoint,
            TransactionV1Checkpoint::VisiblePublishComplete(index)
                | TransactionV1Checkpoint::JournalApplyReceiptPersisted(index)
                if *index == operation_index
        )),
        "rollback must not publish or journalize an incomplete directory apply receipt: \
         {checkpoints:?}"
    );
    assert_eq!(durable["direction"], "rollback");
    assert_eq!(durable["phase"], "rollback_requested");
    assert_eq!(
        durable["operation_cursor"], before_cursor,
        "rollback direction must preserve the cursor for explicit abort normalization"
    );
    assert_eq!(
        durable["in_flight_operation"], before_in_flight,
        "rollback direction must preserve the exact in-flight operation"
    );
    assert_eq!(
        durable["in_flight_operation"].as_u64(),
        Some(operation_index as u64)
    );
    assert!(
        !fixture.target.exists(),
        "rollback direction must not publish the directory"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt remains"),
        receipt_identity
    );
    assert_eq!(
        fs::read(&receipt).expect("private apply receipt bytes remain"),
        receipt_bytes
    );
    assert_eq!(
        publish_claim_after,
        Some(publish_claim_identity),
        "the exact private directory claim must remain available for abort normalization"
    );
    assert_eq!(
        publish_claim_entries_after.as_deref(),
        Some(publish_claim_entries.as_slice()),
        "the private directory claim contents must remain exact"
    );
}

#[test]
fn rollback_after_create_directory_prepublication_receipt_preserves_foreign_target() {
    let fixture = interrupt_create_directory_after_private_receipt_before_publication();
    let operation_index = persisted_step_index(&fixture);
    let receipt = private_receipt_path(&fixture);
    let receipt_identity =
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt identity");
    let receipt_bytes = fs::read(&receipt).expect("private apply receipt bytes");
    let publish_claim = private_claim_path(&fixture, operation_index, "publish");
    let publish_claim_identity =
        PhysicalIdentity::from_path(&publish_claim).expect("private publish claim identity");
    let publish_claim_entries = fs::read_dir(&publish_claim)
        .expect("private publish claim")
        .map(|entry| entry.expect("private publish claim entry").file_name())
        .collect::<Vec<_>>();
    let foreign_bytes = b"foreign visible target must survive rollback direction\n";
    fs::write(&fixture.target, foreign_bytes).expect("foreign visible target");
    let foreign_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("foreign target identity");
    let (_, before) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    let before_cursor = before["operation_cursor"].clone();
    let before_in_flight = before["in_flight_operation"].clone();

    let checkpoints = RefCell::new(Vec::new());
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Rollback {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                checkpoints.borrow_mut().push(checkpoint);
                if checkpoint == TransactionV1Checkpoint::RollbackRequested {
                    panic!("lose acknowledgement of durable rollback direction");
                }
            },
        )
        .expect("rollback must reach its durable direction checkpoint");
    }));
    let checkpoints = checkpoints.into_inner();
    let (_, durable) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);

    assert_eq!(
        checkpoints.first(),
        Some(&TransactionV1Checkpoint::RollbackRequested),
        "RollbackRequested must be durable before inspecting a foreign target: {checkpoints:?}"
    );
    assert!(
        interrupted.is_err(),
        "the rollback-direction checkpoint must interrupt"
    );
    assert!(
        !checkpoints.iter().any(|checkpoint| matches!(
            checkpoint,
            TransactionV1Checkpoint::VisiblePublishComplete(index)
                | TransactionV1Checkpoint::JournalApplyReceiptPersisted(index)
                if *index == operation_index
        )),
        "rollback must neither publish nor journalize an incomplete directory receipt: \
         {checkpoints:?}"
    );
    assert_eq!(durable["direction"], "rollback");
    assert_eq!(durable["phase"], "rollback_requested");
    assert_eq!(durable["operation_cursor"], before_cursor);
    assert_eq!(durable["in_flight_operation"], before_in_flight);
    assert_eq!(
        durable["in_flight_operation"].as_u64(),
        Some(operation_index as u64)
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("foreign target remains"),
        foreign_identity
    );
    assert_eq!(
        fs::read(&fixture.target).expect("foreign target bytes remain"),
        foreign_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt remains"),
        receipt_identity
    );
    assert_eq!(
        fs::read(&receipt).expect("private apply receipt bytes remain"),
        receipt_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&publish_claim).expect("private publish claim remains"),
        publish_claim_identity
    );
    assert_eq!(
        fs::read_dir(&publish_claim)
            .expect("private publish claim remains")
            .map(|entry| entry.expect("private publish claim entry").file_name())
            .collect::<Vec<_>>(),
        publish_claim_entries
    );
}

#[test]
fn rollback_promotes_restored_move_private_receipt_after_temporary_conflict() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::PrivateReceipt,
    );
    let operation_index = persisted_step_index(&fixture);
    let receipt = private_receipt_path(&fixture);
    let receipt_identity =
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt identity");
    let receipt_bytes = fs::read(&receipt).expect("private apply receipt bytes");
    let receipt_record: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).expect("private apply receipt JSON");
    let expected_published_identity = receipt_record["after_identity_sha256"]
        .as_str()
        .expect("receipt published identity")
        .to_owned();
    let source_claim = source_claim_path(&fixture);
    let source_claim_identity =
        PhysicalIdentity::from_path(&source_claim).expect("exact source claim identity");
    let source_claim_bytes = fs::read(&source_claim).expect("exact source claim bytes");
    let published_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("exact published identity");
    let published_bytes = fs::read(&fixture.target).expect("exact published bytes");
    let retained_published = fixture.root.path().join("retained-exact-published-leaf");
    fs::rename(&fixture.target, &retained_published).expect("retain exact published leaf");
    fs::write(&fixture.target, &published_bytes).expect("temporary same-byte foreign target");
    let temporary_foreign_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("temporary foreign identity");
    assert_ne!(temporary_foreign_identity, published_identity);

    let _ = expect_conflicted(
        public_recover(&fixture),
        "temporary exact-visible identity mismatch",
    );
    let (_, conflicted) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(conflicted["direction"], "apply");
    assert_eq!(conflicted["phase"], "conflicted");
    assert_eq!(
        conflicted["in_flight_operation"].as_u64(),
        Some(operation_index as u64)
    );

    fs::remove_file(&fixture.target).expect("remove temporary foreign target");
    fs::rename(&retained_published, &fixture.target).expect("restore exact published leaf");
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("restored published identity"),
        published_identity
    );
    assert_eq!(
        fs::read(&fixture.target).expect("restored published bytes"),
        published_bytes
    );

    let checkpoints = RefCell::new(Vec::new());
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Rollback {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                checkpoints.borrow_mut().push(checkpoint);
                if checkpoint == TransactionV1Checkpoint::RollbackRequested {
                    panic!("lose acknowledgement of durable rollback direction");
                }
            },
        )
        .expect("restored exact receipt must promote before rollback direction");
    }));
    let checkpoints = checkpoints.into_inner();
    assert!(
        interrupted.is_err(),
        "rollback-direction checkpoint must interrupt"
    );
    assert_eq!(
        checkpoints,
        vec![
            TransactionV1Checkpoint::JournalApplyReceiptPersisted(operation_index),
            TransactionV1Checkpoint::RollbackRequested,
        ],
        "restored exact apply evidence must be journalized, never aborted"
    );
    let (_, durable) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(durable["direction"], "rollback");
    assert_eq!(durable["phase"], "rollback_requested");
    assert_eq!(
        durable["receipts"]
            .as_array()
            .expect("durable apply receipts")
            .iter()
            .find(|record| record["operation_index"].as_u64() == Some(operation_index as u64))
            .and_then(|record| record["published_identity_sha256"].as_str()),
        Some(expected_published_identity.as_str())
    );
    assert_eq!(
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt remains"),
        receipt_identity
    );
    assert_eq!(
        fs::read(&receipt).expect("private apply receipt bytes remain"),
        receipt_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&source_claim).expect("exact source claim remains"),
        source_claim_identity
    );
    assert_eq!(
        fs::read(&source_claim).expect("exact source claim bytes remain"),
        source_claim_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("exact published identity remains"),
        published_identity
    );
    assert_eq!(
        fs::read(&fixture.target).expect("exact published bytes remain"),
        published_bytes
    );
}

#[test]
fn rollback_promotes_postpublication_create_directory_private_receipt() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::CreateDirectory),
        LostAcknowledgement::PrivateReceipt,
    );
    let operation_index = persisted_step_index(&fixture);
    let receipt = private_receipt_path(&fixture);
    let receipt_identity =
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt identity");
    let receipt_bytes = fs::read(&receipt).expect("private apply receipt bytes");
    let directory_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("published directory identity");

    let checkpoints = RefCell::new(Vec::new());
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Rollback {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                checkpoints.borrow_mut().push(checkpoint);
                if checkpoint == TransactionV1Checkpoint::RollbackRequested {
                    panic!("lose acknowledgement of durable rollback direction");
                }
            },
        )
        .expect("postpublication directory receipt must promote before rollback direction");
    }));

    assert!(
        interrupted.is_err(),
        "rollback-direction checkpoint must interrupt"
    );
    assert_eq!(
        checkpoints.into_inner(),
        vec![
            TransactionV1Checkpoint::JournalApplyReceiptPersisted(operation_index),
            TransactionV1Checkpoint::RollbackRequested,
        ]
    );
    let (_, durable) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(durable["direction"], "rollback");
    assert_eq!(durable["phase"], "rollback_requested");
    assert_eq!(
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt remains"),
        receipt_identity
    );
    assert_eq!(
        fs::read(&receipt).expect("private apply receipt bytes remain"),
        receipt_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("published directory remains"),
        directory_identity
    );
}

#[test]
fn rollback_rejects_same_byte_foreign_identity_during_move_receipt_promotion() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::PrivateReceipt,
    );
    let operation_index = persisted_step_index(&fixture);
    let receipt = private_receipt_path(&fixture);
    let receipt_identity =
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt identity");
    let receipt_bytes = fs::read(&receipt).expect("private apply receipt bytes");
    let source_claim = source_claim_path(&fixture);
    let source_claim_identity =
        PhysicalIdentity::from_path(&source_claim).expect("exact source claim identity");
    let source_claim_bytes = fs::read(&source_claim).expect("exact source claim bytes");
    let published_bytes = fs::read(&fixture.target).expect("published target bytes");
    let exact_published_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("exact published identity");
    let retained_exact = fixture.root.path().join("retained-exact-promotion-leaf");
    fs::rename(&fixture.target, &retained_exact).expect("retain exact published identity");
    fs::write(&fixture.target, &published_bytes).expect("same-byte foreign target");
    let foreign_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("same-byte foreign identity");
    assert_ne!(foreign_identity, exact_published_identity);

    let checkpoints = RefCell::new(Vec::new());
    let result = run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
        |checkpoint| checkpoints.borrow_mut().push(checkpoint),
    );
    let (_, conflicts) = expect_conflicted(
        result,
        "same-byte foreign identity during private receipt promotion",
    );
    assert!(
        checkpoints
            .into_inner()
            .iter()
            .all(|checkpoint| match checkpoint {
                TransactionV1Checkpoint::JournalApplyReceiptPersisted(index) => {
                    *index != operation_index
                }
                TransactionV1Checkpoint::RollbackRequested => false,
                _ => true,
            }),
        "foreign visible identity must never be promoted into the journal"
    );
    let (_, durable) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(durable["direction"], "apply");
    assert_eq!(durable["phase"], "conflicted");
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("foreign target remains"),
        foreign_identity
    );
    assert_eq!(
        fs::read(&fixture.target).expect("foreign target bytes remain"),
        published_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&retained_exact).expect("exact target evidence remains"),
        exact_published_identity
    );
    assert_eq!(
        PhysicalIdentity::from_path(&receipt).expect("private apply receipt remains"),
        receipt_identity
    );
    assert_eq!(
        fs::read(&receipt).expect("private apply receipt bytes remain"),
        receipt_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&source_claim).expect("exact source claim remains"),
        source_claim_identity
    );
    assert_eq!(
        fs::read(&source_claim).expect("exact source claim bytes remain"),
        source_claim_bytes
    );
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .affected_paths
                .iter()
                .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))
        }),
        "durable conflict evidence must name the same-byte foreign target"
    );
}

fn apply_closed_leaf(kind: ClosedLeafKind) -> ClosedLeafFixture {
    let mut fixture = approved_closed_leaf(kind);
    apply_migration(fixture.approved.take().expect("approved migration"))
        .expect("apply closed leaf");
    match fs::remove_file(migration_result_path(
        fixture.root.path(),
        &fixture.migration_id,
    )) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove transitional result.json: {error}"),
    }
    fixture
}

fn expect_conflicted(
    result: Result<MigrationOutcome>,
    reason: &str,
) -> (String, Vec<MigrationConflict>) {
    match result {
        Ok(MigrationOutcome::Conflicted {
            migration_id,
            conflicts,
        }) if !conflicts.is_empty() => {
            assert!(
                conflicts.iter().all(|conflict| {
                    !conflict.affected_paths.is_empty()
                        && conflict.affected_paths.iter().all(|path| {
                            !path.as_os_str().is_empty()
                                && path
                                    .components()
                                    .all(|component| matches!(component, Component::Normal(_)))
                        })
                }),
                "{reason} must expose only nonempty program-relative affected paths: {conflicts:?}"
            );
            (migration_id, conflicts)
        }
        Ok(other) => panic!("{reason} must return a nonempty Conflicted outcome, got {other:?}"),
        Err(error) => {
            panic!(
                "{reason} must return durable conflict evidence through the public seam: {error}"
            )
        }
    }
}

fn assert_unchanged_conflict_retry_is_idempotent(
    fixture: &ClosedLeafFixture,
    expected_conflicts: &[MigrationConflict],
) {
    let (journal_path, journal) =
        latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    let journal_bytes = fs::read(&journal_path).expect("durable conflict generation");

    let (_, retry_conflicts) = expect_conflicted(
        public_recover(fixture),
        "an unchanged conflict retry through the public seam",
    );
    let (retry_path, retry_journal) =
        latest_journal_generation(fixture.root.path(), &fixture.migration_id);

    assert_eq!(
        retry_conflicts, expected_conflicts,
        "an unchanged conflict retry must return the same durable conflict evidence"
    );
    assert_eq!(
        retry_path, journal_path,
        "an unchanged conflict retry must not append a journal generation"
    );
    assert_eq!(
        fs::read(&retry_path).expect("retried conflict generation"),
        journal_bytes,
        "an unchanged conflict retry must not rewrite its terminal generation"
    );
    assert_eq!(
        retry_journal["generation"], journal["generation"],
        "an unchanged conflict retry must retain the same generation number"
    );
}

fn public_recover(fixture: &ClosedLeafFixture) -> Result<MigrationOutcome> {
    run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
        |_| {},
    )
}

fn public_rollback(fixture: &ClosedLeafFixture) -> Result<MigrationOutcome> {
    run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
        |_| {},
    )
}

fn expected_regular_bytes(fixture: &ClosedLeafFixture) -> &[u8] {
    match &fixture.expected {
        ExpectedVisibleLeaf::Regular(bytes) => bytes,
        ExpectedVisibleLeaf::Directory => panic!("fixture is not a regular leaf"),
    }
}

fn recorded_path_matches(root: &Path, recorded: &Path, absolute: &Path) -> bool {
    !recorded.is_absolute() && root.join(recorded) == absolute
}

fn assert_same_byte_substitution_before_claim_conflicts(kind: ClosedLeafKind) {
    let fixture = interrupt_closed_leaf(approved_closed_leaf(kind), LostAcknowledgement::Intent);
    let contested = match kind {
        ClosedLeafKind::CreateFile => &fixture.target,
        ClosedLeafKind::ReplaceFile | ClosedLeafKind::MoveFile => {
            fixture.source.as_ref().expect("destructive source")
        }
        ClosedLeafKind::CreateDirectory => panic!("same-byte substitution requires a regular leaf"),
    };
    let expected = if contested.exists() {
        fs::read(contested).expect("approved visible bytes")
    } else {
        expected_regular_bytes(&fixture).to_vec()
    };
    let foreign_identity = if contested.exists() {
        substitute_regular(contested, &expected)
    } else {
        fs::write(contested, &expected).expect("foreign absent-leaf competitor");
        PhysicalIdentity::from_path(contested).expect("foreign identity")
    };

    let (_, conflicts) = expect_conflicted(
        public_recover(&fixture),
        "same-byte foreign identity before claim",
    );
    assert_eq!(
        fs::read(contested).expect("foreign leaf remains"),
        expected,
        "foreign bytes must remain visible"
    );
    assert_eq!(
        PhysicalIdentity::from_path(contested).expect("foreign identity remains"),
        foreign_identity
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(fixture.root.path(), path, contested))),
        "durable conflict evidence must name the contested visible leaf"
    );
}

#[test]
fn create_file_same_byte_foreign_identity_before_claim_conflicts() {
    assert_same_byte_substitution_before_claim_conflicts(ClosedLeafKind::CreateFile);
}

#[test]
fn replace_file_same_byte_foreign_identity_before_claim_conflicts() {
    assert_same_byte_substitution_before_claim_conflicts(ClosedLeafKind::ReplaceFile);
}

#[test]
fn move_file_same_byte_foreign_identity_before_claim_conflicts() {
    assert_same_byte_substitution_before_claim_conflicts(ClosedLeafKind::MoveFile);
}

#[cfg(unix)]
#[test]
fn move_source_hardlink_alias_after_apply_intent_conflicts_before_claim() {
    let mut fixture = approved_closed_leaf(ClosedLeafKind::MoveFile);
    let approved = fixture.approved.take().expect("approved move");
    let source = fixture.source.as_ref().expect("move source");
    let alias = fixture.root.path().join("source-hardlink-alias.md");
    let changed = RefCell::new(false);

    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        if checkpoint
            == TransactionV1Checkpoint::ApplyIntentPersisted(persisted_step_index(&fixture))
            && !*changed.borrow()
        {
            fs::hard_link(source, &alias).expect("install visible hard-link alias");
            *changed.borrow_mut() = true;
        }
    });

    assert!(result.is_err(), "new named alias must invalidate the claim");
    assert!(
        source.is_file(),
        "claim rejection must preserve the source name"
    );
    assert!(
        alias.is_file(),
        "claim rejection must preserve the foreign alias"
    );
    assert!(!fixture.target.exists(), "no destination may be published");
    assert!(
        !source_claim_path(&fixture).exists(),
        "pre-claim topology rejection must not create private evidence"
    );
}

#[cfg(unix)]
#[test]
fn move_source_fidelity_drift_after_apply_intent_conflicts_before_claim() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut fixture = approved_closed_leaf(ClosedLeafKind::MoveFile);
    let approved = fixture.approved.take().expect("approved move");
    let source = fixture.source.as_ref().expect("move source");
    let approved_mode = fs::metadata(source).expect("source metadata").mode() & 0o7777;
    let changed_mode = approved_mode & !0o222;
    let changed = RefCell::new(false);

    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        if checkpoint
            == TransactionV1Checkpoint::ApplyIntentPersisted(persisted_step_index(&fixture))
            && !*changed.borrow()
        {
            fs::set_permissions(source, fs::Permissions::from_mode(changed_mode))
                .expect("change source fidelity");
            *changed.borrow_mut() = true;
        }
    });

    assert!(result.is_err(), "fidelity drift must invalidate the claim");
    assert!(
        source.is_file(),
        "claim rejection must preserve the source name"
    );
    assert_eq!(
        fs::metadata(source)
            .expect("changed source metadata")
            .mode()
            & 0o7777,
        changed_mode,
        "claim rejection must not repair user-owned fidelity"
    );
    assert!(!fixture.target.exists(), "no destination may be published");
    assert!(
        !source_claim_path(&fixture).exists(),
        "pre-claim fidelity rejection must not create private evidence"
    );
}

fn assert_same_byte_substitution_after_publish_conflicts(kind: ClosedLeafKind) {
    let fixture = interrupt_closed_leaf(approved_closed_leaf(kind), LostAcknowledgement::Publish);
    let expected = fs::read(&fixture.target).expect("published visible leaf");
    let foreign_identity = substitute_regular(&fixture.target, &expected);

    let (_, conflicts) = expect_conflicted(
        public_recover(&fixture),
        "same-byte foreign identity after publish",
    );
    assert_eq!(
        fs::read(&fixture.target).expect("foreign published name remains"),
        expected
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("foreign identity remains"),
        foreign_identity
    );
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .affected_paths
                .iter()
                .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))
        }),
        "durable conflict evidence must name the foreign published leaf"
    );
    if matches!(kind, ClosedLeafKind::ReplaceFile | ClosedLeafKind::MoveFile) {
        assert!(
            source_claim_path(&fixture).is_file(),
            "the exact original must remain in its named private claim"
        );
    }
}

#[test]
fn create_file_same_byte_foreign_identity_after_publish_conflicts() {
    assert_same_byte_substitution_after_publish_conflicts(ClosedLeafKind::CreateFile);
}

#[test]
fn replace_file_same_byte_foreign_identity_after_publish_conflicts() {
    assert_same_byte_substitution_after_publish_conflicts(ClosedLeafKind::ReplaceFile);
}

#[test]
fn move_file_same_byte_foreign_identity_after_publish_conflicts() {
    assert_same_byte_substitution_after_publish_conflicts(ClosedLeafKind::MoveFile);
}

fn assert_recover_reverifies_completed_regular_leaf(kind: ClosedLeafKind) {
    let fixture = apply_closed_leaf(kind);
    let expected = fs::read(&fixture.target).expect("applied visible leaf");
    let foreign_identity = substitute_regular(&fixture.target, &expected);

    let (_, conflicts) = expect_conflicted(
        public_recover(&fixture),
        "post-journal same-byte replacement",
    );

    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("foreign identity remains"),
        foreign_identity,
        "recovery must preserve the post-journal replacement"
    );
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .affected_paths
                .iter()
                .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))
        }),
        "durable conflict evidence must name the completed visible leaf"
    );
    let (_, latest) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(
        latest["phase"], "conflicted",
        "recovery must durably record the terminal revalidation conflict"
    );
}

#[test]
fn recover_reverifies_a_completed_created_file_before_reporting_applied() {
    assert_recover_reverifies_completed_regular_leaf(ClosedLeafKind::CreateFile);
}

#[test]
fn recover_reverifies_a_completed_replaced_file_before_reporting_applied() {
    assert_recover_reverifies_completed_regular_leaf(ClosedLeafKind::ReplaceFile);
}

#[test]
fn recover_reverifies_a_completed_moved_file_before_reporting_applied() {
    assert_recover_reverifies_completed_regular_leaf(ClosedLeafKind::MoveFile);
}

#[test]
fn recover_rejects_a_replaced_created_parent_before_publishing_its_child() {
    let mut fixture = approved_closed_leaf(ClosedLeafKind::CreateFile);
    let approved = fixture.approved.take().expect("approved migration");
    let created_parent = fixture.root.path().join("Organized");
    let retained_parent = fixture.root.path().join(".approved-organized-parent");
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_transaction_hook(approved, |checkpoint| {
            let TransactionV1Checkpoint::JournalApplyReceiptPersisted(index) = checkpoint else {
                return;
            };
            let program: serde_json::Value = serde_json::from_slice(
                &fs::read(program_path_for(fixture.root.path(), &fixture.migration_id))
                    .expect("persisted mutation program"),
            )
            .expect("persisted mutation program JSON");
            let step = &program["steps"][index];
            if step["kind"] == "create_directory" && step["target"]["path"] == "Organized" {
                fs::rename(&created_parent, &retained_parent)
                    .expect("retain exact transaction-created parent");
                fs::create_dir(&created_parent).expect("install foreign parent at the same name");
                panic!("simulate loss after replacing a completed parent");
            }
        })
    }));
    assert!(
        interrupted.is_err(),
        "fixture must interrupt after parent receipt"
    );
    let foreign_parent_identity =
        PhysicalIdentity::from_path(&created_parent).expect("foreign parent identity");

    let (_, conflicts) = expect_conflicted(
        public_recover(&fixture),
        "created parent identity replacement",
    );

    assert_eq!(
        PhysicalIdentity::from_path(&created_parent).expect("foreign parent remains"),
        foreign_parent_identity,
        "recovery must preserve the foreign parent"
    );
    assert!(
        !fixture.target.exists(),
        "no child may be published through a replaced CreatedBy authority"
    );
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .affected_paths
                .iter()
                .any(|path| path.ends_with(Path::new("Organized")))
        }),
        "durable conflict evidence must name the replaced parent: {conflicts:?}"
    );
}

#[test]
fn parent_swap_after_prepublication_validation_cannot_redirect_a_child_write() {
    let mut fixture = approved_closed_leaf(ClosedLeafKind::CreateFile);
    let approved = fixture.approved.take().expect("approved migration");
    let created_parent = fixture.root.path().join("Organized");
    let retained_parent = fixture.root.path().join(".approved-organized-parent");
    let published_child = RefCell::new(None::<PathBuf>);

    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        let TransactionV1Checkpoint::ParentsRevalidatedBeforePublish(index) = checkpoint else {
            return;
        };
        if published_child.borrow().is_some() {
            return;
        }
        let program: serde_json::Value = serde_json::from_slice(
            &fs::read(program_path_for(fixture.root.path(), &fixture.migration_id))
                .expect("persisted mutation program"),
        )
        .expect("persisted mutation program JSON");
        let Some(target) = program["steps"][index]
            .get("target")
            .and_then(|target| target.get("path"))
            .and_then(serde_json::Value::as_str)
        else {
            return;
        };
        let target = Path::new(target);
        let Ok(child) = target.strip_prefix("Organized") else {
            return;
        };
        if child.as_os_str().is_empty() {
            return;
        }
        fs::rename(&created_parent, &retained_parent)
            .expect("detach the exact verified CreatedBy parent");
        fs::create_dir(&created_parent).expect("install foreign parent after validation");
        *published_child.borrow_mut() = Some(child.to_path_buf());
    });

    assert!(
        result.is_err(),
        "the post-publication ambient-parent recheck must reject the swap"
    );
    assert_eq!(
        fs::read_dir(&created_parent)
            .expect("foreign parent")
            .count(),
        0,
        "the foreign replacement parent must receive zero transaction writes"
    );
    assert!(
        retained_parent
            .join(
                published_child
                    .into_inner()
                    .expect("a child publication checkpoint")
            )
            .exists(),
        "publication must use the retained verified parent capability"
    );
    let (_, latest) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(latest["phase"], "conflicted");
}

#[test]
fn existing_parent_swap_after_prepublication_validation_cannot_redirect_a_move() {
    let mut fixture = approved_closed_leaf(ClosedLeafKind::MoveFile);
    let approved = fixture.approved.take().expect("approved move");
    let destination_parent = fixture.target.parent().expect("destination parent");
    let retained_parent = fixture.root.path().join("retained-archive-parent");
    let swapped = RefCell::new(false);

    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        if checkpoint
            == TransactionV1Checkpoint::ParentsRevalidatedBeforePublish(persisted_step_index(
                &fixture,
            ))
            && !*swapped.borrow()
        {
            fs::rename(destination_parent, &retained_parent)
                .expect("detach exact verified destination parent");
            fs::create_dir(destination_parent)
                .expect("install foreign destination parent after validation");
            *swapped.borrow_mut() = true;
        }
    });

    assert!(
        result.is_err(),
        "the postpublication parent recheck must fail"
    );
    assert_eq!(
        fs::read_dir(destination_parent)
            .expect("foreign destination parent")
            .count(),
        0,
        "the foreign existing parent must receive zero transaction writes"
    );
    assert!(
        retained_parent.join("notes.md").is_file(),
        "the move must publish only through the retained verified parent"
    );
}

fn latest_journal_generation(root: &Path, migration_id: &str) -> (PathBuf, serde_json::Value) {
    let journal = transaction_v1_root(root, migration_id).join("journal");
    let mut names = fs::read_dir(&journal)
        .expect("transaction journal")
        .map(|entry| entry.expect("journal entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    let name = names.last().expect("journal generation");
    let path = journal.join(name);
    let value = serde_json::from_slice(&fs::read(&path).expect("journal bytes"))
        .expect("journal generation JSON");
    (path, value)
}

#[allow(dead_code)]
fn journal_generation_checksum(value: &serde_json::Value) -> String {
    let inverse_receipts = value
        .get("inverse_receipts")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let abort_receipts = value
        .get("abort_receipts")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let controlled = if value.get("active_publication").is_some() {
        serde_json::json!([
            value["format"],
            value["transaction_id"],
            value["program_digest"],
            value["generation"],
            value["previous_checksum"],
            value["direction"],
            value["phase"],
            value["operation_cursor"],
            value["in_flight_operation"],
            value["active_publication"],
            value["receipts"],
            inverse_receipts,
            abort_receipts,
            value["conflicts"],
        ])
    } else if value.get("abort_receipts").is_some() {
        serde_json::json!([
            value["format"],
            value["transaction_id"],
            value["program_digest"],
            value["generation"],
            value["previous_checksum"],
            value["direction"],
            value["phase"],
            value["operation_cursor"],
            value["in_flight_operation"],
            value["receipts"],
            inverse_receipts,
            abort_receipts,
            value["conflicts"],
        ])
    } else if value.get("inverse_receipts").is_some() {
        serde_json::json!([
            value["format"],
            value["transaction_id"],
            value["program_digest"],
            value["generation"],
            value["previous_checksum"],
            value["direction"],
            value["phase"],
            value["operation_cursor"],
            value["in_flight_operation"],
            value["receipts"],
            value["inverse_receipts"],
            value["conflicts"],
        ])
    } else {
        serde_json::json!([
            value["format"],
            value["transaction_id"],
            value["program_digest"],
            value["generation"],
            value["previous_checksum"],
            value["direction"],
            value["phase"],
            value["operation_cursor"],
            value["in_flight_operation"],
            value["receipts"],
            value["conflicts"],
        ])
    };
    let mut digest = Sha256::new();
    digest.update(b"folderbase-migration-journal-generation-v1");
    digest.update([0]);
    digest.update(serde_json::to_vec(&controlled).expect("controlled journal encoding"));
    format!("{:x}", digest.finalize())
}

fn append_checksum_valid_forged_generation(
    root: &Path,
    migration_id: &str,
    next: &transaction_v1::TransactionJournalGenerationV1,
) -> PathBuf {
    let journal = transaction_v1_root(root, migration_id).join("journal");
    let path = journal.join(next.file_name());
    fs::write(
        &path,
        next.encode(&path).expect("canonical forged journal bytes"),
    )
    .expect("append checksum-valid forged generation");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private journal mode");
    }
    path
}

fn journal_generation_records(
    root: &Path,
    migration_id: &str,
) -> Vec<transaction_v1::TransactionJournalGenerationV1> {
    let journal = transaction_v1_root(root, migration_id).join("journal");
    let mut names = fs::read_dir(&journal)
        .expect("transaction journal")
        .map(|entry| entry.expect("journal entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let path = journal.join(name);
            transaction_v1::TransactionJournalGenerationV1::decode(
                &path,
                &fs::read(&path).expect("journal generation bytes"),
            )
            .expect("canonical journal generation")
        })
        .collect()
}

fn journal_active_publication_generation(
    root: &Path,
    migration_id: &str,
) -> transaction_v1::TransactionJournalGenerationV1 {
    journal_generation_records(root, migration_id)
        .into_iter()
        .find(|generation| generation.active_publication().is_some())
        .expect("one journal-bound publication generation")
}

#[allow(dead_code)]
fn append_test_journal_generation(
    fixture: &ClosedLeafFixture,
    direction: &str,
    phase: &str,
    in_flight_operation: Option<usize>,
) {
    let (previous_path, previous) =
        latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    let mut next = previous.clone();
    let next_generation = previous["generation"]
        .as_u64()
        .expect("journal generation number")
        + 1;
    next["generation"] = serde_json::Value::from(next_generation);
    next["previous_checksum"] = previous["checksum"].clone();
    next["direction"] = serde_json::Value::String(direction.to_owned());
    next["phase"] = serde_json::Value::String(phase.to_owned());
    next["in_flight_operation"] = in_flight_operation
        .map(serde_json::Value::from)
        .unwrap_or(serde_json::Value::Null);
    next["checksum"] = serde_json::Value::String(journal_generation_checksum(&next));
    let path = previous_path
        .parent()
        .expect("journal parent")
        .join(format!("{next_generation:020}.json"));
    fs::write(&path, serde_json::to_vec(&next).expect("journal bytes"))
        .expect("append test journal generation");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private journal mode");
    }
}

fn request_test_rollback(fixture: &ClosedLeafFixture) {
    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("migration filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id);
    let mut transaction =
        reopen_transaction_v1(&filesystem, &migration_root, None).expect("applied transaction-v1");
    let requested = transaction
        .generations
        .last()
        .expect("applied generation")
        .next_rollback_requested(&transaction.program)
        .expect("rollback requested generation");
    append_transaction_v1_generation(&filesystem, &mut transaction, requested)
        .expect("persist rollback requested");
}

fn begin_test_rollback(fixture: &ClosedLeafFixture) {
    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("migration filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id);
    let mut transaction = reopen_transaction_v1(&filesystem, &migration_root, None)
        .expect("rollback-requested transaction-v1");
    let cursor = transaction
        .generations
        .last()
        .expect("rollback-requested generation")
        .operation_cursor();
    assert!(cursor > 0, "rollback tracer requires an applied leaf");
    let intent = transaction
        .generations
        .last()
        .expect("rollback-requested generation")
        .next_rollback_intent(&transaction.program, cursor - 1)
        .expect("rollback intent generation");
    append_transaction_v1_generation(&filesystem, &mut transaction, intent)
        .expect("persist rollback intent");
}

#[test]
fn recover_after_rollback_requested_continues_rollback() {
    let fixture = apply_closed_leaf(ClosedLeafKind::MoveFile);
    request_test_rollback(&fixture);

    let outcome =
        public_recover(&fixture).expect("Recover must honor the durable rollback direction");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_eq!(
        fs::read(fixture.source.as_ref().expect("move source")).expect("restored source"),
        expected_regular_bytes(&fixture)
    );
    assert!(!fixture.target.exists());
}

#[test]
fn rollback_from_prepared_preserves_the_unmodified_workspace() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let original_identity = PhysicalIdentity::from_path(&fixture.source).expect("source identity");

    let outcome = run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
        |_| {},
    );
    let outcome = outcome.expect("rollback prepared transaction");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.source).expect("unchanged source identity"),
        original_identity
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn rollback_from_mid_apply_restores_a_claimed_original() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Publish,
    );
    let source = fixture.source.as_ref().expect("move source");

    let outcome = public_rollback(&fixture).expect("rollback mid-apply transaction");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_eq!(
        fs::read(source).expect("restored move source"),
        expected_regular_bytes(&fixture)
    );
    assert!(!fixture.target.exists());
}

#[test]
fn rollback_from_conflicted_in_flight_apply_does_not_retry_forward_publication() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Claim,
    );
    let source = fixture.source.as_ref().expect("move source");
    let original = expected_regular_bytes(&fixture).to_vec();
    let competitor = b"foreign destination must remain\n";
    fs::write(&fixture.target, competitor).expect("install destination competitor");
    let competitor_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("competitor identity");

    let _ = expect_conflicted(
        public_recover(&fixture),
        "blocked forward publication must become durable conflict",
    );
    assert!(
        !source.exists(),
        "the exact original is still privately claimed"
    );
    assert!(
        source_claim_path(&fixture).is_file(),
        "the exact original claim must survive the apply conflict"
    );

    let outcome = public_rollback(&fixture)
        .expect("Rollback must switch direction without retrying forward publication");
    assert!(
        matches!(outcome, MigrationOutcome::RolledBack(_)),
        "the unreceipted in-flight move must abort into rollback"
    );
    assert_eq!(fs::read(source).expect("restored move source"), original);
    assert_eq!(
        fs::read(&fixture.target).expect("competitor remains"),
        competitor
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("competitor identity remains"),
        competitor_identity
    );
    assert!(
        !source_claim_path(&fixture).exists(),
        "terminal rollback must release private authority over the restored source"
    );
    let (_, latest) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(latest["direction"], "rollback");
    assert_eq!(latest["phase"], "rolled_back");
}

#[test]
fn rollback_direction_is_durable_before_aborting_a_conflicted_in_flight_apply() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Claim,
    );
    let source = fixture.source.as_ref().expect("move source");
    let competitor = b"foreign destination survives restart\n";
    fs::write(&fixture.target, competitor).expect("install destination competitor");
    let _ = expect_conflicted(
        public_recover(&fixture),
        "blocked forward publication must become durable conflict",
    );

    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Rollback {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                if checkpoint == TransactionV1Checkpoint::RollbackRequested {
                    panic!("lose acknowledgement of durable rollback direction");
                }
            },
        )
        .expect("checkpoint interrupts before outcome");
    }));
    assert!(
        interrupted.is_err(),
        "rollback direction checkpoint must interrupt"
    );
    let (_, requested) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(requested["direction"], "rollback");
    assert_eq!(requested["phase"], "rollback_requested");
    assert!(
        requested["in_flight_operation"].is_number(),
        "the durable rollback request must retain the partial apply classification"
    );
    assert!(!source.exists());
    assert!(source_claim_path(&fixture).is_file());
    assert_eq!(
        fs::read(&fixture.target).expect("competitor remains"),
        competitor
    );

    let outcome = public_recover(&fixture).expect("Recover must continue the durable rollback");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_eq!(
        fs::read(source).expect("source restored after restart"),
        expected_regular_bytes(&fixture)
    );
    assert_eq!(
        fs::read(&fixture.target).expect("competitor remains"),
        competitor
    );
}

fn conflicted_move_abort_fixture() -> ClosedLeafFixture {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Claim,
    );
    fs::write(
        &fixture.target,
        b"foreign destination survives abort recovery\n",
    )
    .expect("install destination competitor");
    let _ = expect_conflicted(
        public_recover(&fixture),
        "blocked forward publication must become durable conflict",
    );
    fixture
}

fn private_abort_receipt_path(fixture: &ClosedLeafFixture) -> PathBuf {
    transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        .join("receipts")
        .join(format!(
            "{:08}.abort.receipt",
            persisted_step_index(fixture)
        ))
}

fn interrupt_create_abort_at(
    fixture: ClosedLeafFixture,
    expected_checkpoint: TransactionV1Checkpoint,
) -> ClosedLeafFixture {
    let observed = RefCell::new(false);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Recover {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                if checkpoint == expected_checkpoint {
                    *observed.borrow_mut() = true;
                    panic!("lose acknowledgement at {expected_checkpoint:?}");
                }
            },
        )
        .expect("create abort must reach the requested durable checkpoint");
    }));
    assert!(
        *observed.borrow(),
        "create abort never reached {expected_checkpoint:?}; interrupted={}",
        interrupted.is_err()
    );
    assert!(
        interrupted.is_err(),
        "create abort checkpoint must interrupt"
    );
    fixture
}

fn requested_unreceipted_create_fixture(
    kind: ClosedLeafKind,
    lost_acknowledgement: LostAcknowledgement,
    foreign_target: Option<&[u8]>,
) -> (ClosedLeafFixture, Option<(PhysicalIdentity, Vec<u8>)>) {
    assert!(matches!(
        kind,
        ClosedLeafKind::CreateDirectory | ClosedLeafKind::CreateFile
    ));
    assert!(
        !matches!(
            (kind, lost_acknowledgement),
            (
                ClosedLeafKind::CreateDirectory,
                LostAcknowledgement::Publish
            )
        ),
        "CreateDirectory publication is already backed by a private apply receipt"
    );
    let fixture = interrupt_closed_leaf(approved_closed_leaf(kind), lost_acknowledgement);
    let foreign = foreign_target.map(|bytes| {
        fs::write(&fixture.target, bytes).expect("foreign create target");
        (
            PhysicalIdentity::from_path(&fixture.target).expect("foreign target identity"),
            bytes.to_vec(),
        )
    });
    request_test_rollback(&fixture);
    let (_, requested) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(requested["direction"], "rollback");
    assert_eq!(requested["phase"], "rollback_requested");
    assert_eq!(
        requested["in_flight_operation"].as_u64(),
        Some(persisted_step_index(&fixture) as u64)
    );
    (fixture, foreign)
}

fn sha256_test_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn assert_create_abort_receipt_contract(
    fixture: &ClosedLeafFixture,
    journaled: bool,
    required_claim: Option<(&str, &str)>,
    allowed_claims: &[(&str, &str)],
) {
    let operation_index = persisted_step_index(fixture);
    let path = private_abort_receipt_path(fixture);
    let bytes = fs::read(&path).expect("canonical private abort-work receipt");
    let receipt: serde_json::Value =
        serde_json::from_slice(&bytes).expect("private abort-work receipt JSON");
    assert_eq!(
        serde_json::to_vec(&receipt).expect("canonical private abort-work receipt JSON"),
        bytes
    );
    let (_, latest) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(receipt["format"], "folderbase-private-abort-work-v1");
    assert_eq!(receipt["transaction_id"], latest["transaction_id"]);
    assert_eq!(receipt["program_digest"], latest["program_digest"]);
    assert_eq!(
        receipt["operation_index"].as_u64(),
        Some(operation_index as u64)
    );
    assert!(
        receipt["visible_post_identity_sha256"].is_null(),
        "a create abort leaves no transaction-owned visible post identity"
    );
    let claims = receipt["claims"]
        .as_array()
        .expect("private abort exact claims");
    let names = claims
        .iter()
        .map(|claim| {
            (
                claim["name"].as_str().expect("abort claim name"),
                claim["kind"].as_str().expect("abort claim kind"),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        names.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "abort claims must be sorted and unique: {names:?}"
    );
    if let Some((required_suffix, required_kind)) = required_claim {
        let required_name = private_claim_name(operation_index, required_suffix);
        assert!(
            names
                .iter()
                .any(|(name, kind)| *name == required_name && *kind == required_kind),
            "abort receipt is missing required exact claim \
             ({required_name:?}, {required_kind:?}): {names:?}"
        );
    }
    assert!(
        names.iter().all(
            |(name, kind)| allowed_claims.iter().any(|(suffix, allowed_kind)| {
                *name == private_claim_name(operation_index, suffix) && kind == allowed_kind
            })
        ),
        "abort receipt contains an impossible create claim: {names:?}"
    );

    let prefix = format!("{operation_index:08}.");
    let mut actual_claim_names = fs::read_dir(
        transaction_v1_root(fixture.root.path(), &fixture.migration_id).join("claims"),
    )
    .expect("private claims")
    .filter_map(|entry| {
        let name = entry.expect("private claim entry").file_name();
        let name = name.to_string_lossy().into_owned();
        name.starts_with(&prefix).then_some(name)
    })
    .collect::<Vec<_>>();
    actual_claim_names.sort();
    assert_eq!(
        actual_claim_names,
        names
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect::<Vec<_>>(),
        "receipt must describe the complete surviving exact claim set"
    );
    for (claim, (name, kind)) in claims.iter().zip(names.iter()) {
        let claim_path =
            private_claim_path(fixture, operation_index, name.split('.').nth(1).unwrap());
        let identity =
            PhysicalIdentity::from_path(&claim_path).expect("receipt-bound private claim identity");
        let metadata = fs::metadata(&claim_path).expect("receipt-bound private claim metadata");
        assert_eq!(
            claim["physical_identity_sha256"].as_str(),
            Some(identity.stable_sha256().as_str())
        );
        assert_eq!(
            claim["device_sha256"].as_str(),
            Some(identity.device_sha256().as_str())
        );
        match *kind {
            "regular" => {
                let claim_bytes = fs::read(&claim_path).expect("exact regular abort claim");
                assert_eq!(claim["bytes"].as_u64(), Some(claim_bytes.len() as u64));
                assert_eq!(
                    claim["sha256"].as_str(),
                    Some(sha256_test_bytes(&claim_bytes).as_str())
                );
            }
            "directory" => {
                assert_eq!(claim["empty"].as_bool(), Some(true));
                assert_eq!(
                    fs::read_dir(&claim_path)
                        .expect("exact directory abort claim")
                        .count(),
                    0,
                    "a create-directory abort claim must be empty"
                );
            }
            other => panic!("unsupported abort claim kind {other}"),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let mode = metadata.permissions().mode();
            assert_eq!(
                claim["read_only"].as_bool(),
                Some(mode & 0o222 == 0),
                "abort claim read-only fidelity"
            );
            assert_eq!(
                claim["executable"].as_bool(),
                Some(mode & 0o111 != 0),
                "abort claim executable fidelity"
            );
            if *kind == "regular" {
                assert_eq!(
                    claim["link_count"].as_u64(),
                    Some(metadata.nlink()),
                    "abort claim link topology"
                );
            }
        }
    }

    let controlled = serde_json::json!([
        receipt["format"],
        receipt["transaction_id"],
        receipt["program_digest"],
        receipt["operation_index"],
        receipt["visible_post_identity_sha256"],
        receipt["claims"],
    ]);
    let mut checksum = Sha256::new();
    checksum.update(b"folderbase-private-abort-work-v1");
    checksum.update([0]);
    checksum.update(serde_json::to_vec(&controlled).expect("abort checksum controlled bytes"));
    assert_eq!(
        receipt["checksum"].as_str(),
        Some(format!("{:x}", checksum.finalize()).as_str())
    );
    let receipt_digest = sha256_test_bytes(&bytes);
    let abort_receipts = latest
        .get("abort_receipts")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if journaled {
        assert_eq!(abort_receipts.len(), 1, "one journal abort receipt");
        assert_eq!(
            abort_receipts[0]["operation_index"].as_u64(),
            Some(operation_index as u64)
        );
        assert_eq!(
            abort_receipts[0]["private_receipt_sha256"].as_str(),
            Some(receipt_digest.as_str())
        );
    } else {
        assert!(
            abort_receipts.is_empty(),
            "private receipt must precede its one journal receipt"
        );
        assert_eq!(
            latest["in_flight_operation"].as_u64(),
            Some(operation_index as u64)
        );
    }
}

#[test]
fn create_abort_private_receipt_restart_matrix_is_canonical() {
    let cases = [
        (
            "create_directory_claim",
            ClosedLeafKind::CreateDirectory,
            LostAcknowledgement::Claim,
            None,
            &[("publish", "directory")][..],
        ),
        (
            "create_file_visible",
            ClosedLeafKind::CreateFile,
            LostAcknowledgement::Publish,
            Some(("rollback", "regular")),
            &[("publish", "regular"), ("rollback", "regular")][..],
        ),
    ];
    let mut failures = Vec::new();
    for (label, kind, lost_acknowledgement, required_claim, allowed_claims) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (fixture, _) =
                requested_unreceipted_create_fixture(kind, lost_acknowledgement, None);
            let operation_index = persisted_step_index(&fixture);
            let fixture = interrupt_create_abort_at(
                fixture,
                TransactionV1Checkpoint::PrivateAbortReceiptPersisted(operation_index),
            );
            assert_create_abort_receipt_contract(&fixture, false, required_claim, allowed_claims);
            let outcome =
                public_recover(&fixture).expect("restart journalizes exact abort receipt");
            assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
            assert_create_abort_receipt_contract(&fixture, true, required_claim, allowed_claims);
            assert!(!fixture.target.exists());
        }));
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "create abort private-receipt restart cases failed: {failures:?}"
    );
}

#[test]
fn create_abort_terminal_matrix_covers_reachable_unreceipted_shapes() {
    let foreign = b"foreign create target survives abort\n";
    let cases = [
        (
            "create_directory_intent_absent",
            ClosedLeafKind::CreateDirectory,
            LostAcknowledgement::Intent,
            None,
        ),
        (
            "create_directory_claim_foreign",
            ClosedLeafKind::CreateDirectory,
            LostAcknowledgement::Claim,
            Some(foreign.as_slice()),
        ),
        (
            "create_file_intent_absent",
            ClosedLeafKind::CreateFile,
            LostAcknowledgement::Intent,
            None,
        ),
        (
            "create_file_claim_foreign",
            ClosedLeafKind::CreateFile,
            LostAcknowledgement::Claim,
            Some(foreign.as_slice()),
        ),
    ];
    let mut failures = Vec::new();
    for (label, kind, lost_acknowledgement, foreign_target) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (fixture, foreign_target) =
                requested_unreceipted_create_fixture(kind, lost_acknowledgement, foreign_target);
            let outcome = public_recover(&fixture).expect("recover exact create abort");
            assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
            assert_create_abort_receipt_contract(&fixture, true, None, &[]);
            if let Some((identity, bytes)) = foreign_target {
                assert_eq!(
                    PhysicalIdentity::from_path(&fixture.target).expect("foreign target remains"),
                    identity
                );
                assert_eq!(
                    fs::read(&fixture.target).expect("foreign target bytes remain"),
                    bytes
                );
            } else {
                assert!(!fixture.target.exists());
            }
        }));
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "reachable unreceipted create abort cases failed: {failures:?}"
    );
}

#[test]
fn journaled_create_abort_rejects_extra_or_missing_exact_claims() {
    let cases = [
        (
            "create_directory_extra_claim",
            ClosedLeafKind::CreateDirectory,
            LostAcknowledgement::Claim,
            "extra",
            false,
        ),
        (
            "create_file_missing_rollback_claim",
            ClosedLeafKind::CreateFile,
            LostAcknowledgement::Publish,
            "rollback",
            true,
        ),
    ];
    let mut failures = Vec::new();
    for (label, kind, lost_acknowledgement, claim_kind, remove) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (fixture, _) =
                requested_unreceipted_create_fixture(kind, lost_acknowledgement, None);
            let operation_index = persisted_step_index(&fixture);
            let fixture = interrupt_create_abort_at(
                fixture,
                TransactionV1Checkpoint::JournalAbortReceiptPersisted(operation_index),
            );
            let claim = private_claim_path(&fixture, operation_index, claim_kind);
            if remove {
                fs::remove_file(&claim).expect("remove exact create abort claim");
            } else {
                fs::write(&claim, b"impossible extra create abort claim\n")
                    .expect("install extra create abort claim");
            }
            let error = public_recover(&fixture)
                .expect_err("journaled create abort must reject changed exact claim evidence");
            assert!(
                error.to_string().contains(
                    claim
                        .file_name()
                        .expect("affected claim name")
                        .to_string_lossy()
                        .as_ref()
                ),
                "claim integrity error must identify its concrete private path: {error}"
            );
            let (_, journaled) =
                latest_journal_generation(fixture.root.path(), &fixture.migration_id);
            assert_eq!(
                journaled["abort_receipts"]
                    .as_array()
                    .expect("journal abort receipts")
                    .len(),
                1,
                "claim rejection must not duplicate the journal abort receipt"
            );
        }));
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "journaled create abort claim-shape cases failed: {failures:?}"
    );
}

struct RetainedCreateParentFixture {
    leaf: ClosedLeafFixture,
    parent: PathBuf,
    parent_index: usize,
    parent_identity: PhysicalIdentity,
    #[cfg(unix)]
    parent_mode: u32,
}

fn create_file_retained_parent_fixture() -> RetainedCreateParentFixture {
    let foreign = b"foreign descendant retains its transaction-created parent\n";
    let (leaf, foreign_fact) = requested_unreceipted_create_fixture(
        ClosedLeafKind::CreateFile,
        LostAcknowledgement::Claim,
        Some(foreign),
    );
    let (foreign_identity, foreign_bytes) = foreign_fact.expect("foreign descendant fact");
    assert_eq!(
        PhysicalIdentity::from_path(&leaf.target).expect("foreign descendant identity"),
        foreign_identity
    );
    assert_eq!(
        fs::read(&leaf.target).expect("foreign descendant bytes"),
        foreign_bytes
    );
    let parent = leaf
        .target
        .parent()
        .expect("created target parent")
        .to_path_buf();
    let relative_parent = parent
        .strip_prefix(leaf.root.path())
        .expect("created parent beneath root")
        .to_string_lossy();
    let program: serde_json::Value = serde_json::from_slice(
        &fs::read(program_path_for(leaf.root.path(), &leaf.migration_id))
            .expect("persisted mutation program"),
    )
    .expect("persisted mutation program JSON");
    let parent_index = program["steps"]
        .as_array()
        .expect("closed mutation steps")
        .iter()
        .position(|step| {
            step["kind"].as_str() == Some("create_directory")
                && step["target"]["path"].as_str() == Some(relative_parent.as_ref())
        })
        .expect("transaction-created direct parent step");
    let parent_identity =
        PhysicalIdentity::from_path(&parent).expect("published parent physical identity");
    let (_, requested) = latest_journal_generation(leaf.root.path(), &leaf.migration_id);
    assert_eq!(
        requested["receipts"]
            .as_array()
            .expect("apply receipts")
            .iter()
            .find(|receipt| receipt["operation_index"].as_u64() == Some(parent_index as u64))
            .and_then(|receipt| receipt["published_identity_sha256"].as_str()),
        Some(parent_identity.stable_sha256().as_str()),
        "the apply journal must bind the original published parent identity"
    );
    #[cfg(unix)]
    let parent_mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(&parent)
            .expect("published parent metadata")
            .permissions()
            .mode()
    };
    RetainedCreateParentFixture {
        leaf,
        parent,
        parent_index,
        parent_identity,
        #[cfg(unix)]
        parent_mode,
    }
}

fn private_rollback_receipt_path(fixture: &ClosedLeafFixture, operation_index: usize) -> PathBuf {
    transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        .join("receipts")
        .join(format!("{operation_index:08}.rollback.receipt"))
}

fn interrupt_retained_parent_rollback_at(
    fixture: &RetainedCreateParentFixture,
    expected_checkpoint: TransactionV1Checkpoint,
) {
    let observed = RefCell::new(false);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.leaf.root.path(),
            MigrationCommand::Recover {
                migration_id: &fixture.leaf.migration_id,
            },
            |checkpoint| {
                if checkpoint == expected_checkpoint {
                    *observed.borrow_mut() = true;
                    panic!("lose retained-parent acknowledgement at {expected_checkpoint:?}");
                }
            },
        )
        .expect("retained-parent rollback must reach its exact durable checkpoint");
    }));
    assert!(
        *observed.borrow(),
        "retained-parent rollback never reached {expected_checkpoint:?}; interrupted={}",
        interrupted.is_err()
    );
    assert!(
        interrupted.is_err(),
        "retained-parent checkpoint must interrupt"
    );
}

fn assert_retained_parent_exact(fixture: &RetainedCreateParentFixture) {
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.parent).expect("retained parent identity"),
        fixture.parent_identity
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&fixture.parent)
                .expect("retained parent metadata")
                .permissions()
                .mode(),
            fixture.parent_mode,
            "retained parent fidelity"
        );
    }
    assert!(
        !private_claim_path(&fixture.leaf, fixture.parent_index, "rollback").exists(),
        "retained disposition needs no private rollback claim"
    );
}

#[test]
fn retained_create_parent_receipts_bind_identity_and_survive_descendant_removal() {
    let fixture = create_file_retained_parent_fixture();
    interrupt_retained_parent_rollback_at(
        &fixture,
        TransactionV1Checkpoint::PrivateRollbackReceiptPersisted(fixture.parent_index),
    );
    let private_receipt_path = private_rollback_receipt_path(&fixture.leaf, fixture.parent_index);
    let private_receipt_bytes =
        fs::read(&private_receipt_path).expect("retained-parent private rollback receipt");
    let private_receipt: serde_json::Value =
        serde_json::from_slice(&private_receipt_bytes).expect("private rollback receipt JSON");
    let expected_identity = fixture.parent_identity.stable_sha256();
    assert_eq!(private_receipt["direction"], "rollback");
    assert_eq!(
        private_receipt["operation_index"].as_u64(),
        Some(fixture.parent_index as u64)
    );
    assert_eq!(
        private_receipt["before_identity_sha256"].as_str(),
        Some(expected_identity.as_str()),
        "retained parent rollback must start from the exact published identity"
    );
    assert_eq!(
        private_receipt["after_identity_sha256"].as_str(),
        Some(expected_identity.as_str()),
        "retained disposition must bind the exact surviving parent identity, not null"
    );
    assert_retained_parent_exact(&fixture);

    interrupt_retained_parent_rollback_at(
        &fixture,
        TransactionV1Checkpoint::JournalRollbackReceiptPersisted(fixture.parent_index),
    );
    let (_, journaled) =
        latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
    let matching_inverse = journaled["inverse_receipts"]
        .as_array()
        .expect("durable inverse receipts")
        .iter()
        .filter(|receipt| receipt["operation_index"].as_u64() == Some(fixture.parent_index as u64))
        .collect::<Vec<_>>();
    assert_eq!(
        matching_inverse.len(),
        1,
        "one retained-parent inverse receipt"
    );
    assert_eq!(
        matching_inverse[0]["published_identity_sha256"].as_str(),
        Some(expected_identity.as_str()),
        "durable inverse receipt must bind the exact retained parent identity"
    );
    assert_retained_parent_exact(&fixture);

    fs::remove_file(&fixture.leaf.target).expect("remove foreign descendant after disposition");
    assert!(
        fs::read_dir(&fixture.parent)
            .expect("now-empty retained parent")
            .next()
            .is_none(),
        "descendant removal makes the retained parent empty"
    );
    let outcome =
        public_recover(&fixture.leaf).expect("receipt-backed retained disposition restarts");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_retained_parent_exact(&fixture);
    let reopened =
        public_recover(&fixture.leaf).expect("terminal retained disposition reopens idempotently");
    assert!(matches!(reopened, MigrationOutcome::RolledBack(_)));
    assert_retained_parent_exact(&fixture);
}

#[test]
fn substituted_retained_parent_fails_closed_without_journal_advance() {
    let fixture = create_file_retained_parent_fixture();
    interrupt_retained_parent_rollback_at(
        &fixture,
        TransactionV1Checkpoint::JournalRollbackReceiptPersisted(fixture.parent_index),
    );
    let retained_original = fixture
        .leaf
        .root
        .path()
        .join("retained-original-created-parent");
    fs::rename(&fixture.parent, &retained_original).expect("retain exact created parent");
    fs::create_dir(&fixture.parent).expect("substitute retained parent identity");
    fs::write(
        fixture.parent.join(
            fixture
                .leaf
                .target
                .file_name()
                .expect("foreign descendant name"),
        ),
        b"same logical foreign descendant under substituted parent\n",
    )
    .expect("substituted parent descendant");
    let foreign_parent_identity =
        PhysicalIdentity::from_path(&fixture.parent).expect("foreign parent identity");
    assert_ne!(foreign_parent_identity, fixture.parent_identity);
    let (before_path, before) =
        latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);

    let result = public_recover(&fixture.leaf);
    assert!(
        result.is_err() || matches!(result, Ok(MigrationOutcome::Conflicted { .. })),
        "substituted receipt-bound parent must fail closed"
    );
    let (after_path, after) =
        latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
    assert_eq!(
        after_path, before_path,
        "no journal generation may be appended"
    );
    assert_eq!(after["generation"], before["generation"]);
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.parent).expect("foreign parent remains"),
        foreign_parent_identity
    );
    assert_eq!(
        PhysicalIdentity::from_path(&retained_original).expect("exact parent remains preserved"),
        fixture.parent_identity
    );
}

#[test]
fn removed_create_directory_receipt_remains_null() {
    let fixture = apply_closed_leaf(ClosedLeafKind::CreateDirectory);
    let operation_index = persisted_step_index(&fixture);
    let observed = RefCell::new(false);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Rollback {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                if checkpoint
                    == TransactionV1Checkpoint::PrivateRollbackReceiptPersisted(operation_index)
                {
                    *observed.borrow_mut() = true;
                    panic!("lose removed-directory private receipt acknowledgement");
                }
            },
        )
        .expect("removed directory rollback checkpoint");
    }));
    assert!(*observed.borrow());
    assert!(interrupted.is_err());
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(private_rollback_receipt_path(&fixture, operation_index))
            .expect("removed-directory private rollback receipt"),
    )
    .expect("private rollback receipt JSON");
    assert!(
        receipt["after_identity_sha256"].is_null(),
        "removed disposition remains null"
    );
    assert!(
        private_claim_path(&fixture, operation_index, "rollback").is_dir(),
        "removed directory keeps its exact private inverse claim"
    );
}

struct ReplaceAbortFixture {
    leaf: ClosedLeafFixture,
    original_identity: PhysicalIdentity,
    original_bytes: Vec<u8>,
    #[cfg(unix)]
    original_mode: u32,
    published_identity: Option<PhysicalIdentity>,
    published_bytes: Option<Vec<u8>>,
}

fn requested_unreceipted_replace_fixture(
    lost_acknowledgement: LostAcknowledgement,
) -> ReplaceAbortFixture {
    assert!(matches!(
        lost_acknowledgement,
        LostAcknowledgement::Intent | LostAcknowledgement::Claim | LostAcknowledgement::Publish
    ));
    let leaf = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::ReplaceFile),
        lost_acknowledgement,
    );
    let source_claim = source_claim_path(&leaf);
    let original_path = if source_claim.exists() {
        source_claim.as_path()
    } else {
        leaf.target.as_path()
    };
    let original_identity =
        PhysicalIdentity::from_path(original_path).expect("exact replace original identity");
    let original_bytes = fs::read(original_path).expect("exact replace original bytes");
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(original_path)
            .expect("exact replace original metadata")
            .permissions()
            .mode()
    };
    let published = matches!(lost_acknowledgement, LostAcknowledgement::Publish).then(|| {
        (
            PhysicalIdentity::from_path(&leaf.target).expect("published replacement identity"),
            fs::read(&leaf.target).expect("published replacement bytes"),
        )
    });
    request_test_rollback(&leaf);
    ReplaceAbortFixture {
        leaf,
        original_identity,
        original_bytes,
        #[cfg(unix)]
        original_mode,
        published_identity: published.as_ref().map(|(identity, _)| *identity),
        published_bytes: published.map(|(_, bytes)| bytes),
    }
}

fn assert_replace_original_restored(fixture: &ReplaceAbortFixture) {
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.leaf.target).expect("restored replace target"),
        fixture.original_identity
    );
    assert_eq!(
        fs::read(&fixture.leaf.target).expect("restored replace bytes"),
        fixture.original_bytes
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&fixture.leaf.target)
                .expect("restored replace metadata")
                .permissions()
                .mode(),
            fixture.original_mode,
            "restored original fidelity"
        );
    }
}

fn assert_replace_abort_receipt_contract(
    fixture: &ReplaceAbortFixture,
    lost_acknowledgement: LostAcknowledgement,
    journaled: bool,
) {
    let operation_index = persisted_step_index(&fixture.leaf);
    let path = private_abort_receipt_path(&fixture.leaf);
    let bytes = fs::read(&path).expect("canonical Replace abort-work receipt");
    let receipt: serde_json::Value =
        serde_json::from_slice(&bytes).expect("Replace abort-work receipt JSON");
    assert_eq!(
        serde_json::to_vec(&receipt).expect("canonical Replace abort receipt"),
        bytes
    );
    let (_, latest) =
        latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
    assert_eq!(receipt["format"], "folderbase-private-abort-work-v1");
    assert_eq!(receipt["transaction_id"], latest["transaction_id"]);
    assert_eq!(receipt["program_digest"], latest["program_digest"]);
    assert_eq!(
        receipt["operation_index"].as_u64(),
        Some(operation_index as u64)
    );
    assert_eq!(
        receipt["visible_post_identity_sha256"].as_str(),
        Some(fixture.original_identity.stable_sha256().as_str()),
        "Replace abort receipt must bind the exact restored original identity"
    );
    let expected_suffixes: &[&str] = match lost_acknowledgement {
        LostAcknowledgement::Intent => &[],
        LostAcknowledgement::Claim => &[],
        LostAcknowledgement::Publish => &["rollback"],
        LostAcknowledgement::PrivateReceipt | LostAcknowledgement::JournalReceipt => {
            unreachable!("receipted Replace is not an abort shape")
        }
    };
    let claims = receipt["claims"]
        .as_array()
        .expect("Replace abort exact claims");
    let expected_names = expected_suffixes
        .iter()
        .map(|suffix| private_claim_name(operation_index, suffix))
        .collect::<Vec<_>>();
    assert_eq!(
        claims
            .iter()
            .map(|claim| claim["name"].as_str().expect("Replace abort claim name"))
            .collect::<Vec<_>>(),
        expected_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "Replace abort receipt must retain only exact rollback evidence when needed"
    );
    assert!(
        !private_claim_path(&fixture.leaf, operation_index, "publish").exists(),
        "transaction-only publish evidence must be cleaned only after exact verification"
    );
    for (claim, suffix) in claims.iter().zip(expected_suffixes.iter()) {
        assert_eq!(claim["kind"], "regular");
        let claim_path = private_claim_path(&fixture.leaf, operation_index, suffix);
        let identity =
            PhysicalIdentity::from_path(&claim_path).expect("exact Replace abort claim identity");
        let claim_bytes = fs::read(&claim_path).expect("exact Replace abort claim bytes");
        assert_eq!(
            claim["physical_identity_sha256"].as_str(),
            Some(identity.stable_sha256().as_str())
        );
        assert_eq!(
            claim["device_sha256"].as_str(),
            Some(identity.device_sha256().as_str())
        );
        assert_eq!(claim["bytes"].as_u64(), Some(claim_bytes.len() as u64));
        assert_eq!(
            claim["sha256"].as_str(),
            Some(sha256_test_bytes(&claim_bytes).as_str())
        );
        assert_eq!(*suffix, "rollback");
        assert_eq!(Some(identity), fixture.published_identity);
        assert_eq!(Some(claim_bytes), fixture.published_bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::metadata(&claim_path).expect("Replace abort claim metadata");
            let mode = metadata.permissions().mode();
            assert_eq!(claim["read_only"].as_bool(), Some(mode & 0o222 == 0));
            assert_eq!(claim["executable"].as_bool(), Some(mode & 0o111 != 0));
            assert_eq!(claim["link_count"].as_u64(), Some(metadata.nlink()));
        }
    }
    assert_replace_original_restored(fixture);

    let receipt_digest = sha256_test_bytes(&bytes);
    let abort_receipts = latest
        .get("abort_receipts")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if journaled {
        assert_eq!(abort_receipts.len(), 1);
        assert_eq!(
            abort_receipts[0]["operation_index"].as_u64(),
            Some(operation_index as u64)
        );
        assert_eq!(
            abort_receipts[0]["private_receipt_sha256"].as_str(),
            Some(receipt_digest.as_str())
        );
    } else {
        assert!(abort_receipts.is_empty());
        assert_eq!(
            latest["in_flight_operation"].as_u64(),
            Some(operation_index as u64)
        );
    }
}

#[test]
fn replace_abort_terminal_matrix_restores_exact_original() {
    let cases = [
        ("intent", LostAcknowledgement::Intent),
        ("claim", LostAcknowledgement::Claim),
        ("visible", LostAcknowledgement::Publish),
    ];
    let mut failures = Vec::new();
    for (label, lost_acknowledgement) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let fixture = requested_unreceipted_replace_fixture(lost_acknowledgement);
            let outcome =
                public_recover(&fixture.leaf).expect("recover canonical Replace abort receipt");
            assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
            assert_replace_abort_receipt_contract(&fixture, lost_acknowledgement, true);
        }));
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "reachable unreceipted Replace abort cases failed: {failures:?}"
    );
}

#[test]
fn replace_visible_abort_private_receipt_restart_is_canonical() {
    let fixture = requested_unreceipted_replace_fixture(LostAcknowledgement::Publish);
    let operation_index = persisted_step_index(&fixture.leaf);
    let observed = RefCell::new(false);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.leaf.root.path(),
            MigrationCommand::Recover {
                migration_id: &fixture.leaf.migration_id,
            },
            |checkpoint| {
                if checkpoint
                    == TransactionV1Checkpoint::PrivateAbortReceiptPersisted(operation_index)
                {
                    *observed.borrow_mut() = true;
                    panic!("lose Replace private abort receipt acknowledgement");
                }
            },
        )
        .expect("Replace abort must reach its private receipt");
    }));
    assert!(*observed.borrow(), "Replace private abort checkpoint");
    assert!(interrupted.is_err());
    assert_replace_abort_receipt_contract(&fixture, LostAcknowledgement::Publish, false);
    let outcome = public_recover(&fixture.leaf).expect("restart journals Replace abort receipt");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_replace_abort_receipt_contract(&fixture, LostAcknowledgement::Publish, true);
}

#[test]
fn foreign_replace_target_blocks_abort_without_overwrite_or_repeat_generation() {
    let cases = [
        ("claim", LostAcknowledgement::Claim),
        ("visible", LostAcknowledgement::Publish),
    ];
    let foreign_bytes = b"foreign Replace target must survive abort\n";
    let mut failures = Vec::new();
    for (label, lost_acknowledgement) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let leaf = interrupt_closed_leaf(
                approved_closed_leaf(ClosedLeafKind::ReplaceFile),
                lost_acknowledgement,
            );
            if leaf.target.exists() {
                fs::remove_file(&leaf.target).expect("remove transaction-visible replacement");
            }
            fs::write(&leaf.target, foreign_bytes).expect("foreign Replace target");
            let foreign_identity =
                PhysicalIdentity::from_path(&leaf.target).expect("foreign Replace identity");
            request_test_rollback(&leaf);
            let _ = expect_conflicted(public_recover(&leaf), "foreign Replace abort target");
            let (conflicted_path, conflicted) =
                latest_journal_generation(leaf.root.path(), &leaf.migration_id);
            assert_eq!(
                PhysicalIdentity::from_path(&leaf.target).expect("foreign target remains"),
                foreign_identity
            );
            assert_eq!(
                fs::read(&leaf.target).expect("foreign bytes remain"),
                foreign_bytes
            );
            assert!(!private_abort_receipt_path(&leaf).exists());

            let _ = expect_conflicted(
                public_recover(&leaf),
                "repeated foreign Replace abort target",
            );
            let (retry_path, retry) =
                latest_journal_generation(leaf.root.path(), &leaf.migration_id);
            assert_eq!(
                retry_path, conflicted_path,
                "no repeated conflict generation"
            );
            assert_eq!(retry["generation"], conflicted["generation"]);
            assert_eq!(
                PhysicalIdentity::from_path(&leaf.target).expect("foreign target remains exact"),
                foreign_identity
            );
        }));
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "foreign Replace abort cases failed: {failures:?}"
    );
}

#[test]
fn journaled_replace_abort_rejects_tampered_missing_or_extra_evidence() {
    let cases = ["tampered_receipt", "missing_rollback", "extra_claim"];
    let mut failures = Vec::new();
    for case in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let fixture = requested_unreceipted_replace_fixture(LostAcknowledgement::Publish);
            let operation_index = persisted_step_index(&fixture.leaf);
            let observed = RefCell::new(false);
            let interrupted = catch_unwind(AssertUnwindSafe(|| {
                run_transaction_v1_with_hook(
                    fixture.leaf.root.path(),
                    MigrationCommand::Recover {
                        migration_id: &fixture.leaf.migration_id,
                    },
                    |checkpoint| {
                        if checkpoint
                            == TransactionV1Checkpoint::JournalAbortReceiptPersisted(
                                operation_index,
                            )
                        {
                            *observed.borrow_mut() = true;
                            panic!("lose Replace journal abort receipt acknowledgement");
                        }
                    },
                )
                .expect("Replace abort must reach its journal receipt");
            }));
            assert!(*observed.borrow(), "Replace journal abort checkpoint");
            assert!(interrupted.is_err());
            assert_replace_abort_receipt_contract(&fixture, LostAcknowledgement::Publish, true);

            let affected = match case {
                "tampered_receipt" => {
                    let receipt = private_abort_receipt_path(&fixture.leaf);
                    fs::write(&receipt, b"tampered Replace abort receipt\n")
                        .expect("tamper Replace abort receipt");
                    receipt
                }
                "missing_rollback" => {
                    let claim = private_claim_path(&fixture.leaf, operation_index, "rollback");
                    fs::remove_file(&claim).expect("remove Replace rollback evidence");
                    claim
                }
                "extra_claim" => {
                    let claim = private_claim_path(&fixture.leaf, operation_index, "extra");
                    fs::write(&claim, b"impossible extra Replace abort claim\n")
                        .expect("install extra Replace abort evidence");
                    claim
                }
                _ => unreachable!(),
            };
            let (before_path, before) =
                latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
            let error = public_recover(&fixture.leaf)
                .expect_err("changed journaled Replace evidence must fail closed");
            assert!(
                error.to_string().contains(
                    affected
                        .file_name()
                        .expect("affected private artifact name")
                        .to_string_lossy()
                        .as_ref()
                ),
                "integrity error must identify the concrete private artifact: {error}"
            );
            let (after_path, after) =
                latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
            assert_eq!(after_path, before_path, "no integrity-conflict generation");
            assert_eq!(after["generation"], before["generation"]);
            assert_replace_original_restored(&fixture);
        }));
        if result.is_err() {
            failures.push(case);
        }
    }
    assert!(
        failures.is_empty(),
        "journaled Replace abort integrity cases failed: {failures:?}"
    );
}

#[cfg(unix)]
#[test]
fn replace_conflict_fingerprint_uses_one_retained_observation_after_ambient_root_replacement() {
    use std::os::unix::fs::MetadataExt;

    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::ReplaceFile),
        LostAcknowledgement::Intent,
    );
    let operation_index = persisted_step_index(&fixture);
    let relative_target = fixture
        .target
        .strip_prefix(fixture.root.path())
        .expect("relative Replace target")
        .to_path_buf();
    let original_bytes = fs::read(&fixture.target).expect("retained target bytes");
    let original_metadata = fs::metadata(&fixture.target).expect("retained target metadata");
    let original_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("retained target identity");
    let original_digest = sha256_test_bytes(&original_bytes);
    let expected_regular = format!(
        "regular:{}:{}:{}:{}:{}:{:?}:{}",
        original_identity.stable_sha256(),
        original_identity.device_sha256(),
        original_bytes.len(),
        original_digest,
        original_metadata.mode() & 0o222 == 0,
        Some(original_metadata.mode() & 0o7777),
        original_metadata.nlink()
    );

    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("retained filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id);
    let transaction =
        reopen_transaction_v1(&filesystem, &migration_root, None).expect("reopen transaction");
    let regular_target = match transaction
        .program
        .step(operation_index)
        .expect("Replace program step")
    {
        ProgramStepV1::ReplaceFile { target, .. } => target,
        other => panic!("expected Replace program step, got {other:?}"),
    };

    let visible_root = fixture.root.path().to_path_buf();
    let detached_root =
        visible_root.with_file_name(format!(".replace-conflict-retained-{}", Uuid::now_v7()));
    fs::rename(&visible_root, &detached_root).expect("detach retained root");
    fs::create_dir(&visible_root).expect("replacement ambient root");
    fs::write(
        visible_root.join(&relative_target),
        b"ambient replacement must never supply conflict bytes\n",
    )
    .expect("ambient replacement target");
    let observed_regular = replace_abort_conflict_target_fact(&filesystem, regular_target);
    fs::remove_dir_all(&visible_root).expect("remove replacement ambient root");
    fs::rename(&detached_root, &visible_root).expect("restore retained root pathname");
    assert_eq!(
        observed_regular.expect("retained regular conflict observation"),
        expected_regular,
        "kind, identity, device, bytes, digest, fidelity, and link topology must come from one retained no-follow leaf authority"
    );
}

#[cfg(unix)]
#[test]
fn replace_conflict_link_fingerprint_reads_target_through_retained_authority() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::ReplaceFile),
        LostAcknowledgement::Intent,
    );
    let operation_index = persisted_step_index(&fixture);
    let relative_target = fixture
        .target
        .strip_prefix(fixture.root.path())
        .expect("relative Replace target")
        .to_path_buf();
    fs::remove_file(&fixture.target).expect("replace regular target with retained symlink");
    let retained_link_target = PathBuf::from("retained-link-target");
    symlink(&retained_link_target, &fixture.target).expect("retained target symlink");
    let link_metadata = fs::symlink_metadata(&fixture.target).expect("retained link metadata");
    let expected_link = format!(
        "other:{}:{}:{}:{}:{}:{}:{:?}",
        link_metadata.dev(),
        link_metadata.ino(),
        link_metadata.mode(),
        link_metadata.nlink(),
        link_metadata.len(),
        link_metadata.mtime_nsec(),
        Some(retained_link_target)
    );

    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("retained filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id);
    let transaction =
        reopen_transaction_v1(&filesystem, &migration_root, None).expect("reopen transaction");
    let regular_target = match transaction
        .program
        .step(operation_index)
        .expect("Replace program step")
    {
        ProgramStepV1::ReplaceFile { target, .. } => target,
        other => panic!("expected Replace program step, got {other:?}"),
    };

    let visible_root = fixture.root.path().to_path_buf();
    let detached_root =
        visible_root.with_file_name(format!(".replace-conflict-link-{}", Uuid::now_v7()));
    fs::rename(&visible_root, &detached_root).expect("detach retained symlink root");
    fs::create_dir(&visible_root).expect("replacement symlink ambient root");
    symlink("ambient-link-target", visible_root.join(&relative_target))
        .expect("ambient replacement symlink");
    let observed_link = replace_abort_conflict_target_fact(&filesystem, regular_target);
    fs::remove_dir_all(&visible_root).expect("remove replacement symlink root");
    fs::rename(&detached_root, &visible_root).expect("restore retained symlink root pathname");
    assert_eq!(
        observed_link.expect("retained link conflict observation"),
        expected_link,
        "a supported link target must come from the same retained no-follow authority"
    );
}

#[test]
fn replace_conflict_fingerprint_rejects_same_length_write_during_retained_read() {
    let root = initialized_root();
    let relative = Path::new("AGENTS.md");
    let target = root.path().join(relative);
    let original = fs::read(&target).expect("original fingerprint bytes");
    let replacement = vec![b'X'; original.len()];
    assert_ne!(replacement, original);
    let state = FolderbaseState::open_existing(root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, root.path()).expect("retained filesystem");

    let observed =
        filesystem.retained_nofollow_leaf_fingerprint_with_regular_open_hook(relative, || {
            fs::write(&target, &replacement).expect("same-length in-place writer race");
        });
    match observed {
        Err(FolderbaseError::MigrationSourceChanged(path)) => assert_eq!(path, target),
        Ok(fingerprint) => {
            panic!("changed file version must not return a conflict fingerprint: {fingerprint:?}")
        }
        Err(other) => panic!("changed file version must be classified exactly: {other}"),
    }
    assert_eq!(
        fs::read(&target).expect("writer bytes remain"),
        replacement,
        "fingerprinting never repairs or overwrites the racing writer"
    );
}

#[test]
fn replace_conflict_fingerprint_rejects_namespace_rebinding_of_opened_leaf() {
    let root = initialized_root();
    let relative = Path::new("AGENTS.md");
    let target = root.path().join(relative);
    let detached = root.path().join("AGENTS.detached-by-writer.md");
    let original = fs::read(&target).expect("original fingerprint bytes");
    let original_identity =
        PhysicalIdentity::from_path(&target).expect("original fingerprint identity");
    let replacement = vec![b'Y'; original.len()];
    assert_ne!(replacement, original);
    let state = FolderbaseState::open_existing(root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, root.path()).expect("retained filesystem");

    let observed =
        filesystem.retained_nofollow_leaf_fingerprint_with_regular_open_hook(relative, || {
            fs::rename(&target, &detached).expect("detach the opened target");
            fs::write(&target, &replacement).expect("publish a new inode at the retained name");
        });
    match observed {
        Err(FolderbaseError::MigrationSourceChanged(path)) => assert_eq!(path, target),
        Ok(fingerprint) => {
            panic!("a detached handle must not supply the namespace conflict fact: {fingerprint:?}")
        }
        Err(other) => panic!("namespace rebinding must be classified exactly: {other}"),
    }
    assert_eq!(
        PhysicalIdentity::from_path(&detached).expect("detached original identity"),
        original_identity
    );
    assert_eq!(
        fs::read(&detached).expect("detached original bytes"),
        original
    );
    assert_ne!(
        PhysicalIdentity::from_path(&target).expect("new visible identity"),
        original_identity
    );
    assert_eq!(fs::read(&target).expect("new visible bytes"), replacement);
}

#[test]
fn replace_publish_claim_precedes_source_claim_and_aborts_without_private_residue() {
    let mut leaf = approved_closed_leaf(ClosedLeafKind::ReplaceFile);
    let original_identity =
        PhysicalIdentity::from_path(&leaf.target).expect("original Replace identity");
    let original_bytes = fs::read(&leaf.target).expect("original Replace bytes");
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(&leaf.target)
            .expect("original Replace metadata")
            .permissions()
            .mode()
    };
    let approved = leaf.approved.take().expect("approved Replace migration");
    let observed = RefCell::new(None);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_transaction_hook(approved, |checkpoint| {
            if let TransactionV1Checkpoint::ReplacePublishClaimPrepared(index) = checkpoint {
                *observed.borrow_mut() = Some(index);
                panic!("lose acknowledgement before Replace source claim");
            }
        })
    }));
    assert!(
        interrupted.is_err(),
        "pre-source Replace checkpoint must crash"
    );
    let operation_index = observed
        .into_inner()
        .expect("Replace publish-claim checkpoint");
    assert_eq!(operation_index, persisted_step_index(&leaf));
    let publish_claim = private_claim_path(&leaf, operation_index, "publish");
    let publish_identity =
        PhysicalIdentity::from_path(&publish_claim).expect("exact prepared publish claim");
    let publish_bytes = fs::read(&publish_claim).expect("prepared publish bytes");
    assert!(
        !source_claim_path(&leaf).exists(),
        "source was never claimed"
    );
    assert!(!private_claim_path(&leaf, operation_index, "rollback").exists());
    assert_eq!(
        PhysicalIdentity::from_path(&leaf.target).expect("original remains visible"),
        original_identity
    );
    assert_eq!(
        fs::read(&leaf.target).expect("original visible bytes"),
        original_bytes
    );

    request_test_rollback(&leaf);
    let outcome = public_recover(&leaf).expect("abort exact pre-source Replace state");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert!(
        !publish_claim.exists(),
        "unpublished prepared bytes are removed"
    );
    assert!(!source_claim_path(&leaf).exists());
    assert!(!private_claim_path(&leaf, operation_index, "rollback").exists());
    assert_eq!(
        PhysicalIdentity::from_path(&leaf.target).expect("terminal original identity"),
        original_identity
    );
    assert_eq!(
        fs::read(&leaf.target).expect("terminal original bytes"),
        original_bytes
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&leaf.target)
                .expect("terminal original metadata")
                .permissions()
                .mode(),
            original_mode
        );
    }
    let receipt_bytes =
        fs::read(private_abort_receipt_path(&leaf)).expect("pre-source abort receipt");
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).expect("pre-source abort receipt JSON");
    assert_eq!(
        receipt["visible_post_identity_sha256"].as_str(),
        Some(original_identity.stable_sha256().as_str())
    );
    assert_eq!(
        receipt["claims"].as_array().map(Vec::len),
        Some(0),
        "no source, publish, or rollback claim survives"
    );
    let (_, terminal) = latest_journal_generation(leaf.root.path(), &leaf.migration_id);
    assert_eq!(terminal["phase"], "rolled_back");
    assert_eq!(terminal["in_flight_operation"], serde_json::Value::Null);
    assert_eq!(
        terminal["abort_receipts"]
            .as_array()
            .expect("journal abort receipt")
            .len(),
        1
    );
    assert_ne!(
        publish_identity, original_identity,
        "prepared new bytes are independent of the original"
    );
    assert!(!publish_bytes.is_empty());

    let reopened = public_recover(&leaf).expect("terminal pre-source Replace reopen");
    assert!(matches!(reopened, MigrationOutcome::RolledBack(_)));
}

#[test]
fn terminal_replace_abort_allows_ordinary_edits_without_live_source_authority() {
    let cases = [
        ("claim", LostAcknowledgement::Claim),
        ("visible", LostAcknowledgement::Publish),
    ];
    let mut failures = Vec::new();
    for (label, lost_acknowledgement) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let fixture = requested_unreceipted_replace_fixture(lost_acknowledgement);
            let operation_index = persisted_step_index(&fixture.leaf);
            let outcome = public_recover(&fixture.leaf).expect("terminal Replace abort");
            assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
            let source_claim = source_claim_path(&fixture.leaf);
            assert!(
                !source_claim.exists(),
                "terminal Replace abort must normalize away live source authority"
            );
            let rollback_claim = private_claim_path(&fixture.leaf, operation_index, "rollback");
            match lost_acknowledgement {
                LostAcknowledgement::Claim => {
                    assert!(
                        !rollback_claim.exists(),
                        "Claim has no published new output"
                    );
                }
                LostAcknowledgement::Publish => {
                    assert_eq!(
                        PhysicalIdentity::from_path(&rollback_claim)
                            .expect("immutable replacement evidence"),
                        fixture
                            .published_identity
                            .expect("published replacement identity")
                    );
                    assert_eq!(
                        fs::read(&rollback_claim)
                            .expect("immutable replacement bytes")
                            .as_slice(),
                        fixture
                            .published_bytes
                            .as_ref()
                            .expect("published replacement bytes")
                            .as_slice()
                    );
                }
                _ => unreachable!(),
            }

            let receipt_path = private_abort_receipt_path(&fixture.leaf);
            let receipt_bytes = fs::read(&receipt_path).expect("terminal abort receipt");
            let receipt: serde_json::Value =
                serde_json::from_slice(&receipt_bytes).expect("terminal abort receipt JSON");
            let expected_claims = match lost_acknowledgement {
                LostAcknowledgement::Claim => Vec::new(),
                LostAcknowledgement::Publish => {
                    vec![private_claim_name(operation_index, "rollback")]
                }
                _ => unreachable!(),
            };
            assert_eq!(
                receipt["claims"]
                    .as_array()
                    .expect("normalized terminal claims")
                    .iter()
                    .map(|claim| claim["name"].as_str().expect("claim name").to_owned())
                    .collect::<Vec<_>>(),
                expected_claims
            );
            let (journal_path, journal) =
                latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
            let journal_bytes = fs::read(&journal_path).expect("terminal journal bytes");
            assert_eq!(journal["phase"], "rolled_back");

            let edited = format!("ordinary post-abort edit for {label}\n").into_bytes();
            fs::write(&fixture.leaf.target, &edited).expect("ordinary in-place edit");
            assert_eq!(
                PhysicalIdentity::from_path(&fixture.leaf.target)
                    .expect("in-place edit keeps visible identity"),
                fixture.original_identity
            );
            for _ in 0..2 {
                let reopened =
                    public_recover(&fixture.leaf).expect("edited terminal Replace reopen");
                assert!(matches!(reopened, MigrationOutcome::RolledBack(_)));
                assert_eq!(
                    fs::read(&fixture.leaf.target).expect("ordinary edit remains visible"),
                    edited
                );
                assert!(!source_claim.exists());
                assert_eq!(
                    fs::read(&receipt_path).expect("immutable private receipt"),
                    receipt_bytes
                );
                assert_eq!(
                    fs::read(&journal_path).expect("immutable terminal journal"),
                    journal_bytes
                );
                let (latest_path, latest) =
                    latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
                assert_eq!(latest_path, journal_path);
                assert_eq!(latest["generation"], journal["generation"]);
            }
        }));
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "terminal Replace abort stability cases failed: {failures:?}"
    );
}

#[test]
fn terminal_replace_abort_allows_user_owned_path_replacement_and_edits() {
    let cases = [
        ("claim", LostAcknowledgement::Claim),
        ("visible", LostAcknowledgement::Publish),
    ];
    let mut failures = Vec::new();
    for (label, lost_acknowledgement) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let fixture = requested_unreceipted_replace_fixture(lost_acknowledgement);
            let operation_index = persisted_step_index(&fixture.leaf);
            let terminal = public_recover(&fixture.leaf).expect("terminal Replace abort");
            assert!(matches!(terminal, MigrationOutcome::RolledBack(_)));
            let source_claim = source_claim_path(&fixture.leaf);
            let publish_claim = private_claim_path(&fixture.leaf, operation_index, "publish");
            let rollback_claim = private_claim_path(&fixture.leaf, operation_index, "rollback");
            assert!(!source_claim.exists());
            assert!(!publish_claim.exists());

            let receipt_path = private_abort_receipt_path(&fixture.leaf);
            let receipt_bytes = fs::read(&receipt_path).expect("immutable abort receipt");
            let (journal_path, journal) =
                latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
            let journal_bytes = fs::read(&journal_path).expect("immutable terminal journal");
            assert_eq!(journal["phase"], "rolled_back");
            let rollback_evidence = rollback_claim.exists().then(|| {
                (
                    PhysicalIdentity::from_path(&rollback_claim)
                        .expect("immutable rollback identity"),
                    fs::read(&rollback_claim).expect("immutable rollback bytes"),
                )
            });
            assert_eq!(
                rollback_evidence.is_some(),
                matches!(lost_acknowledgement, LostAcknowledgement::Publish)
            );

            let replacement =
                format!("user-owned post-abort replacement for {label}\n").into_bytes();
            let replacement_identity = substitute_regular(&fixture.leaf.target, &replacement);
            assert_ne!(replacement_identity, fixture.original_identity);
            let edited =
                format!("edited user-owned post-abort replacement for {label}\n").into_bytes();
            fs::write(&fixture.leaf.target, &edited).expect("ordinary edit of new inode");
            assert_eq!(
                PhysicalIdentity::from_path(&fixture.leaf.target)
                    .expect("edited replacement identity"),
                replacement_identity
            );

            for _ in 0..2 {
                let reopened =
                    public_recover(&fixture.leaf).expect("replaced terminal pathname reopen");
                assert!(matches!(reopened, MigrationOutcome::RolledBack(_)));
                assert_eq!(
                    PhysicalIdentity::from_path(&fixture.leaf.target)
                        .expect("user-owned inode remains"),
                    replacement_identity
                );
                assert_eq!(
                    fs::read(&fixture.leaf.target).expect("user-owned edit remains"),
                    edited
                );
                assert!(!source_claim.exists());
                assert!(!publish_claim.exists());
                assert_eq!(
                    fs::read(&receipt_path).expect("private receipt remains immutable"),
                    receipt_bytes
                );
                assert_eq!(
                    fs::read(&journal_path).expect("terminal journal remains immutable"),
                    journal_bytes
                );
                let (latest_path, latest) =
                    latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
                assert_eq!(latest_path, journal_path);
                assert_eq!(latest["generation"], journal["generation"]);
                match rollback_evidence.as_ref() {
                    Some((identity, bytes)) => {
                        assert_eq!(
                            PhysicalIdentity::from_path(&rollback_claim)
                                .expect("rollback identity remains immutable"),
                            *identity
                        );
                        assert_eq!(
                            fs::read(&rollback_claim).expect("rollback bytes remain immutable"),
                            *bytes
                        );
                    }
                    None => assert!(!rollback_claim.exists()),
                }
            }
        }));
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "terminal Replace pathname-replacement cases failed: {failures:?}"
    );
}

struct ProgramCreatedAbortFixture {
    root: TempDir,
    migration_id: String,
    operation_index: usize,
    manifest: PathBuf,
    competitor: PathBuf,
    competitor_bytes: Vec<u8>,
}

fn conflicted_program_created_abort_fixture() -> ProgramCreatedAbortFixture {
    let root = tempfile::tempdir().expect("ordinary source folder");
    fs::write(root.path().join("README.md"), b"ordinary project context\n")
        .expect("ordinary source");
    let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approved additive migration");
    let competitor = RefCell::new(None::<PathBuf>);
    let competitor_bytes = b"foreign descendant blocks publication\n".to_vec();
    let installed = RefCell::new(false);
    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        let TransactionV1Checkpoint::JournalApplyReceiptPersisted(index) = checkpoint else {
            return;
        };
        if *installed.borrow() {
            return;
        }
        let program: serde_json::Value = serde_json::from_slice(
            &fs::read(program_path_for(root.path(), &migration_id))
                .expect("persisted mutation program"),
        )
        .expect("persisted mutation program JSON");
        let steps = program["steps"].as_array().expect("closed program steps");
        if steps[index]["target"]["path"].as_str() != Some("Organized/.folderbase/manifest.json") {
            return;
        }
        let later = steps
            .iter()
            .skip(index + 1)
            .filter_map(|step| step["target"]["path"].as_str())
            .map(PathBuf::from)
            .find(|path| path.starts_with("Organized") && !root.path().join(path).exists())
            .expect("later descendant publication");
        let absolute = root.path().join(later);
        fs::write(&absolute, &competitor_bytes).expect("install descendant competitor");
        *competitor.borrow_mut() = Some(absolute);
        *installed.borrow_mut() = true;
    });
    assert!(
        result.is_err(),
        "descendant competitor must leave a conflicted in-flight operation"
    );
    let (_, latest) = latest_journal_generation(root.path(), &migration_id);
    assert_eq!(latest["phase"], "conflicted");
    let operation_index = latest["in_flight_operation"]
        .as_u64()
        .expect("conflicted operation index") as usize;
    let competitor = competitor.into_inner().expect("competitor target");
    ProgramCreatedAbortFixture {
        manifest: root.path().join("Organized/.folderbase/manifest.json"),
        root,
        migration_id,
        operation_index,
        competitor,
        competitor_bytes,
    }
}

#[test]
fn changed_program_created_boundary_blocks_conflicted_abort_and_retains_in_flight() {
    let fixture = conflicted_program_created_abort_fixture();
    let changed = RefCell::new(false);
    let foreign_identity = RefCell::new(None::<PhysicalIdentity>);
    let result = run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
        |checkpoint| {
            if checkpoint == TransactionV1Checkpoint::RollbackRequested && !*changed.borrow() {
                let bytes = fs::read(&fixture.manifest).expect("generated manifest");
                *foreign_identity.borrow_mut() =
                    Some(substitute_regular(&fixture.manifest, &bytes));
                *changed.borrow_mut() = true;
            }
        },
    );
    let (migration_id, conflicts) = expect_conflicted(
        result,
        "changed program-created boundary must block conflicted abort work",
    );
    assert_eq!(migration_id, fixture.migration_id);
    assert!(!conflicts.is_empty());
    let (_, latest) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(latest["direction"], "rollback");
    assert_eq!(latest["phase"], "conflicted");
    assert_eq!(
        latest["in_flight_operation"].as_u64(),
        Some(fixture.operation_index as u64),
        "failed boundary proof must retain the same exact in-flight operation"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.manifest).expect("foreign manifest remains"),
        foreign_identity
            .into_inner()
            .expect("foreign manifest identity")
    );
    assert_eq!(
        fs::read(&fixture.competitor).expect("competitor remains"),
        fixture.competitor_bytes
    );
}

fn interrupt_conflicted_abort_at(
    fixture: &ClosedLeafFixture,
    expected_checkpoint: TransactionV1Checkpoint,
) {
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.root.path(),
            MigrationCommand::Rollback {
                migration_id: &fixture.migration_id,
            },
            |checkpoint| {
                if checkpoint == expected_checkpoint {
                    panic!("lose acknowledgement at {expected_checkpoint:?}");
                }
            },
        )
        .expect("checkpoint interrupts before outcome");
    }));
    assert!(
        interrupted.is_err(),
        "abort must expose the durable {expected_checkpoint:?} checkpoint"
    );
}

#[test]
fn private_abort_receipt_restart_does_not_repeat_visible_work() {
    let fixture = conflicted_move_abort_fixture();
    let source = fixture.source.as_ref().expect("move source");
    interrupt_conflicted_abort_at(
        &fixture,
        TransactionV1Checkpoint::PrivateAbortReceiptPersisted(persisted_step_index(&fixture)),
    );
    let restored_identity =
        PhysicalIdentity::from_path(source).expect("abort restored the exact source");
    assert!(
        private_abort_receipt_path(&fixture).is_file(),
        "visible abort work must have a private durable receipt"
    );
    let (_, private_receipted) =
        latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert!(
        private_receipted["in_flight_operation"].is_number(),
        "private receipt alone must not clear the durable in-flight operation"
    );

    let outcome = public_recover(&fixture).expect("restart verifies and journals abort work");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_eq!(
        PhysicalIdentity::from_path(source).expect("restart preserves restored source"),
        restored_identity,
        "restart must not repeat or replace already-receipted visible abort work"
    );
}

#[test]
fn journaled_abort_rejects_missing_or_altered_private_receipt() {
    for altered in [false, true] {
        let fixture = conflicted_move_abort_fixture();
        interrupt_conflicted_abort_at(
            &fixture,
            TransactionV1Checkpoint::JournalAbortReceiptPersisted(persisted_step_index(&fixture)),
        );
        let receipt = private_abort_receipt_path(&fixture);
        if altered {
            fs::write(&receipt, b"altered abort receipt\n").expect("alter private abort receipt");
        } else {
            fs::remove_file(&receipt).expect("remove private abort receipt");
        }
        let error = public_recover(&fixture)
            .expect_err("journaled abort requires its exact private receipt");
        assert!(
            error.to_string().contains(
                receipt
                    .file_name()
                    .expect("receipt name")
                    .to_string_lossy()
                    .as_ref()
            ),
            "abort receipt mismatch must fail at its concrete private path: {error}"
        );
    }
}

#[test]
fn journaled_move_abort_rejects_extra_exact_claims() {
    let fixture = conflicted_move_abort_fixture();
    interrupt_conflicted_abort_at(
        &fixture,
        TransactionV1Checkpoint::JournalAbortReceiptPersisted(persisted_step_index(&fixture)),
    );
    assert!(
        !source_claim_path(&fixture).exists(),
        "journaled Move abort owns no live source claim"
    );
    let rollback_claim = private_claim_path(&fixture, persisted_step_index(&fixture), "rollback");
    fs::hard_link(
        fixture.source.as_ref().expect("restored move source"),
        &rollback_claim,
    )
    .expect("install extra exact abort claim");
    let error = public_recover(&fixture)
        .expect_err("journaled Move abort rejects an undeclared private claim");
    assert!(
        error.to_string().contains(
            rollback_claim
                .file_name()
                .expect("claim name")
                .to_string_lossy()
                .as_ref()
        ),
        "abort claim mismatch must fail at its concrete private path: {error}"
    );
}

fn assert_same_byte_substitution_during_rollback_conflicts(kind: ClosedLeafKind) {
    let fixture = apply_closed_leaf(kind);
    request_test_rollback(&fixture);
    begin_test_rollback(&fixture);
    let expected = fs::read(&fixture.target).expect("published leaf");
    let foreign_identity = substitute_regular(&fixture.target, &expected);

    let (_, conflicts) = expect_conflicted(
        public_recover(&fixture),
        "same-byte foreign identity during rollback",
    );
    assert_eq!(
        fs::read(&fixture.target).expect("foreign leaf remains"),
        expected
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("foreign identity remains"),
        foreign_identity
    );
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .affected_paths
                .iter()
                .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))
        }),
        "rollback conflict must name the foreign visible leaf"
    );
}

#[test]
fn replace_file_same_byte_foreign_identity_during_rollback_conflicts() {
    assert_same_byte_substitution_during_rollback_conflicts(ClosedLeafKind::ReplaceFile);
}

#[test]
fn move_file_same_byte_foreign_identity_during_rollback_conflicts() {
    assert_same_byte_substitution_during_rollback_conflicts(ClosedLeafKind::MoveFile);
}

#[test]
fn rollback_changed_additive_file_conflict_is_durable_and_idempotent() {
    const USER_EDIT: &[u8] = b"user edit after additive apply\n";

    let fixture = apply_closed_leaf(ClosedLeafKind::CreateFile);
    let operation_index = persisted_step_index(&fixture);
    let source = fixture.source.as_ref().expect("ordinary copy source");
    let source_identity =
        PhysicalIdentity::from_path(source).expect("ordinary source identity before rollback");
    let source_bytes = fs::read(source).expect("ordinary source bytes before rollback");
    let target_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("created target identity");

    fs::write(&fixture.target, USER_EDIT).expect("in-place user edit");
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("edited target identity"),
        target_identity,
        "the fixture must exercise an in-place edit rather than pathname replacement"
    );

    let (migration_id, conflicts) = expect_conflicted(
        public_rollback(&fixture),
        "changed additive output before rollback",
    );

    assert_eq!(migration_id, fixture.migration_id);
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("edited target remains"),
        target_identity
    );
    assert_eq!(
        fs::read(&fixture.target).expect("edited target bytes remain"),
        USER_EDIT
    );
    assert_eq!(
        PhysicalIdentity::from_path(source).expect("ordinary source remains"),
        source_identity
    );
    assert_eq!(
        fs::read(source).expect("ordinary source bytes remain"),
        source_bytes
    );
    assert!(
        !private_claim_path(&fixture, operation_index, "rollback").exists(),
        "rollback must stop before claiming the edited output"
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))),
        "durable conflict evidence must name the edited additive output"
    );
    let (_, journal) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(journal["direction"], "rollback");
    assert_eq!(journal["phase"], "conflicted");
    assert_eq!(
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id)
            .expect("durable conflicted plan")
            .state,
        MigrationState::Conflicted
    );

    assert_unchanged_conflict_retry_is_idempotent(&fixture, &conflicts);
}

#[test]
fn public_rollback_resumes_after_a_leaf_conflict_is_resolved() {
    let fixture = apply_closed_leaf(ClosedLeafKind::CreateFile);
    let applied_bytes = expected_regular_bytes(&fixture).to_vec();
    fs::write(&fixture.target, b"temporary user edit\n").expect("create rollback conflict");

    let first = public_rollback(&fixture).expect("first Rollback classifies the edit");
    assert!(matches!(first, MigrationOutcome::Conflicted { .. }));
    fs::write(&fixture.target, &applied_bytes).expect("restore the exact applied bytes");

    let resumed = public_rollback(&fixture)
        .expect("resolved Rollback conflict must resume the durable inverse direction");
    assert!(matches!(resumed, MigrationOutcome::RolledBack(_)));
    assert!(!fixture.target.exists());
    assert!(
        MigrationResult::reopen(fixture.root.path(), &fixture.migration_id).is_ok(),
        "a successful rollback retry must leave a reopenable journal"
    );
}

#[test]
fn rollback_in_place_edited_move_preserves_user_bytes_and_identifies_immutable_snapshot() {
    const USER_EDIT: &[u8] = b"user edit after move apply\n";

    let fixture = apply_closed_leaf(ClosedLeafKind::MoveFile);
    let operation_index = persisted_step_index(&fixture);
    let source = fixture.source.as_ref().expect("move source");
    let source_claim = source_claim_path(&fixture);
    let snapshot = rollback_snapshot_path(&fixture);
    let original_bytes = expected_regular_bytes(&fixture).to_vec();
    let target_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("published move identity");
    let snapshot_identity =
        PhysicalIdentity::from_path(&snapshot).expect("immutable rollback snapshot identity");

    assert_eq!(
        PhysicalIdentity::from_path(&source_claim).expect("live move source claim"),
        target_identity,
        "the published move and its live source claim share one claimed inode"
    );
    assert_ne!(
        snapshot_identity, target_identity,
        "the rollback snapshot must be inode-isolated from the published move"
    );
    assert_eq!(
        fs::read(&snapshot).expect("rollback snapshot bytes"),
        original_bytes
    );

    fs::write(&fixture.target, USER_EDIT).expect("in-place destination edit");
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("edited destination identity"),
        target_identity
    );

    let (migration_id, conflicts) = expect_conflicted(
        public_rollback(&fixture),
        "in-place edited move destination before rollback",
    );

    assert_eq!(migration_id, fixture.migration_id);
    assert!(
        !source.exists(),
        "rollback must not republish the move source"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("edited destination remains"),
        target_identity
    );
    assert_eq!(
        fs::read(&fixture.target).expect("edited destination bytes remain"),
        USER_EDIT
    );
    assert_eq!(
        PhysicalIdentity::from_path(&source_claim).expect("live source claim remains"),
        target_identity
    );
    assert_eq!(
        fs::read(&source_claim).expect("hard-linked source claim reflects user edit"),
        USER_EDIT
    );
    assert_eq!(
        PhysicalIdentity::from_path(&snapshot).expect("rollback snapshot remains"),
        snapshot_identity
    );
    assert_eq!(
        fs::read(&snapshot).expect("exact rollback bytes remain"),
        original_bytes
    );
    assert!(
        !private_claim_path(&fixture, operation_index, "rollback").exists(),
        "rollback must stop before claiming the edited destination"
    );
    assert!(
        !private_claim_path(&fixture, operation_index, "restore").exists(),
        "rollback must not stage a restore around unowned destination bytes"
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))),
        "durable conflict evidence must name the edited destination"
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .preserved_artifact
            .as_ref()
            .is_some_and(|path| recorded_path_matches(fixture.root.path(), path, &snapshot))),
        "the conflict must identify the immutable rollback snapshot, not the mutated source claim"
    );
    let (_, journal) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(journal["direction"], "rollback");
    assert_eq!(journal["phase"], "conflicted");
    assert_eq!(
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id)
            .expect("durable conflicted plan")
            .state,
        MigrationState::Conflicted
    );

    assert_unchanged_conflict_retry_is_idempotent(&fixture, &conflicts);
}

#[cfg(unix)]
#[test]
fn rollback_reverse_move_hardlink_alias_conflicts_without_unlinking_either_name() {
    use std::os::unix::fs::MetadataExt;

    let fixture = apply_closed_leaf(ClosedLeafKind::MoveFile);
    let operation_index = persisted_step_index(&fixture);
    let source = fixture.source.as_ref().expect("move source");
    let source_claim = source_claim_path(&fixture);
    let snapshot = rollback_snapshot_path(&fixture);
    let original_bytes = expected_regular_bytes(&fixture).to_vec();
    let published_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("published move identity");
    let snapshot_identity =
        PhysicalIdentity::from_path(&snapshot).expect("immutable rollback snapshot identity");

    fs::hard_link(&fixture.target, source).expect("reverse-move hard-link alias");
    let source_metadata = fs::metadata(source).expect("hard-linked source metadata");
    let destination_metadata =
        fs::metadata(&fixture.target).expect("hard-linked destination metadata");
    let claim_metadata = fs::metadata(&source_claim).expect("hard-linked source claim metadata");
    assert_eq!(
        (source_metadata.dev(), source_metadata.ino()),
        (destination_metadata.dev(), destination_metadata.ino())
    );
    assert_eq!(
        (source_metadata.dev(), source_metadata.ino()),
        (claim_metadata.dev(), claim_metadata.ino())
    );
    assert_eq!(source_metadata.nlink(), 3);

    let (migration_id, conflicts) = expect_conflicted(
        public_rollback(&fixture),
        "reverse-move hard-link alias before rollback",
    );

    assert_eq!(migration_id, fixture.migration_id);
    for path in [source, &fixture.target, &source_claim] {
        assert_eq!(
            PhysicalIdentity::from_path(path).expect("hard-linked identity remains"),
            published_identity
        );
        assert_eq!(
            fs::read(path).expect("hard-linked bytes remain"),
            original_bytes
        );
    }
    assert_eq!(
        PhysicalIdentity::from_path(&snapshot).expect("rollback snapshot remains"),
        snapshot_identity
    );
    assert_eq!(
        fs::read(&snapshot).expect("exact rollback snapshot bytes remain"),
        original_bytes
    );
    assert!(
        !private_claim_path(&fixture, operation_index, "rollback").exists(),
        "rollback must stop before claiming the aliased destination"
    );
    assert!(
        !private_claim_path(&fixture, operation_index, "restore").exists(),
        "rollback must not stage a restore around the alias"
    );
    assert!(
        conflicts.iter().any(|conflict| {
            [source, &fixture.target].iter().all(|affected| {
                conflict
                    .affected_paths
                    .iter()
                    .any(|path| recorded_path_matches(fixture.root.path(), path, affected))
            })
        }),
        "durable conflict evidence must name both visible hard-link aliases"
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .preserved_artifact
            .as_ref()
            .is_some_and(|path| recorded_path_matches(fixture.root.path(), path, &snapshot))),
        "the conflict must identify the immutable rollback snapshot"
    );
    let (_, journal) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(journal["direction"], "rollback");
    assert_eq!(journal["phase"], "conflicted");
    assert_eq!(
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id)
            .expect("durable conflicted plan")
            .state,
        MigrationState::Conflicted
    );

    assert_unchanged_conflict_retry_is_idempotent(&fixture, &conflicts);
}

#[test]
fn competing_destination_between_claim_and_publish_preserves_both_sides() {
    const COMPETITOR: &[u8] = b"uncoordinated destination bytes\n";
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Claim,
    );
    let claim = source_claim_path(&fixture);
    let original = fs::read(&claim).expect("claimed original");
    fs::write(&fixture.target, COMPETITOR).expect("competing destination");
    let competitor_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("competitor identity");

    let (migration_id, conflicts) = expect_conflicted(
        public_recover(&fixture),
        "competing destination between claim and publish",
    );
    assert_eq!(migration_id, fixture.migration_id);
    assert_eq!(
        fs::read(&claim).expect("preserved private original"),
        original
    );
    assert_eq!(
        fs::read(&fixture.target).expect("preserved competitor"),
        COMPETITOR
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("competitor identity remains"),
        competitor_identity
    );
    assert!(
        conflicts.iter().any(|conflict| {
            conflict
                .preserved_artifact
                .as_ref()
                .is_some_and(|path| path == &claim || fixture.root.path().join(path) == claim)
        }),
        "durable conflict evidence must name the private original"
    );
}

fn applied_additive_root() -> ClosedLeafFixture {
    apply_closed_leaf(ClosedLeafKind::CreateDirectory)
}

#[test]
fn rollback_preserves_a_nonempty_transaction_created_directory() {
    let fixture = applied_additive_root();
    let directory = fixture.root.path().join("Organized/Decisions");
    assert!(directory.is_dir(), "template-created directory");
    fs::write(
        directory.join("human-note.md"),
        b"human-owned after apply\n",
    )
    .expect("human-owned descendant");

    let (_, conflicts) = expect_conflicted(
        public_rollback(&fixture),
        "nonempty created directory before rollback",
    );
    assert_eq!(
        fs::read(directory.join("human-note.md")).expect("human note remains"),
        b"human-owned after apply\n"
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(fixture.root.path(), path, &directory))),
        "conflict evidence must name the nonempty directory"
    );
    assert_unchanged_conflict_retry_is_idempotent(&fixture, &conflicts);
}

#[cfg(unix)]
#[test]
fn rollback_created_file_hardlink_alias_drift_conflicts_before_claim() {
    let fixture = apply_closed_leaf(ClosedLeafKind::CreateFile);
    let alias = fixture.root.path().join("created-file-hardlink-alias.bin");
    fs::hard_link(&fixture.target, &alias).expect("install created-file alias");
    let target_identity = PhysicalIdentity::from_path(&fixture.target).expect("target identity");

    let (_, conflicts) = expect_conflicted(
        public_rollback(&fixture),
        "created-file alias topology changed before rollback claim",
    );

    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("target remains"),
        target_identity
    );
    assert_eq!(
        PhysicalIdentity::from_path(&alias).expect("alias remains"),
        target_identity
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(fixture.root.path(), path, &fixture.target))),
        "rollback conflict must name the aliased created file"
    );
}

#[cfg(unix)]
#[test]
fn rollback_created_directory_fidelity_drift_conflicts_before_claim() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = applied_additive_root();
    let directory = fixture.root.path().join("Organized/Decisions");
    let approved_mode = fs::metadata(&directory)
        .expect("created directory metadata")
        .mode()
        & 0o7777;
    let changed_mode = approved_mode & !0o222;
    fs::set_permissions(&directory, fs::Permissions::from_mode(changed_mode))
        .expect("change created-directory fidelity");

    let (_, conflicts) = expect_conflicted(
        public_rollback(&fixture),
        "created-directory fidelity changed before rollback claim",
    );

    assert!(directory.is_dir(), "changed directory must remain visible");
    assert_eq!(
        fs::metadata(&directory)
            .expect("changed directory metadata")
            .mode()
            & 0o7777,
        changed_mode,
        "rollback must not repair user-owned directory fidelity"
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(fixture.root.path(), path, &directory))),
        "rollback conflict must name the changed directory"
    );
}

#[test]
fn rollback_preserves_a_replacement_at_a_created_directory_name() {
    let fixture = applied_additive_root();
    let directory = fixture.root.path().join("Organized/Decisions");
    let created_identity = PhysicalIdentity::from_path(&directory).expect("created identity");
    let retained_created = fixture.root.path().join("retained-created-directory");
    fs::rename(&directory, &retained_created).expect("retain transaction-created directory");
    fs::create_dir(&directory).expect("foreign replacement directory");
    let foreign_identity = PhysicalIdentity::from_path(&directory).expect("foreign identity");
    assert_ne!(created_identity, foreign_identity);

    let (_, conflicts) = expect_conflicted(
        public_rollback(&fixture),
        "created directory identity replacement before rollback",
    );
    assert_eq!(
        PhysicalIdentity::from_path(&directory).expect("foreign directory remains"),
        foreign_identity
    );
    assert_eq!(
        PhysicalIdentity::from_path(&retained_created).expect("created directory remains"),
        created_identity
    );
    assert!(
        conflicts.iter().any(|conflict| conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(fixture.root.path(), path, &directory))),
        "conflict evidence must name the replaced directory"
    );
}

fn private_receipt_path(fixture: &ClosedLeafFixture) -> PathBuf {
    let operation_index = persisted_step_index(fixture);
    transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        .join("receipts")
        .join(format!("{operation_index:08}.apply.receipt"))
}

fn private_claim_path(fixture: &ClosedLeafFixture, operation_index: usize, kind: &str) -> PathBuf {
    transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        .join("claims")
        .join(format!("{operation_index:08}.{kind}.claim"))
}

fn assert_private_artifact_error(
    fixture: &ClosedLeafFixture,
    expected_component: &str,
    reason: &str,
) {
    let error = public_recover(fixture).expect_err(reason);
    assert!(
        error.to_string().contains(expected_component),
        "{reason} must fail at the affected private artifact, not fall back to another format: \
         {error}"
    );
}

#[test]
fn missing_expected_claim_fails_closed_at_the_claim_artifact() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Publish,
    );
    fs::remove_file(source_claim_path(&fixture)).expect("remove expected claim");

    assert_private_artifact_error(&fixture, "claims", "missing expected source claim");
}

#[test]
fn missing_expected_receipt_fails_closed_at_the_receipt_artifact() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::CreateFile),
        LostAcknowledgement::JournalReceipt,
    );
    let receipt = private_receipt_path(&fixture);
    assert!(
        receipt.exists(),
        "journal receipt requires private evidence"
    );
    fs::remove_file(&receipt).expect("remove expected private receipt");

    assert_private_artifact_error(&fixture, "receipts", "missing expected apply receipt");
}

fn assert_impossible_claim_fails_at_its_concrete_path(
    fixture: &ClosedLeafFixture,
    artifact: &Path,
    reason: &str,
) {
    let (_, before) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    fs::write(artifact, b"impossible private claim\n").expect("impossible private claim");
    let error = public_recover(fixture).expect_err(reason);
    let (_, after) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    let file_name = artifact
        .file_name()
        .expect("claim file name")
        .to_string_lossy();
    assert!(
        error.to_string().contains(file_name.as_ref()),
        "{reason} must fail at {artifact:?}, got {error}"
    );
    assert_eq!(
        after["generation"], before["generation"],
        "{reason} must be rejected during reopen before transaction execution"
    );
}

#[test]
fn future_operation_claim_is_rejected_at_its_concrete_path() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::CreateFile),
        LostAcknowledgement::Intent,
    );
    let current = persisted_step_index(&fixture);
    let program: serde_json::Value = serde_json::from_slice(
        &fs::read(program_path_for(fixture.root.path(), &fixture.migration_id))
            .expect("persisted mutation program"),
    )
    .expect("persisted mutation program JSON");
    let future = current + 1;
    assert!(
        future < program["steps"].as_array().expect("program steps").len(),
        "fixture requires a future operation"
    );
    let artifact = private_claim_path(&fixture, future, "publish");
    assert_impossible_claim_fails_at_its_concrete_path(
        &fixture,
        &artifact,
        "future operation claim",
    );
}

#[test]
fn create_file_source_claim_is_rejected_at_its_concrete_path() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::CreateFile),
        LostAcknowledgement::Intent,
    );
    let artifact = private_claim_path(&fixture, persisted_step_index(&fixture), "source");
    assert_impossible_claim_fails_at_its_concrete_path(
        &fixture,
        &artifact,
        "CreateFile source claim",
    );
}

#[test]
fn apply_phase_restore_claim_is_rejected_at_its_concrete_path() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Claim,
    );
    let artifact = private_claim_path(&fixture, persisted_step_index(&fixture), "restore");
    assert_impossible_claim_fails_at_its_concrete_path(
        &fixture,
        &artifact,
        "apply-phase restore claim",
    );
}

#[test]
fn apply_phase_rollback_claim_is_rejected_at_its_concrete_path() {
    let fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Claim,
    );
    let artifact = private_claim_path(&fixture, persisted_step_index(&fixture), "rollback");
    assert_impossible_claim_fails_at_its_concrete_path(
        &fixture,
        &artifact,
        "apply-phase rollback claim",
    );
}

#[test]
fn extra_claim_and_receipt_artifacts_fail_closed() {
    for (directory, name) in [
        ("claims", "unexpected.claim"),
        ("claims", ".unexpected.claim.ownership.json"),
        ("receipts", "unexpected.receipt"),
    ] {
        let fixture = interrupt_closed_leaf(
            approved_closed_leaf(ClosedLeafKind::MoveFile),
            LostAcknowledgement::Intent,
        );
        let artifact = transaction_v1_root(fixture.root.path(), &fixture.migration_id)
            .join(directory)
            .join(name);
        fs::write(&artifact, b"unknown private artifact\n").expect("unknown private artifact");

        assert_private_artifact_error(&fixture, directory, "extra private artifact");
        assert!(artifact.exists(), "unknown private state must be retained");
    }
}

#[test]
fn corrupt_claim_and_receipt_artifacts_fail_closed() {
    let claim_fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::Claim,
    );
    fs::write(source_claim_path(&claim_fixture), b"corrupt original\n").expect("corrupt claim");
    assert_private_artifact_error(&claim_fixture, "claims", "corrupt source claim");

    let receipt_fixture = interrupt_closed_leaf(
        approved_closed_leaf(ClosedLeafKind::MoveFile),
        LostAcknowledgement::JournalReceipt,
    );
    fs::write(
        private_receipt_path(&receipt_fixture),
        b"{\"corrupt\":true}",
    )
    .expect("corrupt receipt");
    assert_private_artifact_error(&receipt_fixture, "receipts", "corrupt apply receipt");
}

#[cfg(unix)]
#[test]
fn aliased_claim_and_receipt_artifacts_fail_closed() {
    for receipt in [false, true] {
        let fixture = interrupt_closed_leaf(
            approved_closed_leaf(ClosedLeafKind::MoveFile),
            LostAcknowledgement::Intent,
        );
        let artifact = if receipt {
            private_receipt_path(&fixture)
        } else {
            source_claim_path(&fixture)
        };
        fs::hard_link(
            program_path_for(fixture.root.path(), &fixture.migration_id),
            &artifact,
        )
        .expect("aliased private artifact");
        assert_private_artifact_error(
            &fixture,
            if receipt { "receipts" } else { "claims" },
            "aliased private artifact",
        );
    }
}

#[cfg(unix)]
#[test]
fn insecure_claim_and_receipt_modes_fail_closed_without_repair() {
    use std::os::unix::fs::PermissionsExt;

    for receipt in [false, true] {
        let fixture = interrupt_closed_leaf(
            approved_closed_leaf(ClosedLeafKind::MoveFile),
            LostAcknowledgement::Intent,
        );
        let artifact = if receipt {
            private_receipt_path(&fixture)
        } else {
            source_claim_path(&fixture)
        };
        fs::write(&artifact, b"insecure private artifact\n").expect("private artifact");
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644))
            .expect("insecure private mode");
        assert_private_artifact_error(
            &fixture,
            if receipt { "receipts" } else { "claims" },
            "insecure private artifact",
        );
        assert_eq!(
            fs::metadata(&artifact)
                .expect("private artifact remains")
                .permissions()
                .mode()
                & 0o777,
            0o644,
            "reopen must not repair untrusted private state"
        );
    }
}

#[test]
fn changed_source_identity_is_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    substitute_regular(&fixture.source, &fixture.source_bytes);

    expect_conflicted(
        retry_prepared_apply(&fixture),
        "changed source identity at public Apply",
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn changed_source_length_is_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let identity = PhysicalIdentity::from_path(&fixture.source).expect("source identity");
    fs::write(
        &fixture.source,
        b"approved move bytes with a changed length\n",
    )
    .expect("change source length in place");
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.source).expect("source identity remains"),
        identity
    );

    expect_conflicted(
        retry_prepared_apply(&fixture),
        "changed source length at public Apply",
    );
    assert_eq!(
        fs::read(&fixture.source).expect("changed source remains"),
        b"approved move bytes with a changed length\n"
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn changed_source_kind_is_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    fs::remove_file(&fixture.source).expect("remove source file");
    fs::create_dir(&fixture.source).expect("replace source with directory");

    expect_conflicted(
        retry_prepared_apply(&fixture),
        "changed source kind at public Apply",
    );
    assert!(fixture.source.is_dir());
    assert!(!fixture.destination.exists());
}

#[test]
fn changed_destination_absence_is_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    fs::write(&fixture.destination, b"competing destination\n").expect("destination competitor");

    expect_conflicted(
        retry_prepared_apply(&fixture),
        "occupied destination at public Apply",
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert_eq!(
        fs::read(&fixture.destination).expect("competitor remains"),
        b"competing destination\n"
    );
}

#[test]
fn changed_nested_boundary_facts_are_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let destination_parent = fixture.destination.parent().expect("destination parent");
    fs::create_dir(destination_parent.join(".folderbase")).expect("nested state marker");
    fs::write(
        destination_parent.join(".folderbase/manifest.json"),
        br#"{"protocol_version":"0.5.0"}"#,
    )
    .expect("nested manifest marker");

    expect_conflicted(
        retry_prepared_apply(&fixture),
        "changed nested boundary facts at public Apply",
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn program_created_manifest_identity_is_bound_before_later_descendant_publication() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    fs::write(root.path().join("README.md"), b"ordinary project context\n")
        .expect("ordinary source");
    let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approved additive migration");
    let changed = RefCell::new(false);
    let later_descendant = RefCell::new(None::<PathBuf>);
    let foreign_manifest_identity = RefCell::new(None::<PhysicalIdentity>);
    let foreign_manifest_bytes = RefCell::new(None::<Vec<u8>>);

    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        let TransactionV1Checkpoint::JournalApplyReceiptPersisted(index) = checkpoint else {
            return;
        };
        if *changed.borrow() {
            return;
        }
        let program: serde_json::Value = serde_json::from_slice(
            &fs::read(program_path_for(root.path(), &migration_id))
                .expect("persisted mutation program"),
        )
        .expect("persisted mutation program JSON");
        let steps = program["steps"].as_array().expect("closed program steps");
        let manifest_relative = Path::new("Organized/.folderbase/manifest.json");
        let current_path = steps[index]["target"]["path"].as_str().map(Path::new);
        if current_path != Some(manifest_relative) {
            return;
        }
        let later = steps
            .iter()
            .skip(index + 1)
            .filter_map(|step| step["target"]["path"].as_str())
            .map(PathBuf::from)
            .find(|path| path.starts_with("Organized") && !root.path().join(path).exists())
            .expect("later descendant publication after the manifest");
        let manifest = root.path().join(manifest_relative);
        let bytes = fs::read(&manifest).expect("published generated manifest");
        let approved_identity =
            PhysicalIdentity::from_path(&manifest).expect("approved generated manifest identity");
        let foreign_identity = substitute_regular(&manifest, &bytes);
        assert_ne!(
            foreign_identity, approved_identity,
            "same-byte replacement must change the physical identity"
        );
        *later_descendant.borrow_mut() = Some(root.path().join(later));
        *foreign_manifest_identity.borrow_mut() = Some(foreign_identity);
        *foreign_manifest_bytes.borrow_mut() = Some(bytes);
        *changed.borrow_mut() = true;
    });

    assert!(
        *changed.borrow(),
        "fixture must replace the receipt-bound generated manifest"
    );
    assert!(
        result.is_err(),
        "a later descendant step must reject the replaced generated manifest"
    );
    let manifest = root.path().join("Organized/.folderbase/manifest.json");
    let observed_identity =
        PhysicalIdentity::from_path(&manifest).expect("foreign manifest remains visible");
    assert_eq!(
        &observed_identity,
        foreign_manifest_identity
            .borrow()
            .as_ref()
            .expect("foreign manifest identity"),
        "the rejected boundary proof must preserve the user-visible foreign manifest"
    );
    assert_eq!(
        fs::read(&manifest).expect("foreign manifest bytes remain visible"),
        *foreign_manifest_bytes
            .borrow()
            .as_ref()
            .expect("foreign manifest bytes"),
        "the rejected boundary proof must not rewrite the foreign manifest bytes"
    );
    assert!(
        !later_descendant
            .borrow()
            .as_ref()
            .expect("later descendant target")
            .exists(),
        "no later descendant may publish after the boundary manifest identity changes"
    );
}

#[test]
fn changed_policy_facts_are_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let policy = fixture.root.path().join(".folderbaseignore");
    fs::write(&policy, b"Inbox/**\n").expect("changed policy from absence to presence");

    expect_conflicted(
        retry_prepared_apply(&fixture),
        "changed capture policy at public Apply",
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn absent_capture_policy_replaced_by_directory_is_rejected_before_leaf_mutation() {
    let mut fixture = approved_closed_leaf(ClosedLeafKind::MoveFile);
    let approved = fixture.approved.take().expect("approved move");
    let changed = RefCell::new(false);
    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        if matches!(checkpoint, TransactionV1Checkpoint::ApplyIntentPersisted(_))
            && !*changed.borrow()
        {
            fs::create_dir(fixture.root.path().join(".folderbaseignore"))
                .expect("install capture-policy directory");
            *changed.borrow_mut() = true;
        }
    });

    assert!(result.is_err(), "absent-to-directory change must conflict");
    assert!(
        fixture.source.as_ref().expect("move source").is_file(),
        "source must remain before the rejected mutation"
    );
    assert!(!fixture.target.exists());
}

#[test]
fn same_byte_capture_policy_identity_swap_is_rejected_before_leaf_mutation() {
    let root = initialized_root();
    let policy = root.path().join(".folderbaseignore");
    let source = root.path().join("notes.md");
    let destination = root.path().join("Archive/notes.md");
    fs::write(&policy, b"node_modules/\n").expect("capture policy");
    fs::write(&source, b"approved source\n").expect("move source");
    fs::create_dir(root.path().join("Archive")).expect("destination parent");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .expect("move proposal");
    let approved = approve_migration(plan).expect("approve move");
    let swapped = RefCell::new(false);

    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        if matches!(checkpoint, TransactionV1Checkpoint::ApplyIntentPersisted(_))
            && !*swapped.borrow()
        {
            substitute_regular(&policy, b"node_modules/\n");
            *swapped.borrow_mut() = true;
        }
    });

    assert!(
        result.is_err(),
        "same-byte capture-policy identity swap must conflict"
    );
    assert!(source.is_file(), "source must remain");
    assert!(!destination.exists());
}

#[test]
fn approved_ignore_policy_transition_does_not_conflict_with_its_own_claim() {
    let root = initialized_root();
    let policy = root.path().join(".folderbaseignore");
    fs::write(&policy, b"node_modules/\n").expect("initial capture policy");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_ignore_policy(
            "node_modules/\nDerived/\n",
        )],
    )
    .expect("ignore-policy proposal");

    apply_migration(approve_migration(plan).expect("approve ignore-policy update"))
        .expect("approved ignore-policy update must apply");

    assert_eq!(
        fs::read(&policy).expect("updated capture policy"),
        b"node_modules/\nDerived/\n"
    );
}

#[test]
fn approved_manifest_policy_transition_does_not_conflict_with_its_own_claim() {
    let root = initialized_root();
    let manifest = root.path().join(".folderbase/manifest.json");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_policy(
            "cloud_sync",
            serde_json::json!("enabled"),
        )],
    )
    .expect("manifest-policy proposal");

    apply_migration(approve_migration(plan).expect("approve manifest-policy update"))
        .expect("approved manifest-policy update must apply");

    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).expect("updated manifest"))
            .expect("manifest JSON");
    assert_eq!(document["policies"]["cloud_sync"], "enabled");
}

#[test]
fn approved_manifest_kind_transition_does_not_conflict_with_its_own_claim() {
    let root = initialized_root();
    let manifest = root.path().join(".folderbase/manifest.json");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::change_kind(
            crate::model::FolderbaseKind::Organization,
        )],
    )
    .expect("kind-change proposal");

    apply_migration(approve_migration(plan).expect("approve kind change"))
        .expect("approved kind change must apply");

    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).expect("updated manifest"))
            .expect("manifest JSON");
    assert_eq!(document["folderbase"]["kind"], "organization");
}

#[test]
fn approved_manifest_transition_recovers_from_private_receipt_after_publication() {
    let root = initialized_root();
    let manifest = root.path().join(".folderbase/manifest.json");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_policy(
            "cloud_sync",
            serde_json::json!("enabled"),
        )],
    )
    .expect("manifest-policy proposal");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approve manifest-policy update");
    let observed_receipt_boundary = RefCell::new(false);

    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_transaction_hook(approved, |checkpoint| {
            if matches!(
                checkpoint,
                TransactionV1Checkpoint::PrivateApplyReceiptPersisted(_)
            ) && manifest.is_file()
            {
                *observed_receipt_boundary.borrow_mut() = true;
                panic!("lose process after exact private receipt after manifest publication");
            }
        })
    }));
    assert!(interrupted.is_err(), "fixture must interrupt apply");
    assert!(
        *observed_receipt_boundary.borrow(),
        "private evidence must follow exact visible manifest publication"
    );

    let recovered = run_transaction_v1_with_hook(
        root.path(),
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
        |_| {},
    )
    .expect("recover exact receipt-backed manifest transition");
    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).expect("recovered manifest"))
            .expect("manifest JSON");
    assert_eq!(document["policies"]["cloud_sync"], "enabled");
}

fn interrupted_manifest_private_receipt() -> (TempDir, String, PathBuf, PathBuf) {
    let root = initialized_root();
    let manifest = root.path().join(".folderbase/manifest.json");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_policy(
            "cloud_sync",
            serde_json::json!("enabled"),
        )],
    )
    .expect("manifest-policy proposal");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approve manifest-policy update");
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_transaction_hook(approved, |checkpoint| {
            if matches!(
                checkpoint,
                TransactionV1Checkpoint::PrivateApplyReceiptPersisted(_)
            ) {
                panic!("leave a private receipt ahead of the journal");
            }
        })
    }));
    assert!(interrupted.is_err(), "fixture must interrupt apply");
    let receipts = transaction_v1_root(root.path(), &migration_id).join("receipts");
    let receipt = fs::read_dir(&receipts)
        .expect("private receipts")
        .map(|entry| entry.expect("private receipt").path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".apply.receipt"))
        })
        .expect("one private apply receipt");
    (root, migration_id, manifest, receipt)
}

#[test]
fn private_receipt_staging_recovers_synced_and_final_link_checkpoints() {
    for checkpoint in ["staged_sync", "final_link"] {
        let (root, migration_id, manifest, receipt) = interrupted_manifest_private_receipt();
        let staging = receipt.with_file_name(format!(
            ".{}.preparing",
            receipt.file_name().expect("receipt name").to_string_lossy()
        ));
        match checkpoint {
            "staged_sync" => {
                fs::rename(&receipt, &staging).expect("leave fully synced receipt staging");
            }
            "final_link" => {
                fs::hard_link(&receipt, &staging)
                    .expect("leave final receipt installed before staging retirement");
            }
            _ => unreachable!("bounded checkpoint table"),
        }

        let recovered = MigrationExecution::run(
            RootClaim::Current {
                display_root: root.path(),
            },
            MigrationCommand::Recover {
                migration_id: &migration_id,
            },
        )
        .unwrap_or_else(|error| panic!("{checkpoint} receipt recovery failed: {error:?}"));
        assert!(matches!(recovered, MigrationOutcome::Applied(_)));
        assert!(receipt.is_file());
        assert!(!staging.exists());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(manifest).expect("recovered manifest"))
                .expect("manifest JSON");
        assert_eq!(manifest["policies"]["cloud_sync"], "enabled");
    }
}

#[test]
fn private_receipt_staging_retains_a_partial_or_changed_artifact() {
    let (root, migration_id, manifest, receipt) = interrupted_manifest_private_receipt();
    let staging = receipt.with_file_name(format!(
        ".{}.preparing",
        receipt.file_name().expect("receipt name").to_string_lossy()
    ));
    fs::rename(&receipt, &staging).expect("move receipt to staging");
    fs::write(&staging, b"{\"partial\":").expect("replace the durable receipt after interruption");
    let manifest_before = fs::read(&manifest).expect("published manifest before recovery");

    MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect_err("changed receipt staging must fail closed");

    assert_eq!(
        fs::read(&staging).expect("changed staging is retained"),
        b"{\"partial\":"
    );
    assert!(!receipt.exists(), "changed staging must not be promoted");
    assert_eq!(
        fs::read(manifest).expect("published manifest remains untouched"),
        manifest_before
    );
}

#[test]
fn private_receipt_staging_rejects_receipt_from_another_transaction() {
    let (root, migration_id, manifest, receipt) = interrupted_manifest_private_receipt();
    let (_foreign_root, _foreign_id, _foreign_manifest, foreign_receipt) =
        interrupted_manifest_private_receipt();
    let staging = receipt.with_file_name(format!(
        ".{}.preparing",
        receipt.file_name().expect("receipt name").to_string_lossy()
    ));
    fs::remove_file(&receipt).expect("remove admitted receipt");
    fs::copy(&foreign_receipt, &staging).expect("stage foreign valid receipt bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))
            .expect("private staging mode");
    }
    let before = PhysicalIdentity::from_path(&manifest).expect("published manifest identity");

    MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect_err("foreign transaction receipt must fail closed");

    assert_eq!(
        PhysicalIdentity::from_path(&manifest).expect("manifest survives"),
        before
    );
    assert!(!receipt.exists(), "foreign staging must not be promoted");
}

#[test]
fn bounded_conflict_evidence_reserves_terminal_apply_and_complete_rollback_capacity() {
    for operation_count in [1_usize, 2] {
        let root = initialized_root();
        let mut operations = vec![MigrationOperation::update_adapter(
            "AGENTS.md",
            "Use the durable Folderbase transaction.",
        )];
        if operation_count == 2 {
            operations.push(MigrationOperation::update_adapter(
                "CLAUDE.md",
                "Use the same durable Folderbase transaction.",
            ));
        }
        let plan = MigrationPlan::propose_structural(root.path(), operations)
            .expect("structural proposal");
        let migration_id = plan.id.clone();
        let approved = approve_migration(plan).expect("approve proposal");
        let approval_digest = approved.approval_digest().to_owned();
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_migration_with_hook(approved, |checkpoint| {
                if checkpoint == ApplyCheckpoint::JournalPrepared {
                    panic!("leave a one-generation prepared transaction");
                }
            })
        }));
        assert!(interrupted.is_err(), "fixture must interrupt preparation");

        let target = root.path().join("AGENTS.md");
        let backup = tempfile::tempdir_in(root.path().parent().expect("fixture parent"))
            .expect("same-filesystem identity backup");
        let admitted_target = backup.path().join("AGENTS.md");
        fs::rename(&target, &admitted_target).expect("retain exact approved target identity");

        for attempt in 0..transaction_v1::MAX_RETAINED_CONFLICTS {
            if target.exists() {
                fs::remove_file(&target).expect("remove prior conflict");
            }
            fs::write(&target, format!("distinct conflict {attempt}\n"))
                .expect("install distinct conflict");
            let outcome = MigrationExecution::run(
                RootClaim::Current {
                    display_root: root.path(),
                },
                MigrationCommand::Apply {
                    migration_id: &migration_id,
                    approval_digest: &approval_digest,
                },
            )
            .unwrap_or_else(|error| {
                panic!("attempt {attempt} must remain a representable public conflict: {error:?}")
            });
            assert!(
                matches!(outcome, MigrationOutcome::Conflicted { .. }),
                "attempt {attempt} must remain conflicted"
            );
        }

        let canonical_root = root.path().canonicalize().expect("canonical root");
        let state = FolderbaseState::open_existing(&canonical_root).expect("state");
        let filesystem =
            MigrationFilesystem::from_state(&state, root.path()).expect("migration filesystem");
        let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&migration_id);
        let transaction =
            reopen_transaction_v1(&filesystem, &migration_root, None).expect("bounded journal");
        assert_eq!(
            transaction
                .generations
                .last()
                .expect("conflicted generation")
                .conflict_records()
                .len(),
            transaction_v1::MAX_RETAINED_CONFLICTS,
            "additional distinct observations must not consume completion capacity"
        );

        fs::remove_file(&target).expect("remove final conflict");
        fs::rename(&admitted_target, &target).expect("restore exact approved target identity");
        let applied = MigrationExecution::run(
            RootClaim::Current {
                display_root: root.path(),
            },
            MigrationCommand::Apply {
                migration_id: &migration_id,
                approval_digest: &approval_digest,
            },
        )
        .expect("resolved transaction must still have Apply capacity");
        assert!(matches!(applied, MigrationOutcome::Applied(_)));

        let rolled_back = MigrationExecution::run(
            RootClaim::Current {
                display_root: root.path(),
            },
            MigrationCommand::Rollback {
                migration_id: &migration_id,
            },
        )
        .expect("applied transaction must retain complete Rollback capacity");
        assert!(matches!(rolled_back, MigrationOutcome::RolledBack(_)));
    }
}

#[test]
fn twelve_replace_operations_complete_the_full_apply_and_rollback_journal_lifecycle() {
    const REPLACEMENTS: usize = 12;
    let root = initialized_root();
    let mut paths = Vec::new();
    let mut operations = Vec::new();
    for index in 0..REPLACEMENTS {
        let relative = PathBuf::from(format!("workspace-{index:02}/AGENTS.md"));
        let path = root.path().join(&relative);
        fs::create_dir(path.parent().expect("adapter parent")).expect("adapter parent directory");
        fs::write(&path, format!("original adapter {index}\n")).expect("original adapter");
        paths.push((path, format!("original adapter {index}\n").into_bytes()));
        operations.push(MigrationOperation::update_adapter(
            relative,
            format!("journal-bound replacement {index}"),
        ));
    }
    let plan = MigrationPlan::propose_structural(root.path(), operations)
        .expect("multi-replace structural proposal");
    let migration_id = plan.id.clone();

    let applied = apply_migration(approve_migration(plan).expect("approve multi-replace"))
        .expect("all replacements must fit the apply journal budget");
    assert_eq!(applied.state, MigrationState::Verified);

    let rolled_back = run_transaction_v1_with_hook(
        root.path(),
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
        |_| {},
    )
    .expect("all replacement restores must fit the rollback journal budget");
    assert!(matches!(rolled_back, MigrationOutcome::RolledBack(_)));
    for (path, original) in paths {
        assert_eq!(
            fs::read(path).expect("restored adapter"),
            original,
            "rollback restores every original adapter"
        );
    }
}

#[test]
fn approved_manifest_transition_rolls_back_to_the_exact_initial_fact() {
    let root = initialized_root();
    let manifest = root.path().join(".folderbase/manifest.json");
    let before = fs::read(&manifest).expect("initial manifest");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::change_kind(
            crate::model::FolderbaseKind::Organization,
        )],
    )
    .expect("kind-change proposal");
    let migration_id = plan.id.clone();
    apply_migration(approve_migration(plan).expect("approve kind change"))
        .expect("apply kind change");

    let rolled_back = run_transaction_v1_with_hook(
        root.path(),
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
        |_| {},
    )
    .expect("rollback owned manifest transition");
    assert!(
        matches!(rolled_back, MigrationOutcome::RolledBack(_)),
        "owned manifest rollback must complete: {rolled_back:?}"
    );

    assert_eq!(
        fs::read(&manifest).expect("restored manifest"),
        before,
        "rollback must restore the exact approved manifest"
    );
}

#[derive(Clone, Copy, Debug)]
enum EnvironmentLeafKind {
    Manifest,
    Ignore,
}

struct EnvironmentLeafFixture {
    root: TempDir,
    migration_id: String,
    approved: Option<ApprovedMigration>,
    path: PathBuf,
}

fn approved_environment_leaf(kind: EnvironmentLeafKind) -> EnvironmentLeafFixture {
    let root = initialized_root();
    let (path, operation) = match kind {
        EnvironmentLeafKind::Manifest => (
            root.path().join(".folderbase/manifest.json"),
            MigrationOperation::change_kind(crate::model::FolderbaseKind::Organization),
        ),
        EnvironmentLeafKind::Ignore => {
            let path = root.path().join(".folderbaseignore");
            fs::write(&path, b"node_modules/\n").expect("initial capture policy");
            (
                path,
                MigrationOperation::update_ignore_policy("node_modules/\nDerived/\n"),
            )
        }
    };
    let plan = MigrationPlan::propose_structural(root.path(), vec![operation])
        .expect("environment-leaf proposal");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approve environment-leaf update");
    EnvironmentLeafFixture {
        root,
        migration_id,
        approved: Some(approved),
        path,
    }
}

fn environment_leaf_step_index(fixture: &EnvironmentLeafFixture) -> usize {
    let program: serde_json::Value = serde_json::from_slice(
        &fs::read(program_path_for(fixture.root.path(), &fixture.migration_id))
            .expect("persisted mutation program"),
    )
    .expect("program JSON");
    let relative = fixture
        .path
        .strip_prefix(fixture.root.path())
        .expect("relative environment path")
        .to_string_lossy();
    program["steps"]
        .as_array()
        .expect("program steps")
        .iter()
        .position(|step| step["target"]["path"].as_str() == Some(relative.as_ref()))
        .expect("environment step")
}

fn current_environment_validation(fixture: &EnvironmentLeafFixture) -> Result<()> {
    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("migration filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id);
    let transaction =
        reopen_transaction_v1(&filesystem, &migration_root, None).expect("reopen transaction");
    let current = transaction
        .generations
        .last()
        .expect("current journal generation");
    validate_transaction_v1_environment(&filesystem, &transaction, current)
}

fn environment_private_claim_path(
    fixture: &EnvironmentLeafFixture,
    operation_index: usize,
    kind: &str,
) -> PathBuf {
    transaction_v1_root(fixture.root.path(), &fixture.migration_id)
        .join("claims")
        .join(format!("{operation_index:08}.{kind}.claim"))
}

#[test]
fn apply_phase_does_not_accept_the_exact_initial_environment_inode_after_private_proof() {
    for kind in [EnvironmentLeafKind::Manifest, EnvironmentLeafKind::Ignore] {
        let mut fixture = approved_environment_leaf(kind);
        let approved = fixture.approved.take().expect("approved update");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            apply_migration_with_transaction_hook(approved, |checkpoint| {
                if matches!(
                    checkpoint,
                    TransactionV1Checkpoint::PrivateApplyReceiptPersisted(_)
                ) {
                    panic!("stop at receipt-backed prepublication phase");
                }
            })
        }));
        assert!(interrupted.is_err(), "{kind:?} fixture must interrupt");
        let index = environment_leaf_step_index(&fixture);
        fs::remove_file(&fixture.path).expect("remove receipt-bound published environment leaf");
        fs::hard_link(
            environment_private_claim_path(&fixture, index, "source"),
            &fixture.path,
        )
        .expect("reinstall exact initial inode at the wrong phase");

        assert!(
            current_environment_validation(&fixture).is_err(),
            "{kind:?} apply phase must require absence backed by its private receipt, not accept \
             the exact pre-state inode"
        );
    }
}

#[test]
fn apply_phase_propagates_an_initial_manifest_integrity_error() {
    let mut fixture = approved_environment_leaf(EnvironmentLeafKind::Manifest);
    let approved = fixture.approved.take().expect("approved update");
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_transaction_hook(approved, |checkpoint| {
            if matches!(checkpoint, TransactionV1Checkpoint::ApplyIntentPersisted(_)) {
                panic!("stop before the environment claim");
            }
        })
    }));
    assert!(interrupted.is_err(), "fixture must interrupt");
    fs::remove_file(&fixture.path).expect("remove exact manifest");
    fs::create_dir(&fixture.path).expect("install invalid manifest directory");

    let error = current_environment_validation(&fixture)
        .expect_err("invalid manifest shape must fail with its exact integrity error");
    assert!(
        matches!(error, FolderbaseError::UnsafePath(ref path) if path == &fixture.path),
        "the phase validator must not swallow the exact no-follow integrity error: {error:?}"
    );
}

#[test]
fn rollback_phase_requires_the_exact_new_restored_environment_identity() {
    for kind in [EnvironmentLeafKind::Manifest, EnvironmentLeafKind::Ignore] {
        let mut fixture = approved_environment_leaf(kind);
        apply_migration(fixture.approved.take().expect("approved update"))
            .expect("apply environment update");
        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            run_transaction_v1_with_hook(
                fixture.root.path(),
                MigrationCommand::Rollback {
                    migration_id: &fixture.migration_id,
                },
                |checkpoint| {
                    if matches!(
                        checkpoint,
                        TransactionV1Checkpoint::PrivateRollbackReceiptPersisted(_)
                    ) {
                        panic!("stop after rollback receipt");
                    }
                },
            )
            .expect("checkpoint must interrupt rollback");
        }));
        assert!(interrupted.is_err(), "{kind:?} fixture must interrupt");
        let index = environment_leaf_step_index(&fixture);
        fs::remove_file(&fixture.path).expect("remove receipt-bound restore");
        fs::hard_link(
            environment_private_claim_path(&fixture, index, "source"),
            &fixture.path,
        )
        .expect("reinstall exact initial inode instead of receipt-bound restored inode");

        assert!(
            current_environment_validation(&fixture).is_err(),
            "{kind:?} rollback must require the exact new identity in its private receipt"
        );
    }
}

#[test]
fn mutation_program_rejects_duplicate_environment_leaf_writers_before_mutation() {
    let root = initialized_root();
    let manifest = root.path().join(".folderbase/manifest.json");
    let before = fs::read(&manifest).expect("initial manifest");
    let error = MigrationPlan::propose_structural(
        root.path(),
        vec![
            MigrationOperation::update_policy("cloud_sync", serde_json::json!("enabled")),
            MigrationOperation::change_kind(crate::model::FolderbaseKind::Organization),
        ],
    )
    .expect_err("duplicate environment writers must fail during proposal");
    assert!(matches!(
        error,
        FolderbaseError::InvalidRecord { ref message, .. }
            if message.contains("may mutate a path only once")
    ));
    assert_eq!(
        fs::read(&manifest).expect("unchanged manifest"),
        before,
        "duplicate writers must fail before the first visible mutation"
    );
}

fn apply_move_with_fact_change_after_claim(
    change: impl FnOnce(&ClosedLeafFixture),
) -> (ClosedLeafFixture, Result<MigrationResult>) {
    let mut fixture = approved_closed_leaf(ClosedLeafKind::MoveFile);
    let approved = fixture.approved.take().expect("approved move");
    let change = RefCell::new(Some(change));
    let result = apply_migration_with_transaction_hook(approved, |checkpoint| {
        if let TransactionV1Checkpoint::ClaimComplete(index) = checkpoint
            && change.borrow().is_some()
        {
            let program: serde_json::Value = serde_json::from_slice(
                &fs::read(program_path_for(fixture.root.path(), &fixture.migration_id))
                    .expect("persisted mutation program"),
            )
            .expect("persisted mutation program JSON");
            let step = &program["steps"][index];
            if step["kind"] == "move_file"
                && step["destination"]["path"].as_str()
                    == Some(
                        fixture
                            .target
                            .strip_prefix(fixture.root.path())
                            .expect("relative destination")
                            .to_string_lossy()
                            .as_ref(),
                    )
                && let Some(change) = change.borrow_mut().take()
            {
                change(&fixture);
            }
        }
    });
    assert!(
        change.borrow().is_none(),
        "fixture must change the immutable fact after claim"
    );
    (fixture, result)
}

#[test]
fn mid_apply_manifest_change_is_rejected_before_visible_publication() {
    let (fixture, result) = apply_move_with_fact_change_after_claim(|fixture| {
        fs::write(
            fixture.root.path().join(".folderbase/manifest.json"),
            br#"{"folderbase":{"id":"foreign"},"protocol_version":"0.5.0"}"#,
        )
        .expect("replace manifest bytes after claim");
    });
    assert!(result.is_err(), "changed immutable manifest must conflict");
    assert!(!fixture.target.exists(), "no destination may be published");
}

#[test]
fn mid_apply_state_identity_change_is_rejected_before_visible_publication() {
    let (fixture, result) = apply_move_with_fact_change_after_claim(|fixture| {
        let state = fixture.root.path().join(".folderbase");
        let retained = fixture.root.path().join(".folderbase-retained");
        fs::rename(&state, &retained).expect("retain approved state directory");
        fs::create_dir(&state).expect("install foreign state directory");
    });
    assert!(
        result.is_err(),
        "changed immutable state identity must conflict"
    );
    assert!(!fixture.target.exists(), "no destination may be published");
}

#[test]
fn mid_apply_capture_policy_change_is_rejected_before_visible_publication() {
    let (fixture, result) = apply_move_with_fact_change_after_claim(|fixture| {
        fs::write(
            fixture.root.path().join(".folderbaseignore"),
            b"Archive/**\n",
        )
        .expect("install foreign capture policy");
    });
    assert!(result.is_err(), "changed capture policy must conflict");
    assert!(!fixture.target.exists(), "no destination may be published");
}

#[test]
fn mid_apply_nested_boundary_change_is_rejected_before_visible_publication() {
    let (fixture, result) = apply_move_with_fact_change_after_claim(|fixture| {
        let destination_parent = fixture.target.parent().expect("destination parent");
        fs::create_dir(destination_parent.join(".folderbase"))
            .expect("install nested state marker");
        fs::write(
            destination_parent.join(".folderbase/manifest.json"),
            br#"{"protocol_version":"0.5.0"}"#,
        )
        .expect("install nested manifest marker");
    });
    assert!(
        result.is_err(),
        "changed nested boundary fact must conflict"
    );
    assert!(!fixture.target.exists(), "no destination may be published");
}

#[test]
fn mid_rollback_manifest_change_is_rejected_before_visible_restore() {
    let fixture = apply_closed_leaf(ClosedLeafKind::MoveFile);
    request_test_rollback(&fixture);
    let changed = RefCell::new(false);
    let outcome = run_transaction_v1_with_hook(
        fixture.root.path(),
        MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
        |checkpoint| {
            if checkpoint
                == TransactionV1Checkpoint::InverseClaimComplete(persisted_step_index(&fixture))
                && !*changed.borrow()
            {
                fs::write(
                    fixture.root.path().join(".folderbase/manifest.json"),
                    br#"{"folderbase":{"id":"foreign"},"protocol_version":"0.5.0"}"#,
                )
                .expect("replace manifest bytes during rollback");
                *changed.borrow_mut() = true;
            }
        },
    )
    .expect("rollback returns durable conflict outcome");
    assert!(
        matches!(outcome, MigrationOutcome::Conflicted { .. }),
        "changed immutable manifest must stop rollback restore"
    );
    assert!(
        !fixture.source.as_ref().expect("move source").exists(),
        "source restore must not proceed after the immutable fact changes"
    );
}

#[test]
fn changed_source_and_destination_parent_identities_fail_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let root = fixture.root.path();
    remove_transitional_legacy_result(&fixture);

    let source_parent = fixture.source.parent().expect("source parent");
    let retained_source_parent = root.join("retained-source-parent");
    fs::rename(source_parent, &retained_source_parent).expect("retain original source parent");
    fs::create_dir(source_parent).expect("replacement source parent");
    fs::hard_link(
        retained_source_parent.join(fixture.source.file_name().expect("source name")),
        &fixture.source,
    )
    .expect("preserve exact source leaf identity");

    let destination_parent = fixture.destination.parent().expect("destination parent");
    let retained_destination_parent = root.join("retained-destination-parent");
    fs::rename(destination_parent, &retained_destination_parent)
        .expect("retain original destination parent");
    fs::create_dir(destination_parent).expect("replacement destination parent");

    let outcome = MigrationExecution::run(
        RootClaim::Current { display_root: root },
        MigrationCommand::Apply {
            migration_id: &fixture.migration_id,
            approval_digest: &fixture.approval_digest,
        },
    );

    expect_conflicted(outcome, "program-bound parent replacement at public Apply");
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

fn released_applying_journal(
    plan: &MigrationPlan,
    approval_digest: String,
    in_flight_operation: Option<usize>,
) -> MigrationJournal {
    MigrationJournal {
        protocol_version: "0.2.0".to_owned(),
        id: plan.id.clone(),
        root: plan.root.clone(),
        state: MigrationState::Applying,
        approval_digest,
        approval_scheme: Some("migration_plan_v0.2".to_owned()),
        source_inventory: plan.source_inventory.clone(),
        answers: plan.answers.clone(),
        template_references: plan.template_references.clone(),
        targets: plan.targets.clone(),
        operations: plan.operations.clone(),
        exclusions: plan.exclusions.clone(),
        plan_extensions: plan.extensions.clone(),
        materialized_folderbases: Vec::new(),
        materialized_workspace: None,
        created_paths: Vec::new(),
        completed_operations: 0,
        in_flight_operation,
        transaction_program_digest: None,
        operation_precondition_identities: Vec::new(),
        operation_result_identities: Vec::new(),
    }
}

fn released_legacy_applying_journal(
    plan: &MigrationPlan,
    approval_digest: String,
    in_flight_operation: Option<usize>,
) -> MigrationJournal {
    let mut journal = released_applying_journal(plan, approval_digest, in_flight_operation);
    journal.approval_scheme = None;
    journal.template_references.clear();
    journal.targets.clear();
    journal.plan_extensions.clear();
    journal.approval_digest =
        journal_plan_digest(&journal).expect("released legacy approval digest");
    journal
}

fn write_released_result_json(path: &Path, journal: &MigrationJournal) -> Vec<u8> {
    let mut value = serde_json::to_value(journal).expect("released result value");
    let object = value.as_object_mut().expect("released result object");
    for transaction_v1_only in [
        "transaction_program_digest",
        "operation_precondition_identities",
        "operation_result_identities",
    ] {
        object.remove(transaction_v1_only);
    }
    let mut bytes = serde_json::to_vec_pretty(&value).expect("released result bytes");
    bytes.push(b'\n');
    fs::write(path, &bytes).expect("released result.json");
    bytes
}

fn install_released_additive_outputs(plan: &MigrationPlan) -> Vec<PathBuf> {
    fn create_missing_directories(root: &Path, relative: &Path, created_paths: &mut Vec<PathBuf>) {
        let mut current = PathBuf::new();
        for component in relative.components() {
            current.push(component);
            let absolute = root.join(&current);
            if absolute.exists() {
                assert!(absolute.is_dir(), "additive parent must be a directory");
                continue;
            }
            fs::create_dir(&absolute).expect("released additive directory");
            created_paths.push(current.clone());
        }
    }

    let mut created_paths = Vec::new();
    for operation in &plan.operations {
        match operation {
            MigrationOperation::CreateFolder { path } => {
                create_missing_directories(&plan.root, path, &mut created_paths);
            }
            MigrationOperation::CopyFile {
                source_path,
                destination_path,
                expected_sha256,
            } => {
                if let Some(parent) = destination_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    create_missing_directories(&plan.root, parent, &mut created_paths);
                }
                let source = plan.root.join(source_path);
                let destination = plan.root.join(destination_path);
                fs::copy(&source, &destination).expect("released additive copy");
                assert_eq!(
                    format!(
                        "{:x}",
                        Sha256::digest(fs::read(&destination).expect("copied output"))
                    ),
                    *expected_sha256,
                    "released additive output matches its approved digest"
                );
                created_paths.push(destination_path.clone());
            }
            operation => panic!("released additive fixture contains {operation:?}"),
        }
    }
    created_paths
}

fn assert_released_result_remains_legacy_rolled_back(result_path: &Path) {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(result_path).expect("terminal released result"))
            .expect("terminal released result JSON");
    assert_eq!(value["state"], "rolled_back");
    let object = value.as_object().expect("released result object");
    for transaction_v1_only in [
        "transaction_program_digest",
        "operation_precondition_identities",
        "operation_result_identities",
    ] {
        assert!(
            !object.contains_key(transaction_v1_only),
            "legacy rollback must not add transaction-v1 field {transaction_v1_only}"
        );
    }
}

#[test]
fn legacy_only_recovery_keeps_the_released_move_semantics() {
    let (root, migration_id, approved, source, destination, source_bytes) =
        approved_structural_leaf(StructuralLeafKind::Move);
    let destination = destination.expect("move destination");
    let mut plan = approved.plan;
    fs::rename(&source, &destination).expect("released leaf transition");
    let journal = released_applying_journal(&plan, approved.approval_digest, Some(0));
    let result_path = migration_result_path(root.path(), &migration_id);
    let released_bytes = write_released_result_json(&result_path, &journal);
    let released_text = std::str::from_utf8(&released_bytes).expect("released result UTF-8");
    assert!(!released_text.contains("transaction_program_digest"));
    assert!(!released_text.contains("operation_precondition_identities"));
    assert!(!released_text.contains("operation_result_identities"));
    plan.state = MigrationState::Applying;
    persist_plan(&plan).expect("released applying plan");

    assert!(!source.exists());
    assert_eq!(
        fs::read(&destination).expect("applied destination"),
        source_bytes
    );
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect("released legacy recovery");

    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_eq!(fs::read(&source).expect("restored source"), source_bytes);
    assert!(!destination.exists());
}

#[test]
fn released_terminal_result_states_reopen_semantically_without_byte_rewrite() {
    for state in [
        MigrationState::Verified,
        MigrationState::Conflicted,
        MigrationState::RolledBack,
    ] {
        let root = tempfile::tempdir().expect("ordinary source folder");
        fs::write(root.path().join("README.md"), b"released terminal state\n").expect("source");
        let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
        let answers = typed_answers(&analysis);
        let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
        let migration_id = plan.id.clone();
        let approved = approve_migration(plan).expect("approved migration");
        let mut plan = approved.plan;
        let mut journal = released_legacy_applying_journal(&plan, approved.approval_digest, None);
        journal.state = state;
        if state == MigrationState::Verified {
            let created = install_released_additive_outputs(&plan);
            journal.created_paths = created;
            journal.completed_operations = journal.operations.len();
        }
        let result_path = migration_result_path(root.path(), &migration_id);
        let released_bytes = write_released_result_json(&result_path, &journal);
        plan.state = state;
        persist_plan(&plan).expect("released terminal plan");

        let outcome = MigrationExecution::run(
            RootClaim::Current {
                display_root: root.path(),
            },
            MigrationCommand::Recover {
                migration_id: &migration_id,
            },
        )
        .expect("released terminal recovery");
        match state {
            MigrationState::Verified => {
                assert!(matches!(
                    outcome,
                    MigrationOutcome::Applied(MigrationResult {
                        state: MigrationState::Verified,
                        ..
                    })
                ));
            }
            MigrationState::Conflicted => {
                let MigrationOutcome::Conflicted { conflicts, .. } = outcome else {
                    panic!("released conflicted result must remain a semantic conflict");
                };
                assert_eq!(conflicts.len(), 1);
                assert_eq!(
                    conflicts[0].direction,
                    MigrationConflictDirection::LegacyUnknown,
                    "a released conflict does not prove whether Apply or Rollback was active"
                );
                assert_eq!(
                    serde_json::to_value(conflicts[0].direction)
                        .expect("serialize legacy conflict direction"),
                    serde_json::json!("legacy_unknown")
                );
            }
            MigrationState::RolledBack => {
                assert!(matches!(
                    outcome,
                    MigrationOutcome::RolledBack(RollbackResult {
                        state: MigrationState::RolledBack,
                        ..
                    })
                ));
            }
            _ => unreachable!(),
        }
        assert_eq!(
            fs::read(&result_path).expect("released result remains"),
            released_bytes,
            "terminal {state:?} result.json must remain byte-exact"
        );
        assert!(!transaction_v1_root(root.path(), &migration_id).exists());

        let reopened = MigrationResult::recover(root.path(), &migration_id)
            .expect("released compatibility adapter must preserve terminal legacy state");
        assert_eq!(reopened.state, state);
        assert_eq!(
            fs::read(&result_path).expect("released result remains"),
            released_bytes,
            "adapter must preserve terminal {state:?} result.json byte-exactly"
        );
        assert!(!transaction_v1_root(root.path(), &migration_id).exists());
    }
}

#[test]
fn released_result_recover_adapter_uses_legacy_recovery_for_applying() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    fs::write(root.path().join("README.md"), b"released applying\n").expect("source");
    let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approved migration");
    let mut plan = approved.plan;
    let journal = released_legacy_applying_journal(&plan, approved.approval_digest, None);
    let result_path = migration_result_path(root.path(), &migration_id);
    let released_bytes = write_released_result_json(&result_path, &journal);
    plan.state = MigrationState::Applying;
    persist_plan(&plan).expect("released applying plan");

    let recovered = MigrationResult::recover(root.path(), &migration_id)
        .expect("released adapter must dispatch Applying through legacy Recover");

    assert_eq!(recovered.state, MigrationState::RolledBack);
    assert_ne!(
        fs::read(&result_path).expect("terminal released result"),
        released_bytes,
        "active legacy recovery is expected to durably advance result.json"
    );
    assert_released_result_remains_legacy_rolled_back(&result_path);
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());
}

#[test]
fn released_result_recover_adapter_uses_legacy_recovery_for_rolling_back() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    let source = root.path().join("README.md");
    fs::write(&source, b"released rolling back\n").expect("source");
    let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approved migration");
    let mut plan = approved.plan;
    let created_paths = install_released_additive_outputs(&plan);
    let mut journal = released_legacy_applying_journal(&plan, approved.approval_digest, None);
    journal.state = MigrationState::RollingBack;
    journal.completed_operations = journal.operations.len();
    journal.created_paths = created_paths.clone();
    let result_path = migration_result_path(root.path(), &migration_id);
    let released_bytes = write_released_result_json(&result_path, &journal);
    plan.state = MigrationState::Verified;
    persist_plan(&plan).expect("released verified plan with rolling-back journal");

    let recovered = MigrationResult::recover(root.path(), &migration_id)
        .expect("released adapter must dispatch RollingBack through legacy Recover");
    assert_eq!(recovered.state, MigrationState::RolledBack);
    for path in &created_paths {
        assert!(!root.path().join(path).exists());
    }
    assert_ne!(
        fs::read(&result_path).expect("terminal result"),
        released_bytes,
        "nonterminal RollingBack is expected to advance durably"
    );
    assert_released_result_remains_legacy_rolled_back(&result_path);
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());
}

#[test]
fn released_legacy_result_recovery_rejects_non_execution_states_without_rewrite() {
    for state in [
        MigrationState::Analyzing,
        MigrationState::Questions,
        MigrationState::Proposed,
        MigrationState::Approved,
        MigrationState::Rejected,
    ] {
        let root = tempfile::tempdir().expect("ordinary source folder");
        fs::write(
            root.path().join("README.md"),
            b"unsupported released state\n",
        )
        .expect("source");
        let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
        let answers = typed_answers(&analysis);
        let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
        let migration_id = plan.id.clone();
        let approved = approve_migration(plan).expect("approved migration");
        let mut plan = approved.plan;
        let mut journal = released_legacy_applying_journal(&plan, approved.approval_digest, None);
        journal.state = state;
        let result_path = migration_result_path(root.path(), &migration_id);
        let released_bytes = write_released_result_json(&result_path, &journal);
        plan.state = state;
        persist_plan(&plan).expect("unsupported released-state plan");

        MigrationResult::recover(root.path(), &migration_id)
            .expect_err("non-execution released state must fail closed at the adapter boundary");
        assert_eq!(
            fs::read(&result_path).expect("unsupported result remains"),
            released_bytes,
            "unsupported {state:?} result.json must remain byte-exact"
        );
        assert!(!transaction_v1_root(root.path(), &migration_id).exists());
    }
}

#[test]
fn legacy_only_verified_additive_rollback_keeps_the_released_result_semantics() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    let source = root.path().join("README.md");
    let source_bytes = b"released additive source\n";
    fs::write(&source, source_bytes).expect("ordinary source");
    let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approved additive migration");
    let mut plan = approved.plan;
    let created_paths = install_released_additive_outputs(&plan);
    assert!(
        !created_paths.is_empty(),
        "fixture must install additive outputs"
    );

    let mut journal = released_legacy_applying_journal(&plan, approved.approval_digest, None);
    journal.state = MigrationState::Verified;
    journal.completed_operations = journal.operations.len();
    journal.created_paths = created_paths.clone();
    let result_path = migration_result_path(root.path(), &migration_id);
    write_released_result_json(&result_path, &journal);
    plan.state = MigrationState::Verified;
    persist_plan(&plan).expect("released verified plan");
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    )
    .expect("released additive rollback");

    let MigrationOutcome::RolledBack(rollback) = outcome else {
        panic!("released additive Rollback must return RolledBack");
    };
    assert_eq!(rollback.state, MigrationState::RolledBack);
    assert_eq!(
        fs::read(&source).expect("ordinary source remains"),
        source_bytes
    );
    for created in &created_paths {
        assert!(
            !root.path().join(created).exists(),
            "released additive path survives rollback: {}",
            created.display()
        );
    }
    assert_eq!(
        MigrationResult::reopen(root.path(), &migration_id)
            .expect("reopen released additive rollback")
            .state,
        MigrationState::RolledBack
    );
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .expect("reopen released additive plan")
            .state,
        MigrationState::RolledBack
    );
    assert_released_result_remains_legacy_rolled_back(&result_path);
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());

    let terminal_bytes = fs::read(&result_path).expect("terminal released result");
    let repeated = MigrationResult::rollback_by_id(root.path(), &migration_id)
        .expect("repeated semantic rollback must be terminal-idempotent");
    assert_eq!(repeated.state, MigrationState::RolledBack);
    assert!(repeated.removed_paths.is_empty());
    assert_eq!(
        fs::read(&result_path).expect("terminal released result"),
        terminal_bytes,
        "terminal-idempotent rollback must not rewrite released result.json"
    );
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());
}

#[test]
fn legacy_only_verified_structural_move_rollback_keeps_the_released_result_semantics() {
    let (root, migration_id, approved, source, destination, source_bytes) =
        approved_structural_leaf(StructuralLeafKind::Move);
    let destination = destination.expect("move destination");
    let mut plan = approved.plan;
    fs::rename(&source, &destination).expect("released verified Move");

    let mut journal = released_applying_journal(&plan, approved.approval_digest, None);
    journal.state = MigrationState::Verified;
    journal.completed_operations = journal.operations.len();
    let result_path = migration_result_path(root.path(), &migration_id);
    write_released_result_json(&result_path, &journal);
    plan.state = MigrationState::Verified;
    persist_plan(&plan).expect("released verified plan");
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    )
    .expect("released structural Move rollback");

    let MigrationOutcome::RolledBack(rollback) = outcome else {
        panic!("released structural Move Rollback must return RolledBack");
    };
    assert_eq!(rollback.state, MigrationState::RolledBack);
    assert_eq!(
        fs::read(&source).expect("restored Move source"),
        source_bytes
    );
    assert!(!destination.exists());
    assert_eq!(
        MigrationResult::reopen(root.path(), &migration_id)
            .expect("reopen released structural rollback")
            .state,
        MigrationState::RolledBack
    );
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .expect("reopen released structural plan")
            .state,
        MigrationState::RolledBack
    );
    assert_released_result_remains_legacy_rolled_back(&result_path);
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());
}

#[test]
fn prepared_transaction_v1_without_legacy_result_recovers_to_applied() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let result_path = migration_result_path(fixture.root.path(), &fixture.migration_id);
    remove_transitional_legacy_result(&fixture);

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: fixture.root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
    )
    .expect("prepared transaction-v1 recovery");

    assert!(
        matches!(outcome, MigrationOutcome::Applied(_)),
        "prepared transaction-v1 recovery must complete the requested apply direction"
    );
    assert!(!fixture.source.exists());
    assert_eq!(
        fs::read(&fixture.destination).expect("applied destination"),
        fixture.source_bytes
    );
    assert!(
        !result_path.exists(),
        "transaction-v1 recovery must not publish a legacy result.json"
    );
}

#[test]
fn synced_private_publish_staging_recovers_without_exposing_a_partial_final_claim() {
    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"restart-safe bytes\n")]);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            root.path(),
            MigrationCommand::Apply {
                migration_id: &migration_id,
                approval_digest: &approval_digest,
            },
            |checkpoint| {
                if matches!(
                    checkpoint,
                    TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
                ) {
                    panic!("simulate process exit after the private staging file is durable");
                }
            },
        )
    }));
    assert!(
        interrupted.is_err(),
        "fixture must stop at the staging checkpoint"
    );

    let claims = transaction_v1_root(root.path(), &migration_id).join("claims");
    let staged = fs::read_dir(&claims)
        .expect("private claims directory")
        .map(|entry| entry.expect("claim entry").file_name())
        .filter(|name| name.to_string_lossy().ends_with(".preparing"))
        .collect::<Vec<_>>();
    assert_eq!(
        staged.len(),
        1,
        "only the recoverable staging name is visible"
    );
    let final_name = staged[0]
        .to_string_lossy()
        .trim_start_matches('.')
        .trim_end_matches(".preparing")
        .to_owned();
    assert!(
        !claims.join(final_name).exists(),
        "the deterministic final claim name must not expose partial publication"
    );

    let recovered = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect("restart resumes from the verified private staging file");
    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    assert!(
        fs::read_dir(claims)
            .expect("claims after recovery")
            .all(|entry| !entry
                .expect("claim entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".preparing")),
        "recovery retires the staging name after atomic no-clobber installation"
    );
}

struct BoundPublicationFixture {
    root: TempDir,
    migration_id: String,
    claims: PathBuf,
    claim_name: String,
}

impl BoundPublicationFixture {
    fn final_claim(&self) -> PathBuf {
        self.claims.join(&self.claim_name)
    }

    fn stage(&self) -> PathBuf {
        self.claims.join(format!(".{}.preparing", self.claim_name))
    }

    fn ownership(&self) -> PathBuf {
        self.claims
            .join(format!(".{}.ownership.json", self.claim_name))
    }

    fn ownership_stage(&self) -> PathBuf {
        self.claims
            .join(format!("..{}.ownership.json.preparing", self.claim_name))
    }

    fn recover(&self) -> Result<MigrationOutcome> {
        MigrationExecution::run(
            RootClaim::Current {
                display_root: self.root.path(),
            },
            MigrationCommand::Recover {
                migration_id: &self.migration_id,
            },
        )
    }
}

fn interrupt_bound_publication(
    stop: impl Fn(TransactionV1Checkpoint) -> bool,
) -> BoundPublicationFixture {
    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"journal-bound bytes\n")]);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            root.path(),
            MigrationCommand::Apply {
                migration_id: &migration_id,
                approval_digest: &approval_digest,
            },
            |checkpoint| {
                if stop(checkpoint) {
                    let (_, journal) = latest_journal_generation(root.path(), &migration_id);
                    if journal["active_publication"].is_object() {
                        panic!("stop at journal-bound publication checkpoint");
                    }
                }
            },
        )
    }));
    assert!(interrupted.is_err(), "fixture must interrupt");
    let (_, journal) = latest_journal_generation(root.path(), &migration_id);
    let claim_name = journal["active_publication"]["claim_name"]
        .as_str()
        .expect("durable active publication claim")
        .to_owned();
    let claims = transaction_v1_root(root.path(), &migration_id).join("claims");
    BoundPublicationFixture {
        root,
        migration_id,
        claims,
        claim_name,
    }
}

fn substitute_preserving_permissions(path: &Path) -> PhysicalIdentity {
    let bytes = fs::read(path).expect("bound artifact bytes");
    let permissions = fs::metadata(path)
        .expect("bound artifact metadata")
        .permissions();
    let identity = substitute_regular(path, &bytes);
    fs::set_permissions(path, permissions).expect("preserve artifact fidelity");
    identity
}

#[test]
fn coherent_same_byte_new_inode_stage_and_sidecar_are_rejected_by_the_journal_binding() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
        )
    });
    let stage = fixture.stage();
    let ownership = fixture.ownership();
    let stage_identity = substitute_preserving_permissions(&stage);
    let ownership_identity = substitute_preserving_permissions(&ownership);

    fixture
        .recover()
        .expect_err("coherent same-byte substitutions do not inherit publication ownership");

    assert_eq!(
        PhysicalIdentity::from_path(&stage).expect("foreign stage remains"),
        stage_identity
    );
    assert_eq!(
        PhysicalIdentity::from_path(&ownership).expect("foreign sidecar remains"),
        ownership_identity
    );
    assert!(!fixture.final_claim().exists());
}

#[test]
fn same_byte_new_inode_sidecar_is_retained_when_receipted_cleanup_rejects_it() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::JournalApplyReceiptPersisted(_)
        )
    });
    let ownership = fixture.ownership();
    let foreign_identity = substitute_preserving_permissions(&ownership);

    fixture
        .recover()
        .expect_err("cleanup requires the exact journal-bound ownership sidecar");

    assert_eq!(
        PhysicalIdentity::from_path(&ownership).expect("foreign sidecar remains"),
        foreign_identity
    );
}

#[test]
fn fidelity_only_sidecar_tampering_is_retained_when_cleanup_rejects_it() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::JournalApplyReceiptPersisted(_)
        )
    });
    let ownership = fixture.ownership();
    let mut permissions = fs::metadata(&ownership)
        .expect("ownership metadata")
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&ownership, permissions).expect("tamper sidecar fidelity");

    fixture
        .recover()
        .expect_err("cleanup rejects fidelity-only sidecar tampering");

    assert!(ownership.exists(), "tampered sidecar remains for review");
    assert!(
        fs::metadata(&ownership)
            .expect("tampered sidecar metadata")
            .permissions()
            .readonly()
    );
}

#[test]
fn bound_ownership_staging_recovers_before_claim_installation() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
        )
    });
    fs::rename(fixture.ownership(), fixture.ownership_stage())
        .expect("leave exact bound sidecar at its recoverable staging name");

    let recovered = fixture
        .recover()
        .expect("journal binding authorizes exact ownership staging recovery");

    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    assert!(!fixture.ownership_stage().exists());
}

#[test]
fn unbound_private_publication_staging_is_retained_and_reported() {
    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"unbound staging\n")]);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            root.path(),
            MigrationCommand::Apply {
                migration_id: &migration_id,
                approval_digest: &approval_digest,
            },
            |checkpoint| {
                if matches!(checkpoint, TransactionV1Checkpoint::ApplyIntentPersisted(_)) {
                    panic!("stop before any publication binding");
                }
            },
        )
    }));
    assert!(interrupted.is_err());
    let claims = transaction_v1_root(root.path(), &migration_id).join("claims");
    let unbound = claims.join(".00000000.publish.claim.preparing");
    fs::write(&unbound, b"unbound but retained\n").expect("unbound staging artifact");

    MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect_err("unbound staging has no mutation authority");

    assert_eq!(
        fs::read(&unbound).expect("unbound staging remains"),
        b"unbound but retained\n"
    );
}

#[test]
fn foreign_staging_beside_an_exact_final_claim_is_rejected_and_retained() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
        )
    });
    fs::rename(fixture.stage(), fixture.final_claim()).expect("install exact final claim");
    fs::write(fixture.stage(), b"foreign staging peer\n").expect("foreign staging peer");

    fixture
        .recover()
        .expect_err("a foreign staging peer cannot accompany the exact final claim");

    assert_eq!(
        fs::read(fixture.stage()).expect("foreign staging remains"),
        b"foreign staging peer\n"
    );
    assert!(fixture.final_claim().exists());
}

#[test]
fn exact_two_link_private_publication_converges_but_a_mismatch_does_not() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
        )
    });
    fs::hard_link(fixture.stage(), fixture.final_claim())
        .expect("leave exact final-link checkpoint");
    let recovered = fixture
        .recover()
        .expect("exact two-link publication converges");
    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    assert!(!fixture.stage().exists());

    let mismatch = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
        )
    });
    fs::rename(mismatch.stage(), mismatch.final_claim()).expect("install exact final");
    fs::write(mismatch.stage(), b"mismatched peer\n").expect("mismatched peer");
    mismatch
        .recover()
        .expect_err("mismatched final/staging topology is retained");
    assert!(mismatch.stage().exists());
    assert!(mismatch.final_claim().exists());
}

#[test]
fn crash_after_journal_receipt_before_publication_cleanup_converges() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::JournalApplyReceiptPersisted(_)
        )
    });
    assert!(fixture.ownership().exists());
    assert!(
        latest_journal_generation(fixture.root.path(), &fixture.migration_id)
            .1["active_publication"]
            .is_object()
    );

    let recovered = fixture
        .recover()
        .expect("receipt-backed publication cleanup resumes");

    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    assert!(!fixture.ownership().exists());
    assert!(
        latest_journal_generation(fixture.root.path(), &fixture.migration_id)
            .1
            .get("active_publication")
            .is_none()
    );
}

#[test]
fn crash_after_publication_cleanup_before_binding_clear_converges() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::PrivatePublicationOwnershipRetired(_)
        )
    });
    assert!(!fixture.ownership().exists());
    assert!(
        latest_journal_generation(fixture.root.path(), &fixture.migration_id)
            .1["active_publication"]
            .is_object()
    );

    let recovered = fixture
        .recover()
        .expect("cleanup-before-clear is idempotent");

    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    assert!(
        latest_journal_generation(fixture.root.path(), &fixture.migration_id)
            .1
            .get("active_publication")
            .is_none()
    );
}

#[test]
fn checksum_valid_unreceipted_publication_clear_is_rejected_by_the_journal_grammar() {
    let fixture = interrupt_bound_publication(|checkpoint| {
        matches!(
            checkpoint,
            TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
        )
    });
    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("migration filesystem");
    let transaction = reopen_transaction_v1(
        &filesystem,
        &PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id),
        None,
    )
    .expect("unreceipted bound transaction");
    let constructor_error = transaction
        .generations
        .last()
        .expect("journal head")
        .next_private_publication_cleared(&transaction.program)
        .expect_err("the transition constructor also requires a durable receipt");
    assert!(
        constructor_error
            .to_string()
            .contains("matching durable receipt")
    );
    let head = journal_generation_records(fixture.root.path(), &fixture.migration_id)
        .pop()
        .expect("journal head");
    let forged = head
        .checksum_valid_forged_publication_clear()
        .expect("checksum-valid forged clear");
    append_checksum_valid_forged_generation(fixture.root.path(), &fixture.migration_id, &forged);

    let error = fixture
        .recover()
        .expect_err("an unreceipted binding cannot be cleared");

    assert!(
        error.to_string().contains("illegal state transition"),
        "the durable grammar rejects the forged clear before artifact reconciliation: {error}"
    );
}

#[test]
fn checksum_valid_postreceipt_publication_bind_is_rejected_by_the_journal_grammar() {
    let fixture = apply_closed_leaf(ClosedLeafKind::ReplaceFile);
    let binding = journal_active_publication_generation(fixture.root.path(), &fixture.migration_id);
    let (_, head) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert!(head["in_flight_operation"].is_null());
    assert!(
        head["receipts"]
            .as_array()
            .is_some_and(|receipts| !receipts.is_empty())
    );
    let head_record = journal_generation_records(fixture.root.path(), &fixture.migration_id)
        .pop()
        .expect("journal head");
    let forged = head_record
        .checksum_valid_forged_publication_bind(&binding)
        .expect("checksum-valid post-receipt bind");
    append_checksum_valid_forged_generation(fixture.root.path(), &fixture.migration_id, &forged);

    let error = public_recover(&fixture)
        .expect_err("a publication cannot be newly bound after its durable receipt");

    assert!(
        error.to_string().contains("illegal state transition"),
        "the durable grammar rejects post-receipt binding: {error}"
    );
}

#[test]
fn checksum_valid_cross_direction_publication_bind_is_rejected_by_the_journal_grammar() {
    let fixture = apply_closed_leaf(ClosedLeafKind::ReplaceFile);
    let binding = journal_active_publication_generation(fixture.root.path(), &fixture.migration_id);
    let binding_operation = binding
        .active_publication()
        .expect("active publication")
        .operation_index();
    request_test_rollback(&fixture);
    begin_test_rollback(&fixture);
    let (_, head) = latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(head["direction"], "rollback");
    assert_eq!(head["in_flight_operation"], binding_operation);
    assert_eq!(
        binding.active_publication().expect("binding").direction(),
        TransactionDirectionV1::Apply
    );
    let state = FolderbaseState::open_existing(fixture.root.path()).expect("state capability");
    let filesystem =
        MigrationFilesystem::from_state(&state, fixture.root.path()).expect("migration filesystem");
    let transaction = reopen_transaction_v1(
        &filesystem,
        &PathBuf::from(MIGRATIONS_DIR).join(&fixture.migration_id),
        None,
    )
    .expect("rollback-intent transaction");
    transaction
        .generations
        .last()
        .expect("journal head")
        .next_private_publication_bound(
            &transaction.program,
            binding.active_publication().expect("binding").clone(),
        )
        .expect_err("the transition constructor rejects a cross-direction bind");
    let head_record = journal_generation_records(fixture.root.path(), &fixture.migration_id)
        .pop()
        .expect("journal head");
    let forged = head_record
        .checksum_valid_forged_publication_bind(&binding)
        .expect("checksum-valid cross-direction bind");
    append_checksum_valid_forged_generation(fixture.root.path(), &fixture.migration_id, &forged);

    let error =
        public_recover(&fixture).expect_err("an apply publication cannot be bound during rollback");

    assert!(
        error.to_string().contains("illegal state transition"),
        "the durable grammar rejects cross-direction binding: {error}"
    );
}

#[test]
fn changed_private_publish_staging_is_retained_without_exposing_a_final_claim() {
    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"restart-safe bytes\n")]);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            root.path(),
            MigrationCommand::Apply {
                migration_id: &migration_id,
                approval_digest: &approval_digest,
            },
            |checkpoint| {
                if matches!(
                    checkpoint,
                    TransactionV1Checkpoint::PrivatePublishClaimStaged(_)
                ) {
                    panic!("simulate process exit after the private staging file is durable");
                }
            },
        )
    }));
    assert!(
        interrupted.is_err(),
        "fixture must stop after durable staging"
    );

    let claims = transaction_v1_root(root.path(), &migration_id).join("claims");
    let staged = fs::read_dir(&claims)
        .expect("private claims directory")
        .map(|entry| entry.expect("claim entry").file_name())
        .find(|name| name.to_string_lossy().ends_with(".preparing"))
        .expect("one staged private claim");
    let staged_path = claims.join(&staged);
    fs::write(&staged_path, b"changed after interruption").expect("replace the exact staged bytes");
    let final_name = staged
        .to_string_lossy()
        .trim_start_matches('.')
        .trim_end_matches(".preparing")
        .to_owned();

    MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect_err("changed private staging must fail closed");

    assert_eq!(
        fs::read(&staged_path).expect("changed staging remains"),
        b"changed after interruption"
    );
    assert!(
        !claims.join(final_name).exists(),
        "changed staging must not be promoted"
    );
}

#[test]
fn deterministic_journal_generation_staging_recovers_synced_and_final_link_checkpoints() {
    for checkpoint in ["staged_sync", "final_link"] {
        let (root, migration_id, _) =
            prepared_additive_v1_fixture_with_digest(&[("README.md", b"journal restart\n")]);
        let state = FolderbaseState::open_existing(root.path()).expect("state");
        let filesystem =
            MigrationFilesystem::from_state(&state, root.path()).expect("migration filesystem");
        let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&migration_id);
        let transaction =
            reopen_transaction_v1(&filesystem, &migration_root, None).expect("prepared journal");
        let current = transaction.generations.last().expect("prepared generation");
        let staged_generation = current
            .next_apply_intent(&transaction.program, current.operation_cursor())
            .expect("next intent");
        let staged_bytes = staged_generation
            .encode(Path::new("<staged-generation>"))
            .expect("encoded intent");
        let staging = transaction_v1_root(root.path(), &migration_id)
            .join("journal")
            .join(JOURNAL_GENERATION_STAGING_NAME);
        fs::write(&staging, staged_bytes).expect("process-kill staging bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))
                .expect("private staging mode");
        }
        if checkpoint == "final_link" {
            fs::hard_link(
                &staging,
                staging.with_file_name(staged_generation.file_name()),
            )
            .expect("final link published before staging retirement");
        }

        let recovered = MigrationExecution::run(
            RootClaim::Current {
                display_root: root.path(),
            },
            MigrationCommand::Recover {
                migration_id: &migration_id,
            },
        )
        .expect("restart repairs or completes the one bounded staging name");
        assert!(matches!(recovered, MigrationOutcome::Applied(_)));
        assert!(!staging.exists(), "staging is retired after recovery");
        let reopened =
            reopen_transaction_v1(&filesystem, &migration_root, None).expect("contiguous journal");
        assert_eq!(
            reopened
                .generations
                .last()
                .expect("terminal generation")
                .phase(),
            TransactionPhaseV1::Applied
        );
    }
}

#[test]
fn partial_journal_generation_staging_is_retained_and_reported() {
    let (root, migration_id, _) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"journal restart\n")]);
    let staging = transaction_v1_root(root.path(), &migration_id)
        .join("journal")
        .join(JOURNAL_GENERATION_STAGING_NAME);
    fs::write(&staging, b"{\"partial\":").expect("leave partial journal staging");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))
            .expect("private staging mode");
    }

    MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect_err("partial journal staging must fail closed");

    assert_eq!(
        fs::read(&staging).expect("partial staging is retained"),
        b"{\"partial\":"
    );
}

#[test]
fn zero_byte_uncommitted_journal_write_is_discarded_before_recovery() {
    let (root, migration_id, _) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"journal restart\n")]);
    let writing = transaction_v1_root(root.path(), &migration_id)
        .join("journal")
        .join(JOURNAL_GENERATION_WRITE_NAME);
    fs::write(&writing, []).expect("interrupt after creating the journal write scratch");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&writing, fs::Permissions::from_mode(0o600))
            .expect("private write scratch mode");
    }

    let recovered = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect("an uncommitted journal write is not a durable malformed stage");

    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    assert!(
        !writing.exists(),
        "recovery retires the uncommitted scratch"
    );
}

#[test]
fn generation_zero_singleton_staging_recovers_after_final_install_is_interrupted() {
    let (root, migration_id, _) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"generation zero\n")]);
    let journal = transaction_v1_root(root.path(), &migration_id).join("journal");
    let generation_zero = journal.join("00000000000000000000.json");
    let staging = journal.join(JOURNAL_GENERATION_STAGING_NAME);
    fs::rename(&generation_zero, &staging)
        .expect("model synced generation zero before final no-clobber install");

    let recovered = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect("generation-zero singleton staging must be a recoverable journal state");

    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
    assert!(generation_zero.is_file());
    assert!(!staging.exists());
}

#[test]
fn public_apply_rebuilds_every_provable_prepared_prefix_without_ordinary_mutation() {
    for checkpoint in [
        "transaction_root",
        "directory_prefix",
        "private_blob_staging",
        "program_staging",
        "program_final",
        "journal_staging",
    ] {
        let (root, migration_id, approval_digest) =
            prepared_additive_v1_fixture_with_digest(&[("README.md", b"prepared prefix\n")]);
        let transaction = transaction_v1_root(root.path(), &migration_id);
        let journal = transaction.join("journal");
        let generation_zero = journal.join("00000000000000000000.json");
        match checkpoint {
            "transaction_root" => {
                fs::remove_dir_all(&transaction).expect("remove prepared transaction");
                fs::create_dir(&transaction).expect("leave only the transaction root");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&transaction, fs::Permissions::from_mode(0o700))
                        .expect("private transaction root mode");
                }
            }
            "directory_prefix" => {
                for entry in fs::read_dir(&transaction).expect("transaction entries") {
                    let entry = entry.expect("transaction entry");
                    if entry.file_type().expect("entry type").is_dir() {
                        fs::remove_dir_all(entry.path()).expect("remove private directory");
                    } else {
                        fs::remove_file(entry.path()).expect("remove private file");
                    }
                }
                fs::create_dir(&journal).expect("leave the first private child");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&journal, fs::Permissions::from_mode(0o700))
                        .expect("private journal mode");
                }
            }
            "private_blob_staging" => {
                fs::remove_file(&generation_zero).expect("remove prepared generation");
                fs::remove_file(transaction.join("program.json")).expect("remove program");
                let stages = transaction.join("stages");
                let mut blobs = fs::read_dir(&stages)
                    .expect("private stages")
                    .map(|entry| entry.expect("private blob").path())
                    .collect::<Vec<_>>();
                blobs.sort();
                let blob = blobs.into_iter().next().expect("one private blob");
                let blob_name = blob
                    .file_name()
                    .expect("private blob name")
                    .to_string_lossy();
                fs::rename(&blob, stages.join(format!(".{blob_name}.preparing")))
                    .expect("leave synced private blob staging");
            }
            "program_staging" => {
                fs::remove_file(&generation_zero).expect("remove prepared generation");
                fs::rename(
                    transaction.join("program.json"),
                    transaction.join(".program.json.preparing"),
                )
                .expect("leave synced program staging");
            }
            "program_final" => {
                fs::remove_file(&generation_zero).expect("leave final program before journal");
            }
            "journal_staging" => {
                fs::rename(
                    &generation_zero,
                    journal.join(JOURNAL_GENERATION_STAGING_NAME),
                )
                .expect("leave synced initial journal staging");
            }
            _ => unreachable!("bounded checkpoint table"),
        }

        let outcome = MigrationExecution::run(
            RootClaim::Current {
                display_root: root.path(),
            },
            MigrationCommand::Apply {
                migration_id: &migration_id,
                approval_digest: &approval_digest,
            },
        )
        .unwrap_or_else(|error| panic!("{checkpoint} must be recoverable: {error:?}"));
        assert!(
            matches!(outcome, MigrationOutcome::Applied(_)),
            "{checkpoint} must resume through the public execution boundary"
        );
        assert_eq!(
            fs::read(root.path().join("Organized/README.md"))
                .expect("applied ordinary destination"),
            b"prepared prefix\n"
        );
    }
}

#[test]
fn public_apply_rejects_ambiguous_prepared_prefix_without_ordinary_mutation() {
    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"foreign prefix\n")]);
    let transaction = transaction_v1_root(root.path(), &migration_id);
    fs::remove_file(transaction.join("journal/00000000000000000000.json"))
        .expect("remove durable prepared generation");
    fs::write(
        transaction.join("foreign.bin"),
        b"not a Core creation checkpoint",
    )
    .expect("install foreign private artifact");
    let source = root.path().join("README.md");
    let source_identity = PhysicalIdentity::from_path(&source).expect("source identity");

    MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect_err("ambiguous private state must fail closed");

    assert_eq!(
        PhysicalIdentity::from_path(&source).expect("source survives"),
        source_identity
    );
    assert!(!root.path().join("Organized").exists());
}

#[test]
fn released_result_recover_adapter_conservatively_rolls_back_prepared_transaction_v1() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);

    let result = MigrationResult::recover(fixture.root.path(), &fixture.migration_id)
        .expect("released recovery adapter must preserve conservative rollback semantics");

    assert_eq!(result.state, MigrationState::RolledBack);
    assert_eq!(
        fs::read(&fixture.source).expect("source remains after conservative recovery"),
        fixture.source_bytes
    );
    assert!(
        !fixture.destination.exists(),
        "the released adapter must not resume the prepared apply direction"
    );
}

#[test]
fn active_legacy_result_and_transaction_v1_coexistence_fails_closed() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let source_identity = PhysicalIdentity::from_path(&fixture.source).expect("source identity");
    remove_transitional_legacy_result(&fixture);
    let plan =
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id).expect("approved plan");
    let result_path = migration_result_path(fixture.root.path(), &fixture.migration_id);
    let journal = released_applying_journal(&plan, fixture.approval_digest.clone(), None);
    let released_bytes = write_released_result_json(&result_path, &journal);

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: fixture.root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
    );

    assert!(
        outcome.is_err(),
        "coexisting active legacy and transaction-v1 formats must fail closed"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.source).expect("source remains"),
        source_identity
    );
    assert!(!fixture.destination.exists());
    assert_eq!(
        fs::read(&result_path).expect("legacy result remains"),
        released_bytes,
        "format dispatch must not rewrite either active state before rejecting coexistence"
    );
}

#[derive(Clone, Copy, Debug)]
enum PublicFormatCommand {
    Recover,
    Rollback,
}

type RawTreeEntry = (
    PathBuf,
    &'static str,
    PhysicalIdentity,
    Option<Vec<u8>>,
    Option<u32>,
);

fn run_public_format_command(
    root: &Path,
    migration_id: &str,
    command: PublicFormatCommand,
) -> Result<MigrationOutcome> {
    let command = match command {
        PublicFormatCommand::Recover => MigrationCommand::Recover { migration_id },
        PublicFormatCommand::Rollback => MigrationCommand::Rollback { migration_id },
    };
    MigrationExecution::run(RootClaim::Current { display_root: root }, command)
}

fn raw_tree_snapshot(root: &Path) -> Vec<RawTreeEntry> {
    let mut snapshot = walkdir::WalkDir::new(root)
        .min_depth(1)
        .into_iter()
        .map(|entry| entry.expect("execution-state entry"))
        .map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type();
            let kind = if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "regular"
            } else {
                "other"
            };
            let bytes = file_type
                .is_file()
                .then(|| fs::read(path).expect("execution-state bytes"));
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;

                Some(
                    fs::symlink_metadata(path)
                        .expect("execution-state metadata")
                        .permissions()
                        .mode(),
                )
            };
            #[cfg(not(unix))]
            let mode = None;
            (
                path.strip_prefix(root)
                    .expect("execution-state relative path")
                    .to_path_buf(),
                kind,
                PhysicalIdentity::from_path(path).expect("execution-state identity"),
                bytes,
                mode,
            )
        })
        .collect::<Vec<_>>();
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}

#[test]
fn public_apply_rejects_legacy_and_transaction_v1_coexistence_before_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let plan =
        MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id).expect("approved plan");
    let result_path = migration_result_path(fixture.root.path(), &fixture.migration_id);
    let journal = released_applying_journal(&plan, fixture.approval_digest.clone(), None);
    let released_bytes = write_released_result_json(&result_path, &journal);
    let transaction_root = transaction_v1_root(fixture.root.path(), &fixture.migration_id);
    let transaction_identity =
        PhysicalIdentity::from_path(&transaction_root).expect("transaction identity");
    let transaction_snapshot = raw_tree_snapshot(&transaction_root);
    let result_identity =
        PhysicalIdentity::from_path(&result_path).expect("legacy result identity");
    let source_identity =
        PhysicalIdentity::from_path(&fixture.source).expect("source identity before Apply");

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: fixture.root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &fixture.migration_id,
            approval_digest: &fixture.approval_digest,
        },
    );

    assert!(
        outcome.is_err(),
        "Apply must reject ambiguous active execution formats"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&transaction_root).expect("transaction remains"),
        transaction_identity
    );
    assert_eq!(
        raw_tree_snapshot(&transaction_root),
        transaction_snapshot,
        "Apply rejection must not append or rewrite transaction-v1 state"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&result_path).expect("legacy result remains"),
        result_identity
    );
    assert_eq!(
        fs::read(&result_path).expect("legacy result bytes remain"),
        released_bytes
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.source).expect("source remains"),
        source_identity
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source bytes remain"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn public_apply_rejects_wrong_approval_digest_before_transaction_v1_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let transaction_root = transaction_v1_root(fixture.root.path(), &fixture.migration_id);
    let transaction_identity =
        PhysicalIdentity::from_path(&transaction_root).expect("transaction identity");
    let transaction_snapshot = raw_tree_snapshot(&transaction_root);
    let plan_path = migration_result_path(fixture.root.path(), &fixture.migration_id)
        .with_file_name("plan.json");
    let plan_identity = PhysicalIdentity::from_path(&plan_path).expect("plan identity");
    let plan_bytes = fs::read(&plan_path).expect("plan bytes");
    let source_identity =
        PhysicalIdentity::from_path(&fixture.source).expect("source identity before Apply");
    let wrong_approval_digest = format!(
        "{:x}",
        Sha256::digest(b"wrong approval digest for transaction-v1")
    );
    assert_ne!(wrong_approval_digest, fixture.approval_digest);

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: fixture.root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &fixture.migration_id,
            approval_digest: &wrong_approval_digest,
        },
    );

    assert!(
        matches!(outcome, Err(FolderbaseError::MigrationApprovalMismatch)),
        "wrong approval digest must fail at the public Apply boundary: {outcome:?}"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&transaction_root).expect("transaction remains"),
        transaction_identity
    );
    assert_eq!(
        raw_tree_snapshot(&transaction_root),
        transaction_snapshot,
        "approval rejection must not append or rewrite transaction-v1 state"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&plan_path).expect("plan remains"),
        plan_identity
    );
    assert_eq!(fs::read(&plan_path).expect("plan bytes remain"), plan_bytes);
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.source).expect("source remains"),
        source_identity
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source bytes remain"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

fn assert_approved_root_claim_is_rejected(command: PublicFormatCommand) {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let approved = ApprovedMigration::reopen(fixture.root.path(), &fixture.migration_id)
        .expect("reopen approved token");
    let transaction_root = transaction_v1_root(fixture.root.path(), &fixture.migration_id);
    let transaction_identity =
        PhysicalIdentity::from_path(&transaction_root).expect("transaction identity");
    let transaction_snapshot = raw_tree_snapshot(&transaction_root);
    let source_identity =
        PhysicalIdentity::from_path(&fixture.source).expect("source identity before command");
    let migration_command = match command {
        PublicFormatCommand::Recover => MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
        PublicFormatCommand::Rollback => MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
    };

    let outcome = MigrationExecution::run(
        RootClaim::Approved {
            approved_migration: approved,
        },
        migration_command,
    );

    assert!(
        outcome.is_err(),
        "RootClaim::Approved must be apply-only; {command:?} must be rejected"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&transaction_root).expect("transaction remains"),
        transaction_identity
    );
    assert_eq!(
        raw_tree_snapshot(&transaction_root),
        transaction_snapshot,
        "rejected {command:?} must not append or rewrite transaction-v1 state"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.source).expect("source remains"),
        source_identity
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source bytes remain"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn approved_root_claim_is_rejected_for_public_recover() {
    assert_approved_root_claim_is_rejected(PublicFormatCommand::Recover);
}

#[test]
fn approved_root_claim_is_rejected_for_public_rollback() {
    assert_approved_root_claim_is_rejected(PublicFormatCommand::Rollback);
}

#[test]
fn state_only_additive_transaction_coordinator_owns_the_shared_lease() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    fs::write(root.path().join("README.md"), b"ordinary project context\n")
        .expect("ordinary source");
    let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
    let approved = approve_migration(plan).expect("approved additive migration");
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_hook(approved, |checkpoint| {
            if checkpoint == ApplyCheckpoint::JournalPrepared {
                panic!("leave state-only transaction-v1 prepared");
            }
        })
    }));
    assert!(interrupted.is_err(), "fixture must leave prepared state");

    let canonical = canonical_root(root.path()).expect("canonical ordinary root");
    let root_identity = RetainedPhysicalIdentity::from_path(&canonical)
        .expect("retained root identity")
        .identity();
    let coordinator = acquire_existing_folderbase_transaction_lock(&canonical, root_identity)
        .expect("state-only transaction coordinator");

    let lock_path = root.path().join(".folderbase/locks/transactions.lock");
    let competing = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("shared transaction lock file");
    assert!(
        matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "format dispatch through terminal verification requires one shared lease even before the \
         migration creates an exact Folderbase boundary"
    );
    drop(coordinator);
}

#[cfg(unix)]
#[test]
fn transaction_v1_recovery_never_mutates_a_replacement_root_after_authority_is_bound() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let visible_root = fixture.root.path().to_path_buf();
    let detached_root =
        visible_root.with_file_name(format!(".recovery-retained-{}", Uuid::now_v7()));
    let replacement_before = RefCell::new(None);

    let outcome = run_current_migration_command_with_hooks(
        &visible_root,
        MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
        || {
            fs::rename(&visible_root, &detached_root).expect("detach retained root");
            copy_tree(&detached_root, &visible_root);
            *replacement_before.borrow_mut() = Some(raw_tree_snapshot(&visible_root));
        },
        |_| {},
    );
    let replacement_after = raw_tree_snapshot(&visible_root);
    let retained_source_exists = detached_root.join("Inbox/notes.md").exists();
    let retained_destination =
        fs::read(detached_root.join("Archive/notes.md")).expect("retained recovery destination");

    fs::remove_dir_all(&visible_root).expect("remove replacement root");
    fs::rename(&detached_root, &visible_root).expect("restore retained root");

    assert!(
        matches!(outcome, Ok(MigrationOutcome::Applied(_))),
        "prepared transaction-v1 recovery must complete against the retained root: {outcome:?}"
    );
    assert!(
        !retained_source_exists,
        "recovery must retire the source in the retained root"
    );
    assert_eq!(retained_destination, fixture.source_bytes);
    assert_eq!(
        replacement_after,
        replacement_before
            .into_inner()
            .expect("replacement snapshot after authority binding"),
        "recovery must not mutate any object in the foreign replacement root"
    );
}

#[cfg(unix)]
#[test]
fn transaction_v1_rollback_never_mutates_a_replacement_root_after_authority_is_bound() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let applied = MigrationExecution::run(
        RootClaim::Current {
            display_root: fixture.root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
    )
    .expect("complete transaction-v1 Apply before Rollback");
    assert!(matches!(applied, MigrationOutcome::Applied(_)));

    let visible_root = fixture.root.path().to_path_buf();
    let detached_root =
        visible_root.with_file_name(format!(".rollback-retained-{}", Uuid::now_v7()));
    let replacement_before = RefCell::new(None);

    let outcome = run_current_migration_command_with_hooks(
        &visible_root,
        MigrationCommand::Rollback {
            migration_id: &fixture.migration_id,
        },
        || {
            fs::rename(&visible_root, &detached_root).expect("detach retained root");
            copy_tree(&detached_root, &visible_root);
            *replacement_before.borrow_mut() = Some(raw_tree_snapshot(&visible_root));
        },
        |_| {},
    );
    let replacement_after = raw_tree_snapshot(&visible_root);
    let retained_source =
        fs::read(detached_root.join("Inbox/notes.md")).expect("retained rollback source");
    let retained_destination_exists = detached_root.join("Archive/notes.md").exists();

    fs::remove_dir_all(&visible_root).expect("remove replacement root");
    fs::rename(&detached_root, &visible_root).expect("restore retained root");

    assert!(
        matches!(outcome, Ok(MigrationOutcome::RolledBack(_))),
        "transaction-v1 rollback must complete against the retained root: {outcome:?}"
    );
    assert_eq!(retained_source, fixture.source_bytes);
    assert!(
        !retained_destination_exists,
        "rollback must retire the destination in the retained root"
    );
    assert_eq!(
        replacement_after,
        replacement_before
            .into_inner()
            .expect("replacement snapshot after authority binding"),
        "rollback must not mutate any object in the foreign replacement root"
    );
}

#[test]
fn transaction_v1_recovery_holds_the_shared_lease_through_terminal_dispatch() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let recovery_root = fixture.root.path().to_path_buf();
    let recovery_id = fixture.migration_id.clone();
    let (paused_sender, paused_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let recovery = thread::spawn(move || {
        run_current_migration_command_with_hooks(
            &recovery_root,
            MigrationCommand::Recover {
                migration_id: &recovery_id,
            },
            || {
                paused_sender
                    .send(())
                    .expect("announce retained recovery coordinator");
                resume_receiver
                    .recv()
                    .expect("resume transaction-v1 recovery");
            },
            |_| {},
        )
    });
    paused_receiver
        .recv()
        .expect("recovery must reach the retained coordinator seam");

    let lock_path = fixture
        .root
        .path()
        .join(".folderbase/locks/transactions.lock");
    let competing = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("shared transaction lock file");
    assert!(
        matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "transaction-v1 Recover must exclude protocol activation after format dispatch"
    );

    resume_sender
        .send(())
        .expect("resume transaction-v1 recovery");
    let outcome = recovery
        .join()
        .expect("recovery thread")
        .expect("transaction-v1 recovery");
    assert!(matches!(outcome, MigrationOutcome::Applied(_)));
    assert!(!fixture.source.exists());
    assert_eq!(
        fs::read(&fixture.destination).expect("recovered destination"),
        fixture.source_bytes
    );
}

#[test]
fn transaction_v1_rollback_holds_the_shared_lease_through_terminal_dispatch() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    remove_transitional_legacy_result(&fixture);
    let applied = MigrationExecution::run(
        RootClaim::Current {
            display_root: fixture.root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &fixture.migration_id,
        },
    )
    .expect("complete transaction-v1 Apply before Rollback");
    assert!(matches!(applied, MigrationOutcome::Applied(_)));

    let rollback_root = fixture.root.path().to_path_buf();
    let rollback_id = fixture.migration_id.clone();
    let (paused_sender, paused_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let rollback = thread::spawn(move || {
        run_current_migration_command_with_hooks(
            &rollback_root,
            MigrationCommand::Rollback {
                migration_id: &rollback_id,
            },
            || {
                paused_sender
                    .send(())
                    .expect("announce retained rollback coordinator");
                resume_receiver
                    .recv()
                    .expect("resume transaction-v1 rollback");
            },
            |_| {},
        )
    });
    paused_receiver
        .recv()
        .expect("rollback must reach the retained coordinator seam");

    let lock_path = fixture
        .root
        .path()
        .join(".folderbase/locks/transactions.lock");
    let competing = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("shared transaction lock file");
    assert!(
        matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "transaction-v1 Rollback must exclude protocol activation after format dispatch"
    );

    resume_sender
        .send(())
        .expect("resume transaction-v1 rollback");
    let outcome = rollback
        .join()
        .expect("rollback thread")
        .expect("transaction-v1 rollback");
    assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
    assert_eq!(
        fs::read(&fixture.source).expect("restored source"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn partial_or_malformed_transaction_v1_with_valid_legacy_fails_before_mutation() {
    #[derive(Clone, Copy, Debug)]
    enum Corruption {
        MissingProgram,
        MalformedProgram,
    }

    for corruption in [Corruption::MissingProgram, Corruption::MalformedProgram] {
        let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
        remove_transitional_legacy_result(&fixture);
        let plan = MigrationPlan::reopen(fixture.root.path(), &fixture.migration_id).expect("plan");
        let result_path = migration_result_path(fixture.root.path(), &fixture.migration_id);
        let journal = released_applying_journal(&plan, fixture.approval_digest.clone(), None);
        let released_bytes = write_released_result_json(&result_path, &journal);
        let program = program_path(&fixture);
        match corruption {
            Corruption::MissingProgram => fs::remove_file(&program).expect("remove program"),
            Corruption::MalformedProgram => {
                fs::write(&program, b"{\"format\":\"truncated").expect("malformed program")
            }
        }

        let transaction_root = transaction_v1_root(fixture.root.path(), &fixture.migration_id);
        let transaction_identity =
            PhysicalIdentity::from_path(&transaction_root).expect("transaction identity");
        let transaction_snapshot = raw_tree_snapshot(&transaction_root);
        let result_identity =
            PhysicalIdentity::from_path(&result_path).expect("legacy result identity");
        let source_identity =
            PhysicalIdentity::from_path(&fixture.source).expect("source identity");

        let outcome = run_public_format_command(
            fixture.root.path(),
            &fixture.migration_id,
            PublicFormatCommand::Recover,
        );

        assert!(
            outcome.is_err(),
            "{corruption:?} transaction-v1 must not fall back to a valid legacy result"
        );
        assert_eq!(
            PhysicalIdentity::from_path(&transaction_root).expect("transaction remains"),
            transaction_identity
        );
        assert_eq!(
            raw_tree_snapshot(&transaction_root),
            transaction_snapshot,
            "transaction generations and raw records must remain unchanged"
        );
        assert_eq!(
            PhysicalIdentity::from_path(&result_path).expect("legacy result remains"),
            result_identity
        );
        assert_eq!(
            fs::read(&result_path).expect("legacy result bytes"),
            released_bytes
        );
        assert_eq!(
            PhysicalIdentity::from_path(&fixture.source).expect("source remains"),
            source_identity
        );
        assert_eq!(
            fs::read(&fixture.source).expect("source bytes"),
            fixture.source_bytes
        );
        assert!(!fixture.destination.exists());
    }
}

#[test]
fn malformed_or_unsafe_legacy_only_result_never_creates_transaction_v1() {
    #[derive(Clone, Copy, Debug)]
    enum LegacyShape {
        Malformed,
        UnsafeDirectory,
    }

    for shape in [LegacyShape::Malformed, LegacyShape::UnsafeDirectory] {
        for command in [PublicFormatCommand::Recover, PublicFormatCommand::Rollback] {
            let (root, migration_id, _approved, source, destination, source_bytes) =
                approved_structural_leaf(StructuralLeafKind::Move);
            let destination = destination.expect("move destination");
            let result_path = migration_result_path(root.path(), &migration_id);
            let plan_path = result_path.with_file_name("plan.json");
            let plan_identity = PhysicalIdentity::from_path(&plan_path).expect("plan identity");
            let plan_bytes = fs::read(&plan_path).expect("plan bytes");
            match shape {
                LegacyShape::Malformed => {
                    fs::write(&result_path, b"{\"protocol_version\":").expect("malformed result")
                }
                LegacyShape::UnsafeDirectory => {
                    fs::create_dir(&result_path).expect("unsafe result directory")
                }
            }
            let result_identity =
                PhysicalIdentity::from_path(&result_path).expect("result identity");
            let source_identity = PhysicalIdentity::from_path(&source).expect("source identity");
            let transaction_root = transaction_v1_root(root.path(), &migration_id);
            assert!(!transaction_root.exists());

            let outcome = run_public_format_command(root.path(), &migration_id, command);

            assert!(
                outcome.is_err(),
                "{shape:?} legacy result must fail for {command:?}"
            );
            assert!(
                !transaction_root.exists(),
                "legacy dispatch failure must not compile the plan into transaction-v1"
            );
            assert_eq!(
                PhysicalIdentity::from_path(&result_path).expect("result remains"),
                result_identity
            );
            match shape {
                LegacyShape::Malformed => assert_eq!(
                    fs::read(&result_path).expect("malformed result bytes"),
                    b"{\"protocol_version\":"
                ),
                LegacyShape::UnsafeDirectory => assert_eq!(
                    fs::read_dir(&result_path)
                        .expect("unsafe result directory remains")
                        .count(),
                    0
                ),
            }
            assert_eq!(
                PhysicalIdentity::from_path(&plan_path).expect("plan remains"),
                plan_identity
            );
            assert_eq!(fs::read(&plan_path).expect("plan remains"), plan_bytes);
            assert_eq!(
                PhysicalIdentity::from_path(&source).expect("source remains"),
                source_identity
            );
            assert_eq!(fs::read(&source).expect("source bytes"), source_bytes);
            assert!(!destination.exists());
        }
    }
}

fn prepared_additive_v1_fixture_with_digest(files: &[(&str, &[u8])]) -> (TempDir, String, String) {
    let root = tempfile::tempdir().expect("ordinary source folder");
    for (relative, bytes) in files {
        let path = root.path().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("source parent");
        }
        fs::write(path, bytes).expect("ordinary source file");
    }
    let analysis = analyze_migration(root.path()).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approved additive migration");
    let approval_digest = approved.approval_digest.clone();

    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_hook(approved, |checkpoint| {
            if checkpoint == ApplyCheckpoint::JournalPrepared {
                panic!("leave prepared additive transaction-v1");
            }
        })
    }));
    assert!(interrupted.is_err(), "additive fixture must interrupt");
    match fs::remove_file(migration_result_path(root.path(), &migration_id)) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => panic!("remove transitional result.json: {source}"),
    }
    (root, migration_id, approval_digest)
}

fn prepared_additive_v1_fixture(files: &[(&str, &[u8])]) -> (TempDir, String) {
    let (root, migration_id, _) = prepared_additive_v1_fixture_with_digest(files);
    (root, migration_id)
}

fn approved_additive_plan_in(root: &Path, destination: &str) -> ApprovedMigration {
    let analysis = analyze_migration(root).expect("ordinary-folder analysis");
    let answers = typed_answers(&analysis);
    approve_migration(
        plan_migration(analysis, answers, destination).expect("additive migration plan"),
    )
    .expect("approved additive migration")
}

#[test]
fn nonterminal_sibling_transaction_blocks_compile_until_that_migration_recovers() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    fs::write(root.path().join("README.md"), b"two migration plans\n").expect("source");
    let first = approved_additive_plan_in(root.path(), "First");
    let first_id = first.plan.id.clone();
    let second = approved_additive_plan_in(root.path(), "Second");
    let second_id = second.plan.id.clone();

    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_hook(first, |checkpoint| {
            if checkpoint == ApplyCheckpoint::JournalPrepared {
                panic!("leave the first transaction prepared");
            }
        })
    }));
    assert!(interrupted.is_err());

    let error = apply_migration(second)
        .expect_err("a sibling prepared transaction must block compilation of another migration");
    assert!(matches!(error, FolderbaseError::RecoveryRequired { .. }));
    assert!(
        !transaction_v1_root(root.path(), &second_id).exists(),
        "the blocked migration must not compile or publish transaction state"
    );

    let recovered = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &first_id,
        },
    )
    .expect("the requested current migration ID is admitted through the pending-work scan");
    assert!(matches!(recovered, MigrationOutcome::Applied(_)));
}

#[test]
fn forged_terminal_plan_projection_cannot_hide_a_nonterminal_sibling_transaction() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    fs::write(root.path().join("README.md"), b"durable sibling state\n").expect("source");
    let first = approved_additive_plan_in(root.path(), "First");
    let first_id = first.plan.id.clone();
    let second = approved_additive_plan_in(root.path(), "Second");
    let second_id = second.plan.id.clone();
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        apply_migration_with_hook(first, |checkpoint| {
            if checkpoint == ApplyCheckpoint::JournalPrepared {
                panic!("leave first transaction nonterminal");
            }
        })
    }));
    assert!(
        interrupted.is_err(),
        "fixture must interrupt first migration"
    );

    let first_plan = root
        .path()
        .join(MIGRATIONS_DIR)
        .join(&first_id)
        .join("plan.json");
    let mut projection: serde_json::Value =
        serde_json::from_slice(&fs::read(&first_plan).expect("first plan")).expect("plan JSON");
    projection["state"] = serde_json::json!("verified");
    let mut bytes = serde_json::to_vec_pretty(&projection).expect("forged projection");
    bytes.push(b'\n');
    fs::write(&first_plan, bytes).expect("forge terminal plan projection");

    let error = apply_migration(second)
        .expect_err("durable nonterminal journal must override the forged plan projection");
    assert!(matches!(error, FolderbaseError::RecoveryRequired { .. }));
    assert!(
        !transaction_v1_root(root.path(), &second_id).exists(),
        "blocked sibling must not publish transaction state"
    );
}

#[test]
fn sibling_scan_classifies_all_legacy_execution_states_from_result_evidence() {
    for (legacy_state, expected_terminal) in [
        (MigrationState::Applying, false),
        (MigrationState::Verified, true),
        (MigrationState::Conflicted, false),
        (MigrationState::RollingBack, false),
        (MigrationState::RolledBack, true),
    ] {
        let root = tempfile::tempdir().expect("ordinary source folder");
        fs::write(root.path().join("README.md"), b"legacy state evidence\n").expect("source");
        let analysis = analyze_migration(root.path()).expect("analysis");
        let answers = typed_answers(&analysis);
        let plan = plan_migration(analysis, answers, "Organized").expect("additive migration plan");
        let migration_id = plan.id.clone();
        let approved = approve_migration(plan).expect("approved migration");
        let mut plan = approved.plan;
        let mut journal = released_legacy_applying_journal(&plan, approved.approval_digest, None);
        if matches!(
            legacy_state,
            MigrationState::Verified | MigrationState::RollingBack
        ) {
            journal.created_paths = install_released_additive_outputs(&plan);
            journal.completed_operations = journal.operations.len();
        }
        journal.state = legacy_state;
        journal.approval_digest = journal_plan_digest(&journal).expect("legacy execution digest");
        write_released_result_json(&migration_result_path(root.path(), &migration_id), &journal);
        plan.state = MigrationState::Rejected;
        persist_plan(&plan).expect("deliberately misleading terminal plan");

        let canonical_root = root.path().canonicalize().expect("canonical root");
        let state = FolderbaseState::open_existing(&canonical_root).expect("state");
        assert_eq!(
            durable_migration_execution_is_terminal(&state, &migration_id)
                .expect("exact legacy execution classification"),
            Some(expected_terminal),
            "legacy {legacy_state:?} must be classified from result.json"
        );
    }
}

#[test]
fn sibling_scan_accepts_terminal_transaction_v1_and_rejects_corruption_or_coexistence() {
    let (root, migration_id, _) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"terminal sibling\n")]);
    let applied = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect("apply prepared transaction");
    assert!(matches!(applied, MigrationOutcome::Applied(_)));
    let canonical_root = root.path().canonicalize().expect("canonical root");
    let state = FolderbaseState::open_existing(&canonical_root).expect("state");
    assert_eq!(
        durable_migration_execution_is_terminal(&state, &migration_id)
            .expect("terminal transaction classification"),
        Some(true)
    );

    let transaction = transaction_v1_root(root.path(), &migration_id);
    fs::write(
        root.path()
            .join(MIGRATIONS_DIR)
            .join(&migration_id)
            .join("result.json"),
        b"{}",
    )
    .expect("install coexistence");
    assert!(
        durable_migration_execution_is_terminal(&state, &migration_id).is_err(),
        "coexisting execution formats must fail closed"
    );
    fs::remove_file(
        root.path()
            .join(MIGRATIONS_DIR)
            .join(&migration_id)
            .join("result.json"),
    )
    .expect("remove coexistence");
    fs::write(transaction.join("program.json"), b"{\"corrupt\":true}")
        .expect("corrupt transaction program");
    assert!(
        durable_migration_execution_is_terminal(&state, &migration_id).is_err(),
        "corrupt durable execution evidence must fail closed"
    );
}

#[test]
fn active_workspace_transactions_block_migration_before_compile() {
    for marker in [
        ".folderbase/transactions/folderbase-version-captures/active.json",
        ".folderbase/transactions/folderbase-version-restores/active.json",
        ".folderbase/transactions/folderbase-version-restores/cleanup.json",
        ".folderbase/reorganizations/active.json",
        ".folderbase/transactions/0197f831-2cc4-7000-8000-000000000001.json",
    ] {
        let root = tempfile::tempdir().expect("ordinary source folder");
        fs::write(root.path().join("README.md"), b"pending work\n").expect("source");
        let approved = approved_additive_plan_in(root.path(), "Organized");
        let migration_id = approved.plan.id.clone();
        let marker = root.path().join(marker);
        fs::create_dir_all(marker.parent().expect("marker parent")).expect("marker parent");
        fs::write(&marker, b"{}").expect("pending marker");

        let error = apply_migration(approved)
            .expect_err("active workspace work must block migration compilation");
        assert!(
            matches!(error, FolderbaseError::RecoveryRequired { .. }),
            "unexpected error for {}: {error}",
            marker.display()
        );
        assert!(!transaction_v1_root(root.path(), &migration_id).exists());
    }
}

#[test]
fn public_execution_returns_pending_work_as_a_semantic_recovery_outcome() {
    let root = tempfile::tempdir().expect("ordinary source folder");
    fs::write(root.path().join("README.md"), b"pending semantic work\n").expect("source");
    let approved = approved_additive_plan_in(root.path(), "Organized");
    let migration_id = approved.plan.id.clone();
    let approval_digest = approved.approval_digest().to_owned();
    drop(approved);
    let marker = root.path().join(".folderbase/reorganizations/active.json");
    fs::create_dir_all(marker.parent().expect("marker parent")).expect("marker parent");
    fs::write(marker, b"{}").expect("pending reorganization");

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect("pending work is a semantic execution outcome");

    let MigrationOutcome::RecoveryRequired {
        migration_id: blocked_id,
        work,
    } = outcome
    else {
        panic!("expected RecoveryRequired outcome, got {outcome:?}");
    };
    assert_eq!(blocked_id, migration_id);
    assert!(work.contains("reorganization"));
    assert!(!transaction_v1_root(root.path(), &migration_id).exists());
}

const EXPECTED_MIGRATION_ADAPTER: &[u8] = b"<!-- folderbase:begin -->\n\
# Folderbase\n\n\
Confirm this root through `.folderbase/manifest.json`, then work with its ordinary \
files using Folderbase Core context and boundary rules. Treat summaries and questions \
as optional hints, never as mutation or sharing authority.\n\
<!-- folderbase:end -->\n";

#[test]
fn public_apply_returns_durable_collision_as_conflict_data_and_rollback_converges() {
    const SOURCE: &[u8] = b"ordinary source notes\n";
    const COMPETITOR: &[u8] = b"user-owned destination competitor\n";

    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", SOURCE)]);
    let competitor = root.path().join("Organized");
    fs::write(&competitor, COMPETITOR).expect("occupy the first created pathname");
    let competitor_identity =
        PhysicalIdentity::from_path(&competitor).expect("competitor identity");

    let outcome = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect("a validated durable Apply conflict is semantic outcome data");
    let MigrationOutcome::Conflicted {
        migration_id: conflicted_id,
        conflicts,
    } = outcome
    else {
        panic!("destination collision must return Conflicted");
    };
    assert_eq!(conflicted_id, migration_id);
    assert!(!conflicts.is_empty());
    assert!(
        conflicts
            .iter()
            .all(|conflict| conflict.direction == MigrationConflictDirection::Apply)
    );
    let encoded = serde_json::to_value(&conflicts).expect("conflicts are public serializable data");
    assert_eq!(encoded[0]["direction"], "apply");
    assert!(conflicts.iter().any(|conflict| {
        conflict
            .affected_paths
            .iter()
            .any(|path| recorded_path_matches(root.path(), path, &competitor))
    }));
    assert_eq!(
        PhysicalIdentity::from_path(&competitor).expect("competitor remains"),
        competitor_identity
    );
    assert_eq!(fs::read(&competitor).expect("competitor bytes"), COMPETITOR);
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .expect("conflicted plan projection")
            .state,
        MigrationState::Conflicted
    );
    assert!(
        !migration_result_path(root.path(), &migration_id).exists(),
        "transaction-v1 Apply conflict must not publish result.json"
    );
    let (conflict_generation, _) = latest_journal_generation(root.path(), &migration_id);
    let conflict_generation_bytes =
        fs::read(&conflict_generation).expect("first durable conflict generation");
    let repeated = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect("repeated public Apply must reopen the immutable transaction");
    let MigrationOutcome::Conflicted {
        migration_id: repeated_id,
        conflicts: repeated_conflicts,
    } = repeated
    else {
        panic!("repeated collided Apply must return the same Conflicted outcome");
    };
    assert_eq!(repeated_id, migration_id);
    assert_eq!(repeated_conflicts, conflicts);
    let (repeated_generation, _) = latest_journal_generation(root.path(), &migration_id);
    assert_eq!(repeated_generation, conflict_generation);
    assert_eq!(
        fs::read(&repeated_generation).expect("unchanged durable conflict generation"),
        conflict_generation_bytes,
        "unchanged public Apply retry must not append a duplicate conflict generation"
    );

    let rollback = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    )
    .expect("explicit rollback converges the unstarted collided create");
    assert!(matches!(rollback, MigrationOutcome::RolledBack(_)));
    assert_eq!(
        PhysicalIdentity::from_path(&competitor).expect("competitor survives rollback"),
        competitor_identity
    );
    assert_eq!(
        fs::read(&competitor).expect("competitor survives rollback"),
        COMPETITOR
    );
    assert_eq!(fs::read(root.path().join("README.md")).unwrap(), SOURCE);
}

#[test]
fn stale_conflicted_head_does_not_mask_an_unrelated_execution_error() {
    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"causal conflict\n")]);
    fs::write(root.path().join("Organized"), b"competitor\n").expect("collision");
    let first = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect("first conflict");
    assert!(matches!(first, MigrationOutcome::Conflicted { .. }));

    let state = FolderbaseState::open_existing(root.path()).expect("state");
    let filesystem =
        MigrationFilesystem::from_state(&state, root.path()).expect("migration filesystem");
    let migration_root = PathBuf::from(MIGRATIONS_DIR).join(&migration_id);
    let unrelated_path = root.path().join(".folderbase/unrelated-durability-failure");
    let mapped = map_durable_transaction_v1_conflict(
        &filesystem,
        &migration_root,
        &migration_id,
        Err(FolderbaseError::io(
            &unrelated_path,
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unrelated fsync failure",
            ),
        )),
        false,
    );

    match mapped {
        Err(FolderbaseError::Io { path, source }) => {
            assert_eq!(path, unrelated_path);
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("stale conflict must not mask unrelated failure: {other:?}"),
    }
}

#[test]
fn public_apply_resumes_after_a_prepared_conflict_is_resolved() {
    const SOURCE: &[u8] = b"ordinary source notes\n";
    const COMPETITOR: &[u8] = b"temporary destination competitor\n";

    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", SOURCE)]);
    let competitor = root.path().join("Organized");
    fs::write(&competitor, COMPETITOR).expect("occupy the first created pathname");

    let first = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect("first Apply classifies the collision");
    assert!(matches!(first, MigrationOutcome::Conflicted { .. }));
    fs::remove_file(&competitor).expect("resolve the destination collision");

    let resumed = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect("resolved Apply conflict must resume the immutable transaction");
    assert!(matches!(resumed, MigrationOutcome::Applied(_)));
    assert_eq!(fs::read(root.path().join("README.md")).unwrap(), SOURCE);
    assert!(
        MigrationResult::reopen(root.path(), &migration_id).is_ok(),
        "a successful conflict retry must leave a reopenable journal"
    );
}

#[cfg(unix)]
#[test]
fn public_execution_and_result_reopen_reject_a_caller_root_symlink() {
    use std::os::unix::fs::symlink;

    let (root, migration_id, approval_digest) =
        prepared_additive_v1_fixture_with_digest(&[("README.md", b"source\n")]);
    let alias_parent = TempDir::new().expect("root alias parent");
    let alias = alias_parent.path().join("folderbase-root-link");
    symlink(root.path(), &alias).expect("caller root symlink");

    for command in [
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    ] {
        assert!(
            matches!(
                MigrationExecution::run(
                    RootClaim::Current {
                        display_root: &alias,
                    },
                    command,
                ),
                Err(FolderbaseError::UnsafePath(path)) if path == alias
            ),
            "every public command must reject the caller-supplied root symlink"
        );
    }
    assert!(
        matches!(
            MigrationResult::reopen(&alias, &migration_id),
            Err(FolderbaseError::UnsafePath(path)) if path == alias
        ),
        "result reopen must reject the caller-supplied root symlink"
    );
}

#[cfg(unix)]
#[test]
fn caller_root_substitution_after_nofollow_open_is_rejected_before_replacement_writes() {
    for command in ["apply", "recover", "rollback", "reopen"] {
        let (root, migration_id, approval_digest) =
            prepared_additive_v1_fixture_with_digest(&[("README.md", b"root authority\n")]);
        let caller_root = root.path().to_path_buf();
        let parent = caller_root.parent().expect("fixture parent");
        let nonce = Uuid::now_v7();
        let detached = parent.join(format!("detached-root-{nonce}"));
        let replacement = parent.join(format!("replacement-root-{nonce}"));
        fs::create_dir(&replacement).expect("replacement root");
        fs::write(
            replacement.join("sentinel"),
            b"replacement must remain untouched",
        )
        .expect("replacement sentinel");
        let before = raw_tree_snapshot(&replacement);

        let substitute = || {
            fs::rename(&caller_root, &detached).expect("detach initially opened root");
            fs::rename(&replacement, &caller_root).expect("substitute caller root");
        };
        let result = match command {
            "apply" => run_existing_transaction_v1_apply_with_root_hook(
                &caller_root,
                &migration_id,
                &approval_digest,
                substitute,
                |_| {},
            )
            .map(|_| ()),
            "recover" => run_current_migration_command_with_root_hook(
                &caller_root,
                MigrationCommand::Recover {
                    migration_id: &migration_id,
                },
                substitute,
                || {},
                |_| {},
            )
            .map(|_| ()),
            "rollback" => run_current_migration_command_with_root_hook(
                &caller_root,
                MigrationCommand::Rollback {
                    migration_id: &migration_id,
                },
                substitute,
                || {},
                |_| {},
            )
            .map(|_| ()),
            "reopen" => {
                reopen_migration_result_with_root_hook(&caller_root, &migration_id, substitute)
                    .map(|_| ())
            }
            _ => unreachable!("bounded command table"),
        };
        let error = result.expect_err("root substitution must fail closed");

        assert!(
            matches!(
                error,
                FolderbaseError::UnsafePath(_) | FolderbaseError::MigrationSourceChanged(_)
            ),
            "{command} must reject the replacement root: {error:?}"
        );
        assert_eq!(
            raw_tree_snapshot(&caller_root),
            before,
            "{command} replacement root must receive zero writes"
        );
        fs::remove_dir_all(&caller_root).expect("remove replacement root after assertion");
        fs::rename(&detached, &caller_root).expect("restore TempDir path for cleanup");
    }
}

#[cfg(unix)]
#[test]
fn public_apply_retains_one_root_authority_from_classification_through_new_transaction_compile() {
    let root = initialized_root();
    fs::write(root.path().join("README.md"), b"approved retained source\n").expect("source");
    let analysis = analyze_migration(root.path()).expect("analysis");
    let answers = typed_answers(&analysis);
    let plan = plan_migration(analysis, answers, "Organized").expect("migration plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approval");
    let approval_digest = approved.approval_digest().to_owned();
    drop(approved);

    let visible_root = root.path().to_path_buf();
    let detached_root =
        visible_root.with_file_name(format!(".public-apply-retained-{}", Uuid::now_v7()));
    let mut replacement_before = None;
    let outcome = run_current_transaction_v1_apply_with_hooks(
        &visible_root,
        &migration_id,
        &approval_digest,
        || {
            fs::rename(&visible_root, &detached_root).expect("detach retained Folderbase Root");
            copy_tree(&detached_root, &visible_root);
            fs::write(
                visible_root.join("README.md"),
                b"foreign replacement source must never be read\n",
            )
            .expect("foreign replacement source");
            fs::write(
                visible_root.join("replacement-only.txt"),
                b"public Apply must never observe this replacement\n",
            )
            .expect("replacement sentinel");
            replacement_before = Some(raw_tree_snapshot(&visible_root));
        },
        |_| {},
        |_| {},
    )
    .expect("public Apply must continue through its retained root authority");

    let replacement_after = raw_tree_snapshot(&visible_root);
    let retained_source =
        fs::read(detached_root.join("Organized/README.md")).expect("retained output");
    let retained_transaction =
        transaction_v1_root(&detached_root, &migration_id).join("program.json");
    let replacement_transaction = transaction_v1_root(&visible_root, &migration_id);
    let retained_transaction_exists = retained_transaction.is_file();
    let replacement_transaction_exists = replacement_transaction.exists();
    fs::remove_dir_all(&visible_root).expect("remove replacement root");
    fs::rename(&detached_root, &visible_root).expect("restore TempDir pathname");

    assert!(matches!(outcome, MigrationOutcome::Applied(_)));
    assert_eq!(retained_source, b"approved retained source\n");
    assert!(
        retained_transaction_exists,
        "new transaction state must be compiled beneath the retained root"
    );
    assert_eq!(
        replacement_after,
        replacement_before.expect("replacement snapshot"),
        "the replacement root must receive zero reads-derived or writes-visible changes"
    );
    assert!(
        !replacement_transaction_exists,
        "the replacement root must receive no transaction-v1 state"
    );
}

#[test]
fn additive_transaction_v1_recovers_materialization_and_rolls_back_its_namespace() {
    const README: &[u8] = b"ordinary source notes\n";
    const MIXED: &[u8] = b"\x00binary\xff\r\nordinary mixed bytes\n";

    let (root, migration_id) =
        prepared_additive_v1_fixture(&[("README.md", README), ("Media/mixed.dat", MIXED)]);
    let result_path = migration_result_path(root.path(), &migration_id);

    let recovered = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect("transaction-v1-only additive recovery");
    assert!(matches!(recovered, MigrationOutcome::Applied(_)));

    let organized = root.path().join("Organized");
    assert_eq!(
        fs::read(organized.join("README.md")).expect("copied text"),
        README
    );
    assert_eq!(
        fs::read(organized.join("Media/mixed.dat")).expect("copied mixed bytes"),
        MIXED
    );
    for directory in ["Media", "Decisions", "Deliverables", ".folderbase"] {
        assert!(
            organized.join(directory).is_dir(),
            "recovery must create required directory {directory}"
        );
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(organized.join(".folderbase/manifest.json")).expect("generated manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["protocol_version"], "0.5.0");
    assert_eq!(manifest["folderbase"]["kind"], "project");
    assert_eq!(
        manifest["folderbase"]["template_provenance"]["id"],
        "folderbase.project"
    );
    assert_eq!(
        manifest["folderbase"]["template_provenance"]["version"],
        "0.2.2"
    );
    assert_eq!(
        fs::read(organized.join("AGENTS.md")).expect("Codex adapter"),
        EXPECTED_MIGRATION_ADAPTER
    );
    assert_eq!(
        fs::read(organized.join("CLAUDE.md")).expect("Claude adapter"),
        EXPECTED_MIGRATION_ADAPTER
    );
    let entry = fs::read_to_string(organized.join("FOLDERBASE.md")).expect("template entry");
    for expected in [
        "## Purpose",
        "## Current state",
        "## Navigate",
        "## Operating rules",
        "## Unresolved work",
        "Review the migrated files and refine this folderbase's executive summary.",
    ] {
        assert!(
            entry.contains(expected),
            "template entry must contain {expected:?}"
        );
    }
    assert!(
        !result_path.exists(),
        "transaction-v1 recovery must not create result.json"
    );

    fs::write(
        root.path().join("unrelated-after-recovery.txt"),
        b"user-owned sibling\n",
    )
    .expect("unrelated sibling");
    let rolled_back = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    )
    .expect("transaction-v1 rollback by id");
    assert!(matches!(rolled_back, MigrationOutcome::RolledBack(_)));
    assert!(
        !organized.exists(),
        "rollback must remove the program-created namespace"
    );
    assert_eq!(fs::read(root.path().join("README.md")).unwrap(), README);
    assert_eq!(
        fs::read(root.path().join("Media/mixed.dat")).unwrap(),
        MIXED
    );
    assert_eq!(
        fs::read(root.path().join("unrelated-after-recovery.txt")).unwrap(),
        b"user-owned sibling\n"
    );
    assert!(!result_path.exists());
}

#[test]
fn additive_transaction_v1_preserves_a_copied_template_target() {
    const USER_ENTRY: &[u8] = b"# User-owned migration entry\n\n\
## Purpose\nPreserve this exact ordinary file.\n\n\
## Current state\nThe source is ready for migration.\n\n\
## Navigate\nUse `payload.bin` as the mixed-file fixture.\n\n\
## Operating rules\nDo not overwrite user-authored template targets.\n\n\
## Unresolved work\nNone.\n";
    const PAYLOAD: &[u8] = b"\x10\x00copied payload\xff\n";

    let (root, migration_id) =
        prepared_additive_v1_fixture(&[("FOLDERBASE.md", USER_ENTRY), ("payload.bin", PAYLOAD)]);
    let result_path = migration_result_path(root.path(), &migration_id);

    let recovered = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Recover {
            migration_id: &migration_id,
        },
    )
    .expect("additive recovery with occupied template target");
    assert!(matches!(recovered, MigrationOutcome::Applied(_)));

    let organized = root.path().join("Organized");
    assert_eq!(
        fs::read(organized.join("FOLDERBASE.md")).expect("preserved template target"),
        USER_ENTRY
    );
    assert_eq!(
        fs::read(organized.join("payload.bin")).expect("copied payload"),
        PAYLOAD
    );
    assert!(organized.join(".folderbase/manifest.json").is_file());
    assert_eq!(
        fs::read(organized.join("AGENTS.md")).expect("generated adapter"),
        EXPECTED_MIGRATION_ADAPTER
    );
    assert!(
        !result_path.exists(),
        "transaction-v1 recovery must not create result.json"
    );

    let rolled_back = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Rollback {
            migration_id: &migration_id,
        },
    )
    .expect("rollback preserved-target migration");
    assert!(matches!(rolled_back, MigrationOutcome::RolledBack(_)));
    assert!(!organized.exists());
    assert_eq!(
        fs::read(root.path().join("FOLDERBASE.md")).expect("source entry remains"),
        USER_ENTRY
    );
    assert_eq!(
        fs::read(root.path().join("payload.bin")).expect("source payload remains"),
        PAYLOAD
    );
    assert!(!result_path.exists());
}

#[test]
fn unreceipted_abort_adversarial_matrix_preserves_every_unowned_leaf_and_exact_private_fact() {
    #[derive(Clone, Copy, Debug)]
    enum Adversary {
        CreateFileVisibleSameByteForeign,
        ReplaceIntentSameByteForeignOriginal,
        MoveIntentSameByteForeignSource,
        MoveVisibleForeignDestination,
        CreateDirectoryClaimGainsChild,
        CreateFileVisibleClaimBytesMutated,
        ReplaceVisibleRollbackEvidenceGainsAlias,
        MoveClaimSourceClaimSameByteSubstitution,
        AbortReceiptNoncanonical,
        AbortReceiptInvalidChecksum,
        AbortReceiptSemanticIdentityMutation,
    }

    let cases = [
        (
            "create_file/V same-byte foreign visible replacement",
            Adversary::CreateFileVisibleSameByteForeign,
        ),
        (
            "replace_file/I same-byte foreign original substitution",
            Adversary::ReplaceIntentSameByteForeignOriginal,
        ),
        (
            "move_file/I same-byte foreign source substitution",
            Adversary::MoveIntentSameByteForeignSource,
        ),
        (
            "move_file/V foreign destination substitution",
            Adversary::MoveVisibleForeignDestination,
        ),
        (
            "create_directory/C mutate private empty-directory claim",
            Adversary::CreateDirectoryClaimGainsChild,
        ),
        (
            "create_file/V mutate retained regular claim bytes",
            Adversary::CreateFileVisibleClaimBytesMutated,
        ),
        (
            "replace_file/V add hard-link alias to rollback evidence",
            Adversary::ReplaceVisibleRollbackEvidenceGainsAlias,
        ),
        (
            "move_file/C replace source claim with same bytes/new inode",
            Adversary::MoveClaimSourceClaimSameByteSubstitution,
        ),
        (
            "private abort receipt rejects noncanonical JSON",
            Adversary::AbortReceiptNoncanonical,
        ),
        (
            "private abort receipt rejects invalid checksum",
            Adversary::AbortReceiptInvalidChecksum,
        ),
        (
            "private abort receipt rejects semantic identity mutation with valid checksum",
            Adversary::AbortReceiptSemanticIdentityMutation,
        ),
    ];

    let mut failures = Vec::new();
    for (label, adversary) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| match adversary {
            Adversary::CreateFileVisibleSameByteForeign => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::CreateFile),
                    LostAcknowledgement::Publish,
                );
                let operation_index = persisted_step_index(&fixture);
                let publish_claim = private_claim_path(&fixture, operation_index, "publish");
                let publish_identity = PhysicalIdentity::from_path(&publish_claim)
                    .expect("exact private publish claim");
                let publish_bytes =
                    fs::read(&publish_claim).expect("exact private publish claim bytes");
                let source = fixture.source.as_ref().expect("ordinary copy source");
                let source_identity =
                    PhysicalIdentity::from_path(source).expect("ordinary source identity");
                let source_bytes = fs::read(source).expect("ordinary source bytes");

                let visible_bytes =
                    fs::read(&fixture.target).expect("transaction-visible create output");
                let foreign_identity = substitute_regular(&fixture.target, &visible_bytes);
                assert_ne!(
                    foreign_identity, publish_identity,
                    "same bytes do not transfer transaction ownership"
                );

                request_test_rollback(&fixture);
                let outcome = public_recover(&fixture)
                    .expect("abort can discard its private create evidence around a foreign leaf");
                assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
                assert_eq!(
                    PhysicalIdentity::from_path(&fixture.target)
                        .expect("same-byte foreign visible leaf remains"),
                    foreign_identity
                );
                assert_eq!(
                    fs::read(&fixture.target).expect("same-byte foreign visible bytes remain"),
                    visible_bytes
                );
                assert_eq!(
                    PhysicalIdentity::from_path(source).expect("ordinary source remains"),
                    source_identity
                );
                assert_eq!(
                    fs::read(source).expect("ordinary source bytes remain"),
                    source_bytes
                );
                assert!(
                    !publish_claim.exists(),
                    "verified transaction-only publish evidence may be discarded, not leaked"
                );
                assert!(
                    private_abort_receipt_path(&fixture).is_file(),
                    "successful abort has one durable private receipt"
                );
                assert_eq!(
                    publish_bytes, visible_bytes,
                    "the adversary changes ownership, not approved content"
                );
            }
            Adversary::ReplaceIntentSameByteForeignOriginal => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::ReplaceFile),
                    LostAcknowledgement::Intent,
                );
                let original_bytes = fs::read(&fixture.target).expect("approved original bytes");
                let original_identity =
                    PhysicalIdentity::from_path(&fixture.target).expect("approved original");
                let foreign_identity = substitute_regular(&fixture.target, &original_bytes);
                assert_ne!(foreign_identity, original_identity);

                request_test_rollback(&fixture);
                let (_, conflicts) = expect_conflicted(
                    public_recover(&fixture),
                    "same-byte foreign Replace original before claim",
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&fixture.target)
                        .expect("foreign Replace original remains"),
                    foreign_identity
                );
                assert_eq!(
                    fs::read(&fixture.target).expect("foreign Replace bytes remain"),
                    original_bytes
                );
                assert!(!source_claim_path(&fixture).exists());
                assert!(!private_abort_receipt_path(&fixture).exists());
                assert!(
                    conflicts.iter().any(|conflict| {
                        conflict.affected_paths.iter().any(|path| {
                            recorded_path_matches(fixture.root.path(), path, &fixture.target)
                        })
                    }),
                    "conflict evidence names the foreign original"
                );
            }
            Adversary::MoveIntentSameByteForeignSource => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::MoveFile),
                    LostAcknowledgement::Intent,
                );
                let source = fixture.source.as_ref().expect("move source");
                let original_bytes = fs::read(source).expect("approved source bytes");
                let original_identity =
                    PhysicalIdentity::from_path(source).expect("approved source identity");
                let foreign_identity = substitute_regular(source, &original_bytes);
                assert_ne!(foreign_identity, original_identity);

                request_test_rollback(&fixture);
                let (_, conflicts) = expect_conflicted(
                    public_recover(&fixture),
                    "same-byte foreign Move source before claim",
                );
                assert_eq!(
                    PhysicalIdentity::from_path(source).expect("foreign Move source remains"),
                    foreign_identity
                );
                assert_eq!(
                    fs::read(source).expect("foreign Move source bytes remain"),
                    original_bytes
                );
                assert!(!fixture.target.exists());
                assert!(!source_claim_path(&fixture).exists());
                assert!(!private_abort_receipt_path(&fixture).exists());
                assert!(
                    conflicts.iter().any(|conflict| {
                        conflict
                            .affected_paths
                            .iter()
                            .any(|path| recorded_path_matches(fixture.root.path(), path, source))
                    }),
                    "conflict evidence names the foreign source"
                );
            }
            Adversary::MoveVisibleForeignDestination => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::MoveFile),
                    LostAcknowledgement::Publish,
                );
                let source = fixture.source.as_ref().expect("move source");
                let source_claim = source_claim_path(&fixture);
                let source_claim_identity =
                    PhysicalIdentity::from_path(&source_claim).expect("exact private source claim");
                let source_claim_bytes =
                    fs::read(&source_claim).expect("exact private source bytes");
                let foreign_bytes = b"foreign Move destination survives abort\n";
                let foreign_identity = substitute_regular(&fixture.target, foreign_bytes);

                request_test_rollback(&fixture);
                let outcome = public_recover(&fixture)
                    .expect("abort restores its source around a foreign destination");
                assert!(matches!(outcome, MigrationOutcome::RolledBack(_)));
                assert_eq!(
                    PhysicalIdentity::from_path(source).expect("exact source restored"),
                    source_claim_identity
                );
                assert_eq!(
                    fs::read(source).expect("exact source bytes restored"),
                    source_claim_bytes
                );
                assert!(
                    !source_claim.exists(),
                    "terminal Move abort releases its private source authority"
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&fixture.target)
                        .expect("foreign destination remains"),
                    foreign_identity
                );
                assert_eq!(
                    fs::read(&fixture.target).expect("foreign destination bytes remain"),
                    foreign_bytes
                );
            }
            Adversary::CreateDirectoryClaimGainsChild => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::CreateDirectory),
                    LostAcknowledgement::Claim,
                );
                let operation_index = persisted_step_index(&fixture);
                let publish_claim = private_claim_path(&fixture, operation_index, "publish");
                let publish_identity = PhysicalIdentity::from_path(&publish_claim)
                    .expect("private empty-directory claim");
                let child = publish_claim.join("foreign-child.txt");
                let child_bytes = b"unowned child inside private directory claim\n";
                fs::write(&child, child_bytes).expect("adversarial private child");
                let child_identity =
                    PhysicalIdentity::from_path(&child).expect("adversarial child identity");

                request_test_rollback(&fixture);
                let (before_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);
                let error = public_recover(&fixture)
                    .expect_err("nonempty private empty-directory claim must fail closed");
                let (after_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);
                assert_eq!(after_path, before_path, "failed proof appends no receipt");
                assert!(
                    error.to_string().contains(
                        publish_claim
                            .file_name()
                            .expect("publish claim name")
                            .to_string_lossy()
                            .as_ref()
                    ),
                    "failure names the corrupted private claim: {error}"
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&publish_claim)
                        .expect("mutated private directory remains"),
                    publish_identity
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&child).expect("unowned private child remains"),
                    child_identity
                );
                assert_eq!(
                    fs::read(&child).expect("unowned private child bytes remain"),
                    child_bytes
                );
                assert!(!fixture.target.exists());
            }
            Adversary::CreateFileVisibleClaimBytesMutated => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::CreateFile),
                    LostAcknowledgement::Publish,
                );
                let operation_index = persisted_step_index(&fixture);
                let publish_claim = private_claim_path(&fixture, operation_index, "publish");
                let claim_identity =
                    PhysicalIdentity::from_path(&publish_claim).expect("private publish claim");
                let foreign_bytes = b"mutated retained private regular claim bytes\n";
                fs::write(&publish_claim, foreign_bytes)
                    .expect("mutate retained private regular claim");
                assert_eq!(
                    PhysicalIdentity::from_path(&fixture.target)
                        .expect("hard-linked visible output"),
                    claim_identity
                );

                let (before_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);
                let error = public_rollback(&fixture)
                    .expect_err("mutated private regular claim must fail closed");
                let (after_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);
                assert_eq!(after_path, before_path, "failed proof appends no receipt");
                assert!(
                    error.to_string().contains(
                        publish_claim
                            .file_name()
                            .expect("publish claim name")
                            .to_string_lossy()
                            .as_ref()
                    ),
                    "failure names the mutated private claim: {error}"
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&publish_claim)
                        .expect("mutated private claim remains"),
                    claim_identity
                );
                assert_eq!(
                    fs::read(&publish_claim).expect("mutated private bytes remain"),
                    foreign_bytes
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&fixture.target)
                        .expect("mutated linked visible output remains"),
                    claim_identity
                );
                assert_eq!(
                    fs::read(&fixture.target).expect("mutated visible bytes remain"),
                    foreign_bytes
                );
            }
            Adversary::ReplaceVisibleRollbackEvidenceGainsAlias => {
                let fixture = requested_unreceipted_replace_fixture(LostAcknowledgement::Publish);
                let operation_index = persisted_step_index(&fixture.leaf);
                let rollback_claim = private_claim_path(&fixture.leaf, operation_index, "rollback");
                let alias = fixture.leaf.root.path().join("foreign-rollback-alias.bin");
                let observed = RefCell::new(false);
                let interrupted = catch_unwind(AssertUnwindSafe(|| {
                    run_transaction_v1_with_hook(
                        fixture.leaf.root.path(),
                        MigrationCommand::Recover {
                            migration_id: &fixture.leaf.migration_id,
                        },
                        |checkpoint| {
                            if checkpoint
                                == TransactionV1Checkpoint::PrivateAbortReceiptPersisted(
                                    operation_index,
                                )
                            {
                                fs::hard_link(&rollback_claim, &alias)
                                    .expect("adversarial hard-link alias");
                                *observed.borrow_mut() = true;
                                panic!("lose acknowledgement after installing rollback alias");
                            }
                        },
                    )
                    .expect("Replace abort reaches its private receipt");
                }));
                assert!(*observed.borrow(), "private abort checkpoint observed");
                assert!(interrupted.is_err(), "private abort is interrupted");
                let rollback_identity = PhysicalIdentity::from_path(&rollback_claim)
                    .expect("rollback evidence remains");
                let rollback_bytes =
                    fs::read(&rollback_claim).expect("rollback evidence bytes remain");
                assert_eq!(
                    PhysicalIdentity::from_path(&alias).expect("foreign alias exists"),
                    rollback_identity
                );

                let (before_path, _) =
                    latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
                let error = public_recover(&fixture.leaf)
                    .expect_err("new alias invalidates exact private rollback evidence");
                let (after_path, _) =
                    latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
                assert_eq!(after_path, before_path, "failed proof appends no receipt");
                assert!(
                    error.to_string().contains(
                        rollback_claim
                            .file_name()
                            .expect("rollback claim name")
                            .to_string_lossy()
                            .as_ref()
                    ),
                    "failure names the aliased rollback evidence: {error}"
                );
                assert_replace_original_restored(&fixture);
                assert_eq!(
                    PhysicalIdentity::from_path(&rollback_claim).expect("rollback claim remains"),
                    rollback_identity
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&alias).expect("foreign alias remains"),
                    rollback_identity
                );
                assert_eq!(
                    fs::read(&rollback_claim).expect("rollback evidence remains exact"),
                    rollback_bytes
                );
                assert_eq!(
                    fs::read(&alias).expect("foreign alias bytes remain"),
                    rollback_bytes
                );
            }
            Adversary::MoveClaimSourceClaimSameByteSubstitution => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::MoveFile),
                    LostAcknowledgement::Claim,
                );
                let source = fixture.source.as_ref().expect("move source");
                let source_claim = source_claim_path(&fixture);
                let original_claim_identity = PhysicalIdentity::from_path(&source_claim)
                    .expect("transaction-owned source claim");
                let claim_bytes = fs::read(&source_claim).expect("source claim bytes");
                let foreign_identity = substitute_regular(&source_claim, &claim_bytes);
                assert_ne!(foreign_identity, original_claim_identity);

                request_test_rollback(&fixture);
                let (before_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);
                let error = public_recover(&fixture)
                    .expect_err("same-byte private source-claim substitution must fail closed");
                let (after_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);
                assert_eq!(after_path, before_path, "failed proof appends no receipt");
                assert!(
                    error.to_string().contains(
                        source_claim
                            .file_name()
                            .expect("source claim name")
                            .to_string_lossy()
                            .as_ref()
                    ),
                    "failure names the substituted source claim: {error}"
                );
                assert_eq!(
                    PhysicalIdentity::from_path(&source_claim)
                        .expect("foreign private source claim remains"),
                    foreign_identity
                );
                assert_eq!(
                    fs::read(&source_claim).expect("foreign private source bytes remain"),
                    claim_bytes
                );
                assert!(!source.exists(), "no unproved source is restored");
                assert!(!fixture.target.exists(), "no destination is published");
            }
            Adversary::AbortReceiptNoncanonical
            | Adversary::AbortReceiptInvalidChecksum
            | Adversary::AbortReceiptSemanticIdentityMutation => {
                let fixture = interrupt_closed_leaf(
                    approved_closed_leaf(ClosedLeafKind::MoveFile),
                    LostAcknowledgement::Claim,
                );
                request_test_rollback(&fixture);
                let operation_index = persisted_step_index(&fixture);
                let observed = RefCell::new(false);
                let interrupted = catch_unwind(AssertUnwindSafe(|| {
                    run_transaction_v1_with_hook(
                        fixture.root.path(),
                        MigrationCommand::Recover {
                            migration_id: &fixture.migration_id,
                        },
                        |checkpoint| {
                            if checkpoint
                                == TransactionV1Checkpoint::PrivateAbortReceiptPersisted(
                                    operation_index,
                                )
                            {
                                *observed.borrow_mut() = true;
                                panic!("lose private abort receipt acknowledgement");
                            }
                        },
                    )
                    .expect("Move abort reaches its private receipt");
                }));
                assert!(*observed.borrow(), "private abort checkpoint observed");
                assert!(interrupted.is_err(), "private abort is interrupted");

                let source = fixture.source.as_ref().expect("restored move source");
                let source_identity =
                    PhysicalIdentity::from_path(source).expect("restored source identity");
                let source_bytes = fs::read(source).expect("restored source bytes");
                let source_claim = source_claim_path(&fixture);
                assert!(
                    !source_claim.exists(),
                    "private Move abort receipt follows source-claim retirement"
                );
                let receipt_path = private_abort_receipt_path(&fixture);
                let canonical_bytes =
                    fs::read(&receipt_path).expect("canonical private abort receipt");
                let mut receipt: serde_json::Value =
                    serde_json::from_slice(&canonical_bytes).expect("private abort receipt JSON");

                let mutated_bytes = match adversary {
                    Adversary::AbortReceiptNoncanonical => {
                        serde_json::to_vec_pretty(&receipt).expect("noncanonical receipt JSON")
                    }
                    Adversary::AbortReceiptInvalidChecksum => {
                        receipt["checksum"] = serde_json::Value::String("0".repeat(64));
                        serde_json::to_vec(&receipt)
                            .expect("canonical receipt with invalid checksum")
                    }
                    Adversary::AbortReceiptSemanticIdentityMutation => {
                        receipt["visible_post_identity_sha256"] =
                            serde_json::Value::String("1".repeat(64));
                        let controlled = serde_json::json!([
                            receipt["format"],
                            receipt["transaction_id"],
                            receipt["program_digest"],
                            receipt["operation_index"],
                            receipt["visible_post_identity_sha256"],
                            receipt["claims"],
                        ]);
                        let mut checksum = Sha256::new();
                        checksum.update(b"folderbase-private-abort-work-v1");
                        checksum.update([0]);
                        checksum.update(
                            serde_json::to_vec(&controlled)
                                .expect("semantic receipt checksum bytes"),
                        );
                        receipt["checksum"] =
                            serde_json::Value::String(format!("{:x}", checksum.finalize()));
                        serde_json::to_vec(&receipt)
                            .expect("canonical semantically altered receipt")
                    }
                    _ => unreachable!("receipt mutation arm"),
                };
                assert_ne!(mutated_bytes, canonical_bytes);
                fs::write(&receipt_path, &mutated_bytes)
                    .expect("install adversarial private abort receipt");
                let (before_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);

                let error = public_recover(&fixture)
                    .expect_err("mutated private abort receipt must fail closed");
                let (after_path, _) =
                    latest_journal_generation(fixture.root.path(), &fixture.migration_id);
                assert_eq!(after_path, before_path, "failed proof appends no receipt");
                assert!(
                    error.to_string().contains(
                        receipt_path
                            .file_name()
                            .expect("receipt name")
                            .to_string_lossy()
                            .as_ref()
                    ),
                    "failure names the mutated private receipt: {error}"
                );
                assert_eq!(
                    fs::read(&receipt_path).expect("mutated receipt remains"),
                    mutated_bytes
                );
                assert_eq!(
                    PhysicalIdentity::from_path(source).expect("restored source remains"),
                    source_identity
                );
                assert_eq!(
                    fs::read(source).expect("restored source bytes remain"),
                    source_bytes
                );
                assert!(
                    !source_claim.exists(),
                    "receipt rejection must not reacquire live source authority"
                );
                assert!(!fixture.target.exists());
            }
        }));

        if let Err(payload) = result {
            let detail = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    payload
                        .downcast_ref::<&'static str>()
                        .map(|message| (*message).to_owned())
                })
                .unwrap_or_else(|| "non-string panic".to_owned());
            failures.push(format!("{label}: {detail}"));
        }
    }

    assert!(
        failures.is_empty(),
        "adversarial unreceipted-abort guarantees failed:\n{}",
        failures.join("\n")
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnreceiptedAbortKind {
    CreateDirectory,
    CreateFile,
    ReplaceFile,
    MoveFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnreceiptedAbortState {
    Intent,
    Claim,
    Visible,
}

#[derive(Clone, Copy, Debug)]
struct UnreceiptedAbortCase {
    label: &'static str,
    kind: UnreceiptedAbortKind,
    state: UnreceiptedAbortState,
}

const UNRECEIPTED_ABORT_CASES: [UnreceiptedAbortCase; 11] = [
    UnreceiptedAbortCase {
        label: "create_directory/I",
        kind: UnreceiptedAbortKind::CreateDirectory,
        state: UnreceiptedAbortState::Intent,
    },
    UnreceiptedAbortCase {
        label: "create_directory/C",
        kind: UnreceiptedAbortKind::CreateDirectory,
        state: UnreceiptedAbortState::Claim,
    },
    UnreceiptedAbortCase {
        label: "create_file/I",
        kind: UnreceiptedAbortKind::CreateFile,
        state: UnreceiptedAbortState::Intent,
    },
    UnreceiptedAbortCase {
        label: "create_file/C",
        kind: UnreceiptedAbortKind::CreateFile,
        state: UnreceiptedAbortState::Claim,
    },
    UnreceiptedAbortCase {
        label: "create_file/V",
        kind: UnreceiptedAbortKind::CreateFile,
        state: UnreceiptedAbortState::Visible,
    },
    UnreceiptedAbortCase {
        label: "replace_file/I",
        kind: UnreceiptedAbortKind::ReplaceFile,
        state: UnreceiptedAbortState::Intent,
    },
    UnreceiptedAbortCase {
        label: "replace_file/C",
        kind: UnreceiptedAbortKind::ReplaceFile,
        state: UnreceiptedAbortState::Claim,
    },
    UnreceiptedAbortCase {
        label: "replace_file/V",
        kind: UnreceiptedAbortKind::ReplaceFile,
        state: UnreceiptedAbortState::Visible,
    },
    UnreceiptedAbortCase {
        label: "move_file/I",
        kind: UnreceiptedAbortKind::MoveFile,
        state: UnreceiptedAbortState::Intent,
    },
    UnreceiptedAbortCase {
        label: "move_file/C",
        kind: UnreceiptedAbortKind::MoveFile,
        state: UnreceiptedAbortState::Claim,
    },
    UnreceiptedAbortCase {
        label: "move_file/V",
        kind: UnreceiptedAbortKind::MoveFile,
        state: UnreceiptedAbortState::Visible,
    },
];

impl UnreceiptedAbortKind {
    fn closed_leaf(self) -> ClosedLeafKind {
        match self {
            Self::CreateDirectory => ClosedLeafKind::CreateDirectory,
            Self::CreateFile => ClosedLeafKind::CreateFile,
            Self::ReplaceFile => ClosedLeafKind::ReplaceFile,
            Self::MoveFile => ClosedLeafKind::MoveFile,
        }
    }
}

impl UnreceiptedAbortState {
    fn lost_acknowledgement(self) -> LostAcknowledgement {
        match self {
            Self::Intent => LostAcknowledgement::Intent,
            Self::Claim => LostAcknowledgement::Claim,
            Self::Visible => LostAcknowledgement::Publish,
        }
    }
}

struct UnreceiptedAbortMatrixFixture {
    case: UnreceiptedAbortCase,
    leaf: ClosedLeafFixture,
    original_identity: Option<PhysicalIdentity>,
    original_bytes: Option<Vec<u8>>,
    ordinary_source: Option<PathBuf>,
    ordinary_source_identity: Option<PhysicalIdentity>,
    ordinary_source_bytes: Option<Vec<u8>>,
    #[cfg(unix)]
    original_mode: Option<u32>,
}

fn requested_unreceipted_abort_matrix_fixture(
    case: UnreceiptedAbortCase,
) -> UnreceiptedAbortMatrixFixture {
    let leaf = approved_closed_leaf(case.kind.closed_leaf());
    let original_path = match case.kind {
        UnreceiptedAbortKind::CreateDirectory | UnreceiptedAbortKind::CreateFile => None,
        UnreceiptedAbortKind::ReplaceFile => Some(leaf.target.as_path()),
        UnreceiptedAbortKind::MoveFile => Some(
            leaf.source
                .as_deref()
                .expect("Move matrix fixture has a source"),
        ),
    };
    let original_identity = original_path
        .map(|path| PhysicalIdentity::from_path(path).expect("matrix original physical identity"));
    let original_bytes =
        original_path.map(|path| fs::read(path).expect("matrix original regular bytes"));
    let ordinary_source = match case.kind {
        UnreceiptedAbortKind::CreateDirectory => Some(leaf.root.path().join("README.md")),
        UnreceiptedAbortKind::CreateFile => leaf.source.clone(),
        UnreceiptedAbortKind::ReplaceFile | UnreceiptedAbortKind::MoveFile => None,
    };
    let ordinary_source_identity = ordinary_source
        .as_deref()
        .map(|path| PhysicalIdentity::from_path(path).expect("ordinary source physical identity"));
    let ordinary_source_bytes = ordinary_source
        .as_deref()
        .map(|path| fs::read(path).expect("ordinary source bytes"));
    #[cfg(unix)]
    let original_mode = original_path.map(|path| {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path)
            .expect("matrix original regular metadata")
            .permissions()
            .mode()
    });

    let leaf = interrupt_closed_leaf(leaf, case.state.lost_acknowledgement());
    request_test_rollback(&leaf);
    let (_, requested) = latest_journal_generation(leaf.root.path(), &leaf.migration_id);
    assert_eq!(requested["direction"], "rollback");
    assert_eq!(requested["phase"], "rollback_requested");
    assert_eq!(
        requested["in_flight_operation"].as_u64(),
        Some(persisted_step_index(&leaf) as u64)
    );

    UnreceiptedAbortMatrixFixture {
        case,
        leaf,
        original_identity,
        original_bytes,
        ordinary_source,
        ordinary_source_identity,
        ordinary_source_bytes,
        #[cfg(unix)]
        original_mode,
    }
}

fn assert_matrix_ordinary_source_unchanged(fixture: &UnreceiptedAbortMatrixFixture) {
    let Some(path) = fixture.ordinary_source.as_ref() else {
        return;
    };
    assert_eq!(
        PhysicalIdentity::from_path(path).expect("ordinary source remains"),
        fixture
            .ordinary_source_identity
            .expect("ordinary source identity"),
        "{} preserves the ordinary source identity",
        fixture.case.label
    );
    assert_eq!(
        fs::read(path).expect("ordinary source bytes remain"),
        *fixture
            .ordinary_source_bytes
            .as_ref()
            .expect("ordinary source bytes"),
        "{} preserves ordinary source bytes",
        fixture.case.label
    );
}

fn assert_unreceipted_abort_visible_terminal(fixture: &UnreceiptedAbortMatrixFixture) {
    match fixture.case.kind {
        UnreceiptedAbortKind::CreateDirectory | UnreceiptedAbortKind::CreateFile => {
            assert!(
                !fixture.leaf.target.exists(),
                "{} transaction-owned target must be absent after abort",
                fixture.case.label
            );
            assert_matrix_ordinary_source_unchanged(fixture);
        }
        UnreceiptedAbortKind::ReplaceFile => {
            assert_eq!(
                PhysicalIdentity::from_path(&fixture.leaf.target)
                    .expect("restored Replace target identity"),
                fixture
                    .original_identity
                    .expect("Replace matrix original identity"),
                "{} restores the exact original identity",
                fixture.case.label
            );
            assert_eq!(
                fs::read(&fixture.leaf.target).expect("restored Replace target bytes"),
                *fixture
                    .original_bytes
                    .as_ref()
                    .expect("Replace matrix original bytes"),
                "{} restores the exact original bytes",
                fixture.case.label
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                assert_eq!(
                    fs::metadata(&fixture.leaf.target)
                        .expect("restored Replace target metadata")
                        .permissions()
                        .mode(),
                    fixture.original_mode.expect("Replace matrix original mode"),
                    "{} restores the exact original mode",
                    fixture.case.label
                );
            }
        }
        UnreceiptedAbortKind::MoveFile => {
            let source = fixture
                .leaf
                .source
                .as_ref()
                .expect("Move matrix source path");
            assert_eq!(
                PhysicalIdentity::from_path(source).expect("restored Move source identity"),
                fixture
                    .original_identity
                    .expect("Move matrix original identity"),
                "{} restores the exact source identity",
                fixture.case.label
            );
            assert_eq!(
                fs::read(source).expect("restored Move source bytes"),
                *fixture
                    .original_bytes
                    .as_ref()
                    .expect("Move matrix original bytes"),
                "{} restores the exact source bytes",
                fixture.case.label
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                assert_eq!(
                    fs::metadata(source)
                        .expect("restored Move source metadata")
                        .permissions()
                        .mode(),
                    fixture.original_mode.expect("Move matrix original mode"),
                    "{} restores the exact source mode",
                    fixture.case.label
                );
            }
            assert!(
                !fixture.leaf.target.exists(),
                "{} removes the transaction-owned Move destination",
                fixture.case.label
            );
        }
    }
}

fn assert_canonical_unreceipted_abort_receipt(
    fixture: &UnreceiptedAbortMatrixFixture,
    journaled: bool,
) -> (PathBuf, Vec<u8>) {
    let operation_index = persisted_step_index(&fixture.leaf);
    let receipt_path = private_abort_receipt_path(&fixture.leaf);
    let receipt_bytes = fs::read(&receipt_path).expect("canonical private abort-work receipt");
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).expect("private abort-work receipt JSON");
    assert_eq!(
        serde_json::to_vec(&receipt).expect("canonical private abort-work receipt JSON"),
        receipt_bytes,
        "{} private abort receipt is canonical JSON",
        fixture.case.label
    );
    let (_, latest) =
        latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
    assert_eq!(receipt["format"], "folderbase-private-abort-work-v1");
    assert_eq!(receipt["transaction_id"], latest["transaction_id"]);
    assert_eq!(receipt["program_digest"], latest["program_digest"]);
    assert_eq!(
        receipt["operation_index"].as_u64(),
        Some(operation_index as u64)
    );
    let expected_visible_identity = match fixture.case.kind {
        UnreceiptedAbortKind::CreateDirectory | UnreceiptedAbortKind::CreateFile => None,
        UnreceiptedAbortKind::ReplaceFile | UnreceiptedAbortKind::MoveFile => Some(
            fixture
                .original_identity
                .expect("destructive matrix original identity")
                .stable_sha256(),
        ),
    };
    assert_eq!(
        receipt["visible_post_identity_sha256"].as_str(),
        expected_visible_identity.as_deref(),
        "{} binds the exact state-specific visible post identity",
        fixture.case.label
    );

    let claims = receipt["claims"]
        .as_array()
        .expect("private abort-work exact claims");
    let claim_names = claims
        .iter()
        .map(|claim| {
            claim["name"]
                .as_str()
                .expect("private abort claim name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let expected_claim_names = match (fixture.case.kind, fixture.case.state) {
        (UnreceiptedAbortKind::CreateDirectory, UnreceiptedAbortState::Claim) => {
            vec![private_claim_name(operation_index, "publish")]
        }
        (UnreceiptedAbortKind::CreateFile, UnreceiptedAbortState::Visible) => vec![
            private_claim_name(operation_index, "publish"),
            private_claim_name(operation_index, "rollback"),
        ],
        (UnreceiptedAbortKind::ReplaceFile, UnreceiptedAbortState::Visible) => {
            vec![private_claim_name(operation_index, "rollback")]
        }
        (
            UnreceiptedAbortKind::CreateDirectory
            | UnreceiptedAbortKind::CreateFile
            | UnreceiptedAbortKind::ReplaceFile
            | UnreceiptedAbortKind::MoveFile,
            UnreceiptedAbortState::Intent
            | UnreceiptedAbortState::Claim
            | UnreceiptedAbortState::Visible,
        ) => Vec::new(),
    };
    assert_eq!(
        claim_names, expected_claim_names,
        "{} has the exact state-specific private claim set",
        fixture.case.label
    );
    assert!(
        claim_names.windows(2).all(|pair| pair[0] < pair[1]),
        "{} abort claims are sorted and unique: {claim_names:?}",
        fixture.case.label
    );
    let claims_root =
        transaction_v1_root(fixture.leaf.root.path(), &fixture.leaf.migration_id).join("claims");
    let prefix = format!("{operation_index:08}.");
    let mut actual_claim_names = fs::read_dir(&claims_root)
        .expect("private claims directory")
        .filter_map(|entry| {
            let name = entry
                .expect("private claim entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            name.starts_with(&prefix).then_some(name)
        })
        .collect::<Vec<_>>();
    actual_claim_names.sort();
    assert_eq!(
        actual_claim_names, claim_names,
        "{} receipt describes the complete exact claim set",
        fixture.case.label
    );
    for claim in claims {
        let name = claim["name"].as_str().expect("abort claim name");
        let path = claims_root.join(name);
        let identity =
            PhysicalIdentity::from_path(&path).expect("receipt-bound private claim identity");
        assert_eq!(
            claim["physical_identity_sha256"].as_str(),
            Some(identity.stable_sha256().as_str())
        );
        assert_eq!(
            claim["device_sha256"].as_str(),
            Some(identity.device_sha256().as_str())
        );
        let metadata = fs::metadata(&path).expect("receipt-bound private claim metadata");
        match claim["kind"].as_str().expect("abort claim kind") {
            "regular" => {
                let bytes = fs::read(&path).expect("receipt-bound regular claim");
                assert_eq!(claim["bytes"].as_u64(), Some(bytes.len() as u64));
                assert_eq!(
                    claim["sha256"].as_str(),
                    Some(sha256_test_bytes(&bytes).as_str())
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;

                    assert_eq!(claim["link_count"].as_u64(), Some(metadata.nlink()));
                }
            }
            "directory" => {
                assert_eq!(claim["empty"].as_bool(), Some(true));
                assert_eq!(
                    fs::read_dir(&path)
                        .expect("receipt-bound directory claim")
                        .count(),
                    0
                );
            }
            other => panic!("unsupported private abort claim kind {other}"),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = metadata.permissions().mode();
            assert_eq!(claim["read_only"].as_bool(), Some(mode & 0o222 == 0));
            assert_eq!(claim["executable"].as_bool(), Some(mode & 0o111 != 0));
        }
    }

    let controlled = serde_json::json!([
        receipt["format"],
        receipt["transaction_id"],
        receipt["program_digest"],
        receipt["operation_index"],
        receipt["visible_post_identity_sha256"],
        receipt["claims"],
    ]);
    let mut checksum = Sha256::new();
    checksum.update(b"folderbase-private-abort-work-v1");
    checksum.update([0]);
    checksum.update(serde_json::to_vec(&controlled).expect("abort checksum controlled bytes"));
    assert_eq!(
        receipt["checksum"].as_str(),
        Some(format!("{:x}", checksum.finalize()).as_str())
    );

    let receipt_digest = sha256_test_bytes(&receipt_bytes);
    let abort_receipts = latest
        .get("abort_receipts")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if journaled {
        assert_eq!(
            abort_receipts.len(),
            1,
            "{} has exactly one journal abort receipt",
            fixture.case.label
        );
        assert_eq!(
            abort_receipts[0]["operation_index"].as_u64(),
            Some(operation_index as u64)
        );
        assert_eq!(
            abort_receipts[0]["private_receipt_sha256"].as_str(),
            Some(receipt_digest.as_str())
        );
    } else {
        assert!(
            abort_receipts.is_empty(),
            "{} private receipt precedes its journal receipt",
            fixture.case.label
        );
        assert_eq!(
            latest["in_flight_operation"].as_u64(),
            Some(operation_index as u64)
        );
    }
    (receipt_path, receipt_bytes)
}

fn interrupt_unreceipted_abort_at(
    fixture: &UnreceiptedAbortMatrixFixture,
    expected_checkpoint: TransactionV1Checkpoint,
) {
    let observed = RefCell::new(false);
    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        run_transaction_v1_with_hook(
            fixture.leaf.root.path(),
            MigrationCommand::Recover {
                migration_id: &fixture.leaf.migration_id,
            },
            |checkpoint| {
                if checkpoint == expected_checkpoint {
                    *observed.borrow_mut() = true;
                    panic!("lose acknowledgement at {expected_checkpoint:?}");
                }
            },
        )
        .expect("unreceipted abort reaches requested durable checkpoint");
    }));
    assert!(
        *observed.borrow(),
        "{} never reached {expected_checkpoint:?}",
        fixture.case.label
    );
    assert!(
        interrupted.is_err(),
        "{} durable checkpoint must interrupt",
        fixture.case.label
    );
}

fn assert_unreceipted_abort_terminal_history_is_idempotent(
    fixture: &UnreceiptedAbortMatrixFixture,
) {
    let outcome = public_recover(&fixture.leaf).expect("unreceipted abort reaches terminal");
    assert!(
        matches!(outcome, MigrationOutcome::RolledBack(_)),
        "{} converges to RolledBack",
        fixture.case.label
    );
    assert_unreceipted_abort_visible_terminal(fixture);
    let (receipt_path, receipt_bytes) = assert_canonical_unreceipted_abort_receipt(fixture, true);
    let (journal_path, journal) =
        latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
    let journal_bytes = fs::read(&journal_path).expect("terminal journal bytes");
    assert_eq!(journal["direction"], "rollback");
    assert_eq!(journal["phase"], "rolled_back");
    assert_eq!(journal["in_flight_operation"], serde_json::Value::Null);
    let transaction_root =
        transaction_v1_root(fixture.leaf.root.path(), &fixture.leaf.migration_id);
    let transaction_snapshot = raw_tree_snapshot(&transaction_root);
    assert_eq!(
        MigrationPlan::reopen(fixture.leaf.root.path(), &fixture.leaf.migration_id)
            .expect("terminal migration plan")
            .state,
        MigrationState::RolledBack,
        "{} projects the terminal transaction into plan.json",
        fixture.case.label
    );

    for restart in 1..=2 {
        let reopened = public_recover(&fixture.leaf).expect("terminal abort reopens");
        assert!(
            matches!(reopened, MigrationOutcome::RolledBack(_)),
            "{} terminal restart {restart} remains RolledBack",
            fixture.case.label
        );
        assert_unreceipted_abort_visible_terminal(fixture);
        assert_eq!(
            raw_tree_snapshot(&transaction_root),
            transaction_snapshot,
            "{} terminal restart {restart} leaves raw transaction history immutable",
            fixture.case.label
        );
        assert_eq!(
            fs::read(&receipt_path).expect("immutable private abort receipt"),
            receipt_bytes
        );
        let (latest_path, latest) =
            latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
        assert_eq!(
            latest_path, journal_path,
            "{} terminal restart {restart} appends no journal generation",
            fixture.case.label
        );
        assert_eq!(latest["generation"], journal["generation"]);
        assert_eq!(
            fs::read(&journal_path).expect("immutable terminal journal"),
            journal_bytes
        );
        assert_eq!(
            MigrationPlan::reopen(fixture.leaf.root.path(), &fixture.leaf.migration_id)
                .expect("reopened terminal plan")
                .state,
            MigrationState::RolledBack
        );
    }
}

fn matrix_panic_detail(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|message| (*message).to_owned())
        })
        .unwrap_or_else(|| "non-string panic".to_owned())
}

enum TerminalUserEdit {
    Directory {
        directory_identity: PhysicalIdentity,
        child: PathBuf,
        child_bytes: Vec<u8>,
    },
    Regular {
        path: PathBuf,
        identity: PhysicalIdentity,
        bytes: Vec<u8>,
    },
}

fn install_terminal_user_edit(fixture: &UnreceiptedAbortMatrixFixture) -> TerminalUserEdit {
    match fixture.case.kind {
        UnreceiptedAbortKind::CreateDirectory => {
            fs::create_dir(&fixture.leaf.target).expect("new user-owned directory");
            let child = fixture.leaf.target.join("user-note.txt");
            let child_bytes =
                format!("ordinary post-abort child for {}\n", fixture.case.label).into_bytes();
            fs::write(&child, &child_bytes).expect("new user-owned directory child");
            TerminalUserEdit::Directory {
                directory_identity: PhysicalIdentity::from_path(&fixture.leaf.target)
                    .expect("new user-owned directory identity"),
                child,
                child_bytes,
            }
        }
        UnreceiptedAbortKind::CreateFile => {
            let path = fixture.leaf.target.clone();
            let bytes =
                format!("ordinary post-abort edit for {}\n", fixture.case.label).into_bytes();
            fs::create_dir_all(path.parent().expect("CreateFile target parent"))
                .expect("recreate user-owned CreateFile parent");
            fs::write(&path, &bytes).expect("new user-owned CreateFile target");
            TerminalUserEdit::Regular {
                identity: PhysicalIdentity::from_path(&path)
                    .expect("new user-owned CreateFile target identity"),
                path,
                bytes,
            }
        }
        UnreceiptedAbortKind::ReplaceFile => {
            let path = fixture.leaf.target.clone();
            let bytes =
                format!("ordinary post-abort edit for {}\n", fixture.case.label).into_bytes();
            fs::write(&path, &bytes).expect("ordinary user-owned regular edit");
            TerminalUserEdit::Regular {
                identity: PhysicalIdentity::from_path(&path)
                    .expect("ordinary user-owned regular identity"),
                path,
                bytes,
            }
        }
        UnreceiptedAbortKind::MoveFile => {
            let path = fixture
                .leaf
                .source
                .as_ref()
                .expect("restored Move source")
                .clone();
            let bytes =
                format!("ordinary post-abort edit for {}\n", fixture.case.label).into_bytes();
            fs::write(&path, &bytes).expect("ordinary restored-source edit");
            TerminalUserEdit::Regular {
                identity: PhysicalIdentity::from_path(&path)
                    .expect("ordinary edited Move source identity"),
                path,
                bytes,
            }
        }
    }
}

fn assert_terminal_user_edit_remains(edit: &TerminalUserEdit) {
    match edit {
        TerminalUserEdit::Directory {
            directory_identity,
            child,
            child_bytes,
        } => {
            let directory = child.parent().expect("edited directory");
            assert_eq!(
                PhysicalIdentity::from_path(directory).expect("user directory remains"),
                *directory_identity
            );
            assert_eq!(
                fs::read(child).expect("user directory child remains"),
                *child_bytes
            );
        }
        TerminalUserEdit::Regular {
            path,
            identity,
            bytes,
        } => {
            assert_eq!(
                PhysicalIdentity::from_path(path).expect("user regular edit remains"),
                *identity
            );
            assert_eq!(fs::read(path).expect("user regular bytes remain"), *bytes);
        }
    }
}

#[test]
fn journaled_abort_history_allows_user_edits_for_every_unreceipted_state() {
    let mut failures = Vec::new();
    for case in UNRECEIPTED_ABORT_CASES {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let fixture = requested_unreceipted_abort_matrix_fixture(case);
            let terminal =
                public_recover(&fixture.leaf).expect("unreceipted abort reaches terminal");
            assert!(matches!(terminal, MigrationOutcome::RolledBack(_)));
            assert_unreceipted_abort_visible_terminal(&fixture);
            let (receipt_path, receipt_bytes) =
                assert_canonical_unreceipted_abort_receipt(&fixture, true);
            let (journal_path, journal) =
                latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
            let journal_bytes = fs::read(&journal_path).expect("terminal journal bytes");
            assert_eq!(journal["phase"], "rolled_back");
            let transaction_root =
                transaction_v1_root(fixture.leaf.root.path(), &fixture.leaf.migration_id);
            let transaction_snapshot = raw_tree_snapshot(&transaction_root);

            let edit = install_terminal_user_edit(&fixture);
            assert_terminal_user_edit_remains(&edit);
            assert_matrix_ordinary_source_unchanged(&fixture);
            assert!(
                raw_tree_snapshot(&transaction_root) == transaction_snapshot,
                "{} ordinary workspace edit must not mutate private abort history",
                case.label
            );

            for restart in 1..=2 {
                let reopened =
                    public_recover(&fixture.leaf).expect("journaled terminal abort reopens");
                assert!(
                    matches!(reopened, MigrationOutcome::RolledBack(_)),
                    "{} edited terminal restart {restart} remains RolledBack",
                    case.label
                );
                assert_terminal_user_edit_remains(&edit);
                assert_matrix_ordinary_source_unchanged(&fixture);
                assert!(
                    raw_tree_snapshot(&transaction_root) == transaction_snapshot,
                    "{} edited terminal restart {restart} leaves history immutable",
                    case.label
                );
                assert_eq!(
                    fs::read(&receipt_path).expect("immutable abort receipt"),
                    receipt_bytes
                );
                let (latest_path, latest) =
                    latest_journal_generation(fixture.leaf.root.path(), &fixture.leaf.migration_id);
                assert_eq!(
                    latest_path, journal_path,
                    "{} edited terminal restart {restart} appends no journal generation",
                    case.label
                );
                assert_eq!(latest["generation"], journal["generation"]);
                assert_eq!(
                    fs::read(&journal_path).expect("immutable terminal journal"),
                    journal_bytes
                );
                assert_eq!(
                    MigrationPlan::reopen(fixture.leaf.root.path(), &fixture.leaf.migration_id)
                        .expect("edited terminal plan")
                        .state,
                    MigrationState::RolledBack
                );
            }
        }));
        if let Err(payload) = result {
            failures.push(format!("{}: {}", case.label, matrix_panic_detail(payload)));
        }
    }
    assert!(
        failures.is_empty(),
        "journaled abort history rejected ordinary user edits:\n{}",
        failures.join("\n")
    );
}

#[test]
fn terminal_directory_rollback_releases_the_visible_name_but_keeps_private_evidence_exact() {
    let fixture = apply_closed_leaf(ClosedLeafKind::CreateDirectory);
    let operation_index = persisted_step_index(&fixture);
    let terminal = public_rollback(&fixture).expect("directory rollback reaches terminal");
    assert!(matches!(terminal, MigrationOutcome::RolledBack(_)));

    let rollback_claim = private_claim_path(&fixture, operation_index, "rollback");
    assert!(rollback_claim.is_dir(), "private rollback claim remains");

    fs::create_dir(&fixture.target).expect("user reuses released visible directory name");
    let user_child = fixture.target.join("user-work.txt");
    let user_bytes = b"ordinary post-rollback work\n";
    fs::write(&user_child, user_bytes).expect("user writes in released directory");
    let user_directory_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("user directory identity");

    fs::write(
        rollback_claim.join("foreign-child.txt"),
        b"tampered immutable evidence\n",
    )
    .expect("make the private empty-directory claim nonempty");
    let (journal_path, journal) =
        latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    let journal_bytes = fs::read(&journal_path).expect("terminal journal bytes");

    let error = public_recover(&fixture)
        .expect_err("terminal recovery must reject mutated private rollback evidence");
    assert!(
        error.to_string().contains("rollback.claim"),
        "failure must identify the mutated private rollback evidence: {error}"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.target).expect("user directory remains"),
        user_directory_identity
    );
    assert_eq!(
        fs::read(&user_child).expect("user work remains"),
        user_bytes
    );
    let (latest_path, latest) =
        latest_journal_generation(fixture.root.path(), &fixture.migration_id);
    assert_eq!(latest_path, journal_path, "failure appends no generation");
    assert_eq!(latest["generation"], journal["generation"]);
    assert_eq!(
        fs::read(&journal_path).expect("terminal journal remains immutable"),
        journal_bytes
    );
}

#[test]
fn unreceipted_abort_restart_matrix_converges_idempotently_at_every_durable_checkpoint() {
    #[derive(Clone, Copy, Debug)]
    enum RestartCut {
        Direct,
        PrivateReceipt,
        JournalReceipt,
    }

    let mut failures = Vec::new();
    for case in UNRECEIPTED_ABORT_CASES {
        for cut in [
            RestartCut::Direct,
            RestartCut::PrivateReceipt,
            RestartCut::JournalReceipt,
        ] {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let fixture = requested_unreceipted_abort_matrix_fixture(case);
                let operation_index = persisted_step_index(&fixture.leaf);
                match cut {
                    RestartCut::Direct => {}
                    RestartCut::PrivateReceipt => {
                        interrupt_unreceipted_abort_at(
                            &fixture,
                            TransactionV1Checkpoint::PrivateAbortReceiptPersisted(operation_index),
                        );
                        assert_unreceipted_abort_visible_terminal(&fixture);
                        assert_canonical_unreceipted_abort_receipt(&fixture, false);
                    }
                    RestartCut::JournalReceipt => {
                        interrupt_unreceipted_abort_at(
                            &fixture,
                            TransactionV1Checkpoint::JournalAbortReceiptPersisted(operation_index),
                        );
                        assert_unreceipted_abort_visible_terminal(&fixture);
                        assert_canonical_unreceipted_abort_receipt(&fixture, true);
                        let (_, journaled) = latest_journal_generation(
                            fixture.leaf.root.path(),
                            &fixture.leaf.migration_id,
                        );
                        assert_eq!(
                            journaled["in_flight_operation"],
                            serde_json::Value::Null,
                            "{} journal receipt clears exact in-flight authority",
                            case.label
                        );
                    }
                }
                assert_unreceipted_abort_terminal_history_is_idempotent(&fixture);
            }));
            if let Err(payload) = result {
                failures.push(format!(
                    "{}@{cut:?}: {}",
                    case.label,
                    matrix_panic_detail(payload)
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "unreceipted abort restart matrix failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn move_abort_claim_retirement_checkpoints_restart_without_live_authority() {
    let cases = [
        (
            UnreceiptedAbortCase {
                label: "move_file/V@rollback_claim_retired",
                kind: UnreceiptedAbortKind::MoveFile,
                state: UnreceiptedAbortState::Visible,
            },
            TransactionV1Checkpoint::MoveAbortRollbackClaimRetired
                as fn(usize) -> TransactionV1Checkpoint,
            true,
        ),
        (
            UnreceiptedAbortCase {
                label: "move_file/C@source_claim_retired",
                kind: UnreceiptedAbortKind::MoveFile,
                state: UnreceiptedAbortState::Claim,
            },
            TransactionV1Checkpoint::MoveAbortSourceClaimRetired,
            false,
        ),
        (
            UnreceiptedAbortCase {
                label: "move_file/V@source_claim_retired",
                kind: UnreceiptedAbortKind::MoveFile,
                state: UnreceiptedAbortState::Visible,
            },
            TransactionV1Checkpoint::MoveAbortSourceClaimRetired,
            false,
        ),
    ];

    let mut failures = Vec::new();
    for (case, checkpoint, source_claim_remains) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let fixture = requested_unreceipted_abort_matrix_fixture(case);
            let operation_index = persisted_step_index(&fixture.leaf);
            interrupt_unreceipted_abort_at(&fixture, checkpoint(operation_index));
            assert_unreceipted_abort_visible_terminal(&fixture);
            assert_eq!(
                source_claim_path(&fixture.leaf).exists(),
                source_claim_remains,
                "{} has the expected transient source authority",
                case.label
            );
            assert!(
                !private_claim_path(&fixture.leaf, operation_index, "rollback").exists(),
                "{} retires rollback authority before source authority",
                case.label
            );
            assert!(
                !private_abort_receipt_path(&fixture.leaf).exists(),
                "{} checkpoint precedes the private abort receipt",
                case.label
            );
            assert_unreceipted_abort_terminal_history_is_idempotent(&fixture);
            assert!(
                !source_claim_path(&fixture.leaf).exists(),
                "{} terminal recovery releases source authority",
                case.label
            );
        }));
        if let Err(payload) = result {
            failures.push(format!("{}: {}", case.label, matrix_panic_detail(payload)));
        }
    }
    assert!(
        failures.is_empty(),
        "Move claim-retirement checkpoint failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn move_abort_receipt_boundary_scopes_live_workspace_authority() {
    let private_case = UnreceiptedAbortCase {
        label: "move_file/V@private_receipt_user_replacement",
        kind: UnreceiptedAbortKind::MoveFile,
        state: UnreceiptedAbortState::Visible,
    };
    let private_fixture = requested_unreceipted_abort_matrix_fixture(private_case);
    let private_index = persisted_step_index(&private_fixture.leaf);
    interrupt_unreceipted_abort_at(
        &private_fixture,
        TransactionV1Checkpoint::PrivateAbortReceiptPersisted(private_index),
    );
    let private_source = private_fixture
        .leaf
        .source
        .as_ref()
        .expect("restored Move source");
    let approved_bytes = fs::read(private_source).expect("restored source bytes");
    let foreign_identity = substitute_regular(private_source, &approved_bytes);
    let private_receipt = private_abort_receipt_path(&private_fixture.leaf);
    let private_receipt_bytes = fs::read(&private_receipt).expect("private receipt before journal");
    let (before_path, before_generation) = latest_journal_generation(
        private_fixture.leaf.root.path(),
        &private_fixture.leaf.migration_id,
    );

    let error = public_recover(&private_fixture.leaf)
        .expect_err("private receipt still proves the exact live source before journalization");
    assert!(
        error.to_string().contains(
            private_source
                .file_name()
                .expect("Move source name")
                .to_string_lossy()
                .as_ref()
        ),
        "pre-journal source replacement is reported at its visible path: {error}"
    );
    assert_eq!(
        PhysicalIdentity::from_path(private_source).expect("foreign source remains"),
        foreign_identity
    );
    assert_eq!(
        fs::read(private_source).expect("same-byte foreign source remains"),
        approved_bytes
    );
    assert!(!private_fixture.leaf.target.exists());
    assert_eq!(
        fs::read(&private_receipt).expect("private receipt remains immutable"),
        private_receipt_bytes
    );
    let (after_path, after_generation) = latest_journal_generation(
        private_fixture.leaf.root.path(),
        &private_fixture.leaf.migration_id,
    );
    assert_eq!(after_path, before_path, "failed proof appends no journal");
    assert_eq!(
        after_generation["generation"],
        before_generation["generation"]
    );

    let journal_case = UnreceiptedAbortCase {
        label: "move_file/V@journal_receipt_user_replacement",
        kind: UnreceiptedAbortKind::MoveFile,
        state: UnreceiptedAbortState::Visible,
    };
    let journal_fixture = requested_unreceipted_abort_matrix_fixture(journal_case);
    let journal_index = persisted_step_index(&journal_fixture.leaf);
    interrupt_unreceipted_abort_at(
        &journal_fixture,
        TransactionV1Checkpoint::JournalAbortReceiptPersisted(journal_index),
    );
    let journal_source = journal_fixture
        .leaf
        .source
        .as_ref()
        .expect("journaled Move source");
    let user_source_bytes = b"user-owned source after journal receipt\n";
    let user_source_identity = substitute_regular(journal_source, user_source_bytes);
    let user_destination_bytes = b"user-owned destination after journal receipt\n";
    fs::write(&journal_fixture.leaf.target, user_destination_bytes)
        .expect("reuse released Move destination");
    let user_destination_identity =
        PhysicalIdentity::from_path(&journal_fixture.leaf.target).expect("user destination");
    let journal_receipt = private_abort_receipt_path(&journal_fixture.leaf);
    let journal_receipt_bytes = fs::read(&journal_receipt).expect("journaled private receipt");
    let (abort_journal_path, abort_journal) = latest_journal_generation(
        journal_fixture.leaf.root.path(),
        &journal_fixture.leaf.migration_id,
    );
    let abort_journal_bytes =
        fs::read(&abort_journal_path).expect("journal abort receipt generation");

    let terminal = public_recover(&journal_fixture.leaf)
        .expect("journaled abort no longer owns either workspace pathname");
    assert!(matches!(terminal, MigrationOutcome::RolledBack(_)));
    let (terminal_path, terminal_generation) = latest_journal_generation(
        journal_fixture.leaf.root.path(),
        &journal_fixture.leaf.migration_id,
    );
    let terminal_bytes = fs::read(&terminal_path).expect("terminal generation");
    for restart in 1..=2 {
        let reopened = public_recover(&journal_fixture.leaf)
            .expect("terminal Move abort reopens around user work");
        assert!(matches!(reopened, MigrationOutcome::RolledBack(_)));
        assert_eq!(
            PhysicalIdentity::from_path(journal_source).expect("user source remains"),
            user_source_identity,
            "restart {restart} preserves the user source inode"
        );
        assert_eq!(
            fs::read(journal_source).expect("user source bytes remain"),
            user_source_bytes
        );
        assert_eq!(
            PhysicalIdentity::from_path(&journal_fixture.leaf.target)
                .expect("user destination remains"),
            user_destination_identity,
            "restart {restart} preserves the reused destination inode"
        );
        assert_eq!(
            fs::read(&journal_fixture.leaf.target).expect("user destination bytes remain"),
            user_destination_bytes
        );
        assert_eq!(
            fs::read(&journal_receipt).expect("immutable private receipt"),
            journal_receipt_bytes
        );
        assert_eq!(
            fs::read(&abort_journal_path).expect("immutable abort journal generation"),
            abort_journal_bytes
        );
        let (latest_path, latest_generation) = latest_journal_generation(
            journal_fixture.leaf.root.path(),
            &journal_fixture.leaf.migration_id,
        );
        assert_eq!(latest_path, terminal_path);
        assert_eq!(
            latest_generation["generation"],
            terminal_generation["generation"]
        );
        assert_eq!(
            fs::read(&terminal_path).expect("immutable terminal generation"),
            terminal_bytes
        );
    }
    assert_eq!(abort_journal["phase"], "rollback_requested");
    assert_eq!(
        abort_journal["in_flight_operation"],
        serde_json::Value::Null
    );
}

#[derive(Clone, Copy, Debug)]
enum G2RollbackSurface {
    AppliedAdditiveTree,
    RestoredMoveParent,
}

#[derive(Clone, Copy, Debug)]
enum G2NestedBoundaryShape {
    Exact,
    StateAlias,
    ManifestAlias,
}

type G2RawTreeEntry = (
    PathBuf,
    &'static str,
    PhysicalIdentity,
    Option<Vec<u8>>,
    Option<u32>,
);

fn install_g2_nested_boundary(boundary: &Path, shape: G2NestedBoundaryShape) -> PathBuf {
    let (state_name, manifest_name) = match shape {
        G2NestedBoundaryShape::Exact => (".folderbase", "manifest.json"),
        G2NestedBoundaryShape::StateAlias => (".FOLDERBASE", "manifest.json"),
        G2NestedBoundaryShape::ManifestAlias => (".folderbase", "manifest.JSON"),
    };
    let state = boundary.join(state_name);
    fs::create_dir_all(&state).expect("nested boundary state directory");
    let marker = state.join(manifest_name);
    fs::write(
        &marker,
        format!("opaque nested boundary marker for {shape:?}\n"),
    )
    .expect("nested boundary marker");
    marker
}

fn g2_snapshot_mutations(before: &[G2RawTreeEntry], after: &[G2RawTreeEntry]) -> Vec<String> {
    let mut paths = before
        .iter()
        .chain(after.iter())
        .map(|entry| entry.0.clone())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .filter_map(|path| {
            let expected = before.iter().find(|entry| entry.0 == path);
            let observed = after.iter().find(|entry| entry.0 == path);
            (expected != observed).then(|| match (expected, observed) {
                (Some(_), None) => format!("removed {}", path.display()),
                (None, Some(_)) => format!("created {}", path.display()),
                (Some(_), Some(_)) => format!("changed {}", path.display()),
                (None, None) => unreachable!("path came from one snapshot"),
            })
        })
        .collect()
}

fn g2_private_artifacts_with_suffix(root: &Path, migration_id: &str, suffix: &str) -> Vec<String> {
    let transaction = transaction_v1_root(root, migration_id);
    ["claims", "receipts"]
        .into_iter()
        .flat_map(|directory| {
            let directory = transaction.join(directory);
            fs::read_dir(directory)
                .into_iter()
                .flatten()
                .map(|entry| entry.expect("private transaction artifact"))
                .filter_map(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .ends_with(suffix)
                        .then(|| entry.path().display().to_string())
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn g2_conflict_names_path_or_descendant(
    conflicts: &[MigrationConflict],
    root: &Path,
    expected: &Path,
) -> bool {
    conflicts.iter().any(|conflict| {
        conflict.affected_paths.iter().any(|recorded| {
            let absolute = if recorded.is_absolute() {
                recorded.clone()
            } else {
                root.join(recorded)
            };
            absolute == expected || absolute.starts_with(expected)
        })
    })
}

fn assert_g2_durable_rollback_conflict(
    root: &Path,
    migration_id: &str,
    conflicts: &[MigrationConflict],
    boundary: &Path,
    leaf: &Path,
    violations: &mut Vec<String>,
) {
    if !g2_conflict_names_path_or_descendant(conflicts, root, boundary) {
        violations.push(format!(
            "conflict evidence omitted nested boundary {}",
            boundary.display()
        ));
    }
    if !g2_conflict_names_path_or_descendant(conflicts, root, leaf) {
        violations.push(format!(
            "conflict evidence omitted affected leaf {}",
            leaf.display()
        ));
    }

    let (_, journal) = latest_journal_generation(root, migration_id);
    if journal["direction"] != "rollback" {
        violations.push(format!(
            "journal direction was {:?}, expected rollback",
            journal["direction"]
        ));
    }
    if journal["phase"] != "conflicted" {
        violations.push(format!(
            "journal phase was {:?}, expected conflicted",
            journal["phase"]
        ));
    }
    let inverse_receipts = journal["inverse_receipts"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default();
    if inverse_receipts != 0 {
        violations.push(format!(
            "journal recorded {inverse_receipts} inverse receipt(s) before rejecting the boundary"
        ));
    }
    let plan_path = root
        .join(MIGRATIONS_DIR)
        .join(migration_id)
        .join("plan.json");
    match fs::read(&plan_path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<MigrationPlan>(&bytes).map_err(|error| error.to_string())
        }) {
        Ok(plan) if plan.state == MigrationState::Conflicted => {}
        Ok(plan) => violations.push(format!(
            "durable plan state was {:?}, expected Conflicted",
            plan.state
        )),
        Err(error) => violations.push(format!(
            "could not read durable plan {}: {error}",
            plan_path.display()
        )),
    }

    for suffix in ["rollback.claim", "rollback.receipt"] {
        let artifacts = g2_private_artifacts_with_suffix(root, migration_id, suffix);
        if !artifacts.is_empty() {
            violations.push(format!(
                "private {suffix} artifact(s) existed before rejection: {}",
                artifacts.join(", ")
            ));
        }
    }
}

fn assert_g2_additive_nested_boundary_case(shape: G2NestedBoundaryShape, label: &str) {
    const README_BYTES: &[u8] = b"ordinary root notes\n";
    const OVERVIEW_BYTES: &[u8] = b"client overview\n";
    let (root, migration_id, approval_digest) = prepared_additive_v1_fixture_with_digest(&[
        ("README.md", README_BYTES),
        ("Client-Shared/Overview.md", OVERVIEW_BYTES),
    ]);
    let applied = MigrationExecution::run(
        RootClaim::Current {
            display_root: root.path(),
        },
        MigrationCommand::Apply {
            migration_id: &migration_id,
            approval_digest: &approval_digest,
        },
    )
    .expect("apply additive transaction");
    assert!(
        matches!(applied, MigrationOutcome::Applied(_)),
        "{label} requires an applied additive transaction"
    );

    let organized = root.path().join("Organized");
    let boundary = organized.join("Client-Shared");
    let affected_leaf = boundary.join("Overview.md");
    let marker = install_g2_nested_boundary(&boundary, shape);
    let organized_before = raw_tree_snapshot(&organized);
    let source_paths = [
        root.path().join("README.md"),
        root.path().join("Client-Shared/Overview.md"),
    ];
    let source_before = source_paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                PhysicalIdentity::from_path(path).expect("ordinary source identity"),
                fs::read(path).expect("ordinary source bytes"),
            )
        })
        .collect::<Vec<_>>();

    let (conflicted_id, conflicts) = expect_conflicted(
        MigrationExecution::run(
            RootClaim::Current {
                display_root: root.path(),
            },
            MigrationCommand::Rollback {
                migration_id: &migration_id,
            },
        ),
        label,
    );
    let mut violations = Vec::new();
    if conflicted_id != migration_id {
        violations.push(format!(
            "conflicted migration id was {conflicted_id}, expected {migration_id}"
        ));
    }
    assert_g2_durable_rollback_conflict(
        root.path(),
        &migration_id,
        &conflicts,
        &boundary,
        &affected_leaf,
        &mut violations,
    );

    let organized_after = if organized.exists() {
        raw_tree_snapshot(&organized)
    } else {
        Vec::new()
    };
    violations.extend(
        g2_snapshot_mutations(&organized_before, &organized_after)
            .into_iter()
            .map(|mutation| format!("ordinary additive tree {mutation}")),
    );
    for (path, expected_identity, expected_bytes) in source_before {
        match PhysicalIdentity::from_path(&path) {
            Ok(observed_identity) if observed_identity == expected_identity => {}
            Ok(_) => violations.push(format!(
                "ordinary source identity changed {}",
                path.display()
            )),
            Err(_) => violations.push(format!("ordinary source disappeared {}", path.display())),
        }
        match fs::read(&path) {
            Ok(observed_bytes) if observed_bytes == expected_bytes => {}
            Ok(_) => violations.push(format!("ordinary source bytes changed {}", path.display())),
            Err(_) => violations.push(format!("ordinary source unreadable {}", path.display())),
        }
    }
    if !marker.exists() {
        violations.push(format!(
            "nested boundary marker disappeared {}",
            marker.display()
        ));
    }

    assert!(
        violations.is_empty(),
        "{label} violated conflict-before-mutation:\n{}",
        violations.join("\n")
    );
}

fn assert_g2_move_nested_boundary_case(shape: G2NestedBoundaryShape, label: &str) {
    let fixture = apply_closed_leaf(ClosedLeafKind::MoveFile);
    let source = fixture.source.as_ref().expect("Move source").clone();
    let boundary = source.parent().expect("Move source parent").to_path_buf();
    let marker = install_g2_nested_boundary(&boundary, shape);
    let boundary_before = raw_tree_snapshot(&boundary);
    let destination_identity =
        PhysicalIdentity::from_path(&fixture.target).expect("applied Move destination identity");
    let destination_bytes = fs::read(&fixture.target).expect("applied Move destination bytes");
    let source_claim = source_claim_path(&fixture);
    let source_claim_identity =
        PhysicalIdentity::from_path(&source_claim).expect("Move source claim identity");
    let source_claim_bytes = fs::read(&source_claim).expect("Move source claim bytes");

    let (conflicted_id, conflicts) = expect_conflicted(public_rollback(&fixture), label);
    let mut violations = Vec::new();
    if conflicted_id != fixture.migration_id {
        violations.push(format!(
            "conflicted migration id was {conflicted_id}, expected {}",
            fixture.migration_id
        ));
    }
    assert_g2_durable_rollback_conflict(
        fixture.root.path(),
        &fixture.migration_id,
        &conflicts,
        &boundary,
        &source,
        &mut violations,
    );

    let boundary_after = raw_tree_snapshot(&boundary);
    violations.extend(
        g2_snapshot_mutations(&boundary_before, &boundary_after)
            .into_iter()
            .map(|mutation| format!("ordinary Move source parent {mutation}")),
    );
    if source.exists() {
        violations.push(format!("Move source was restored {}", source.display()));
    }
    match PhysicalIdentity::from_path(&fixture.target) {
        Ok(identity) if identity == destination_identity => {}
        Ok(_) => violations.push(format!(
            "Move destination identity changed {}",
            fixture.target.display()
        )),
        Err(_) => violations.push(format!(
            "Move destination disappeared {}",
            fixture.target.display()
        )),
    }
    match fs::read(&fixture.target) {
        Ok(bytes) if bytes == destination_bytes => {}
        Ok(_) => violations.push(format!(
            "Move destination bytes changed {}",
            fixture.target.display()
        )),
        Err(_) => violations.push(format!(
            "Move destination became unreadable {}",
            fixture.target.display()
        )),
    }
    match PhysicalIdentity::from_path(&source_claim) {
        Ok(identity) if identity == source_claim_identity => {}
        Ok(_) => violations.push(format!(
            "Move source claim identity changed {}",
            source_claim.display()
        )),
        Err(_) => violations.push(format!(
            "Move source claim disappeared {}",
            source_claim.display()
        )),
    }
    match fs::read(&source_claim) {
        Ok(bytes) if bytes == source_claim_bytes => {}
        Ok(_) => violations.push(format!(
            "Move source claim bytes changed {}",
            source_claim.display()
        )),
        Err(_) => violations.push(format!(
            "Move source claim became unreadable {}",
            source_claim.display()
        )),
    }
    if !marker.exists() {
        violations.push(format!(
            "nested boundary marker disappeared {}",
            marker.display()
        ));
    }

    assert!(
        violations.is_empty(),
        "{label} violated conflict-before-mutation:\n{}",
        violations.join("\n")
    );
}

#[test]
fn rollback_nested_boundary_matrix_conflicts_before_mutating_any_ordinary_leaf() {
    let cases = [
        (
            "applied_additive_tree/exact",
            G2RollbackSurface::AppliedAdditiveTree,
            G2NestedBoundaryShape::Exact,
        ),
        (
            "applied_additive_tree/state_alias",
            G2RollbackSurface::AppliedAdditiveTree,
            G2NestedBoundaryShape::StateAlias,
        ),
        (
            "applied_additive_tree/manifest_alias",
            G2RollbackSurface::AppliedAdditiveTree,
            G2NestedBoundaryShape::ManifestAlias,
        ),
        (
            "restored_move_parent/exact",
            G2RollbackSurface::RestoredMoveParent,
            G2NestedBoundaryShape::Exact,
        ),
        (
            "restored_move_parent/state_alias",
            G2RollbackSurface::RestoredMoveParent,
            G2NestedBoundaryShape::StateAlias,
        ),
        (
            "restored_move_parent/manifest_alias",
            G2RollbackSurface::RestoredMoveParent,
            G2NestedBoundaryShape::ManifestAlias,
        ),
    ];
    let mut failures = Vec::new();
    for (label, surface, shape) in cases {
        let result = catch_unwind(AssertUnwindSafe(|| match surface {
            G2RollbackSurface::AppliedAdditiveTree => {
                assert_g2_additive_nested_boundary_case(shape, label)
            }
            G2RollbackSurface::RestoredMoveParent => {
                assert_g2_move_nested_boundary_case(shape, label)
            }
        }));
        if let Err(payload) = result {
            failures.push(format!("{label}: {}", matrix_panic_detail(payload)));
        }
    }
    assert!(
        failures.is_empty(),
        "nested-boundary rollback matrix failures:\n{}",
        failures.join("\n")
    );
}
