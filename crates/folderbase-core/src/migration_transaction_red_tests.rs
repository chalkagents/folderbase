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
    value["operations"][0]["operation"]["x-checkpoint-e-unknown"] = serde_json::Value::Bool(true);
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
    let operation_count = value["operations"]
        .as_array()
        .expect("program operations")
        .len();
    // Six phase records bracket at most one intent/completion pair in each
    // direction for every compiled leaf operation.
    let maximum_generation_count = 6 + operation_count * 4;
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

fn remove_transitional_legacy_result(fixture: &PreparedV1Fixture) {
    let result_path = fixture
        .root
        .path()
        .join(".folderbase/migrations")
        .join(&fixture.migration_id)
        .join("result.json");
    match fs::remove_file(result_path) {
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

#[test]
fn changed_source_identity_is_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    substitute_regular(&fixture.source, &fixture.source_bytes);

    assert!(retry_prepared_apply(&fixture).is_err());
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

    assert!(retry_prepared_apply(&fixture).is_err());
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

    assert!(retry_prepared_apply(&fixture).is_err());
    assert!(fixture.source.is_dir());
    assert!(!fixture.destination.exists());
}

#[test]
fn changed_destination_absence_is_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    fs::write(&fixture.destination, b"competing destination\n").expect("destination competitor");

    assert!(retry_prepared_apply(&fixture).is_err());
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

    assert!(retry_prepared_apply(&fixture).is_err());
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn changed_policy_facts_are_rejected_before_leaf_mutation() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let policy = fixture.root.path().join(".folderbaseignore");
    fs::write(&policy, b"Inbox/**\n").expect("changed policy from absence to presence");

    assert!(retry_prepared_apply(&fixture).is_err());
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
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

    assert!(
        outcome.is_err(),
        "program-bound parent replacement must fail before mutation"
    );
    assert_eq!(
        fs::read(&fixture.source).expect("source remains"),
        fixture.source_bytes
    );
    assert!(!fixture.destination.exists());
}

#[test]
fn legacy_only_recovery_keeps_the_released_move_semantics() {
    let (root, migration_id, approved, source, destination, source_bytes) =
        approved_structural_leaf(StructuralLeafKind::Move);
    let destination = destination.expect("move destination");
    let mut plan = approved.plan;
    apply_structural_operation(root.path(), &plan.operations[0]).expect("released leaf transition");
    let journal = MigrationJournal {
        protocol_version: "0.2.0".to_owned(),
        id: migration_id.clone(),
        root: plan.root.clone(),
        state: MigrationState::Applying,
        approval_digest: approved.approval_digest,
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
        in_flight_operation: Some(0),
        transaction_program_digest: None,
        operation_precondition_identities: Vec::new(),
        operation_result_identities: Vec::new(),
    };
    let result_path = root
        .path()
        .join(".folderbase/migrations")
        .join(&migration_id)
        .join("result.json");
    persist_journal(&result_path, &journal).expect("released result journal");
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
fn prepared_transaction_v1_cannot_fall_through_the_legacy_recovery_executor() {
    let fixture = prepared_v1_fixture(ApplyCheckpoint::JournalPrepared);
    let source_identity = PhysicalIdentity::from_path(&fixture.source).expect("source identity");

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
        "coexisting active transaction-v1 and legacy state must fail closed"
    );
    assert_eq!(
        PhysicalIdentity::from_path(&fixture.source).expect("source remains"),
        source_identity
    );
    assert!(!fixture.destination.exists());
}
