use std::{fs, path::Path};

use folderbase_core::{
    ApprovedMigration, FolderbaseKind, InitializationOptions, MigrationOperation, MigrationPlan,
    MigrationResult, RollbackResult, apply_migration, approve_migration, initialize,
    plan_initialization,
};
use tempfile::TempDir;

fn initialized_folderbase() -> TempDir {
    let root = tempfile::tempdir().expect("fixture");
    initialize(
        &plan_initialization(
            root.path(),
            InitializationOptions {
                name: Some("Migration Transaction Contract".to_owned()),
                kind: FolderbaseKind::Project,
                create_agent_adapters: true,
            },
        )
        .expect("initialization plan"),
    )
    .expect("initialize fixture");
    root
}

fn approved_move(root: &Path) -> (String, ApprovedMigration) {
    fs::create_dir(root.join("Archive")).expect("archive");
    fs::write(root.join("notes.md"), b"approved bytes\n").expect("source");
    let plan = MigrationPlan::propose_structural(
        root,
        vec![MigrationOperation::move_object(
            "notes.md",
            "Archive/notes.md",
        )],
    )
    .expect("structural plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approval");
    (migration_id, approved)
}

fn applied_move(root: &Path) -> String {
    let (migration_id, approved) = approved_move(root);
    apply_migration(approved).expect("apply");
    migration_id
}

fn transaction_root(root: &Path, migration_id: &str) -> std::path::PathBuf {
    root.join(".folderbase/migrations")
        .join(migration_id)
        .join("transaction-v1")
}

fn assert_recovery_fails_closed(root: &Path, migration_id: &str) {
    let error = MigrationResult::recover(root, migration_id)
        .expect_err("invalid private transaction state must fail closed");
    assert!(matches!(
        error,
        folderbase_core::FolderbaseError::InvalidRecord { .. }
            | folderbase_core::FolderbaseError::UnsafePath(_)
            | folderbase_core::FolderbaseError::Io { .. }
    ));
    assert_eq!(
        fs::read(root.join("Archive/notes.md")).expect("visible result"),
        b"approved bytes\n"
    );
}

#[test]
fn compatibility_surface_keeps_one_apply_recover_and_rollback_entry_each() {
    fn recover(root: &Path, migration_id: &str) -> folderbase_core::Result<MigrationResult> {
        MigrationResult::recover(root, migration_id)
    }
    fn rollback(root: &Path, migration_id: &str) -> folderbase_core::Result<RollbackResult> {
        MigrationResult::rollback_by_id(root, migration_id)
    }

    let _: fn(ApprovedMigration) -> folderbase_core::Result<MigrationResult> = apply_migration;
    let _: fn(&Path, &str) -> folderbase_core::Result<MigrationResult> = recover;
    let _: fn(&Path, &str) -> folderbase_core::Result<RollbackResult> = rollback;
}

#[test]
fn transaction_v1_rejects_noncanonical_program_bytes_before_recovery() {
    let root = initialized_folderbase();
    let migration_id = applied_move(root.path());
    let program = transaction_root(root.path(), &migration_id).join("program.json");
    let mut bytes = fs::read(&program).expect("program");
    bytes.push(b'\n');
    fs::write(&program, bytes).expect("noncanonical program");

    assert_recovery_fails_closed(root.path(), &migration_id);
}

#[test]
fn transaction_v1_rejects_noncanonical_journal_generation_bytes() {
    let root = initialized_folderbase();
    let migration_id = applied_move(root.path());
    let generation =
        transaction_root(root.path(), &migration_id).join("journal/00000000000000000000.json");
    let mut bytes = fs::read(&generation).expect("generation");
    bytes.push(b'\n');
    fs::write(&generation, bytes).expect("noncanonical generation");

    assert_recovery_fails_closed(root.path(), &migration_id);
}

#[test]
fn transaction_v1_rejects_unknown_entries_and_directory_kinds() {
    for unknown_is_directory in [false, true] {
        let root = initialized_folderbase();
        let migration_id = applied_move(root.path());
        let unknown = transaction_root(root.path(), &migration_id).join("unknown");
        if unknown_is_directory {
            fs::create_dir(&unknown).expect("unknown directory");
        } else {
            fs::write(&unknown, b"unknown\n").expect("unknown file");
        }

        assert_recovery_fails_closed(root.path(), &migration_id);
    }
}

#[test]
fn transaction_v1_rejects_missing_and_inner_wrong_kind_entries() {
    let root = initialized_folderbase();
    let migration_id = applied_move(root.path());
    fs::remove_dir(transaction_root(root.path(), &migration_id).join("receipts"))
        .expect("remove expected directory");
    assert_recovery_fails_closed(root.path(), &migration_id);

    let root = initialized_folderbase();
    let migration_id = applied_move(root.path());
    fs::create_dir(transaction_root(root.path(), &migration_id).join("journal/unknown"))
        .expect("wrong-kind journal entry");
    assert_recovery_fails_closed(root.path(), &migration_id);
}

#[test]
fn transaction_v1_journal_bound_is_derived_from_the_operation_count() {
    let root = initialized_folderbase();
    let migration_id = applied_move(root.path());
    let journal = transaction_root(root.path(), &migration_id).join("journal");
    let bytes = fs::read(journal.join("00000000000000000003.json")).expect("terminal generation");
    // One operation admits at most 4(1)+6 = 10 generations, far below the
    // process-wide defensive ceiling.
    for generation in 4..=10 {
        fs::write(journal.join(format!("{generation:020}.json")), &bytes)
            .expect("surplus generation");
    }

    assert_recovery_fails_closed(root.path(), &migration_id);
}

#[cfg(unix)]
#[test]
fn transaction_v1_rejects_insecure_reopened_private_state() {
    use std::os::unix::fs::PermissionsExt;

    for (relative, mode) in [
        ("", 0o755),
        ("program.json", 0o644),
        ("journal/00000000000000000000.json", 0o644),
    ] {
        let root = initialized_folderbase();
        let migration_id = applied_move(root.path());
        let transaction = transaction_root(root.path(), &migration_id);
        fs::set_permissions(transaction.join(relative), fs::Permissions::from_mode(mode))
            .expect("weaken private mode");
        assert_recovery_fails_closed(root.path(), &migration_id);
    }
}

#[cfg(unix)]
#[test]
fn transaction_v1_rejects_an_inner_symlink() {
    use std::os::unix::fs::symlink;

    let root = initialized_folderbase();
    let migration_id = applied_move(root.path());
    let transaction = transaction_root(root.path(), &migration_id);
    symlink(
        transaction.join("program.json"),
        transaction.join("stages/00000000.stage"),
    )
    .expect("inner symlink");

    assert_recovery_fails_closed(root.path(), &migration_id);
}

#[cfg(unix)]
#[test]
fn every_private_migration_directory_is_owner_only_even_under_a_permissive_umask() {
    const CHILD: &str = "FOLDERBASE_MIGRATION_PRIVATE_MODE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "every_private_migration_directory_is_owner_only_even_under_a_permissive_umask",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("isolated test process");
        assert!(
            output.status.success(),
            "isolated permission assertion failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    use std::os::unix::fs::PermissionsExt;

    struct Umask(libc::mode_t);
    impl Umask {
        fn set(mask: libc::mode_t) -> Self {
            // SAFETY: the mode-sensitive body runs in the isolated child above.
            Self(unsafe { libc::umask(mask) })
        }
    }
    impl Drop for Umask {
        fn drop(&mut self) {
            // SAFETY: restore the child process's original mask.
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    let _umask = Umask::set(0o000);
    let root = initialized_folderbase();
    let (_migration_id, approved) = approved_move(root.path());
    let _result = apply_migration(approved).expect("apply");

    let private_root = root.path().join(".folderbase");
    let insecure = walkdir::WalkDir::new(&private_root)
        .into_iter()
        .map(|entry| entry.expect("private state entry"))
        .filter(|entry| entry.file_type().is_dir())
        .filter_map(|entry| {
            let mode = entry
                .metadata()
                .expect("private directory metadata")
                .permissions()
                .mode()
                & 0o777;
            (mode != 0o700).then(|| {
                (
                    entry
                        .path()
                        .strip_prefix(root.path())
                        .expect("relative private path")
                        .to_path_buf(),
                    mode,
                )
            })
        })
        .collect::<Vec<_>>();

    assert!(
        insecure.is_empty(),
        "private Folderbase directories must be 0700; insecure modes: {insecure:?}"
    );
}

#[cfg(windows)]
#[test]
fn structural_apply_rejects_a_windows_reparse_leaf_without_touching_its_target() {
    use std::os::windows::fs::symlink_file;

    let root = initialized_folderbase();
    let adapter = root.path().join("AGENTS.md");
    let plan = MigrationPlan::propose_structural(
        root.path(),
        vec![MigrationOperation::update_adapter(
            "AGENTS.md",
            "Use only the exact Folderbase root.",
        )],
    )
    .expect("replace plan");
    let migration_id = plan.id.clone();
    let approved = approve_migration(plan).expect("approval");
    let foreign = root.path().join("foreign-adapter.md");
    fs::write(&foreign, fs::read(&adapter).expect("approved adapter")).expect("foreign bytes");
    fs::remove_file(&adapter).expect("remove approved leaf");
    symlink_file(&foreign, &adapter).expect("GitHub Windows runners permit file symlinks");

    let error = apply_migration(approved).expect_err("a reparse leaf must fail closed");

    assert!(
        matches!(error, folderbase_core::FolderbaseError::UnsafePath(ref path) if path == &adapter),
        "the mutation boundary must report the reparse leaf explicitly: {error:?}"
    );
    assert_eq!(
        fs::read(&foreign).expect("foreign target"),
        fs::read(&adapter).expect("linked bytes"),
        "rejection must not mutate the reparse target"
    );
    assert_eq!(
        MigrationPlan::reopen(root.path(), &migration_id)
            .expect("exact durable migration")
            .state,
        folderbase_core::MigrationState::Conflicted
    );
}
