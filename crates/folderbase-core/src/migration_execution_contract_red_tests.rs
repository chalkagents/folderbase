use std::path::Path;

use crate::{
    Result,
    migration::{MigrationCommand, MigrationExecution, MigrationOutcome, RootClaim},
};

fn execute_one_semantic_command<'a>(
    root: RootClaim<'a>,
    command: MigrationCommand<'a>,
) -> Result<MigrationOutcome> {
    MigrationExecution::run(root, command)
}

#[test]
fn migration_execution_has_one_semantic_apply_recover_rollback_entry() {
    let root = Path::new("/diagnostic-only");
    let apply = MigrationCommand::Apply {
        migration_id: "migration_00000000-0000-7000-8000-000000000000",
        approval_digest: "0000000000000000000000000000000000000000000000000000000000000000",
    };
    let recover = MigrationCommand::Recover {
        migration_id: "migration_00000000-0000-7000-8000-000000000000",
    };
    let rollback = MigrationCommand::Rollback {
        migration_id: "migration_00000000-0000-7000-8000-000000000000",
    };
    let claim = RootClaim::Current { display_root: root };

    // This is a type-level seam assertion only. Behavior tests enter through
    // the compatibility wrappers and deterministic crate-local fault seam.
    let _ = (
        apply,
        recover,
        rollback,
        claim,
        execute_one_semantic_command,
    );
}

#[allow(dead_code)]
fn every_execution_outcome_is_semantic_and_conflicts_are_explicit(outcome: MigrationOutcome) {
    match outcome {
        MigrationOutcome::Applied(result) => {
            let _ = result.migration_id;
        }
        MigrationOutcome::RolledBack(result) => {
            let _ = result.migration_id;
        }
        MigrationOutcome::Conflicted {
            migration_id,
            conflicts,
        } => {
            assert!(!migration_id.is_empty());
            assert!(!conflicts.is_empty());
        }
    }
}

// Durability acceptance intentionally remains behavior-only at the future
// module-private fake-kernel seam: Unsupported(reason) must be returned before
// any workspace mutation. This RED contract does not freeze NamespaceKernel's
// raw mutation signatures or expose them through MigrationExecution.
