#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceTrigger {
    UserInvoked,
    Heartbeat { enabled: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLimits {
    pub tokens: u64,
    /// Currency represented as integer millionths to avoid floating-point
    /// budget drift.
    pub cost_micros: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetUsage {
    pub tokens: u64,
    pub cost_micros: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelRequestBudget {
    /// Maximum tokens the runner is permitted to consume, not an estimate.
    pub max_tokens: u64,
    /// Maximum charge the runner is permitted to accrue.
    pub max_cost_micros: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLedger {
    limits: BudgetLimits,
    usage: BudgetUsage,
}

impl BudgetLedger {
    pub fn new(limits: BudgetLimits) -> Self {
        Self {
            limits,
            usage: BudgetUsage::default(),
        }
    }

    pub fn from_usage(limits: BudgetLimits, usage: BudgetUsage) -> Self {
        Self { limits, usage }
    }

    pub fn limits(&self) -> BudgetLimits {
        self.limits
    }

    pub fn usage(&self) -> BudgetUsage {
        self.usage
    }

    pub fn remaining(&self) -> BudgetUsage {
        BudgetUsage {
            tokens: self.limits.tokens.saturating_sub(self.usage.tokens),
            cost_micros: self
                .limits
                .cost_micros
                .saturating_sub(self.usage.cost_micros),
        }
    }

    /// Atomically account for observed usage. The ledger is unchanged if the
    /// charge would cross either hard limit.
    pub fn charge(&mut self, delta: BudgetUsage) -> Result<(), BudgetExceeded> {
        let token_total = self.usage.tokens.checked_add(delta.tokens);
        let cost_total = self.usage.cost_micros.checked_add(delta.cost_micros);
        let exceeded = BudgetExceeded {
            tokens: token_total.is_none_or(|total| total > self.limits.tokens),
            cost: cost_total.is_none_or(|total| total > self.limits.cost_micros),
        };

        if exceeded.any() {
            return Err(exceeded);
        }

        self.usage = BudgetUsage {
            tokens: token_total.expect("checked above"),
            cost_micros: cost_total.expect("checked above"),
        };
        Ok(())
    }

    fn can_reserve(self, request: ModelRequestBudget) -> Result<(), BudgetExceeded> {
        let exceeded = BudgetExceeded {
            tokens: self
                .usage
                .tokens
                .checked_add(request.max_tokens)
                .is_none_or(|total| total > self.limits.tokens),
            cost: self
                .usage
                .cost_micros
                .checked_add(request.max_cost_micros)
                .is_none_or(|total| total > self.limits.cost_micros),
        };
        if exceeded.any() {
            Err(exceeded)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExceeded {
    pub tokens: bool,
    pub cost: bool,
}

impl BudgetExceeded {
    pub fn any(self) -> bool {
        self.tokens || self.cost
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightInput {
    pub trigger: MaintenanceTrigger,
    /// Count produced by deterministic inventory/change detection. Model
    /// inference must not be used to manufacture this signal.
    pub meaningful_change_count: u64,
    pub request: ModelRequestBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoOpReason {
    NoMeaningfulChange,
    HeartbeatDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightDecision {
    /// The caller must not invoke a model.
    NoOp(NoOpReason),
    /// A meaningful update exists, but the maximum possible request would
    /// cross a hard budget. The caller must not invoke a model.
    BlockedByBudget(BudgetExceeded),
    /// The model may be invoked with exactly these hard ceilings.
    InvokeModel(ModelRequestBudget),
}

impl PreflightDecision {
    pub fn permits_model_call(self) -> bool {
        matches!(self, Self::InvokeModel(_))
    }
}

/// Decide whether maintenance should reach model inference.
///
/// Deterministic no-op checks deliberately run before budget checks so an
/// unchanged heartbeat remains a cheap no-op even when its budget is empty.
pub fn deterministic_preflight(input: PreflightInput, budget: &BudgetLedger) -> PreflightDecision {
    if input.meaningful_change_count == 0 {
        return PreflightDecision::NoOp(NoOpReason::NoMeaningfulChange);
    }
    if matches!(
        input.trigger,
        MaintenanceTrigger::Heartbeat { enabled: false }
    ) {
        return PreflightDecision::NoOp(NoOpReason::HeartbeatDisabled);
    }

    match budget.can_reserve(input.request) {
        Ok(()) => PreflightDecision::InvokeModel(input.request),
        Err(exceeded) => PreflightDecision::BlockedByBudget(exceeded),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectLifecycle {
    Draft,
    Canonical,
    Superseded,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeChange {
    Unchanged,
    Narrow,
    Expand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuideAction {
    AnalyzeInventory,
    AskMigrationQuestions,
    ProposeStructure,
    ProposeRelationship,
    RefreshDerivedSummary,
    RefreshStaleSignals,
    WriteMigrationPlan { approved: bool },
    ChangePermissions { broadens_access: bool },
    DeleteObject { lifecycle: ObjectLifecycle },
    MoveObject { lifecycle: ObjectLifecycle },
    MergeObjects { includes_canonical: bool },
    ArchiveObject { active_work: bool },
    ChangeScope { change: ScopeChange },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityReason {
    PermissionBroadening,
    PermissionChangeRequiresApproval,
    CanonicalDeletion,
    CanonicalMove,
    CanonicalMerge,
    ActiveArchive,
    ArchiveRequiresApproval,
    ScopeExpansion,
    StructuralChangeRequiresApproval,
    MigrationPlanNotApproved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityDecision {
    Allowed,
    RequiresApproval(AuthorityReason),
    Denied(AuthorityReason),
}

impl AuthorityDecision {
    pub fn is_allowed(self) -> bool {
        self == Self::Allowed
    }
}

/// Apply the Guide's autonomous-authority boundary.
///
/// Denied operations cannot be converted into direct Guide writes by passing
/// an approval flag. An approved structural change must be handed to the
/// migration/change-set executor, preserving separation of authority.
pub fn authorize(action: GuideAction) -> AuthorityDecision {
    match action {
        GuideAction::AnalyzeInventory
        | GuideAction::AskMigrationQuestions
        | GuideAction::ProposeStructure
        | GuideAction::ProposeRelationship
        | GuideAction::RefreshDerivedSummary
        | GuideAction::RefreshStaleSignals
        | GuideAction::ChangeScope {
            change: ScopeChange::Unchanged | ScopeChange::Narrow,
        } => AuthorityDecision::Allowed,
        GuideAction::WriteMigrationPlan { approved: true } => AuthorityDecision::Allowed,
        GuideAction::WriteMigrationPlan { approved: false } => {
            AuthorityDecision::RequiresApproval(AuthorityReason::MigrationPlanNotApproved)
        }
        GuideAction::ChangePermissions {
            broadens_access: true,
        } => AuthorityDecision::Denied(AuthorityReason::PermissionBroadening),
        GuideAction::ChangePermissions {
            broadens_access: false,
        } => AuthorityDecision::RequiresApproval(AuthorityReason::PermissionChangeRequiresApproval),
        GuideAction::DeleteObject {
            lifecycle: ObjectLifecycle::Canonical,
        } => AuthorityDecision::Denied(AuthorityReason::CanonicalDeletion),
        GuideAction::MoveObject {
            lifecycle: ObjectLifecycle::Canonical,
        } => AuthorityDecision::Denied(AuthorityReason::CanonicalMove),
        GuideAction::MergeObjects {
            includes_canonical: true,
        } => AuthorityDecision::Denied(AuthorityReason::CanonicalMerge),
        GuideAction::ArchiveObject { active_work: true } => {
            AuthorityDecision::Denied(AuthorityReason::ActiveArchive)
        }
        GuideAction::ChangeScope {
            change: ScopeChange::Expand,
        } => AuthorityDecision::Denied(AuthorityReason::ScopeExpansion),
        GuideAction::ArchiveObject { active_work: false } => {
            AuthorityDecision::RequiresApproval(AuthorityReason::ArchiveRequiresApproval)
        }
        GuideAction::DeleteObject { .. }
        | GuideAction::MoveObject { .. }
        | GuideAction::MergeObjects { .. } => {
            AuthorityDecision::RequiresApproval(AuthorityReason::StructuralChangeRequiresApproval)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(tokens: u64, cost_micros: u64) -> BudgetLedger {
        BudgetLedger::new(BudgetLimits {
            tokens,
            cost_micros,
        })
    }

    fn changed_request() -> PreflightInput {
        PreflightInput {
            trigger: MaintenanceTrigger::Heartbeat { enabled: true },
            meaningful_change_count: 1,
            request: ModelRequestBudget {
                max_tokens: 100,
                max_cost_micros: 50,
            },
        }
    }

    #[test]
    fn unchanged_heartbeat_is_a_model_free_no_op() {
        let mut input = changed_request();
        input.meaningful_change_count = 0;
        let decision = deterministic_preflight(input, &budget(0, 0));

        assert_eq!(
            decision,
            PreflightDecision::NoOp(NoOpReason::NoMeaningfulChange)
        );
        assert!(!decision.permits_model_call());
    }

    #[test]
    fn a_disabled_heartbeat_does_not_invoke_a_model_for_changes() {
        let mut input = changed_request();
        input.trigger = MaintenanceTrigger::Heartbeat { enabled: false };

        assert_eq!(
            deterministic_preflight(input, &budget(1_000, 1_000)),
            PreflightDecision::NoOp(NoOpReason::HeartbeatDisabled)
        );
    }

    #[test]
    fn preflight_enforces_maximum_token_and_cost_reservations() {
        let at_limit = deterministic_preflight(changed_request(), &budget(100, 50));
        assert!(at_limit.permits_model_call());

        assert_eq!(
            deterministic_preflight(changed_request(), &budget(99, 50)),
            PreflightDecision::BlockedByBudget(BudgetExceeded {
                tokens: true,
                cost: false,
            })
        );
        assert_eq!(
            deterministic_preflight(changed_request(), &budget(100, 49)),
            PreflightDecision::BlockedByBudget(BudgetExceeded {
                tokens: false,
                cost: true,
            })
        );

        let already_exhausted = BudgetLedger::from_usage(
            BudgetLimits {
                tokens: 100,
                cost_micros: 50,
            },
            BudgetUsage {
                tokens: 101,
                cost_micros: 51,
            },
        );
        let mut zero_request = changed_request();
        zero_request.request = ModelRequestBudget {
            max_tokens: 0,
            max_cost_micros: 0,
        };
        assert_eq!(
            deterministic_preflight(zero_request, &already_exhausted),
            PreflightDecision::BlockedByBudget(BudgetExceeded {
                tokens: true,
                cost: true,
            })
        );
    }

    #[test]
    fn ledger_never_mutates_when_a_charge_would_cross_a_hard_limit() {
        let mut ledger = budget(100, 50);
        ledger
            .charge(BudgetUsage {
                tokens: 90,
                cost_micros: 40,
            })
            .unwrap();
        let before = ledger.usage();

        let error = ledger
            .charge(BudgetUsage {
                tokens: 11,
                cost_micros: 1,
            })
            .unwrap_err();
        assert_eq!(
            error,
            BudgetExceeded {
                tokens: true,
                cost: false,
            }
        );
        assert_eq!(ledger.usage(), before);
    }

    #[test]
    fn authority_guard_denies_every_forbidden_autonomous_action() {
        let forbidden = [
            (
                GuideAction::ChangePermissions {
                    broadens_access: true,
                },
                AuthorityReason::PermissionBroadening,
            ),
            (
                GuideAction::DeleteObject {
                    lifecycle: ObjectLifecycle::Canonical,
                },
                AuthorityReason::CanonicalDeletion,
            ),
            (
                GuideAction::MoveObject {
                    lifecycle: ObjectLifecycle::Canonical,
                },
                AuthorityReason::CanonicalMove,
            ),
            (
                GuideAction::MergeObjects {
                    includes_canonical: true,
                },
                AuthorityReason::CanonicalMerge,
            ),
            (
                GuideAction::ArchiveObject { active_work: true },
                AuthorityReason::ActiveArchive,
            ),
            (
                GuideAction::ChangeScope {
                    change: ScopeChange::Expand,
                },
                AuthorityReason::ScopeExpansion,
            ),
        ];

        for (action, reason) in forbidden {
            assert_eq!(
                authorize(action),
                AuthorityDecision::Denied(reason),
                "{action:?}"
            );
        }
    }

    #[test]
    fn safe_analysis_and_approved_plan_writes_are_allowed() {
        for action in [
            GuideAction::AnalyzeInventory,
            GuideAction::AskMigrationQuestions,
            GuideAction::ProposeStructure,
            GuideAction::ProposeRelationship,
            GuideAction::RefreshDerivedSummary,
            GuideAction::RefreshStaleSignals,
            GuideAction::WriteMigrationPlan { approved: true },
        ] {
            assert_eq!(authorize(action), AuthorityDecision::Allowed);
        }

        assert!(matches!(
            authorize(GuideAction::ArchiveObject { active_work: false }),
            AuthorityDecision::RequiresApproval(AuthorityReason::ArchiveRequiresApproval)
        ));
    }
}
