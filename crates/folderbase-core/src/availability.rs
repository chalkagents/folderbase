use std::time::Duration;

/// The storage behavior selected for a folderbase on one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoragePolicy {
    /// Materialize every current object, verify it, and never initiate eviction.
    KeepLocal,
    /// Materialize on demand, but still require an explicit archive decision
    /// before removing local content.
    Managed,
    /// Treat the verified cloud copy as canonical for access on this device.
    ///
    /// Selecting this policy does not itself authorize deletion of existing
    /// local bytes. Local removal still goes through [`evaluate_archive`].
    CloudOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderbaseLifecycle {
    Active,
    Paused,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationState {
    Missing,
    PresentUnverified,
    Verified,
}

impl VerificationState {
    fn is_verified(self) -> bool {
        self == Self::Verified
    }
}

/// Availability facts for one current knowledge object on one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAvailability {
    pub object_id: String,
    pub bytes: u64,
    pub local: VerificationState,
    pub remote: VerificationState,
    /// Whether this object is part of a currently declared task scope.
    pub required_for_session: bool,
    /// Whether the object has been protected from removal for that session.
    pub pinned_for_session: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityInput<'a> {
    pub policy: StoragePolicy,
    pub lifecycle: FolderbaseLifecycle,
    pub objects: &'a [ObjectAvailability],
    /// A session may have an empty object set, so this cannot be inferred only
    /// from `required_for_session`.
    pub session_requested: bool,
    /// Whether every required historical version has been verified remotely.
    pub remote_history_verified: bool,
    /// Whether the platform can honor the no-eviction Keep Local contract.
    pub keep_local_guaranteed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessState {
    LocalComplete,
    SessionReady,
    RemoteReady,
    Incomplete,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessBlocker {
    Archived,
    KeepLocalNotGuaranteed,
    LocalObjectsMissing(u64),
    LocalObjectsUnverified(u64),
    SessionObjectsMissingOrUnverified(u64),
    SessionObjectsUnpinned(u64),
    RemoteObjectsMissingOrUnverified(u64),
    RemoteHistoryUnverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessReport {
    pub state: ReadinessState,
    pub local_complete: bool,
    pub session_ready: bool,
    pub remote_ready: bool,
    pub bytes_required_for_local_complete: u64,
    pub missing_local_object_ids: Vec<String>,
    pub unverified_local_object_ids: Vec<String>,
    pub missing_remote_object_ids: Vec<String>,
    pub unpinned_session_object_ids: Vec<String>,
    pub blockers: Vec<ReadinessBlocker>,
}

/// Evaluate present readiness without materializing, uploading, or removing
/// anything.
pub fn evaluate_readiness(input: &AvailabilityInput<'_>) -> ReadinessReport {
    if input.lifecycle == FolderbaseLifecycle::Archived {
        return ReadinessReport {
            state: ReadinessState::Archived,
            local_complete: false,
            session_ready: false,
            remote_ready: false,
            bytes_required_for_local_complete: input
                .objects
                .iter()
                .filter(|object| !object.local.is_verified())
                .fold(0_u64, |total, object| total.saturating_add(object.bytes)),
            missing_local_object_ids: sorted_ids(
                input
                    .objects
                    .iter()
                    .filter(|object| object.local == VerificationState::Missing),
            ),
            unverified_local_object_ids: sorted_ids(
                input
                    .objects
                    .iter()
                    .filter(|object| object.local == VerificationState::PresentUnverified),
            ),
            missing_remote_object_ids: sorted_ids(
                input
                    .objects
                    .iter()
                    .filter(|object| !object.remote.is_verified()),
            ),
            unpinned_session_object_ids: sorted_ids(
                input
                    .objects
                    .iter()
                    .filter(|object| object.required_for_session && !object.pinned_for_session),
            ),
            blockers: vec![ReadinessBlocker::Archived],
        };
    }

    let missing_local_object_ids = sorted_ids(
        input
            .objects
            .iter()
            .filter(|object| object.local == VerificationState::Missing),
    );
    let unverified_local_object_ids = sorted_ids(
        input
            .objects
            .iter()
            .filter(|object| object.local == VerificationState::PresentUnverified),
    );
    let missing_remote_object_ids = sorted_ids(
        input
            .objects
            .iter()
            .filter(|object| !object.remote.is_verified()),
    );
    let unpinned_session_object_ids = sorted_ids(
        input
            .objects
            .iter()
            .filter(|object| object.required_for_session && !object.pinned_for_session),
    );

    let all_local_verified = input
        .objects
        .iter()
        .all(|object| object.local.is_verified());
    let local_complete = all_local_verified
        && (input.policy != StoragePolicy::KeepLocal || input.keep_local_guaranteed);
    let session_objects_verified = input
        .objects
        .iter()
        .filter(|object| object.required_for_session)
        .all(|object| object.local.is_verified());
    let session_objects_pinned = unpinned_session_object_ids.is_empty();
    let session_ready =
        input.session_requested && session_objects_verified && session_objects_pinned;
    let remote_ready = missing_remote_object_ids.is_empty() && input.remote_history_verified;

    let state = if session_ready {
        ReadinessState::SessionReady
    } else {
        match input.policy {
            StoragePolicy::KeepLocal if local_complete => ReadinessState::LocalComplete,
            StoragePolicy::KeepLocal => ReadinessState::Incomplete,
            StoragePolicy::Managed if local_complete => ReadinessState::LocalComplete,
            StoragePolicy::Managed | StoragePolicy::CloudOnly if remote_ready => {
                ReadinessState::RemoteReady
            }
            StoragePolicy::Managed | StoragePolicy::CloudOnly => ReadinessState::Incomplete,
        }
    };

    let mut blockers = Vec::new();
    if input.policy == StoragePolicy::KeepLocal && !input.keep_local_guaranteed {
        blockers.push(ReadinessBlocker::KeepLocalNotGuaranteed);
    }
    if !missing_local_object_ids.is_empty() {
        blockers.push(ReadinessBlocker::LocalObjectsMissing(
            missing_local_object_ids.len() as u64,
        ));
    }
    if !unverified_local_object_ids.is_empty() {
        blockers.push(ReadinessBlocker::LocalObjectsUnverified(
            unverified_local_object_ids.len() as u64,
        ));
    }
    if input.session_requested && !session_objects_verified {
        let count = input
            .objects
            .iter()
            .filter(|object| object.required_for_session && !object.local.is_verified())
            .count() as u64;
        blockers.push(ReadinessBlocker::SessionObjectsMissingOrUnverified(count));
    }
    if input.session_requested && !session_objects_pinned {
        blockers.push(ReadinessBlocker::SessionObjectsUnpinned(
            unpinned_session_object_ids.len() as u64,
        ));
    }
    if !missing_remote_object_ids.is_empty() {
        blockers.push(ReadinessBlocker::RemoteObjectsMissingOrUnverified(
            missing_remote_object_ids.len() as u64,
        ));
    }
    if !input.remote_history_verified {
        blockers.push(ReadinessBlocker::RemoteHistoryUnverified);
    }

    ReadinessReport {
        state,
        local_complete,
        session_ready,
        remote_ready,
        bytes_required_for_local_complete: input
            .objects
            .iter()
            .filter(|object| !object.local.is_verified())
            .fold(0_u64, |total, object| total.saturating_add(object.bytes)),
        missing_local_object_ids,
        unverified_local_object_ids,
        missing_remote_object_ids,
        unpinned_session_object_ids,
        blockers,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveRequest {
    /// A one-time archive action initiated from an explicit member gesture.
    Manual { approved_by_member: bool },
    /// Evaluation of a member-configured inactivity policy.
    Inactivity {
        idle_for: Duration,
        threshold: Duration,
        /// The member previously opted into automatic execution for this
        /// policy. When false, reaching the threshold creates a proposal.
        automatic_execution_approved: bool,
        /// Approval of this specific proposal.
        proposal_approved_by_member: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveDisposition {
    Eligible,
    ProposalEligible,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveBlocker {
    AlreadyArchived,
    AwaitingMemberApproval,
    InactivityThresholdNotReached,
    RemoteObjectsUnverified(u64),
    RemoteHistoryUnverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEligibility {
    pub disposition: ArchiveDisposition,
    /// The sole policy output that may authorize an executor to remove local
    /// content. A storage policy by itself can never make this true.
    pub may_remove_local_bytes: bool,
    pub remotely_verified_bytes: u64,
    pub expected_restore_bytes: u64,
    pub blockers: Vec<ArchiveBlocker>,
}

/// Decide whether an archive may proceed. This function never removes bytes.
///
/// Remote verification is an invariant even for manually approved or
/// explicitly automatic inactivity policies.
pub fn evaluate_archive(
    input: &AvailabilityInput<'_>,
    request: ArchiveRequest,
) -> ArchiveEligibility {
    let remote_unverified_count = input
        .objects
        .iter()
        .filter(|object| !object.remote.is_verified())
        .count() as u64;
    let remotely_verified_bytes = input
        .objects
        .iter()
        .filter(|object| object.remote.is_verified())
        .fold(0_u64, |total, object| total.saturating_add(object.bytes));
    let expected_restore_bytes = input
        .objects
        .iter()
        .fold(0_u64, |total, object| total.saturating_add(object.bytes));

    let mut blockers = Vec::new();
    if input.lifecycle == FolderbaseLifecycle::Archived {
        blockers.push(ArchiveBlocker::AlreadyArchived);
    }
    if remote_unverified_count > 0 {
        blockers.push(ArchiveBlocker::RemoteObjectsUnverified(
            remote_unverified_count,
        ));
    }
    if !input.remote_history_verified {
        blockers.push(ArchiveBlocker::RemoteHistoryUnverified);
    }

    let threshold_reached;
    let execution_approved;
    match request {
        ArchiveRequest::Manual { approved_by_member } => {
            threshold_reached = true;
            execution_approved = approved_by_member;
            if !approved_by_member {
                blockers.push(ArchiveBlocker::AwaitingMemberApproval);
            }
        }
        ArchiveRequest::Inactivity {
            idle_for,
            threshold,
            automatic_execution_approved,
            proposal_approved_by_member,
        } => {
            threshold_reached = idle_for >= threshold;
            execution_approved = automatic_execution_approved || proposal_approved_by_member;
            if !threshold_reached {
                blockers.push(ArchiveBlocker::InactivityThresholdNotReached);
            } else if !execution_approved {
                blockers.push(ArchiveBlocker::AwaitingMemberApproval);
            }
        }
    }

    let remote_verified = remote_unverified_count == 0 && input.remote_history_verified;
    let may_remove_local_bytes = input.lifecycle != FolderbaseLifecycle::Archived
        && remote_verified
        && threshold_reached
        && execution_approved;
    let disposition = if may_remove_local_bytes {
        ArchiveDisposition::Eligible
    } else if input.lifecycle != FolderbaseLifecycle::Archived
        && remote_verified
        && threshold_reached
        && !execution_approved
    {
        ArchiveDisposition::ProposalEligible
    } else {
        ArchiveDisposition::Blocked
    };

    ArchiveEligibility {
        disposition,
        may_remove_local_bytes,
        remotely_verified_bytes,
        expected_restore_bytes,
        blockers,
    }
}

fn sorted_ids<'a>(objects: impl Iterator<Item = &'a ObjectAvailability>) -> Vec<String> {
    let mut ids: Vec<String> = objects.map(|object| object.object_id.clone()).collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(id: &str, local: VerificationState, remote: VerificationState) -> ObjectAvailability {
        ObjectAvailability {
            object_id: id.to_owned(),
            bytes: 10,
            local,
            remote,
            required_for_session: false,
            pinned_for_session: false,
        }
    }

    fn input<'a>(
        objects: &'a [ObjectAvailability],
        policy: StoragePolicy,
    ) -> AvailabilityInput<'a> {
        AvailabilityInput {
            policy,
            lifecycle: FolderbaseLifecycle::Active,
            objects,
            session_requested: false,
            remote_history_verified: true,
            keep_local_guaranteed: true,
        }
    }

    #[test]
    fn keep_local_requires_verified_content_and_a_platform_guarantee() {
        let objects = vec![
            object(
                "z-missing",
                VerificationState::Missing,
                VerificationState::Verified,
            ),
            object(
                "a-unverified",
                VerificationState::PresentUnverified,
                VerificationState::Verified,
            ),
        ];
        let report = evaluate_readiness(&input(&objects, StoragePolicy::KeepLocal));

        assert_eq!(report.state, ReadinessState::Incomplete);
        assert!(!report.local_complete);
        assert_eq!(report.bytes_required_for_local_complete, 20);
        assert_eq!(report.missing_local_object_ids, ["z-missing"]);
        assert_eq!(report.unverified_local_object_ids, ["a-unverified"]);

        let verified = vec![object(
            "one",
            VerificationState::Verified,
            VerificationState::Verified,
        )];
        let mut facts = input(&verified, StoragePolicy::KeepLocal);
        assert_eq!(
            evaluate_readiness(&facts).state,
            ReadinessState::LocalComplete
        );

        facts.keep_local_guaranteed = false;
        let not_guaranteed = evaluate_readiness(&facts);
        assert_eq!(not_guaranteed.state, ReadinessState::Incomplete);
        assert!(
            not_guaranteed
                .blockers
                .contains(&ReadinessBlocker::KeepLocalNotGuaranteed)
        );
    }

    #[test]
    fn session_ready_requires_verified_and_pinned_scope() {
        let mut objects = vec![
            object(
                "required",
                VerificationState::Verified,
                VerificationState::Missing,
            ),
            object(
                "outside-scope",
                VerificationState::Missing,
                VerificationState::Missing,
            ),
        ];
        objects[0].required_for_session = true;
        let mut facts = input(&objects, StoragePolicy::Managed);
        facts.session_requested = true;

        assert!(!evaluate_readiness(&facts).session_ready);
        objects[0].pinned_for_session = true;
        let mut facts = input(&objects, StoragePolicy::Managed);
        facts.session_requested = true;
        let ready = evaluate_readiness(&facts);
        assert_eq!(ready.state, ReadinessState::SessionReady);
        assert!(ready.session_ready);
        assert!(!ready.local_complete);
    }

    #[test]
    fn cloud_only_reports_remote_ready_but_never_authorizes_eviction() {
        let objects = vec![object(
            "remote",
            VerificationState::Missing,
            VerificationState::Verified,
        )];
        let facts = input(&objects, StoragePolicy::CloudOnly);
        let readiness = evaluate_readiness(&facts);
        assert_eq!(readiness.state, ReadinessState::RemoteReady);

        let archive = evaluate_archive(
            &facts,
            ArchiveRequest::Manual {
                approved_by_member: false,
            },
        );
        assert!(!archive.may_remove_local_bytes);
        assert_eq!(archive.disposition, ArchiveDisposition::ProposalEligible);
    }

    #[test]
    fn archive_requires_remote_verification_even_with_member_approval() {
        let objects = vec![object(
            "not-uploaded",
            VerificationState::Verified,
            VerificationState::Missing,
        )];
        let facts = input(&objects, StoragePolicy::Managed);
        let decision = evaluate_archive(
            &facts,
            ArchiveRequest::Manual {
                approved_by_member: true,
            },
        );

        assert_eq!(decision.disposition, ArchiveDisposition::Blocked);
        assert!(!decision.may_remove_local_bytes);
        assert_eq!(
            decision.blockers,
            [ArchiveBlocker::RemoteObjectsUnverified(1)]
        );
    }

    #[test]
    fn inactivity_creates_a_proposal_unless_automatic_execution_was_approved() {
        let objects = vec![object(
            "safe",
            VerificationState::Verified,
            VerificationState::Verified,
        )];
        let facts = input(&objects, StoragePolicy::Managed);
        let threshold = Duration::from_secs(90 * 24 * 60 * 60);

        let early = evaluate_archive(
            &facts,
            ArchiveRequest::Inactivity {
                idle_for: threshold - Duration::from_secs(1),
                threshold,
                automatic_execution_approved: true,
                proposal_approved_by_member: false,
            },
        );
        assert_eq!(early.disposition, ArchiveDisposition::Blocked);

        let proposal = evaluate_archive(
            &facts,
            ArchiveRequest::Inactivity {
                idle_for: threshold,
                threshold,
                automatic_execution_approved: false,
                proposal_approved_by_member: false,
            },
        );
        assert_eq!(proposal.disposition, ArchiveDisposition::ProposalEligible);
        assert!(!proposal.may_remove_local_bytes);

        let automatic = evaluate_archive(
            &facts,
            ArchiveRequest::Inactivity {
                idle_for: threshold,
                threshold,
                automatic_execution_approved: true,
                proposal_approved_by_member: false,
            },
        );
        assert_eq!(automatic.disposition, ArchiveDisposition::Eligible);
        assert!(automatic.may_remove_local_bytes);
    }
}
