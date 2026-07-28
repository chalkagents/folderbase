use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use folderbase_core::{
    AccessReason, AccessRequest, FolderbaseRegistration, SharePermission, ShareScope,
    SharingControlPlane,
};

fn control_plane() -> SharingControlPlane {
    let mut control = SharingControlPlane::new();
    control
        .register_folderbase(FolderbaseRegistration {
            folderbase_id: "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62".to_owned(),
            owner_member_id: "jerel".to_owned(),
            name: "ChalkAgents".to_owned(),
        })
        .unwrap();
    control
}

fn request(path: &str, permission: SharePermission) -> AccessRequest {
    AccessRequest {
        member_id: "david".to_owned(),
        agent_session: Some("codex".to_owned()),
        folderbase_id: "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62".to_owned(),
        path: path.into(),
        permission,
        at: Utc::now(),
    }
}

#[test]
fn access_is_private_until_explicitly_granted() {
    let control = control_plane();
    let decision = control
        .authorize(&request(
            "Client Company 1/Client Company 2/FOLDERBASE.md",
            SharePermission::Read,
        ))
        .unwrap();
    assert!(!decision.allowed);
    assert_eq!(decision.reason, AccessReason::NoGrant);
}

#[test]
fn folder_grant_scopes_human_and_agent_session_to_the_same_files() {
    let mut control = control_plane();
    control
        .create_grant(
            "jerel",
            "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62",
            "david",
            ShareScope::Folder {
                path: "Client Company 1/Client Company 2".into(),
            },
            BTreeSet::from([SharePermission::Read, SharePermission::Edit]),
            None,
            false,
        )
        .unwrap();

    assert!(
        control
            .authorize(&request(
                "Client Company 1/Client Company 2/FOLDERBASE.md",
                SharePermission::Read,
            ))
            .unwrap()
            .allowed
    );
    let denied = control
        .authorize(&request("Company/Strategy.md", SharePermission::Read))
        .unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.reason, AccessReason::OutsideScope);
}

#[test]
fn relationship_or_nesting_never_grants_access() {
    let control = control_plane();
    let denied = control
        .authorize(&request(
            "Client Company 1/Client Company 2/linked-from-shared-document.md",
            SharePermission::Read,
        ))
        .unwrap();
    assert!(!denied.allowed);
}

#[test]
fn missing_permission_is_denied_even_inside_scope() {
    let mut control = control_plane();
    control
        .create_grant(
            "jerel",
            "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62",
            "david",
            ShareScope::Folderbase,
            BTreeSet::from([SharePermission::Read]),
            None,
            true,
        )
        .unwrap();

    let denied = control
        .authorize(&request("FOLDERBASE.md", SharePermission::Reshare))
        .unwrap();
    assert_eq!(denied.reason, AccessReason::PermissionMissing);
}

#[test]
fn expiration_and_revocation_block_future_access_without_deleting_owner_data() {
    let mut control = control_plane();
    let now = Utc::now();
    let expired = control
        .create_grant(
            "jerel",
            "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62",
            "david",
            ShareScope::Folderbase,
            BTreeSet::from([SharePermission::Read]),
            Some(now - Duration::seconds(1)),
            true,
        )
        .unwrap();
    let mut access = request("FOLDERBASE.md", SharePermission::Read);
    access.at = now;
    assert_eq!(
        control.authorize(&access).unwrap().reason,
        AccessReason::Expired
    );

    let active = control
        .create_grant(
            "jerel",
            "folderbase_019f9b75-0b22-7a18-8f40-3f29f1438b62",
            "david",
            ShareScope::Object {
                object_id: "obj_019f9b75-4f42-7f65-a012-2bfecdd8c473".to_owned(),
                path: "FOLDERBASE.md".into(),
            },
            BTreeSet::from([SharePermission::Read]),
            None,
            false,
        )
        .unwrap();
    control.revoke("jerel", &active.id, now).unwrap();
    assert_eq!(
        control.authorize(&access).unwrap().reason,
        AccessReason::Revoked
    );

    let mut owner_access = access;
    owner_access.member_id = "jerel".to_owned();
    assert!(control.authorize(&owner_access).unwrap().allowed);
    assert!(!expired.id.is_empty());
}
