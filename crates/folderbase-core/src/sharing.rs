use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{FolderbaseError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderbaseRegistration {
    pub folderbase_id: String,
    pub owner_member_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareGrant {
    pub id: String,
    pub folderbase_id: String,
    pub grantee_member_id: String,
    pub scope: ShareScope,
    pub permissions: BTreeSet<SharePermission>,
    pub expires_at: Option<DateTime<Utc>>,
    pub include_future_content: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShareScope {
    Folderbase,
    Folder {
        path: PathBuf,
    },
    Object {
        object_id: String,
        path: PathBuf,
    },
    View {
        view_id: String,
        paths: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SharePermission {
    Read,
    Edit,
    Download,
    Reshare,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessRequest {
    pub member_id: String,
    pub agent_session: Option<String>,
    pub folderbase_id: String,
    pub path: PathBuf,
    pub permission: SharePermission,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessDecision {
    pub allowed: bool,
    pub reason: AccessReason,
    pub grant_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessReason {
    Owner,
    ExplicitGrant,
    NoGrant,
    Expired,
    Revoked,
    OutsideScope,
    PermissionMissing,
}

/// A deterministic authorization/control-plane model.
///
/// It accepts no relationship graph by design: relationships and workspace
/// nesting cannot accidentally become authorization inputs.
#[derive(Debug, Default)]
pub struct SharingControlPlane {
    folderbases: BTreeMap<String, FolderbaseRegistration>,
    grants: BTreeMap<String, ShareGrant>,
}

impl SharingControlPlane {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_folderbase(&mut self, registration: FolderbaseRegistration) -> Result<()> {
        if !registration.folderbase_id.starts_with("folderbase_")
            || registration.owner_member_id.trim().is_empty()
            || registration.name.trim().is_empty()
        {
            return Err(FolderbaseError::InvalidRecord {
                path: PathBuf::from("folderbase-registration"),
                message: "folderbase id, owner, and name are required".to_owned(),
            });
        }
        if self.folderbases.contains_key(&registration.folderbase_id) {
            return Err(FolderbaseError::WouldOverwrite(PathBuf::from(
                registration.folderbase_id,
            )));
        }
        self.folderbases
            .insert(registration.folderbase_id.clone(), registration);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_grant(
        &mut self,
        owner_member_id: &str,
        folderbase_id: &str,
        grantee_member_id: impl Into<String>,
        scope: ShareScope,
        permissions: BTreeSet<SharePermission>,
        expires_at: Option<DateTime<Utc>>,
        include_future_content: bool,
    ) -> Result<ShareGrant> {
        let registration =
            self.folderbases
                .get(folderbase_id)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: PathBuf::from(folderbase_id),
                    message: "folderbase is not registered".to_owned(),
                })?;
        if registration.owner_member_id != owner_member_id {
            return Err(FolderbaseError::InvalidRecord {
                path: PathBuf::from(folderbase_id),
                message: "only the folderbase owner may create a grant".to_owned(),
            });
        }
        validate_scope(&scope)?;
        if permissions.is_empty() {
            return Err(FolderbaseError::InvalidRecord {
                path: PathBuf::from(folderbase_id),
                message: "a grant must name at least one permission".to_owned(),
            });
        }
        let grantee_member_id = grantee_member_id.into();
        if grantee_member_id.trim().is_empty() {
            return Err(FolderbaseError::InvalidRecord {
                path: PathBuf::from(folderbase_id),
                message: "grantee member id is required".to_owned(),
            });
        }
        let grant = ShareGrant {
            id: format!("grant_{}", Uuid::now_v7()),
            folderbase_id: folderbase_id.to_owned(),
            grantee_member_id,
            scope,
            permissions,
            expires_at,
            include_future_content,
            revoked_at: None,
        };
        self.grants.insert(grant.id.clone(), grant.clone());
        Ok(grant)
    }

    pub fn revoke(
        &mut self,
        owner_member_id: &str,
        grant_id: &str,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let grant =
            self.grants
                .get_mut(grant_id)
                .ok_or_else(|| FolderbaseError::InvalidRecord {
                    path: PathBuf::from(grant_id),
                    message: "grant does not exist".to_owned(),
                })?;
        let folderbase = self.folderbases.get(&grant.folderbase_id).ok_or_else(|| {
            FolderbaseError::InvalidRecord {
                path: PathBuf::from(&grant.folderbase_id),
                message: "grant references an unregistered folderbase".to_owned(),
            }
        })?;
        if folderbase.owner_member_id != owner_member_id {
            return Err(FolderbaseError::InvalidRecord {
                path: PathBuf::from(grant_id),
                message: "only the folderbase owner may revoke a grant".to_owned(),
            });
        }
        grant.revoked_at = Some(at);
        Ok(())
    }

    pub fn authorize(&self, request: &AccessRequest) -> Result<AccessDecision> {
        ensure_safe_relative(&request.path)?;
        let registration = self
            .folderbases
            .get(&request.folderbase_id)
            .ok_or_else(|| FolderbaseError::InvalidRecord {
                path: PathBuf::from(&request.folderbase_id),
                message: "folderbase is not registered".to_owned(),
            })?;
        if registration.owner_member_id == request.member_id {
            return Ok(AccessDecision {
                allowed: true,
                reason: AccessReason::Owner,
                grant_id: None,
            });
        }

        let candidates = self
            .grants
            .values()
            .filter(|grant| {
                grant.folderbase_id == request.folderbase_id
                    && grant.grantee_member_id == request.member_id
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Ok(denied(AccessReason::NoGrant));
        }

        let mut most_specific_denial = AccessReason::OutsideScope;
        for grant in candidates {
            if grant
                .revoked_at
                .is_some_and(|revoked| revoked <= request.at)
            {
                most_specific_denial = AccessReason::Revoked;
                continue;
            }
            if grant.expires_at.is_some_and(|expiry| expiry <= request.at) {
                most_specific_denial = AccessReason::Expired;
                continue;
            }
            if !scope_contains(&grant.scope, &request.path) {
                continue;
            }
            if !grant.permissions.contains(&request.permission) {
                most_specific_denial = AccessReason::PermissionMissing;
                continue;
            }
            return Ok(AccessDecision {
                allowed: true,
                reason: AccessReason::ExplicitGrant,
                grant_id: Some(grant.id.clone()),
            });
        }
        Ok(denied(most_specific_denial))
    }
}

fn denied(reason: AccessReason) -> AccessDecision {
    AccessDecision {
        allowed: false,
        reason,
        grant_id: None,
    }
}

fn validate_scope(scope: &ShareScope) -> Result<()> {
    match scope {
        ShareScope::Folderbase => Ok(()),
        ShareScope::Folder { path } | ShareScope::Object { path, .. } => ensure_safe_relative(path),
        ShareScope::View { paths, .. } => {
            if paths.is_empty() {
                return Err(FolderbaseError::InvalidRecord {
                    path: PathBuf::from("view"),
                    message: "a shared view must include at least one path".to_owned(),
                });
            }
            for path in paths {
                ensure_safe_relative(path)?;
            }
            Ok(())
        }
    }
}

fn scope_contains(scope: &ShareScope, requested: &Path) -> bool {
    match scope {
        ShareScope::Folderbase => true,
        ShareScope::Folder { path } => requested == path || requested.starts_with(path),
        ShareScope::Object { path, .. } => requested == path,
        ShareScope::View { paths, .. } => paths
            .iter()
            .any(|path| requested == path || requested.starts_with(path)),
    }
}

fn ensure_safe_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(FolderbaseError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}
