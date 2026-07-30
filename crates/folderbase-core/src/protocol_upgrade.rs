//! Explicit, reviewable transition from legacy live-root semantics to 0.5.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    FolderbaseError, FolderbaseVersionStore, LocalVersionStore, MAX_FOLDERBASEIGNORE_BYTES, Result,
    folderbase_restore_authority::{stable_file_identity_sha256, stable_file_link_count},
    folderbase_state::FolderbaseState,
    root_attestation::{
        DEFAULT_V05_CAPTURE_IGNORE_RULES, MAX_FOLDERBASE_MANIFEST_BYTES, ManifestProtocolProfile,
        PROTOCOL_UPGRADE_RECEIPT_FIELD, PROTOCOL_UPGRADE_RECEIPT_FORMAT,
        attest_folderbase_root_with_profile,
        attest_folderbase_root_with_profile_allowing_upgrade_recovery,
        decode_manifest_protocol_profile,
    },
};

const MANIFEST_PATH: &str = ".folderbase/manifest.json";
const IGNORE_POLICY_PATH: &str = ".folderbaseignore";
const ACTIVE_CAPTURE_PATH: &str =
    ".folderbase/transactions/folderbase-version-captures/active.json";
const ACTIVE_RESTORE_PATH: &str =
    ".folderbase/transactions/folderbase-version-restores/active.json";
const RESTORE_CLEANUP_PATH: &str =
    ".folderbase/transactions/folderbase-version-restores/cleanup.json";
const ACTIVE_REORGANIZATION_PATH: &str = ".folderbase/reorganizations/active.json";
const MIGRATIONS_PATH: &str = ".folderbase/migrations";
const UPGRADE_INTENT_DIRECTORY: &str = "transactions/protocol-upgrades";
const UPGRADE_INTENT_PATH: &str = "transactions/protocol-upgrades/active.json";
const UPGRADE_INTENT_FORMAT: &str = "folderbase-protocol-upgrade-intent-v2";
const MAX_PENDING_RECORD_BYTES: u64 = 16 * 1024 * 1024;
// The intent embeds two manifests as JSON strings. Each manifest can require up
// to twice its original bytes when quotes and escapes are encoded, while the
// fixed record fields need only a small, closed amount of additional space.
const MAX_PROTOCOL_UPGRADE_INTENT_BYTES: u64 = MAX_FOLDERBASE_MANIFEST_BYTES * 4 + 64 * 1024;
const MAX_MIGRATION_DIRECTORIES: usize = 16_384;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolUpgradePlanDigest {
    algorithm: String,
    digest: String,
}

impl ProtocolUpgradePlanDigest {
    pub fn parse_sha256(digest: impl Into<String>) -> Result<Self> {
        let digest = digest.into();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FolderbaseError::InvalidProtocolUpgradePlanDigest);
        }
        Ok(Self {
            algorithm: "sha256".to_owned(),
            digest,
        })
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Serialize)]
pub struct ProtocolUpgradePlan {
    root: PathBuf,
    folderbase_id: String,
    from_protocol_version: String,
    to_protocol_version: String,
    changed_paths: Vec<PathBuf>,
    plan_digest: ProtocolUpgradePlanDigest,
    #[serde(skip_serializing)]
    upgraded_manifest: Vec<u8>,
    #[serde(skip_serializing)]
    attested_manifest: Vec<u8>,
    #[serde(skip_serializing)]
    attested_manifest_sha256: String,
    #[serde(skip_serializing)]
    root_instance_sha256: String,
    #[serde(skip_serializing)]
    attested_ignore_snapshot: Option<IgnorePolicySnapshot>,
    #[serde(skip_serializing)]
    exchange_owner: Option<String>,
    #[serde(skip_serializing)]
    already_applied: bool,
}

impl ProtocolUpgradePlan {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn plan_digest(&self) -> &ProtocolUpgradePlanDigest {
        &self.plan_digest
    }
}

#[derive(Debug, Serialize)]
pub struct ProtocolUpgradeResult {
    pub root: PathBuf,
    pub folderbase_id: String,
    pub from_protocol_version: String,
    pub to_protocol_version: String,
    pub changed_paths: Vec<PathBuf>,
    pub applied_plan_digest: ProtocolUpgradePlanDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolUpgradeReceipt {
    format: String,
    from_protocol_version: String,
    target_manifest_without_receipt_sha256: String,
    plan_digest: ProtocolUpgradePlanDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "presence", rename_all = "snake_case", deny_unknown_fields)]
enum IgnorePolicySnapshot {
    Absent,
    Present {
        kind: String,
        bytes: u64,
        sha256: String,
        physical_identity_sha256: String,
        link_count: u64,
    },
}

impl IgnorePolicySnapshot {
    fn binding_sha256(&self) -> Result<String> {
        let encoded = serde_json::to_vec(self)
            .map_err(|source| FolderbaseError::json(Path::new(IGNORE_POLICY_PATH), source))?;
        let mut digest = Sha256::new();
        digest.update(b"folderbase-protocol-upgrade-ignore-snapshot-v2\0");
        update_bytes(&mut digest, &encoded);
        Ok(format!("{:x}", digest.finalize()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProtocolUpgradeIntent {
    format: String,
    exchange_owner: String,
    folderbase_id: String,
    root_instance_sha256: String,
    from_protocol_version: String,
    to_protocol_version: String,
    plan_digest: ProtocolUpgradePlanDigest,
    source_manifest_sha256: String,
    source_manifest: String,
    target_manifest_sha256: String,
    target_manifest: String,
    ignore_snapshot: IgnorePolicySnapshot,
}

pub fn plan_protocol_upgrade(root: impl AsRef<Path>) -> Result<ProtocolUpgradePlan> {
    let supplied_root = root.as_ref();
    let (supplied_attestation, _, supplied_profile) =
        attest_folderbase_root_with_profile_allowing_upgrade_recovery(supplied_root)
            .map_err(|source| invalid_upgrade(supplied_root, source.to_string()))?;
    let root = supplied_root
        .canonicalize()
        .map_err(|source| FolderbaseError::io(supplied_root, source))?;
    let (attestation, _, profile) =
        attest_folderbase_root_with_profile_allowing_upgrade_recovery(&root)
            .map_err(|source| invalid_upgrade(&root, source.to_string()))?;
    if supplied_attestation.folderbase_id != attestation.folderbase_id
        || supplied_attestation.protocol_version != attestation.protocol_version
        || supplied_attestation.manifest_sha256 != attestation.manifest_sha256
        || supplied_attestation.root_instance_sha256 != attestation.root_instance_sha256
        || supplied_profile != profile
    {
        return Err(invalid_upgrade(
            &root,
            "Folderbase root changed while establishing upgrade authority",
        ));
    }
    let state = FolderbaseState::open_existing_read_only(&root)?;
    state.verify_still_attached()?;
    ensure_no_pending_transactions(&state)?;

    let manifest_bytes = state
        .read_bounded(Path::new("manifest.json"), MAX_FOLDERBASE_MANIFEST_BYTES)?
        .ok_or_else(|| invalid_upgrade(&root, "manifest disappeared during planning"))?;
    let observed_manifest_sha256 = format!("{:x}", Sha256::digest(&manifest_bytes));
    if observed_manifest_sha256 != attestation.manifest_sha256 {
        return Err(invalid_upgrade(
            &root,
            "manifest changed after root attestation",
        ));
    }
    let (mut manifest, folderbase_id, from_protocol_version, decoded_profile) =
        decode_manifest_protocol_profile(&manifest_bytes)
            .map_err(|source| invalid_upgrade(&root, source.to_string()))?;
    if decoded_profile != profile
        || folderbase_id != attestation.folderbase_id
        || from_protocol_version != attestation.protocol_version
    {
        return Err(invalid_upgrade(
            &root,
            "manifest profile changed during planning",
        ));
    }
    let pending_intent = read_protocol_upgrade_intent(&state, &root)?;
    if matches!(profile, ManifestProtocolProfile::OrdinaryV05 { .. }) {
        let Some(_) = manifest.get(PROTOCOL_UPGRADE_RECEIPT_FIELD) else {
            let mut digest = Sha256::new();
            digest.update(b"folderbase-protocol-current-plan-v1\0");
            update_bytes(&mut digest, folderbase_id.as_bytes());
            update_bytes(&mut digest, attestation.root_instance_sha256.as_bytes());
            update_bytes(&mut digest, attestation.manifest_sha256.as_bytes());
            return Ok(ProtocolUpgradePlan {
                root,
                folderbase_id,
                from_protocol_version: "0.5.0".to_owned(),
                to_protocol_version: "0.5.0".to_owned(),
                changed_paths: Vec::new(),
                plan_digest: ProtocolUpgradePlanDigest {
                    algorithm: "sha256".to_owned(),
                    digest: format!("{:x}", digest.finalize()),
                },
                attested_manifest: manifest_bytes.clone(),
                upgraded_manifest: manifest_bytes,
                attested_manifest_sha256: attestation.manifest_sha256,
                root_instance_sha256: attestation.root_instance_sha256,
                attested_ignore_snapshot: None,
                exchange_owner: None,
                already_applied: true,
            });
        };
        let receipt = decode_applied_receipt(&root, &manifest)?;
        return Ok(ProtocolUpgradePlan {
            root,
            folderbase_id,
            from_protocol_version: receipt.from_protocol_version,
            to_protocol_version: "0.5.0".to_owned(),
            changed_paths: vec![PathBuf::from(MANIFEST_PATH)],
            plan_digest: receipt.plan_digest,
            attested_manifest: manifest_bytes.clone(),
            upgraded_manifest: manifest_bytes,
            attested_manifest_sha256: attestation.manifest_sha256,
            root_instance_sha256: attestation.root_instance_sha256,
            attested_ignore_snapshot: None,
            exchange_owner: None,
            already_applied: true,
        });
    }
    if let Some(intent) = pending_intent {
        return plan_from_pending_intent(root, attestation, manifest_bytes, intent);
    }

    if manifest.get(PROTOCOL_UPGRADE_RECEIPT_FIELD).is_some()
        || manifest.pointer("/policies/capture_ignore").is_some()
    {
        return Err(invalid_upgrade(
            &root,
            "legacy extension collides with reserved 0.5 protocol fields",
        ));
    }

    let store = FolderbaseVersionStore::open(&root)
        .map_err(|source| invalid_upgrade(&root, source.to_string()))?;
    let capture = store
        .plan_capture()
        .map_err(|source| invalid_upgrade(&root, source.to_string()))?;
    let ignore_snapshot = read_ignore_snapshot(&state, &root)?;
    let ignore_snapshot_sha256 = ignore_snapshot.binding_sha256()?;
    if let Some(head) = capture.current_local_head() {
        store
            .read_version(head.version_id())
            .map_err(|source| invalid_upgrade(&root, source.to_string()))?;
    }

    let manifest_path = root.join(MANIFEST_PATH);
    let root_record = manifest
        .as_object_mut()
        .ok_or_else(|| invalid_upgrade(&root, "manifest root must be an object"))?;
    root_record.insert(
        "$schema".to_owned(),
        Value::String("https://folderbase.ai/protocol/0.5/folderbase.schema.json".to_owned()),
    );
    root_record.insert(
        "protocol_version".to_owned(),
        Value::String("0.5.0".to_owned()),
    );
    root_record
        .get_mut("folderbase")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid_upgrade(&root, "folderbase must be an object"))?
        .remove("entry");
    let policies = root_record
        .get_mut("policies")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid_upgrade(&root, "policies must be an object"))?;
    policies.insert(
        "capture_ignore".to_owned(),
        json!({
            "format": "folderbase-capture-ignore-v1",
            "rules": DEFAULT_V05_CAPTURE_IGNORE_RULES
        }),
    );
    let upgraded_manifest_without_receipt = serde_json::to_string_pretty(&manifest)
        .map(|encoded| format!("{encoded}\n").into_bytes())
        .map_err(|source| FolderbaseError::json(&manifest_path, source))?;
    validate_generated_upgrade_manifest(&root, &upgraded_manifest_without_receipt)?;

    let mut digest = Sha256::new();
    digest.update(b"folderbase-protocol-upgrade-plan-v1\0");
    update_bytes(&mut digest, attestation.folderbase_id.as_bytes());
    update_bytes(&mut digest, attestation.root_instance_sha256.as_bytes());
    update_bytes(&mut digest, attestation.manifest_sha256.as_bytes());
    update_bytes(&mut digest, capture.ignore_policy_sha256().as_bytes());
    update_bytes(&mut digest, ignore_snapshot_sha256.as_bytes());
    if let Some(head) = capture.current_local_head() {
        digest.update([1]);
        update_bytes(&mut digest, head.version_id().as_bytes());
        update_bytes(&mut digest, head.version_sha256().as_bytes());
    } else {
        digest.update([0]);
    }
    update_bytes(
        &mut digest,
        &Sha256::digest(&upgraded_manifest_without_receipt),
    );
    let plan_digest = ProtocolUpgradePlanDigest {
        algorithm: "sha256".to_owned(),
        digest: format!("{:x}", digest.finalize()),
    };
    let target_manifest_without_receipt_sha256 =
        format!("{:x}", Sha256::digest(&upgraded_manifest_without_receipt));
    manifest
        .as_object_mut()
        .expect("manifest object was checked")
        .insert(
            PROTOCOL_UPGRADE_RECEIPT_FIELD.to_owned(),
            serde_json::to_value(ProtocolUpgradeReceipt {
                format: PROTOCOL_UPGRADE_RECEIPT_FORMAT.to_owned(),
                from_protocol_version: from_protocol_version.clone(),
                target_manifest_without_receipt_sha256,
                plan_digest: plan_digest.clone(),
            })
            .map_err(|source| FolderbaseError::json(&manifest_path, source))?,
        );
    let upgraded_manifest = serde_json::to_string_pretty(&manifest)
        .map(|encoded| format!("{encoded}\n").into_bytes())
        .map_err(|source| FolderbaseError::json(&manifest_path, source))?;
    validate_generated_upgrade_manifest(&root, &upgraded_manifest)?;
    Ok(ProtocolUpgradePlan {
        root,
        folderbase_id,
        from_protocol_version,
        to_protocol_version: "0.5.0".to_owned(),
        changed_paths: vec![PathBuf::from(MANIFEST_PATH)],
        plan_digest,
        upgraded_manifest,
        attested_manifest: manifest_bytes,
        attested_manifest_sha256: attestation.manifest_sha256,
        root_instance_sha256: attestation.root_instance_sha256,
        attested_ignore_snapshot: Some(ignore_snapshot),
        exchange_owner: None,
        already_applied: false,
    })
}

pub fn apply_protocol_upgrade(
    plan: &ProtocolUpgradePlan,
    expected: &ProtocolUpgradePlanDigest,
) -> Result<ProtocolUpgradeResult> {
    apply_protocol_upgrade_with_hooks(plan, expected, || {}, || Ok(()))
}

#[cfg(test)]
fn apply_protocol_upgrade_with_hook(
    plan: &ProtocolUpgradePlan,
    expected: &ProtocolUpgradePlanDigest,
    before_activation: impl FnOnce(),
) -> Result<ProtocolUpgradeResult> {
    apply_protocol_upgrade_with_hooks(plan, expected, before_activation, || Ok(()))
}

fn apply_protocol_upgrade_with_hooks(
    plan: &ProtocolUpgradePlan,
    expected: &ProtocolUpgradePlanDigest,
    before_activation: impl FnOnce(),
    after_activation: impl FnOnce() -> Result<()>,
) -> Result<ProtocolUpgradeResult> {
    expected.validate()?;
    let local = LocalVersionStore::open_read_only(&plan.root)?;
    let state = FolderbaseState::open_existing(&plan.root)?;
    let _lock = local.acquire_transaction_lock_in_allowing_protocol_upgrade(&state)?;
    state.verify_still_attached()?;
    recover_pending_protocol_upgrade(&state, &plan.root, expected)?;
    ensure_no_pending_transactions(&state)?;
    let current = plan_protocol_upgrade(&plan.root)?;
    if current.plan_digest != *expected || current.plan_digest != plan.plan_digest {
        return Err(FolderbaseError::ProtocolUpgradePlanChanged {
            expected: expected.digest.clone(),
            actual: current.plan_digest.digest,
        });
    }
    if current.upgraded_manifest != plan.upgraded_manifest {
        return Err(FolderbaseError::ProtocolUpgradePlanChanged {
            expected: expected.digest.clone(),
            actual: current.plan_digest.digest,
        });
    }
    if current.already_applied {
        return Ok(upgrade_result(&current));
    }
    if current.attested_manifest_sha256 != plan.attested_manifest_sha256 {
        return Err(FolderbaseError::ProtocolUpgradePlanChanged {
            expected: expected.digest.clone(),
            actual: current.plan_digest.digest,
        });
    }
    let intent = ProtocolUpgradeIntent::from_plan(&current)?;
    prepare_protocol_upgrade_intent(&state, &plan.root, &intent)?;
    state
        .compare_exchange_exact_owned_with_hook(
            Path::new(MANIFEST_PATH),
            &plan.attested_manifest,
            &plan.upgraded_manifest,
            &intent.exchange_owner,
            before_activation,
        )
        .map_err(|error| match error {
            FolderbaseError::WouldOverwrite(_) => FolderbaseError::ProtocolUpgradePlanChanged {
                expected: expected.digest.clone(),
                actual: "manifest_changed_at_activation".to_owned(),
            },
            other => other,
        })?;
    after_activation()?;
    let activated_manifest = state
        .read_bounded(Path::new("manifest.json"), MAX_FOLDERBASE_MANIFEST_BYTES)?
        .ok_or_else(|| invalid_upgrade(&plan.root, "manifest disappeared after activation"))?;
    let (attestation, profile) =
        attest_protocol_upgrade_recovery_root(&state, &plan.root, &intent, &activated_manifest)?;
    if attestation.protocol_version != "0.5.0"
        || !matches!(profile, ManifestProtocolProfile::OrdinaryV05 { .. })
        || activated_manifest != intent.target_bytes()
    {
        return Err(invalid_upgrade(
            &plan.root,
            "manifest activation did not produce the exact 0.5 profile",
        ));
    }
    let current_ignore_snapshot = read_ignore_snapshot(&state, &plan.root);
    if !matches!(
        current_ignore_snapshot,
        Ok(ref actual) if actual == &intent.ignore_snapshot
    ) {
        state.verify_still_attached()?;
        rollback_protocol_upgrade(&state, &plan.root, &intent)?;
        return Err(FolderbaseError::ProtocolUpgradePlanChanged {
            expected: expected.digest.clone(),
            actual: "ignore_policy_changed_at_activation".to_owned(),
        });
    }
    state.verify_still_attached()?;
    state.remove_durable(Path::new(UPGRADE_INTENT_PATH))?;
    attest_folderbase_root_with_profile(&plan.root)
        .map_err(|source| invalid_upgrade(&plan.root, source.to_string()))?;
    Ok(upgrade_result(plan))
}

impl ProtocolUpgradePlanDigest {
    fn validate(&self) -> Result<()> {
        if self.algorithm != "sha256"
            || self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FolderbaseError::InvalidProtocolUpgradePlanDigest);
        }
        Ok(())
    }
}

fn ensure_no_pending_transactions(state: &FolderbaseState) -> Result<()> {
    for (path, label) in [
        (ACTIVE_CAPTURE_PATH, "Folderbase Version capture"),
        (ACTIVE_RESTORE_PATH, "Tombstone restore"),
        (RESTORE_CLEANUP_PATH, "Tombstone restore cleanup"),
        (ACTIVE_REORGANIZATION_PATH, "Folderbase reorganization"),
    ] {
        let state_path = path
            .strip_prefix(".folderbase/")
            .expect("pending path is state-relative");
        match state.read_bounded_if_present(Path::new(state_path), MAX_PENDING_RECORD_BYTES) {
            Ok(Some(_)) => return Err(FolderbaseError::ProtocolUpgradeBlocked(label)),
            Ok(None) => {}
            Err(_) => return Err(FolderbaseError::ProtocolUpgradeBlocked(label)),
        }
    }
    let migration_names = state
        .private_directory_names_if_present(
            Path::new(
                MIGRATIONS_PATH
                    .strip_prefix(".folderbase/")
                    .expect("migration path is state-relative"),
            ),
            MAX_MIGRATION_DIRECTORIES,
        )
        .map_err(|_| FolderbaseError::ProtocolUpgradeBlocked("Folderbase migration"))?;
    for migration_name in migration_names {
        let path = Path::new("migrations")
            .join(migration_name)
            .join("plan.json");
        let Some(bytes) = state
            .read_bounded_if_present(&path, MAX_PENDING_RECORD_BYTES)
            .map_err(|_| FolderbaseError::ProtocolUpgradeBlocked("Folderbase migration"))?
        else {
            return Err(FolderbaseError::ProtocolUpgradeBlocked(
                "Folderbase migration",
            ));
        };
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|_| FolderbaseError::ProtocolUpgradeBlocked("Folderbase migration"))?;
        let Some(migration_state) = record.get("state").and_then(Value::as_str) else {
            return Err(FolderbaseError::ProtocolUpgradeBlocked(
                "Folderbase migration",
            ));
        };
        if !matches!(migration_state, "verified" | "rejected" | "rolled_back") {
            return Err(FolderbaseError::ProtocolUpgradeBlocked(
                "Folderbase migration",
            ));
        }
    }
    Ok(())
}

fn decode_applied_receipt(root: &Path, manifest: &Value) -> Result<ProtocolUpgradeReceipt> {
    let receipt: ProtocolUpgradeReceipt = serde_json::from_value(
        manifest
            .get(PROTOCOL_UPGRADE_RECEIPT_FIELD)
            .cloned()
            .ok_or_else(|| {
                invalid_upgrade(root, "0.5 manifest has no applied legacy-upgrade receipt")
            })?,
    )
    .map_err(|source| {
        invalid_upgrade(root, format!("invalid protocol-upgrade receipt: {source}"))
    })?;
    if receipt.format != PROTOCOL_UPGRADE_RECEIPT_FORMAT
        || !matches!(
            semver::Version::parse(&receipt.from_protocol_version),
            Ok(version) if version.major == 0 && matches!(version.minor, 1 | 2)
        )
    {
        return Err(invalid_upgrade(root, "invalid protocol-upgrade receipt"));
    }
    receipt.plan_digest.validate()?;
    if receipt.target_manifest_without_receipt_sha256.len() != 64
        || !receipt
            .target_manifest_without_receipt_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_upgrade(root, "invalid protocol-upgrade receipt"));
    }
    let mut target = manifest.clone();
    target
        .as_object_mut()
        .ok_or_else(|| invalid_upgrade(root, "manifest root must be an object"))?
        .remove(PROTOCOL_UPGRADE_RECEIPT_FIELD);
    let manifest_path = root.join(MANIFEST_PATH);
    let target_encoded = serde_json::to_string_pretty(&target)
        .map(|encoded| format!("{encoded}\n").into_bytes())
        .map_err(|source| FolderbaseError::json(&manifest_path, source))?;
    let actual_target_sha256 = format!("{:x}", Sha256::digest(&target_encoded));
    if receipt.target_manifest_without_receipt_sha256 != actual_target_sha256 {
        return Err(invalid_upgrade(
            root,
            "protocol-upgrade receipt does not bind the activated manifest",
        ));
    }
    Ok(receipt)
}

fn upgrade_result(plan: &ProtocolUpgradePlan) -> ProtocolUpgradeResult {
    ProtocolUpgradeResult {
        root: plan.root.clone(),
        folderbase_id: plan.folderbase_id.clone(),
        from_protocol_version: plan.from_protocol_version.clone(),
        to_protocol_version: plan.to_protocol_version.clone(),
        changed_paths: plan.changed_paths.clone(),
        applied_plan_digest: plan.plan_digest.clone(),
    }
}

fn update_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

impl ProtocolUpgradeIntent {
    fn from_plan(plan: &ProtocolUpgradePlan) -> Result<Self> {
        let ignore_snapshot = plan.attested_ignore_snapshot.clone().ok_or_else(|| {
            invalid_upgrade(&plan.root, "legacy upgrade plan has no ignore snapshot")
        })?;
        let source_manifest = String::from_utf8(plan.attested_manifest.clone())
            .map_err(|_| invalid_upgrade(&plan.root, "source manifest is not UTF-8"))?;
        let target_manifest = String::from_utf8(plan.upgraded_manifest.clone())
            .map_err(|_| invalid_upgrade(&plan.root, "target manifest is not UTF-8"))?;
        Ok(Self {
            format: UPGRADE_INTENT_FORMAT.to_owned(),
            exchange_owner: plan
                .exchange_owner
                .clone()
                .unwrap_or_else(|| Uuid::now_v7().to_string()),
            folderbase_id: plan.folderbase_id.clone(),
            root_instance_sha256: plan.root_instance_sha256.clone(),
            from_protocol_version: plan.from_protocol_version.clone(),
            to_protocol_version: plan.to_protocol_version.clone(),
            plan_digest: plan.plan_digest.clone(),
            source_manifest_sha256: format!("{:x}", Sha256::digest(source_manifest.as_bytes())),
            source_manifest,
            target_manifest_sha256: format!("{:x}", Sha256::digest(target_manifest.as_bytes())),
            target_manifest,
            ignore_snapshot,
        })
    }

    fn validate(&self, root: &Path) -> Result<()> {
        if self.format != UPGRADE_INTENT_FORMAT
            || !matches!(
                Uuid::parse_str(&self.exchange_owner),
                Ok(owner) if owner.hyphenated().to_string() == self.exchange_owner
            )
            || self.to_protocol_version != "0.5.0"
            || !valid_sha256(&self.root_instance_sha256)
            || !valid_sha256(&self.source_manifest_sha256)
            || !valid_sha256(&self.target_manifest_sha256)
            || format!("{:x}", Sha256::digest(self.source_manifest.as_bytes()))
                != self.source_manifest_sha256
            || format!("{:x}", Sha256::digest(self.target_manifest.as_bytes()))
                != self.target_manifest_sha256
        {
            return Err(invalid_upgrade(root, "invalid protocol-upgrade intent"));
        }
        self.plan_digest.validate()?;
        self.ignore_snapshot.validate(root)?;
        let (_, source_id, source_version, source_profile) =
            decode_manifest_protocol_profile(self.source_manifest.as_bytes())
                .map_err(|source| invalid_upgrade(root, source.to_string()))?;
        let (target, target_id, target_version, target_profile) =
            decode_manifest_protocol_profile(self.target_manifest.as_bytes())
                .map_err(|source| invalid_upgrade(root, source.to_string()))?;
        if source_id != self.folderbase_id
            || target_id != self.folderbase_id
            || source_version != self.from_protocol_version
            || target_version != self.to_protocol_version
            || !matches!(source_profile, ManifestProtocolProfile::LegacyV01V02)
            || !matches!(target_profile, ManifestProtocolProfile::OrdinaryV05 { .. })
        {
            return Err(invalid_upgrade(
                root,
                "protocol-upgrade intent does not bind its manifest transition",
            ));
        }
        let receipt = decode_applied_receipt(root, &target)?;
        if receipt.plan_digest != self.plan_digest
            || receipt.from_protocol_version != self.from_protocol_version
        {
            return Err(invalid_upgrade(
                root,
                "protocol-upgrade intent does not bind its target receipt",
            ));
        }
        Ok(())
    }

    fn source_bytes(&self) -> &[u8] {
        self.source_manifest.as_bytes()
    }

    fn target_bytes(&self) -> &[u8] {
        self.target_manifest.as_bytes()
    }
}

impl IgnorePolicySnapshot {
    fn validate(&self, root: &Path) -> Result<()> {
        match self {
            Self::Absent => Ok(()),
            Self::Present {
                kind,
                bytes,
                sha256,
                physical_identity_sha256,
                link_count,
            } if kind == "regular_file"
                && *bytes <= MAX_FOLDERBASEIGNORE_BYTES
                && valid_sha256(sha256)
                && valid_sha256(physical_identity_sha256)
                && *link_count == 1 =>
            {
                Ok(())
            }
            Self::Present { .. } => Err(invalid_upgrade(
                root,
                "protocol-upgrade ignore snapshot is invalid",
            )),
        }
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_generated_upgrade_manifest(root: &Path, manifest: &[u8]) -> Result<()> {
    if u64::try_from(manifest.len()).unwrap_or(u64::MAX) > MAX_FOLDERBASE_MANIFEST_BYTES {
        return Err(invalid_upgrade(
            root,
            "generated protocol-upgrade manifest exceeds the live manifest bound",
        ));
    }
    decode_manifest_protocol_profile(manifest)
        .map_err(|source| invalid_upgrade(root, source.to_string()))?;
    Ok(())
}

fn plan_from_pending_intent(
    root: PathBuf,
    attestation: crate::FolderbaseRootAttestation,
    manifest_bytes: Vec<u8>,
    intent: ProtocolUpgradeIntent,
) -> Result<ProtocolUpgradePlan> {
    intent.validate(&root)?;
    if intent.folderbase_id != attestation.folderbase_id
        || intent.root_instance_sha256 != attestation.root_instance_sha256
        || manifest_bytes != intent.source_bytes()
    {
        return Err(invalid_upgrade(
            &root,
            "pending protocol-upgrade intent does not bind the live legacy root",
        ));
    }
    Ok(ProtocolUpgradePlan {
        root,
        folderbase_id: intent.folderbase_id,
        from_protocol_version: intent.from_protocol_version,
        to_protocol_version: intent.to_protocol_version,
        changed_paths: vec![PathBuf::from(MANIFEST_PATH)],
        plan_digest: intent.plan_digest,
        upgraded_manifest: intent.target_manifest.into_bytes(),
        attested_manifest: manifest_bytes,
        attested_manifest_sha256: attestation.manifest_sha256,
        root_instance_sha256: attestation.root_instance_sha256,
        attested_ignore_snapshot: Some(intent.ignore_snapshot),
        exchange_owner: Some(intent.exchange_owner),
        already_applied: false,
    })
}

fn read_protocol_upgrade_intent(
    state: &FolderbaseState,
    root: &Path,
) -> Result<Option<ProtocolUpgradeIntent>> {
    let Some(encoded) = state.read_bounded_if_present(
        Path::new(UPGRADE_INTENT_PATH),
        MAX_PROTOCOL_UPGRADE_INTENT_BYTES,
    )?
    else {
        return Ok(None);
    };
    let intent: ProtocolUpgradeIntent = serde_json::from_slice(&encoded).map_err(|source| {
        FolderbaseError::json(root.join(".folderbase").join(UPGRADE_INTENT_PATH), source)
    })?;
    intent.validate(root)?;
    Ok(Some(intent))
}

fn prepare_protocol_upgrade_intent(
    state: &FolderbaseState,
    root: &Path,
    intent: &ProtocolUpgradeIntent,
) -> Result<()> {
    intent.validate(root)?;
    let encoded = serde_json::to_string_pretty(intent)
        .map(|encoded| format!("{encoded}\n").into_bytes())
        .map_err(|source| {
            FolderbaseError::json(root.join(".folderbase").join(UPGRADE_INTENT_PATH), source)
        })?;
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_PROTOCOL_UPGRADE_INTENT_BYTES {
        return Err(invalid_upgrade(
            root,
            "protocol-upgrade intent exceeds its durable record bound",
        ));
    }
    state.ensure_private_dir(Path::new(UPGRADE_INTENT_DIRECTORY))?;
    match state.publish_new(Path::new(UPGRADE_INTENT_PATH), &encoded) {
        Ok(()) => Ok(()),
        Err(FolderbaseError::WouldOverwrite(_)) => {
            let existing = state
                .read_bounded(
                    Path::new(UPGRADE_INTENT_PATH),
                    MAX_PROTOCOL_UPGRADE_INTENT_BYTES,
                )?
                .ok_or_else(|| invalid_upgrade(root, "protocol-upgrade intent disappeared"))?;
            if existing == encoded {
                Ok(())
            } else {
                Err(invalid_upgrade(
                    root,
                    "another protocol-upgrade intent is already active",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn recover_pending_protocol_upgrade(
    state: &FolderbaseState,
    root: &Path,
    expected: &ProtocolUpgradePlanDigest,
) -> Result<()> {
    let Some(intent) = read_protocol_upgrade_intent(state, root)? else {
        return Ok(());
    };
    let manifest = state
        .read_bounded(Path::new("manifest.json"), MAX_FOLDERBASE_MANIFEST_BYTES)?
        .ok_or_else(|| invalid_upgrade(root, "manifest disappeared during upgrade recovery"))?;
    attest_protocol_upgrade_recovery_root(state, root, &intent, &manifest)?;
    state.recover_owned_exchange_artifacts(
        Path::new(MANIFEST_PATH),
        &intent.exchange_owner,
        intent.source_bytes(),
        intent.target_bytes(),
    )?;
    state.verify_still_attached()?;
    if manifest == intent.target_bytes() {
        match read_ignore_snapshot(state, root) {
            Ok(snapshot) if snapshot == intent.ignore_snapshot => {
                state.verify_still_attached()?;
                state.remove_durable(Path::new(UPGRADE_INTENT_PATH))?;
                return Ok(());
            }
            _ => {
                rollback_protocol_upgrade(state, root, &intent)?;
                return Err(FolderbaseError::ProtocolUpgradePlanChanged {
                    expected: expected.digest.clone(),
                    actual: "unvalidated_activation_rolled_back".to_owned(),
                });
            }
        }
    }
    if manifest == intent.source_bytes() {
        if matches!(
            read_ignore_snapshot(state, root),
            Ok(ref snapshot) if snapshot == &intent.ignore_snapshot
        ) {
            state.verify_still_attached()?;
            return Ok(());
        }
        state.verify_still_attached()?;
        state.remove_durable(Path::new(UPGRADE_INTENT_PATH))?;
        return Err(FolderbaseError::ProtocolUpgradePlanChanged {
            expected: expected.digest.clone(),
            actual: "source_policy_changed_before_activation".to_owned(),
        });
    }
    Err(invalid_upgrade(
        root,
        "pending protocol-upgrade intent matches neither live manifest state",
    ))
}

fn rollback_protocol_upgrade(
    state: &FolderbaseState,
    root: &Path,
    intent: &ProtocolUpgradeIntent,
) -> Result<()> {
    state.verify_still_attached()?;
    state
        .compare_exchange_exact_owned_with_hook(
            Path::new(MANIFEST_PATH),
            intent.target_bytes(),
            intent.source_bytes(),
            &intent.exchange_owner,
            || {},
        )
        .map_err(|source| {
            invalid_upgrade(
                root,
                format!("protocol-upgrade rollback could not restore its source: {source}"),
            )
        })?;
    let source_manifest = state
        .read_bounded(Path::new("manifest.json"), MAX_FOLDERBASE_MANIFEST_BYTES)?
        .ok_or_else(|| invalid_upgrade(root, "manifest disappeared during upgrade rollback"))?;
    if source_manifest != intent.source_bytes() {
        return Err(invalid_upgrade(
            root,
            "protocol-upgrade rollback did not restore its exact source",
        ));
    }
    let _ = attest_protocol_upgrade_recovery_root(state, root, intent, &source_manifest)?;
    state.verify_still_attached()?;
    state.remove_durable(Path::new(UPGRADE_INTENT_PATH))
}

fn attest_protocol_upgrade_recovery_root(
    state: &FolderbaseState,
    root: &Path,
    intent: &ProtocolUpgradeIntent,
    manifest: &[u8],
) -> Result<(crate::FolderbaseRootAttestation, ManifestProtocolProfile)> {
    state.verify_still_attached()?;
    let (attestation, _, profile) =
        attest_folderbase_root_with_profile_allowing_upgrade_recovery(root)
            .map_err(|source| invalid_upgrade(root, source.to_string()))?;
    state.verify_still_attached()?;
    let manifest_sha256 = format!("{:x}", Sha256::digest(manifest));
    if attestation.folderbase_id != intent.folderbase_id
        || attestation.root_instance_sha256 != intent.root_instance_sha256
        || attestation.manifest_sha256 != manifest_sha256
        || (manifest != intent.source_bytes() && manifest != intent.target_bytes())
    {
        return Err(invalid_upgrade(
            root,
            "pending protocol-upgrade intent does not bind the attached physical root",
        ));
    }
    Ok((attestation, profile))
}

fn read_ignore_snapshot(state: &FolderbaseState, root: &Path) -> Result<IgnorePolicySnapshot> {
    read_ignore_snapshot_with_hook(state, root, || {})
}

#[cfg(test)]
fn read_ignore_snapshot_sha256_with_hook(
    state: &FolderbaseState,
    root: &Path,
    after_read: impl FnOnce(),
) -> Result<String> {
    read_ignore_snapshot_with_hook(state, root, after_read)?.binding_sha256()
}

fn read_ignore_snapshot_with_hook(
    state: &FolderbaseState,
    root: &Path,
    after_read: impl FnOnce(),
) -> Result<IgnorePolicySnapshot> {
    state.verify_still_attached()?;
    if state.workspace_path_is_absent(Path::new(IGNORE_POLICY_PATH))? {
        after_read();
        if !state.workspace_path_is_absent(Path::new(IGNORE_POLICY_PATH))? {
            return Err(invalid_upgrade(
                root,
                "ignore policy presence changed while it was observed",
            ));
        }
        state.verify_still_attached()?;
        return Ok(IgnorePolicySnapshot::Absent);
    }

    let mut first = state.open_workspace_regular_file(Path::new(IGNORE_POLICY_PATH))?;
    let observed = read_open_ignore_snapshot(&mut first, root)?;
    after_read();
    let mut visible = state.open_workspace_regular_file(Path::new(IGNORE_POLICY_PATH))?;
    let revalidated = read_open_ignore_snapshot(&mut visible, root)?;
    if observed != revalidated {
        return Err(invalid_upgrade(
            root,
            "visible ignore policy changed after it was read",
        ));
    }
    state.verify_still_attached()?;
    Ok(observed)
}

fn read_open_ignore_snapshot(
    file: &mut std::fs::File,
    root: &Path,
) -> Result<IgnorePolicySnapshot> {
    let display = root.join(IGNORE_POLICY_PATH);
    let metadata_before = file
        .metadata()
        .map_err(|source| FolderbaseError::io(&display, source))?;
    let identity_before = stable_file_identity_sha256(file)
        .map_err(|source| FolderbaseError::io(&display, source))?;
    let links_before =
        stable_file_link_count(file).map_err(|source| FolderbaseError::io(&display, source))?;
    if !metadata_before.is_file()
        || metadata_before.len() > MAX_FOLDERBASEIGNORE_BYTES
        || links_before != 1
    {
        return Err(invalid_upgrade(
            root,
            "ignore policy must be one bounded, singly-linked regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_FOLDERBASEIGNORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| FolderbaseError::io(&display, source))?;
    let metadata_after = file
        .metadata()
        .map_err(|source| FolderbaseError::io(&display, source))?;
    let identity_after = stable_file_identity_sha256(file)
        .map_err(|source| FolderbaseError::io(&display, source))?;
    let links_after =
        stable_file_link_count(file).map_err(|source| FolderbaseError::io(&display, source))?;
    if bytes.len() as u64 > MAX_FOLDERBASEIGNORE_BYTES
        || metadata_before.len() != metadata_after.len()
        || identity_before != identity_after
        || links_before != links_after
        || links_after != 1
    {
        return Err(invalid_upgrade(
            root,
            "ignore policy changed while its bytes and topology were read",
        ));
    }
    Ok(IgnorePolicySnapshot::Present {
        kind: "regular_file".to_owned(),
        bytes: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        physical_identity_sha256: identity_after,
        link_count: links_after,
    })
}

fn invalid_upgrade(root: &Path, message: impl Into<String>) -> FolderbaseError {
    FolderbaseError::InvalidRecord {
        path: root.join(MANIFEST_PATH),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    const LEGACY_MANIFEST: &[u8] = br#"{
  "$schema": "https://folderbase.ai/protocol/0.1/folderbase.schema.json",
  "protocol_version": "0.1.0",
  "folderbase": {
    "id": "folderbase_019f9b75-4f42-7f65-a012-2bfecdd8c475",
    "name": "Legacy Folderbase",
    "kind": "project",
    "status": "active",
    "created_at": "2026-07-26T00:00:00Z",
    "entry": "FOLDERBASE.md"
  },
  "policies": {
    "availability": "keep_local",
    "structural_changes": "approve",
    "archive": "approve",
    "cloud_sync": "disabled"
  }
}
"#;

    fn write_legacy_root(root: &Path) {
        fs::create_dir_all(root.join(".folderbase")).expect("state");
        fs::write(root.join(".folderbase/manifest.json"), LEGACY_MANIFEST).expect("manifest");
        fs::write(root.join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        fs::write(root.join(".folderbaseignore"), b"node_modules/\n").expect("ignore");
    }

    fn write_legacy_root_with_manifest_bytes(root: &Path, target_bytes: usize) {
        let mut manifest: Value =
            serde_json::from_slice(LEGACY_MANIFEST).expect("legacy manifest value");
        manifest
            .as_object_mut()
            .expect("legacy manifest object")
            .insert("x-padding".to_owned(), Value::String(String::new()));
        let encode = |manifest: &Value| {
            serde_json::to_string_pretty(manifest)
                .map(|encoded| format!("{encoded}\n").into_bytes())
                .expect("encoded legacy manifest")
        };
        let baseline = encode(&manifest);
        let padding_bytes = target_bytes
            .checked_sub(baseline.len())
            .expect("manifest budget");
        manifest
            .as_object_mut()
            .expect("legacy manifest object")
            .insert(
                "x-padding".to_owned(),
                Value::String("x".repeat(padding_bytes)),
            );
        let encoded = encode(&manifest);
        assert_eq!(encoded.len(), target_bytes);

        fs::create_dir_all(root.join(".folderbase")).expect("state");
        fs::write(root.join(".folderbase/manifest.json"), encoded).expect("large manifest");
        fs::write(root.join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        fs::write(root.join(".folderbaseignore"), b"node_modules/\n").expect("ignore");
    }

    fn write_near_maximum_legacy_root(root: &Path) {
        write_legacy_root_with_manifest_bytes(
            root,
            MAX_FOLDERBASE_MANIFEST_BYTES as usize - 64 * 1024,
        );
    }

    fn substitute_root_with_recovery_surface(root: &Path, ignore: &[u8]) {
        let manifest = fs::read(root.join(".folderbase/manifest.json")).expect("live manifest");
        let intent =
            fs::read(root.join(".folderbase").join(UPGRADE_INTENT_PATH)).expect("durable intent");
        let detached = root.with_extension("detached");
        fs::rename(root, &detached).expect("detach original root");
        fs::create_dir_all(root.join(".folderbase").join(UPGRADE_INTENT_DIRECTORY))
            .expect("replacement state");
        fs::write(root.join(".folderbase/manifest.json"), manifest).expect("replacement manifest");
        fs::write(root.join(".folderbase").join(UPGRADE_INTENT_PATH), intent)
            .expect("replacement intent");
        fs::write(root.join("FOLDERBASE.md"), b"# User narrative\n").expect("replacement entry");
        fs::write(root.join(".folderbaseignore"), ignore).expect("replacement ignore");
    }

    #[test]
    fn manifest_replacement_is_a_durable_lost_ack_recovery_point() {
        let root = tempdir().expect("legacy root");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .expect("manifest");
        fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        fs::write(root.path().join(".folderbaseignore"), b"node_modules/\n").expect("ignore");

        let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
        let expected = plan.plan_digest().clone();
        let state = FolderbaseState::open_existing(root.path()).expect("state capability");
        state
            .replace(Path::new(MANIFEST_PATH), &plan.upgraded_manifest)
            .expect("simulate crash after manifest activation");
        drop(state);

        let retry = plan_protocol_upgrade(root.path()).expect("recover applied receipt");
        assert!(retry.already_applied);
        assert_eq!(retry.plan_digest(), &expected);
        let result =
            apply_protocol_upgrade(&retry, &expected).expect("acknowledge exact activation");
        assert_eq!(result.applied_plan_digest, expected);
    }

    #[test]
    fn activation_exchange_restores_a_concurrent_manifest_without_clobbering_it() {
        let root = tempdir().expect("legacy root");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .expect("manifest");
        fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        fs::write(root.path().join(".folderbaseignore"), b"node_modules/\n").expect("ignore");

        let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
        let expected = plan.plan_digest().clone();
        let foreign = [LEGACY_MANIFEST, b" "].concat();
        let manifest_path = root.path().join(MANIFEST_PATH);
        let result = apply_protocol_upgrade_with_hook(&plan, &expected, || {
            fs::write(&manifest_path, &foreign).expect("concurrent manifest edit");
        });

        assert!(matches!(
            result,
            Err(FolderbaseError::ProtocolUpgradePlanChanged { .. })
        ));
        assert_eq!(
            fs::read(&manifest_path).expect("foreign manifest retained"),
            foreign
        );
    }

    #[test]
    fn activation_refuses_concurrent_ignore_policy_presence_and_content_transitions() {
        for replacement in [None, Some(b"dist/\n".as_slice())] {
            let root = tempdir().expect("legacy root");
            fs::create_dir(root.path().join(".folderbase")).expect("state");
            fs::write(
                root.path().join(".folderbase/manifest.json"),
                LEGACY_MANIFEST,
            )
            .expect("manifest");
            fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
            let ignore_path = root.path().join(".folderbaseignore");
            fs::write(&ignore_path, b"node_modules/\n").expect("ignore");

            let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
            let expected = plan.plan_digest().clone();
            let result = apply_protocol_upgrade_with_hook(&plan, &expected, || {
                if let Some(bytes) = replacement {
                    fs::write(&ignore_path, bytes).expect("concurrent ignore edit");
                } else {
                    fs::remove_file(&ignore_path).expect("concurrent ignore delete");
                }
            });

            assert!(matches!(
                result,
                Err(FolderbaseError::ProtocolUpgradePlanChanged { .. })
            ));
            assert_eq!(
                fs::read(root.path().join(MANIFEST_PATH)).expect("legacy manifest retained"),
                LEGACY_MANIFEST
            );
            assert_eq!(fs::read(&ignore_path).ok().as_deref(), replacement);
        }
    }

    #[test]
    fn restart_never_acknowledges_an_unvalidated_policy_transition() {
        let root = tempdir().expect("legacy root");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .expect("manifest");
        fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        let ignore_path = root.path().join(".folderbaseignore");
        fs::write(&ignore_path, b"node_modules/\n").expect("ignore");

        let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
        let expected = plan.plan_digest().clone();
        let interrupted = apply_protocol_upgrade_with_hooks(
            &plan,
            &expected,
            || fs::write(&ignore_path, b"dist/\n").expect("concurrent policy transition"),
            || {
                Err(FolderbaseError::ProtocolUpgradeBlocked(
                    "simulated process interruption",
                ))
            },
        );
        assert!(interrupted.is_err());
        assert_ne!(
            fs::read(root.path().join(MANIFEST_PATH)).expect("activated manifest"),
            LEGACY_MANIFEST
        );
        assert!(
            attest_folderbase_root_with_profile(root.path()).is_err(),
            "ordinary typed admission must stop at the pending recovery intent"
        );
        let local = LocalVersionStore::open_read_only(root.path()).expect("local store");
        assert!(matches!(
            local.acquire_transaction_lock(),
            Err(FolderbaseError::ProtocolUpgradeBlocked(
                "Folderbase protocol upgrade recovery"
            ))
        ));

        let retry = plan_protocol_upgrade(root.path()).expect("restart plan");
        assert!(
            apply_protocol_upgrade(&retry, retry.plan_digest()).is_err(),
            "a receipt cannot acknowledge activation that crashed before policy validation"
        );
        assert_eq!(
            fs::read(root.path().join(MANIFEST_PATH)).expect("safe rollback"),
            LEGACY_MANIFEST
        );
    }

    #[test]
    fn restart_validates_an_exact_pending_activation_before_acknowledgement() {
        let root = tempdir().expect("legacy root");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .expect("manifest");
        fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        fs::write(root.path().join(".folderbaseignore"), b"node_modules/\n").expect("ignore");

        let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
        let expected = plan.plan_digest().clone();
        let interrupted = apply_protocol_upgrade_with_hooks(
            &plan,
            &expected,
            || {},
            || {
                Err(FolderbaseError::ProtocolUpgradeBlocked(
                    "simulated process interruption",
                ))
            },
        );
        assert!(interrupted.is_err());
        assert!(attest_folderbase_root_with_profile(root.path()).is_err());

        let retry = plan_protocol_upgrade(root.path()).expect("restart plan");
        let result =
            apply_protocol_upgrade(&retry, retry.plan_digest()).expect("validated recovery");
        assert_eq!(result.applied_plan_digest, expected);
        attest_folderbase_root_with_profile(root.path()).expect("intent retired after validation");
    }

    #[test]
    fn restart_resumes_an_exact_prepared_source_intent() {
        let root = tempdir().expect("legacy root");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .expect("manifest");
        fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        fs::write(root.path().join(".folderbaseignore"), b"node_modules/\n").expect("ignore");

        let plan = plan_protocol_upgrade(root.path()).expect("upgrade plan");
        let intent = ProtocolUpgradeIntent::from_plan(&plan).expect("intent");
        let state = FolderbaseState::open_existing(root.path()).expect("state");
        prepare_protocol_upgrade_intent(&state, root.path(), &intent).expect("prepared intent");
        drop(state);
        assert!(attest_folderbase_root_with_profile(root.path()).is_err());

        let retry = plan_protocol_upgrade(root.path()).expect("restart plan");
        apply_protocol_upgrade(&retry, retry.plan_digest()).expect("resume prepared activation");
        attest_folderbase_root_with_profile(root.path()).expect("intent retired after activation");
    }

    #[test]
    fn target_recovery_never_acknowledges_a_copied_replacement_root() {
        let parent = tempdir().expect("parent");
        let root = parent.path().join("active");
        write_legacy_root(&root);
        let plan = plan_protocol_upgrade(&root).expect("upgrade plan");
        let expected = plan.plan_digest().clone();
        apply_protocol_upgrade_with_hooks(
            &plan,
            &expected,
            || {},
            || {
                Err(FolderbaseError::ProtocolUpgradeBlocked(
                    "simulated process interruption",
                ))
            },
        )
        .expect_err("simulated interruption");
        substitute_root_with_recovery_surface(&root, b"node_modules/\n");

        let retry = plan_protocol_upgrade(&root).expect("replacement restart plan");
        assert!(
            apply_protocol_upgrade(&retry, retry.plan_digest()).is_err(),
            "target recovery must bind the intent to the current physical root"
        );
        assert!(
            root.join(".folderbase").join(UPGRADE_INTENT_PATH).exists(),
            "foreign-root recovery evidence must remain for explicit repair"
        );
    }

    #[test]
    fn source_recovery_never_retires_an_intent_copied_to_a_replacement_root() {
        let parent = tempdir().expect("parent");
        let root = parent.path().join("active");
        write_legacy_root(&root);
        let plan = plan_protocol_upgrade(&root).expect("upgrade plan");
        let expected = plan.plan_digest().clone();
        let intent = ProtocolUpgradeIntent::from_plan(&plan).expect("intent");
        let state = FolderbaseState::open_existing(&root).expect("state");
        prepare_protocol_upgrade_intent(&state, &root, &intent).expect("prepared intent");
        drop(state);
        substitute_root_with_recovery_surface(&root, b"dist/\n");

        assert!(apply_protocol_upgrade(&plan, &expected).is_err());
        assert!(
            root.join(".folderbase").join(UPGRADE_INTENT_PATH).exists(),
            "source recovery must attest the root before retiring stale intent state"
        );
    }

    #[test]
    fn post_activation_ack_never_accepts_a_replacement_physical_root() {
        let parent = tempdir().expect("parent");
        let root = parent.path().join("active");
        let detached = parent.path().join("detached");
        write_legacy_root(&root);
        let plan = plan_protocol_upgrade(&root).expect("upgrade plan");
        let expected = plan.plan_digest().clone();
        let replacement_manifest = plan.upgraded_manifest.clone();
        let visible_root = root.clone();
        let detached_root = detached.clone();

        let result = apply_protocol_upgrade_with_hooks(
            &plan,
            &expected,
            || {},
            || {
                fs::rename(&visible_root, &detached_root).expect("detach activated root");
                fs::create_dir_all(visible_root.join(".folderbase")).expect("replacement state");
                fs::write(
                    visible_root.join(".folderbase/manifest.json"),
                    replacement_manifest,
                )
                .expect("replacement manifest");
                Ok(())
            },
        );

        assert!(
            result.is_err(),
            "activation acknowledgement must bind the visible physical root"
        );
        assert!(
            detached
                .join(".folderbase")
                .join(UPGRADE_INTENT_PATH)
                .exists(),
            "detached recovery evidence must remain after root substitution"
        );
    }

    #[test]
    fn near_maximum_manifests_leave_a_restart_readable_durable_intent() {
        let root = tempdir().expect("legacy root");
        write_near_maximum_legacy_root(root.path());
        let plan = plan_protocol_upgrade(root.path()).expect("large upgrade plan");
        assert!(plan.attested_manifest.len() as u64 <= MAX_FOLDERBASE_MANIFEST_BYTES);
        assert!(plan.upgraded_manifest.len() as u64 <= MAX_FOLDERBASE_MANIFEST_BYTES);
        let expected = plan.plan_digest().clone();

        apply_protocol_upgrade_with_hooks(
            &plan,
            &expected,
            || {},
            || {
                Err(FolderbaseError::ProtocolUpgradeBlocked(
                    "simulated process interruption",
                ))
            },
        )
        .expect_err("simulated interruption");
        let intent = root.path().join(".folderbase").join(UPGRADE_INTENT_PATH);
        if !intent.exists() {
            assert_eq!(
                fs::read(root.path().join(MANIFEST_PATH)).expect("source manifest"),
                plan.attested_manifest,
                "a pre-publication bound refusal must leave the source untouched"
            );
            return;
        }

        let retry = plan_protocol_upgrade(root.path())
            .expect("every published durable intent must be restart-readable");
        apply_protocol_upgrade(&retry, retry.plan_digest()).expect("restart recovery");
        assert!(!intent.exists(), "restart retires the durable intent");
    }

    #[test]
    fn an_exact_maximum_source_that_expands_past_the_target_bound_is_never_published() {
        let root = tempdir().expect("legacy root");
        write_legacy_root_with_manifest_bytes(root.path(), MAX_FOLDERBASE_MANIFEST_BYTES as usize);
        let manifest_path = root.path().join(MANIFEST_PATH);
        let source_manifest = fs::read(&manifest_path).expect("source manifest");

        let result = plan_protocol_upgrade(root.path());

        assert!(
            result.is_err(),
            "planning must reject a generated target above the live manifest bound"
        );
        assert_eq!(
            fs::read(&manifest_path).expect("unchanged source manifest"),
            source_manifest
        );
        assert!(
            !root
                .path()
                .join(".folderbase")
                .join(UPGRADE_INTENT_PATH)
                .exists(),
            "a rejected target must not publish durable intent"
        );
        let exchange_artifact = fs::read_dir(root.path().join(".folderbase"))
            .expect("state directory")
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".exchange-")
            });
        assert!(
            !exchange_artifact,
            "a rejected target must not begin exchange"
        );
    }

    #[test]
    fn ignore_snapshot_rejects_a_post_read_same_byte_path_replacement() {
        let root = tempdir().expect("legacy root");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .expect("manifest");
        fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        let ignore_path = root.path().join(".folderbaseignore");
        fs::write(&ignore_path, b"node_modules/\n").expect("ignore");
        let state = FolderbaseState::open_existing_read_only(root.path()).expect("state");

        let result = read_ignore_snapshot_sha256_with_hook(&state, root.path(), || {
            fs::remove_file(&ignore_path).expect("remove observed policy");
            fs::write(&ignore_path, b"node_modules/\n").expect("same-byte replacement");
        });

        assert!(
            result.is_err(),
            "the retained file is not enough; the visible path must be reopened and rebound"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn ignore_snapshot_rejects_a_post_read_hard_link_topology_change() {
        let root = tempdir().expect("legacy root");
        fs::create_dir(root.path().join(".folderbase")).expect("state");
        fs::write(
            root.path().join(".folderbase/manifest.json"),
            LEGACY_MANIFEST,
        )
        .expect("manifest");
        fs::write(root.path().join("FOLDERBASE.md"), b"# User narrative\n").expect("entry");
        let ignore_path = root.path().join(".folderbaseignore");
        fs::write(&ignore_path, b"node_modules/\n").expect("ignore");
        let state = FolderbaseState::open_existing_read_only(root.path()).expect("state");

        let result = read_ignore_snapshot_sha256_with_hook(&state, root.path(), || {
            fs::hard_link(&ignore_path, root.path().join("ignore.backup"))
                .expect("new hard-link authority");
        });

        assert!(
            result.is_err(),
            "link topology is part of the approved policy identity"
        );
    }
}
