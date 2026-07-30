//! Explicit, reviewable transition from legacy live-root semantics to 0.5.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    FolderbaseError, FolderbaseVersionStore, LocalVersionStore, Result,
    folderbase_state::FolderbaseState,
    root_attestation::{
        DEFAULT_V05_CAPTURE_IGNORE_RULES, MAX_FOLDERBASE_MANIFEST_BYTES, ManifestProtocolProfile,
        attest_folderbase_root_with_profile, decode_manifest_protocol_profile,
    },
};

const MANIFEST_PATH: &str = ".folderbase/manifest.json";
const ACTIVE_CAPTURE_PATH: &str =
    ".folderbase/transactions/folderbase-version-captures/active.json";
const ACTIVE_RESTORE_PATH: &str =
    ".folderbase/transactions/folderbase-version-restores/active.json";
const RESTORE_CLEANUP_PATH: &str =
    ".folderbase/transactions/folderbase-version-restores/cleanup.json";
const ACTIVE_REORGANIZATION_PATH: &str = ".folderbase/reorganizations/active.json";
const MIGRATIONS_PATH: &str = ".folderbase/migrations";
const MAX_PENDING_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MIGRATION_DIRECTORIES: usize = 16_384;
const UPGRADE_RECEIPT_FORMAT: &str = "folderbase-protocol-upgrade-receipt-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
struct ProtocolUpgradeReceipt {
    format: String,
    from_protocol_version: String,
    target_manifest_without_receipt_sha256: String,
    plan_digest: ProtocolUpgradePlanDigest,
}

pub fn plan_protocol_upgrade(root: impl AsRef<Path>) -> Result<ProtocolUpgradePlan> {
    let supplied_root = root.as_ref();
    let (supplied_attestation, _, supplied_profile) =
        attest_folderbase_root_with_profile(supplied_root)
            .map_err(|source| invalid_upgrade(supplied_root, source.to_string()))?;
    let root = supplied_root
        .canonicalize()
        .map_err(|source| FolderbaseError::io(supplied_root, source))?;
    let (attestation, _, profile) = attest_folderbase_root_with_profile(&root)
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
    if matches!(profile, ManifestProtocolProfile::OrdinaryV05 { .. }) {
        let Some(_) = manifest.get("protocol_upgrade") else {
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
            already_applied: true,
        });
    }

    if manifest.get("protocol_upgrade").is_some()
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
    decode_manifest_protocol_profile(&upgraded_manifest_without_receipt)
        .map_err(|source| invalid_upgrade(&root, source.to_string()))?;

    let mut digest = Sha256::new();
    digest.update(b"folderbase-protocol-upgrade-plan-v1\0");
    update_bytes(&mut digest, attestation.folderbase_id.as_bytes());
    update_bytes(&mut digest, attestation.root_instance_sha256.as_bytes());
    update_bytes(&mut digest, attestation.manifest_sha256.as_bytes());
    update_bytes(&mut digest, capture.ignore_policy_sha256().as_bytes());
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
            "protocol_upgrade".to_owned(),
            serde_json::to_value(ProtocolUpgradeReceipt {
                format: UPGRADE_RECEIPT_FORMAT.to_owned(),
                from_protocol_version: from_protocol_version.clone(),
                target_manifest_without_receipt_sha256,
                plan_digest: plan_digest.clone(),
            })
            .map_err(|source| FolderbaseError::json(&manifest_path, source))?,
        );
    let upgraded_manifest = serde_json::to_string_pretty(&manifest)
        .map(|encoded| format!("{encoded}\n").into_bytes())
        .map_err(|source| FolderbaseError::json(&manifest_path, source))?;
    decode_manifest_protocol_profile(&upgraded_manifest)
        .map_err(|source| invalid_upgrade(&root, source.to_string()))?;
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
        already_applied: false,
    })
}

pub fn apply_protocol_upgrade(
    plan: &ProtocolUpgradePlan,
    expected: &ProtocolUpgradePlanDigest,
) -> Result<ProtocolUpgradeResult> {
    apply_protocol_upgrade_with_hook(plan, expected, || {})
}

fn apply_protocol_upgrade_with_hook(
    plan: &ProtocolUpgradePlan,
    expected: &ProtocolUpgradePlanDigest,
    before_activation: impl FnOnce(),
) -> Result<ProtocolUpgradeResult> {
    expected.validate()?;
    let local = LocalVersionStore::open_read_only(&plan.root)?;
    let state = FolderbaseState::open_existing(&plan.root)?;
    let _lock = local.acquire_transaction_lock_in(&state)?;
    state.verify_still_attached()?;
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
    state
        .compare_exchange_exact_with_hook(
            Path::new(MANIFEST_PATH),
            &plan.attested_manifest,
            &plan.upgraded_manifest,
            before_activation,
        )
        .map_err(|error| match error {
            FolderbaseError::WouldOverwrite(_) => FolderbaseError::ProtocolUpgradePlanChanged {
                expected: expected.digest.clone(),
                actual: "manifest_changed_at_activation".to_owned(),
            },
            other => other,
        })?;
    let (attestation, _, profile) = attest_folderbase_root_with_profile(&plan.root)
        .map_err(|source| invalid_upgrade(&plan.root, source.to_string()))?;
    if attestation.protocol_version != "0.5.0"
        || !matches!(profile, ManifestProtocolProfile::OrdinaryV05 { .. })
    {
        return Err(invalid_upgrade(
            &plan.root,
            "manifest activation did not produce the exact 0.5 profile",
        ));
    }
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
    let receipt: ProtocolUpgradeReceipt =
        serde_json::from_value(manifest.get("protocol_upgrade").cloned().ok_or_else(|| {
            invalid_upgrade(root, "0.5 manifest has no applied legacy-upgrade receipt")
        })?)
        .map_err(|source| {
            invalid_upgrade(root, format!("invalid protocol-upgrade receipt: {source}"))
        })?;
    if receipt.format != UPGRADE_RECEIPT_FORMAT
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
        .remove("protocol_upgrade");
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
}
