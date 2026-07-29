use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::Path,
};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

use crate::{
    FolderbaseError, ObjectId, Result, VersionId, traversal_policy::is_reserved_workspace_component,
};

pub const MAX_REORGANIZATION_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CANONICAL_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_REORGANIZATION_TEXT_CHARACTERS: usize = 2 * 1024 * 1024;
const MAX_REORGANIZATION_PATH_CHARACTERS: usize = 4_096;
const MAX_REORGANIZATION_SCOPE_ENTRIES: usize = 100_000;
const MAX_REORGANIZATION_OPERATIONS: usize = 10_000;
const MAX_REORGANIZATION_QUESTIONS: usize = 1_024;

const REORGANIZATION_PROTOCOL_VERSION: &str = "0.3.0";
const REORGANIZATION_DRAFT_PROFILE: &str = "folderbase-reorganization-draft-v1";
const REORGANIZATION_PLAN_PROFILE: &str = "folderbase-reorganization-plan-v1";
const ANALYSIS_SCOPE_DIGEST_DOMAIN: &[u8] = b"folderbase-reorganization-analysis-scope-v1\0";
const PLAN_DIGEST_DOMAIN: &[u8] = b"folderbase-reorganization-plan-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathProfile {
    #[serde(rename = "portable-case-sensitive-v1")]
    CaseSensitive,
    #[serde(rename = "portable-case-fold-v1")]
    CaseFold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "expectation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeEntry {
    Absent {
        path: String,
    },
    Directory {
        path: String,
    },
    File {
        path: String,
        sha256: String,
        #[serde(deserialize_with = "deserialize_canonical_u64")]
        byte_count: u64,
    },
    TrackedObject {
        path: String,
        object_id: ObjectId,
        version_id: VersionId,
    },
}

impl ScopeEntry {
    fn path(&self) -> &str {
        match self {
            Self::Absent { path }
            | Self::Directory { path }
            | Self::File { path, .. }
            | Self::TrackedObject { path, .. } => path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedBoundary {
    pub path: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisScope {
    pub manifest_sha256: String,
    pub ignore_policy: ScopeEntry,
    pub structural_changes_policy: StructuralChangesPolicy,
    pub nested_boundaries: Vec<NestedBoundary>,
    pub operation_closure: Vec<ScopeEntry>,
    pub declared_entries: Vec<ScopeEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralChangesPolicy {
    Suggest,
    Approve,
    Autonomous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ConsequentialAnswer {
    Text(String),
    Boolean(bool),
    SingleChoice(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsequentialAnswerType {
    Text,
    Boolean,
    SingleChoice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsequentialQuestion {
    pub id: String,
    pub prompt: String,
    pub answer_type: ConsequentialAnswerType,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<ConsequentialAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReorganizationOperation {
    CreateDirectory {
        path: String,
    },
    CreateUtf8File {
        path: String,
        content: String,
    },
    ReplaceUtf8File {
        path: String,
        expected_sha256: String,
        content: String,
    },
    UpdateManagedAgentBlock {
        path: String,
        adapter: String,
        expected_sha256: String,
        content: String,
    },
    MoveFile {
        source_path: String,
        destination_path: String,
        expected_sha256: String,
        #[serde(deserialize_with = "deserialize_canonical_u64")]
        expected_byte_count: u64,
    },
    MoveTrackedObject {
        source_path: String,
        destination_path: String,
        object_id: ObjectId,
        expected_version_id: VersionId,
    },
    MarkCanonical {
        object_record_path: String,
        object_id: ObjectId,
        expected_version_id: VersionId,
        expected_record_sha256: String,
    },
    MarkSuperseded {
        object_record_path: String,
        object_id: ObjectId,
        expected_version_id: VersionId,
        superseded_by: ObjectId,
        expected_record_sha256: String,
    },
    ArchiveObject {
        object_record_path: String,
        object_id: ObjectId,
        expected_version_id: VersionId,
        expected_record_sha256: String,
    },
    AddRelationship {
        object_record_path: String,
        object_id: ObjectId,
        expected_version_id: VersionId,
        relationship_type: String,
        target_object_id: ObjectId,
        expected_record_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReorganizationDraft {
    pub protocol_version: String,
    pub profile: String,
    pub id: String,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    pub generation: u64,
    pub folderbase_id: String,
    pub path_profile: PathProfile,
    pub analysis_scope: AnalysisScope,
    pub questions: Vec<ConsequentialQuestion>,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub template_references: Vec<String>,
    pub operations: Vec<ReorganizationOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReorganizationPlan {
    pub protocol_version: String,
    pub profile: String,
    pub id: String,
    #[serde(deserialize_with = "deserialize_canonical_u64")]
    pub generation: u64,
    pub folderbase_id: String,
    pub path_profile: PathProfile,
    pub analysis_scope: AnalysisScope,
    pub analysis_scope_digest: String,
    pub questions: Vec<ConsequentialQuestion>,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub template_references: Vec<String>,
    pub operations: Vec<ReorganizationOperation>,
    pub plan_digest: String,
}

pub fn decode_reorganization_draft(reader: impl Read) -> Result<ReorganizationDraft> {
    let bytes = read_bounded_record(reader)?;
    decode_reorganization_draft_slice(&bytes)
}

pub fn decode_reorganization_draft_slice(bytes: &[u8]) -> Result<ReorganizationDraft> {
    if bytes.len() > MAX_REORGANIZATION_RECORD_BYTES {
        return invalid_record("reorganization draft exceeds the 8 MiB encoded-record limit");
    }
    let mut draft: ReorganizationDraft = serde_json::from_slice(bytes)
        .map_err(|source| FolderbaseError::json("<reorganization-draft>", source))?;
    validate_draft(&draft)?;
    normalize_draft(&mut draft);
    Ok(draft)
}

pub fn decode_reorganization_plan(reader: impl Read) -> Result<ReorganizationPlan> {
    let bytes = read_bounded_record(reader)?;
    decode_reorganization_plan_slice(&bytes)
}

pub fn decode_reorganization_plan_slice(bytes: &[u8]) -> Result<ReorganizationPlan> {
    if bytes.len() > MAX_REORGANIZATION_RECORD_BYTES {
        return invalid_record("reorganization plan exceeds the 8 MiB encoded-record limit");
    }
    let mut plan: ReorganizationPlan = serde_json::from_slice(bytes)
        .map_err(|source| FolderbaseError::json("<reorganization-plan>", source))?;
    validate_plan(&plan)?;
    normalize_plan(&mut plan);
    Ok(plan)
}

fn read_bounded_record(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REORGANIZATION_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| FolderbaseError::io("<reorganization>", source))?;
    if bytes.len() > MAX_REORGANIZATION_RECORD_BYTES {
        return invalid_record("reorganization record exceeds the 8 MiB encoded-record limit");
    }
    Ok(bytes)
}

pub fn seal_reorganization_draft(mut draft: ReorganizationDraft) -> Result<ReorganizationPlan> {
    validate_draft(&draft)?;
    if draft
        .questions
        .iter()
        .any(|question| question.required && question.answer.is_none())
    {
        return invalid_record(
            "all required consequential questions must be answered before sealing",
        );
    }
    normalize_draft(&mut draft);

    let analysis_scope_digest = reorganization_analysis_scope_sha256(&draft.analysis_scope)?;
    let mut plan = ReorganizationPlan {
        protocol_version: draft.protocol_version,
        profile: REORGANIZATION_PLAN_PROFILE.to_owned(),
        id: draft.id,
        generation: draft.generation,
        folderbase_id: draft.folderbase_id,
        path_profile: draft.path_profile,
        analysis_scope: draft.analysis_scope,
        analysis_scope_digest,
        questions: draft.questions,
        rationale: draft.rationale,
        template_references: draft.template_references,
        operations: draft.operations,
        plan_digest: String::new(),
    };
    plan.plan_digest = canonical_plan_digest(&plan)?;
    validate_plan(&plan)?;
    Ok(plan)
}

pub fn validate_reorganization_draft(draft: &ReorganizationDraft) -> Result<()> {
    validate_draft(draft)
}

pub fn validate_reorganization_plan(plan: &ReorganizationPlan) -> Result<()> {
    validate_plan(plan)
}

pub fn reorganization_analysis_scope_sha256(scope: &AnalysisScope) -> Result<String> {
    ensure_aggregate_record_bound(scope, "reorganization analysis scope")?;
    let mut normalized = scope.clone();
    normalize_scope(&mut normalized);
    canonical_digest(ANALYSIS_SCOPE_DIGEST_DOMAIN, &normalized)
}

pub fn reorganization_plan_sha256(plan: &ReorganizationPlan) -> Result<String> {
    canonical_plan_digest(plan)
}

fn validate_plan(plan: &ReorganizationPlan) -> Result<()> {
    ensure_aggregate_record_bound(plan, "reorganization plan")?;
    if plan.profile != REORGANIZATION_PLAN_PROFILE {
        return invalid_record(format!(
            "unsupported reorganization plan profile {}",
            plan.profile
        ));
    }
    let draft_shape = ReorganizationDraft {
        protocol_version: plan.protocol_version.clone(),
        profile: REORGANIZATION_DRAFT_PROFILE.to_owned(),
        id: plan.id.clone(),
        generation: plan.generation,
        folderbase_id: plan.folderbase_id.clone(),
        path_profile: plan.path_profile,
        analysis_scope: plan.analysis_scope.clone(),
        questions: plan.questions.clone(),
        rationale: plan.rationale.clone(),
        template_references: plan.template_references.clone(),
        operations: plan.operations.clone(),
    };
    validate_draft(&draft_shape)?;
    if plan
        .questions
        .iter()
        .any(|question| question.required && question.answer.is_none())
    {
        return invalid_record("sealed plans require answers to all consequential questions");
    }
    validate_digest(&plan.analysis_scope_digest)?;
    let expected_scope = reorganization_analysis_scope_sha256(&plan.analysis_scope)?;
    if plan.analysis_scope_digest != expected_scope {
        return invalid_record("reorganization analysis-scope digest does not match");
    }
    validate_digest(&plan.plan_digest)?;
    let expected_plan = canonical_plan_digest(plan)?;
    if plan.plan_digest != expected_plan {
        return invalid_record("reorganization plan digest does not match");
    }
    Ok(())
}

fn validate_draft(draft: &ReorganizationDraft) -> Result<()> {
    ensure_aggregate_record_bound(draft, "reorganization draft")?;
    if draft.protocol_version != REORGANIZATION_PROTOCOL_VERSION {
        return invalid_record(format!(
            "unsupported reorganization protocol {}",
            draft.protocol_version
        ));
    }
    if draft.profile != REORGANIZATION_DRAFT_PROFILE {
        return invalid_record(format!(
            "unsupported reorganization draft profile {}",
            draft.profile
        ));
    }
    validate_identifier(&draft.id, "reorganization id", "reorg_")?;
    validate_folderbase_id(&draft.folderbase_id)?;
    if draft.generation == 0 || draft.generation > MAX_CANONICAL_JSON_INTEGER {
        return invalid_record(
            "reorganization generation must be a positive canonical JSON integer",
        );
    }
    validate_digest(&draft.analysis_scope.manifest_sha256)?;
    validate_scope(draft.path_profile, &draft.analysis_scope)?;
    if draft.questions.len() > MAX_REORGANIZATION_QUESTIONS {
        return invalid_record("reorganization draft contains too many questions");
    }
    let mut question_ids = BTreeSet::new();
    for question in &draft.questions {
        validate_question(question)?;
        if !question_ids.insert(question.id.as_str()) {
            return invalid_record(format!("question id must be unique: {}", question.id));
        }
    }
    let mut template_references = BTreeSet::new();
    for reference in &draft.template_references {
        if reference.is_empty()
            || reference.chars().count() > 255
            || reference.chars().any(char::is_control)
            || !template_references.insert(reference)
        {
            return invalid_record(
                "template references must be bounded, unique provenance strings",
            );
        }
    }
    if draft.rationale.is_empty()
        || draft.rationale.chars().count() > MAX_REORGANIZATION_TEXT_CHARACTERS
    {
        return invalid_record("reorganization rationale must be non-empty and bounded");
    }
    if draft.operations.is_empty() || draft.operations.len() > MAX_REORGANIZATION_OPERATIONS {
        return invalid_record("reorganization operations must be non-empty and bounded");
    }
    for operation in &draft.operations {
        validate_operation(operation)?;
    }
    validate_operation_path_uniqueness(draft.path_profile, &draft.operations)?;
    validate_nested_boundary_confinement(
        draft.path_profile,
        &draft.analysis_scope,
        &draft.operations,
    )?;
    validate_operation_closure(draft.path_profile, &draft.analysis_scope, &draft.operations)?;
    Ok(())
}

fn normalize_draft(draft: &mut ReorganizationDraft) {
    normalize_scope(&mut draft.analysis_scope);
    draft.template_references.sort();
}

fn normalize_plan(plan: &mut ReorganizationPlan) {
    normalize_scope(&mut plan.analysis_scope);
    plan.template_references.sort();
}

fn normalize_scope(scope: &mut AnalysisScope) {
    scope
        .nested_boundaries
        .sort_by_key(|boundary| boundary.path.nfc().collect::<String>());
    scope
        .operation_closure
        .sort_by_key(|entry| entry.path().nfc().collect::<String>());
    scope
        .declared_entries
        .sort_by_key(|entry| entry.path().nfc().collect::<String>());
}

fn validate_scope(path_profile: PathProfile, scope: &AnalysisScope) -> Result<()> {
    if scope.nested_boundaries.len() > MAX_REORGANIZATION_SCOPE_ENTRIES {
        return invalid_record("reorganization analysis scope contains too many boundaries");
    }
    if scope.declared_entries.len() > MAX_REORGANIZATION_SCOPE_ENTRIES {
        return invalid_record("reorganization analysis scope contains too many entries");
    }
    if scope.operation_closure.len() > MAX_REORGANIZATION_SCOPE_ENTRIES {
        return invalid_record("reorganization operation closure contains too many entries");
    }
    if scope.ignore_policy.path() != ".folderbaseignore" {
        return invalid_record("ignore policy fact must describe .folderbaseignore");
    }
    if !matches!(
        scope.ignore_policy,
        ScopeEntry::Absent { .. } | ScopeEntry::File { .. }
    ) {
        return invalid_record("ignore policy snapshot must be an exact file or absence fact");
    }
    validate_scope_entry(&scope.ignore_policy)?;
    let mut boundary_paths: BTreeSet<String> = BTreeSet::new();
    for boundary in &scope.nested_boundaries {
        validate_path(&boundary.path)?;
        validate_digest(&boundary.manifest_sha256)?;
        let key = portable_path_key(path_profile, &boundary.path);
        if boundary_paths
            .iter()
            .any(|existing| path_is_at_or_below(&key, existing))
            || boundary_paths
                .iter()
                .any(|existing| path_is_at_or_below(existing, &key))
            || !boundary_paths.insert(key)
        {
            return invalid_record(
                "nested Folderbase boundaries must be unique and non-overlapping",
            );
        }
    }
    for entry in &scope.operation_closure {
        validate_scope_entry(entry)?;
    }
    for entry in &scope.declared_entries {
        validate_scope_entry(entry)?;
    }
    Ok(())
}

fn validate_scope_entry(entry: &ScopeEntry) -> Result<()> {
    validate_path(entry.path())?;
    match entry {
        ScopeEntry::File {
            sha256, byte_count, ..
        } => {
            validate_digest(sha256)?;
            validate_canonical_integer(*byte_count)
        }
        ScopeEntry::TrackedObject {
            object_id,
            version_id,
            ..
        } => {
            validate_object_id(object_id)?;
            validate_version_id(version_id)
        }
        ScopeEntry::Absent { .. } | ScopeEntry::Directory { .. } => Ok(()),
    }
}

fn validate_question(question: &ConsequentialQuestion) -> Result<()> {
    validate_token(&question.id, "question id")?;
    if question.prompt.is_empty()
        || question.prompt.chars().count() > MAX_REORGANIZATION_TEXT_CHARACTERS
    {
        return invalid_record("question prompt must be non-empty and bounded");
    }
    match question.answer_type {
        ConsequentialAnswerType::SingleChoice => {
            if question.options.is_empty() {
                return invalid_record("single-choice questions require options");
            }
            let unique = question.options.iter().collect::<BTreeSet<_>>();
            if unique.len() != question.options.len() {
                return invalid_record("single-choice options must be unique");
            }
            for option in &question.options {
                validate_token(option, "single-choice option")?;
            }
        }
        ConsequentialAnswerType::Text | ConsequentialAnswerType::Boolean => {
            if !question.options.is_empty() {
                return invalid_record("only single-choice questions may declare options");
            }
        }
    }
    if let Some(answer) = &question.answer {
        match (question.answer_type, answer) {
            (ConsequentialAnswerType::Text, ConsequentialAnswer::Text(value)) => {
                if value.is_empty() || value.chars().count() > MAX_REORGANIZATION_TEXT_CHARACTERS {
                    return invalid_record("text answers must be non-empty and bounded");
                }
            }
            (ConsequentialAnswerType::Boolean, ConsequentialAnswer::Boolean(_)) => {}
            (ConsequentialAnswerType::SingleChoice, ConsequentialAnswer::SingleChoice(value))
                if question.options.contains(value) => {}
            _ => return invalid_record("question answer does not match its declared type"),
        }
    }
    Ok(())
}

fn validate_operation(operation: &ReorganizationOperation) -> Result<()> {
    match operation {
        ReorganizationOperation::CreateDirectory { path } => validate_ordinary_content_path(path),
        ReorganizationOperation::CreateUtf8File { path, content } => {
            validate_ordinary_content_path(path)?;
            validate_bounded_text(content)
        }
        ReorganizationOperation::ReplaceUtf8File {
            path,
            expected_sha256,
            content,
        } => {
            validate_ordinary_content_path(path)?;
            validate_digest(expected_sha256)?;
            validate_bounded_text(content)
        }
        ReorganizationOperation::UpdateManagedAgentBlock {
            path,
            adapter,
            expected_sha256,
            content,
        } => {
            validate_agent_adapter_path(path, adapter)?;
            validate_digest(expected_sha256)?;
            validate_bounded_text(content)
        }
        ReorganizationOperation::MoveFile {
            source_path,
            destination_path,
            expected_sha256,
            expected_byte_count,
        } => {
            validate_distinct_paths(source_path, destination_path)?;
            validate_ordinary_content_path(source_path)?;
            validate_ordinary_content_path(destination_path)?;
            validate_digest(expected_sha256)?;
            validate_canonical_integer(*expected_byte_count)
        }
        ReorganizationOperation::MoveTrackedObject {
            source_path,
            destination_path,
            object_id,
            expected_version_id,
        } => {
            validate_distinct_paths(source_path, destination_path)?;
            validate_ordinary_content_path(source_path)?;
            validate_ordinary_content_path(destination_path)?;
            validate_object_id(object_id)?;
            validate_version_id(expected_version_id)
        }
        ReorganizationOperation::MarkCanonical {
            object_record_path,
            object_id,
            expected_version_id,
            expected_record_sha256,
        } => {
            validate_object_id(object_id)?;
            validate_object_record_path(object_record_path, object_id)?;
            validate_version_id(expected_version_id)?;
            validate_digest(expected_record_sha256)
        }
        ReorganizationOperation::MarkSuperseded {
            object_record_path,
            object_id,
            expected_version_id,
            superseded_by,
            expected_record_sha256,
        } => {
            validate_object_id(object_id)?;
            validate_object_record_path(object_record_path, object_id)?;
            validate_version_id(expected_version_id)?;
            validate_digest(expected_record_sha256)?;
            validate_object_id(superseded_by)
        }
        ReorganizationOperation::ArchiveObject {
            object_record_path,
            object_id,
            expected_version_id,
            expected_record_sha256,
        } => {
            validate_object_id(object_id)?;
            validate_object_record_path(object_record_path, object_id)?;
            validate_version_id(expected_version_id)?;
            validate_digest(expected_record_sha256)
        }
        ReorganizationOperation::AddRelationship {
            object_record_path,
            object_id,
            expected_version_id,
            relationship_type,
            target_object_id,
            expected_record_sha256,
        } => {
            validate_object_id(object_id)?;
            validate_object_record_path(object_record_path, object_id)?;
            validate_version_id(expected_version_id)?;
            validate_relationship_type(relationship_type)?;
            validate_object_id(target_object_id)?;
            validate_digest(expected_record_sha256)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClosureRequirement {
    Absent,
    Directory,
    File {
        sha256: String,
        byte_count: Option<u64>,
    },
    TrackedObject {
        object_id: ObjectId,
        version_id: VersionId,
    },
}

fn validate_operation_closure(
    path_profile: PathProfile,
    scope: &AnalysisScope,
    operations: &[ReorganizationOperation],
) -> Result<()> {
    let created_directory_indices = operations
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| match operation {
            ReorganizationOperation::CreateDirectory { path } => {
                Some((portable_path_key(path_profile, path), index))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for operation in operations {
        for path in operation_preexisting_paths(operation) {
            for ancestor in path_ancestors(path) {
                let key = portable_path_key(path_profile, ancestor);
                if created_directory_indices.contains_key(&key) {
                    return invalid_record(format!(
                        "preexisting source cannot be below a planned-created directory: {path}"
                    ));
                }
            }
        }
    }
    for (operation_index, operation) in operations.iter().enumerate() {
        for path in operation_paths(operation) {
            for ancestor in path_ancestors(path) {
                let key = portable_path_key(path_profile, ancestor);
                if created_directory_indices
                    .get(&key)
                    .is_some_and(|created_index| *created_index >= operation_index)
                {
                    return invalid_record(format!(
                        "created parent directory must precede its child operation: {ancestor}"
                    ));
                }
            }
        }
    }
    let created_directories = created_directory_indices
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut expected = BTreeMap::new();
    for operation in operations {
        match operation {
            ReorganizationOperation::CreateDirectory { path }
            | ReorganizationOperation::CreateUtf8File { path, .. } => {
                insert_closure_requirement(
                    path_profile,
                    &mut expected,
                    path,
                    ClosureRequirement::Absent,
                )?;
            }
            ReorganizationOperation::ReplaceUtf8File {
                path,
                expected_sha256,
                ..
            }
            | ReorganizationOperation::UpdateManagedAgentBlock {
                path,
                expected_sha256,
                ..
            } => {
                insert_closure_requirement(
                    path_profile,
                    &mut expected,
                    path,
                    ClosureRequirement::File {
                        sha256: expected_sha256.clone(),
                        byte_count: None,
                    },
                )?;
            }
            ReorganizationOperation::MoveFile {
                source_path,
                destination_path,
                expected_sha256,
                expected_byte_count,
            } => {
                insert_closure_requirement(
                    path_profile,
                    &mut expected,
                    source_path,
                    ClosureRequirement::File {
                        sha256: expected_sha256.clone(),
                        byte_count: Some(*expected_byte_count),
                    },
                )?;
                insert_closure_requirement(
                    path_profile,
                    &mut expected,
                    destination_path,
                    ClosureRequirement::Absent,
                )?;
            }
            ReorganizationOperation::MoveTrackedObject {
                source_path,
                destination_path,
                object_id,
                expected_version_id,
            } => {
                insert_closure_requirement(
                    path_profile,
                    &mut expected,
                    source_path,
                    ClosureRequirement::TrackedObject {
                        object_id: object_id.clone(),
                        version_id: expected_version_id.clone(),
                    },
                )?;
                insert_closure_requirement(
                    path_profile,
                    &mut expected,
                    destination_path,
                    ClosureRequirement::Absent,
                )?;
            }
            ReorganizationOperation::MarkCanonical {
                object_record_path,
                expected_record_sha256,
                ..
            }
            | ReorganizationOperation::MarkSuperseded {
                object_record_path,
                expected_record_sha256,
                ..
            }
            | ReorganizationOperation::ArchiveObject {
                object_record_path,
                expected_record_sha256,
                ..
            }
            | ReorganizationOperation::AddRelationship {
                object_record_path,
                expected_record_sha256,
                ..
            } => {
                insert_closure_requirement(
                    path_profile,
                    &mut expected,
                    object_record_path,
                    ClosureRequirement::File {
                        sha256: expected_record_sha256.clone(),
                        byte_count: None,
                    },
                )?;
            }
        }
        for path in operation_paths(operation) {
            for ancestor in path_ancestors(path) {
                let key = portable_path_key(path_profile, ancestor);
                let requirement = if created_directories.contains(&key) {
                    ClosureRequirement::Absent
                } else {
                    ClosureRequirement::Directory
                };
                insert_closure_requirement(path_profile, &mut expected, ancestor, requirement)?;
            }
        }
    }

    let mut actual = BTreeMap::new();
    for entry in &scope.operation_closure {
        let key = portable_path_key(path_profile, entry.path());
        if actual.insert(key, entry).is_some() {
            return invalid_record(format!(
                "operation closure contains an aliasing path: {}",
                entry.path()
            ));
        }
    }
    if actual.len() != expected.len() {
        return invalid_record(format!(
            "operation closure must contain exactly {} derived path facts, found {}",
            expected.len(),
            actual.len()
        ));
    }
    for (path, requirement) in &expected {
        let Some(entry) = actual.get(path) else {
            return invalid_record(format!(
                "operation closure is missing a derived path fact: {path}"
            ));
        };
        if !closure_entry_matches(entry, requirement) {
            return invalid_record(format!(
                "operation closure fact does not match the derived precondition: {path}"
            ));
        }
    }

    let reserved = expected
        .keys()
        .cloned()
        .chain([
            portable_path_key(path_profile, ".folderbaseignore"),
            portable_path_key(path_profile, ".folderbase/manifest.json"),
        ])
        .collect::<BTreeSet<_>>();
    let mut declared = BTreeSet::new();
    for entry in &scope.declared_entries {
        let key = portable_path_key(path_profile, entry.path());
        if reserved.contains(&key) || !declared.insert(key) {
            return invalid_record(format!(
                "declared analysis entry is not an additional unique path: {}",
                entry.path()
            ));
        }
    }
    Ok(())
}

fn insert_closure_requirement(
    path_profile: PathProfile,
    requirements: &mut BTreeMap<String, ClosureRequirement>,
    path: &str,
    requirement: ClosureRequirement,
) -> Result<()> {
    let key = portable_path_key(path_profile, path);
    if let Some(existing) = requirements.get(&key) {
        if existing != &requirement {
            return invalid_record(format!(
                "operations require incompatible preconditions for {path}"
            ));
        }
        return Ok(());
    }
    requirements.insert(key, requirement);
    Ok(())
}

fn path_ancestors(path: &str) -> Vec<&str> {
    path.match_indices('/')
        .map(|(index, _)| &path[..index])
        .collect()
}

fn closure_entry_matches(entry: &ScopeEntry, requirement: &ClosureRequirement) -> bool {
    match (entry, requirement) {
        (ScopeEntry::Absent { .. }, ClosureRequirement::Absent)
        | (ScopeEntry::Directory { .. }, ClosureRequirement::Directory) => true,
        (
            ScopeEntry::File {
                sha256, byte_count, ..
            },
            ClosureRequirement::File {
                sha256: expected_sha256,
                byte_count: expected_byte_count,
            },
        ) => {
            sha256 == expected_sha256
                && expected_byte_count.is_none_or(|expected| expected == *byte_count)
        }
        (
            ScopeEntry::TrackedObject {
                object_id,
                version_id,
                ..
            },
            ClosureRequirement::TrackedObject {
                object_id: expected_object_id,
                version_id: expected_version_id,
            },
        ) => object_id == expected_object_id && version_id == expected_version_id,
        _ => false,
    }
}

fn validate_operation_path_uniqueness(
    path_profile: PathProfile,
    operations: &[ReorganizationOperation],
) -> Result<()> {
    let mut paths = BTreeMap::new();
    for operation in operations {
        for path in operation_paths(operation) {
            let key = portable_path_key(path_profile, path);
            if let Some(existing) = paths.insert(key, path) {
                return invalid_record(format!(
                    "operation path {path} aliases another operation path {existing}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_nested_boundary_confinement(
    path_profile: PathProfile,
    scope: &AnalysisScope,
    operations: &[ReorganizationOperation],
) -> Result<()> {
    let boundaries = scope
        .nested_boundaries
        .iter()
        .map(|boundary| portable_path_key(path_profile, &boundary.path))
        .collect::<Vec<_>>();

    for entry in scope
        .operation_closure
        .iter()
        .chain(&scope.declared_entries)
    {
        let path = portable_path_key(path_profile, entry.path());
        if boundaries
            .iter()
            .any(|boundary| path_is_at_or_below(&path, boundary))
        {
            return invalid_record(format!(
                "declared analysis path enters a nested Folderbase boundary: {}",
                entry.path()
            ));
        }
    }
    for operation in operations {
        for path in operation_paths(operation) {
            let key = portable_path_key(path_profile, path);
            if boundaries
                .iter()
                .any(|boundary| path_is_at_or_below(&key, boundary))
            {
                return invalid_record(format!(
                    "operation path enters a nested Folderbase boundary: {path}"
                ));
            }
        }
    }
    Ok(())
}

fn operation_paths(operation: &ReorganizationOperation) -> Vec<&str> {
    match operation {
        ReorganizationOperation::CreateDirectory { path }
        | ReorganizationOperation::CreateUtf8File { path, .. }
        | ReorganizationOperation::ReplaceUtf8File { path, .. }
        | ReorganizationOperation::UpdateManagedAgentBlock { path, .. } => vec![path],
        ReorganizationOperation::MoveFile {
            source_path,
            destination_path,
            ..
        }
        | ReorganizationOperation::MoveTrackedObject {
            source_path,
            destination_path,
            ..
        } => vec![source_path, destination_path],
        ReorganizationOperation::MarkCanonical {
            object_record_path, ..
        }
        | ReorganizationOperation::MarkSuperseded {
            object_record_path, ..
        }
        | ReorganizationOperation::ArchiveObject {
            object_record_path, ..
        }
        | ReorganizationOperation::AddRelationship {
            object_record_path, ..
        } => vec![object_record_path],
    }
}

fn operation_preexisting_paths(operation: &ReorganizationOperation) -> Vec<&str> {
    match operation {
        ReorganizationOperation::CreateDirectory { .. }
        | ReorganizationOperation::CreateUtf8File { .. } => Vec::new(),
        ReorganizationOperation::ReplaceUtf8File { path, .. }
        | ReorganizationOperation::UpdateManagedAgentBlock { path, .. } => vec![path],
        ReorganizationOperation::MoveFile { source_path, .. }
        | ReorganizationOperation::MoveTrackedObject { source_path, .. } => vec![source_path],
        ReorganizationOperation::MarkCanonical {
            object_record_path, ..
        }
        | ReorganizationOperation::MarkSuperseded {
            object_record_path, ..
        }
        | ReorganizationOperation::ArchiveObject {
            object_record_path, ..
        }
        | ReorganizationOperation::AddRelationship {
            object_record_path, ..
        } => vec![object_record_path],
    }
}

fn portable_path_key(profile: PathProfile, path: &str) -> String {
    let normalized = path.nfc().collect::<String>();
    match profile {
        PathProfile::CaseSensitive => normalized,
        PathProfile::CaseFold => normalized.case_fold().collect(),
    }
}

fn path_is_at_or_below(path: &str, boundary: &str) -> bool {
    path == boundary
        || path
            .strip_prefix(boundary)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn validate_canonical_integer(value: u64) -> Result<()> {
    if value > MAX_CANONICAL_JSON_INTEGER {
        return invalid_record(format!(
            "value exceeds the maximum canonical JSON integer {MAX_CANONICAL_JSON_INTEGER}"
        ));
    }
    Ok(())
}

fn deserialize_canonical_u64<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let number = serde_json::Number::deserialize(deserializer)?;
    exact_canonical_u64(&number.to_string()).map_err(D::Error::custom)
}

fn exact_canonical_u64(lexeme: &str) -> std::result::Result<u64, String> {
    let (negative, unsigned) = lexeme
        .strip_prefix('-')
        .map_or((false, lexeme), |unsigned| (true, unsigned));
    let exponent_index = unsigned.find(['e', 'E']);
    let (mantissa, exponent_text) = exponent_index.map_or((unsigned, None), |index| {
        (&unsigned[..index], Some(&unsigned[index + 1..]))
    });
    let (integer, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |(integer, fraction)| (integer, fraction));
    let mut digits = String::with_capacity(integer.len() + fraction.len());
    digits.push_str(integer);
    digits.push_str(fraction);
    if digits.bytes().all(|byte| byte == b'0') {
        return Ok(0);
    }
    if negative {
        return Err("expected a non-negative exact canonical JSON integer".to_owned());
    }

    let exponent = parse_bounded_decimal_exponent(exponent_text.unwrap_or("0"))?;
    let fraction_len =
        i64::try_from(fraction.len()).map_err(|_| "number lexeme is too large".to_owned())?;
    let scale = exponent
        .checked_sub(fraction_len)
        .ok_or_else(|| "number exponent is outside the supported range".to_owned())?;
    let significant = digits.trim_start_matches('0');
    let canonical_digits = if scale >= 0 {
        let zero_count =
            usize::try_from(scale).map_err(|_| "number exponent is too large".to_owned())?;
        if significant.len().saturating_add(zero_count) > 16 {
            return Err(format!(
                "canonical JSON integer exceeds {MAX_CANONICAL_JSON_INTEGER}"
            ));
        }
        let mut value = significant.to_owned();
        value.extend(std::iter::repeat_n('0', zero_count));
        value
    } else {
        let removed = usize::try_from(scale.unsigned_abs())
            .map_err(|_| "number exponent is too small".to_owned())?;
        if removed >= digits.len()
            || !digits[digits.len() - removed..]
                .bytes()
                .all(|byte| byte == b'0')
        {
            return Err("expected a non-negative exact canonical JSON integer".to_owned());
        }
        digits[..digits.len() - removed]
            .trim_start_matches('0')
            .to_owned()
    };
    let value = canonical_digits
        .parse::<u64>()
        .map_err(|_| format!("canonical JSON integer exceeds {MAX_CANONICAL_JSON_INTEGER}"))?;
    if value > MAX_CANONICAL_JSON_INTEGER {
        return Err(format!(
            "canonical JSON integer exceeds {MAX_CANONICAL_JSON_INTEGER}"
        ));
    }
    Ok(value)
}

fn parse_bounded_decimal_exponent(value: &str) -> std::result::Result<i64, String> {
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'+') => (false, &value[1..]),
        Some(b'-') => (true, &value[1..]),
        _ => (false, value),
    };
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Ok(0);
    }
    if significant.len() > 9 {
        return Err(if negative {
            "number exponent is too small".to_owned()
        } else {
            "number exponent is too large".to_owned()
        });
    }
    let magnitude = significant
        .parse::<i64>()
        .map_err(|_| "invalid number exponent".to_owned())?;
    Ok(if negative { -magnitude } else { magnitude })
}

fn validate_distinct_paths(source: &str, destination: &str) -> Result<()> {
    validate_path(source)?;
    validate_path(destination)?;
    if source == destination {
        return invalid_record("move source and destination must differ");
    }
    let normalized_source = source.nfc().collect::<String>();
    let normalized_destination = destination.nfc().collect::<String>();
    let folded_source = normalized_source.case_fold().collect::<String>();
    let folded_destination = normalized_destination.case_fold().collect::<String>();
    if folded_source == folded_destination {
        return invalid_record("reorganization-v1 refuses a case-only rename");
    }
    Ok(())
}

fn validate_bounded_text(value: &str) -> Result<()> {
    if value.chars().count() > MAX_REORGANIZATION_TEXT_CHARACTERS {
        return invalid_record("reorganization text content exceeds the 2M-character limit");
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid_record(
            "digest must be exactly 64 lowercase hexadecimal SHA-256 characters",
        );
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str, prefix: &str) -> Result<()> {
    if !value.starts_with(prefix) {
        return invalid_record(format!("{label} must begin with {prefix}"));
    }
    validate_token(value, label)
}

fn validate_folderbase_id(value: &str) -> Result<()> {
    if value
        .strip_prefix("folderbase_")
        .is_none_or(|uuid| uuid::Uuid::parse_str(uuid).is_err())
    {
        return invalid_record("folderbase identifier is invalid");
    }
    Ok(())
}

fn validate_object_id(value: &ObjectId) -> Result<()> {
    if ObjectId::parse(value.as_str().to_owned()).is_err() {
        return invalid_record("object identifier is invalid");
    }
    Ok(())
}

fn validate_version_id(value: &VersionId) -> Result<()> {
    if VersionId::parse(value.as_str().to_owned()).is_err() {
        return invalid_record("version identifier is invalid");
    }
    Ok(())
}

fn validate_relationship_type(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return invalid_record("relationship type must be a lowercase protocol token");
    }
    Ok(())
}

fn validate_ordinary_content_path(path: &str) -> Result<()> {
    validate_path(path)?;
    if Path::new(path)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name),
            _ => None,
        })
        .any(is_reserved_workspace_component)
        || (!path.contains('/')
            && [
                "FOLDERBASE.md",
                "AGENTS.md",
                "CLAUDE.md",
                ".folderbaseignore",
            ]
            .iter()
            .any(|reserved| path.eq_ignore_ascii_case(reserved)))
    {
        return invalid_record(format!(
            "ordinary operation path is reserved and requires an exact typed operation: {path}"
        ));
    }
    Ok(())
}

fn validate_agent_adapter_path(path: &str, adapter: &str) -> Result<()> {
    validate_path(path)?;
    let expected = match adapter {
        "codex" => "AGENTS.md",
        "claude" => "CLAUDE.md",
        _ => return invalid_record("unsupported managed agent adapter"),
    };
    if path != expected {
        return invalid_record(format!(
            "managed {adapter} adapter operation must target {expected}"
        ));
    }
    Ok(())
}

fn validate_object_record_path(path: &str, object_id: &ObjectId) -> Result<()> {
    validate_path(path)?;
    let expected = format!(".folderbase/objects/{object_id}.json");
    if path != expected {
        return invalid_record(format!(
            "object protocol operation must target the canonical object record path {expected}"
        ));
    }
    Ok(())
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return invalid_record(format!("{label} is not a portable token"));
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let has_drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if value.is_empty()
        || value.chars().count() > MAX_REORGANIZATION_PATH_CHARACTERS
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.contains("//")
        || has_drive_prefix
        || value.split('/').any(|part| matches!(part, "" | "." | ".."))
        || Path::new(value).is_absolute()
    {
        return invalid_record(format!("unsafe portable path: {value}"));
    }
    Ok(())
}

fn canonical_plan_digest(plan: &ReorganizationPlan) -> Result<String> {
    ensure_aggregate_record_bound(plan, "reorganization plan")?;
    let mut normalized = plan.clone();
    normalize_plan(&mut normalized);
    let mut value = serde_json::to_value(normalized)
        .map_err(|source| FolderbaseError::json("<reorganization-plan>", source))?;
    value
        .as_object_mut()
        .expect("a plan always serializes as an object")
        .remove("plan_digest");
    canonical_value_digest(PLAN_DIGEST_DOMAIN, &value)
}

fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    ensure_aggregate_record_bound(value, "reorganization digest input")?;
    let value = serde_json::to_value(value)
        .map_err(|source| FolderbaseError::json("<reorganization-digest>", source))?;
    canonical_value_digest(domain, &value)
}

fn ensure_aggregate_record_bound(value: &(impl Serialize + ?Sized), label: &str) -> Result<()> {
    let mut writer = BoundedJsonWriter { written: 0 };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return invalid_record(format!("{label} exceeds the 8 MiB encoded-record limit"));
    }
    Ok(())
}

struct BoundedJsonWriter {
    written: usize,
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.written.saturating_add(bytes.len()) > MAX_REORGANIZATION_RECORD_BYTES {
            return Err(std::io::Error::other(
                "reorganization encoded-record limit exceeded",
            ));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn canonical_value_digest(domain: &[u8], value: &Value) -> Result<String> {
    let mut canonical = Vec::new();
    write_canonical_json(value, &mut canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded = serde_json::to_string(value).map_err(|source| {
                FolderbaseError::json("<reorganization-canonical-json>", source)
            })?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let encoded = serde_json::to_string(key).map_err(|source| {
                    FolderbaseError::json("<reorganization-canonical-json>", source)
                })?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn invalid_record<T>(message: impl Into<String>) -> Result<T> {
    Err(FolderbaseError::InvalidRecord {
        path: "<reorganization>".into(),
        message: message.into(),
    })
}
