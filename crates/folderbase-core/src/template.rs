use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use semver::Version;
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

use crate::{
    FolderbaseError, PlannedTemplateAddition, Result, TemplateAnswerType, TemplateAnswerValue,
    TemplateArtifactKind, TemplateDescriptor, TemplatePackage, TemplateRenderPlan,
};

const BUILTIN_TEMPLATES: [(&str, &str, &str); 8] = [
    (
        "folderbase.person",
        "0.2.0",
        include_str!("../assets/templates/0.2/person/template.json"),
    ),
    (
        "folderbase.organization",
        "0.2.0",
        include_str!("../assets/templates/0.2/organization/template.json"),
    ),
    (
        "folderbase.engagement",
        "0.2.0",
        include_str!("../assets/templates/0.2/engagement/template.json"),
    ),
    (
        "folderbase.project",
        "0.2.1",
        include_str!("../assets/templates/0.2/project-0.2.1/template.json"),
    ),
    (
        "folderbase.project",
        "0.2.2",
        include_str!("../assets/templates/0.2/project-0.2.2/template.json"),
    ),
    (
        "folderbase.customer",
        "0.2.0",
        include_str!("../assets/templates/0.2/customer/template.json"),
    ),
    (
        "folderbase.temporary",
        "0.2.0",
        include_str!("../assets/templates/0.2/temporary/template.json"),
    ),
    (
        "folderbase.custom",
        "0.2.0",
        include_str!("../assets/templates/0.2/custom/template.json"),
    ),
];

/// Load one exact built-in template from bytes embedded in the core binary.
///
/// Exact matching avoids fallback upgrades, and embedding keeps an installed
/// CLI independent of a source checkout or current working directory.
pub fn load_builtin_template(id: &str, version: &str) -> Result<TemplatePackage> {
    let path = PathBuf::from(format!("<built-in:{id}@{version}>"));
    let source = BUILTIN_TEMPLATES
        .iter()
        .find_map(|(candidate_id, candidate_version, source)| {
            (*candidate_id == id && *candidate_version == version).then_some(*source)
        })
        .ok_or_else(|| FolderbaseError::InvalidRecord {
            path: path.clone(),
            message: format!("unknown built-in template {id}@{version}"),
        })?;
    let package: TemplatePackage =
        serde_json::from_str(source).map_err(|source| FolderbaseError::json(&path, source))?;
    validate_runtime_package(&path, &package)?;
    if package.id != id || package.version != version {
        return Err(FolderbaseError::InvalidRecord {
            path,
            message: format!(
                "built-in template identity mismatch: requested {id}@{version}, embedded {}@{}",
                package.id, package.version
            ),
        });
    }
    Ok(package)
}

pub fn list_templates(registry_root: &Path) -> Result<Vec<TemplateDescriptor>> {
    if !registry_root.is_dir() {
        return Err(FolderbaseError::InvalidRoot(registry_root.to_path_buf()));
    }

    let package_paths = package_paths(registry_root)?;

    let mut templates = package_paths
        .into_iter()
        .map(|path| read_descriptor(&path))
        .collect::<Result<Vec<_>>>()?;
    templates.sort_by(|left, right| {
        (&left.id, &left.version, &left.name).cmp(&(&right.id, &right.version, &right.name))
    });
    Ok(templates)
}

pub fn load_template(registry_root: &Path, id: &str, version: &str) -> Result<TemplatePackage> {
    if !registry_root.is_dir() {
        return Err(FolderbaseError::InvalidRoot(registry_root.to_path_buf()));
    }

    let mut matches = package_paths(registry_root)?
        .into_iter()
        .map(|path| read_package(&path))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|package| package.id == id && package.version == version)
        .collect::<Vec<_>>();

    if matches.len() != 1 {
        return Err(FolderbaseError::InvalidRecord {
            path: registry_root.to_path_buf(),
            message: format!(
                "expected exactly one template {id}@{version}, found {}",
                matches.len()
            ),
        });
    }
    Ok(matches.remove(0))
}

pub fn render_template(
    package: &TemplatePackage,
    destination_root: &Path,
    answers: &BTreeMap<String, TemplateAnswerValue>,
) -> Result<TemplateRenderPlan> {
    validate_destination_root(destination_root)?;
    validate_runtime_package(destination_root, package)?;

    validate_answers(package, answers, destination_root)?;

    let mut additions = Vec::new();
    let mut existing_paths = Vec::new();
    for artifact in &package.artifacts {
        if inspect_destination(destination_root, &artifact.target)? == DestinationState::Existing {
            existing_paths.push(artifact.target.clone());
            continue;
        }
        let content = match artifact.kind {
            TemplateArtifactKind::Directory => None,
            TemplateArtifactKind::Text => Some(render_content(
                artifact.content.as_deref().unwrap_or_default(),
                package,
                answers,
                destination_root,
            )?),
        };
        additions.push(PlannedTemplateAddition {
            path: artifact.target.clone(),
            kind: artifact.kind,
            content,
        });
    }
    additions.sort_by(|left, right| left.path.cmp(&right.path));
    existing_paths.sort();

    Ok(TemplateRenderPlan {
        template_id: package.id.clone(),
        template_version: package.version.clone(),
        additions,
        existing_paths,
    })
}

/// Render every artifact for a destination whose presence and type have
/// already been inspected through a retained filesystem capability.
///
/// Unlike `render_template`, this helper performs no ambient destination
/// lookup. The capability-owning caller decides which rendered artifacts are
/// already present and may be preserved.
pub(crate) fn render_template_for_capability_destination(
    package: &TemplatePackage,
    destination_label: &Path,
    answers: &BTreeMap<String, TemplateAnswerValue>,
) -> Result<TemplateRenderPlan> {
    validate_runtime_package(destination_label, package)?;
    validate_answers(package, answers, destination_label)?;

    let mut additions = Vec::new();
    for artifact in &package.artifacts {
        let content = match artifact.kind {
            TemplateArtifactKind::Directory => None,
            TemplateArtifactKind::Text => Some(render_content(
                artifact.content.as_deref().unwrap_or_default(),
                package,
                answers,
                destination_label,
            )?),
        };
        additions.push(PlannedTemplateAddition {
            path: artifact.target.clone(),
            kind: artifact.kind,
            content,
        });
    }
    additions.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(TemplateRenderPlan {
        template_id: package.id.clone(),
        template_version: package.version.clone(),
        additions,
        existing_paths: Vec::new(),
    })
}

pub fn template_package_sha256(package: &TemplatePackage) -> Result<String> {
    let source = PathBuf::from("<template-package>");
    validate_runtime_package(&source, package)?;
    let value =
        serde_json::to_value(package).map_err(|error| FolderbaseError::json(&source, error))?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes);
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .expect("JSON string serialization is infallible")
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output);
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("JSON object key serialization is infallible")
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(value, output);
            }
            output.push(b'}');
        }
    }
}

fn read_descriptor(path: &Path) -> Result<TemplateDescriptor> {
    let package = read_package(path)?;
    Ok(TemplateDescriptor {
        id: package.id,
        version: package.version,
        name: package.name,
    })
}

fn package_paths(registry_root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(registry_root).follow_links(false) {
        let entry = entry.map_err(|error| {
            let path = error
                .path()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| registry_root.to_path_buf());
            if let Some(source) = error.into_io_error() {
                FolderbaseError::io(path, source)
            } else {
                FolderbaseError::InvalidRecord {
                    path,
                    message: "template registry traversal failed".to_owned(),
                }
            }
        })?;
        if entry.file_type().is_file() && entry.file_name() == "template.json" {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn validate_answers(
    package: &TemplatePackage,
    answers: &BTreeMap<String, TemplateAnswerValue>,
    error_path: &Path,
) -> Result<()> {
    let questions = package
        .questions
        .iter()
        .map(|question| (question.id.as_str(), question))
        .collect::<BTreeMap<_, _>>();
    let unknown = answers
        .keys()
        .find(|id| !questions.contains_key(id.as_str()));
    if let Some(id) = unknown {
        return invalid_template(error_path, format!("unknown template answer: {id}"));
    }
    for question in &package.questions {
        let Some(answer) = answers.get(&question.id) else {
            if question.required {
                return invalid_template(
                    error_path,
                    format!("missing required template answer: {}", question.id),
                );
            }
            continue;
        };
        let correct_type = matches!(
            (question.answer_type, answer),
            (TemplateAnswerType::Text, TemplateAnswerValue::Text(_))
                | (TemplateAnswerType::Boolean, TemplateAnswerValue::Boolean(_))
        );
        if !correct_type {
            return invalid_template(
                error_path,
                format!("wrong type for template answer: {}", question.id),
            );
        }
        if question.required
            && matches!(answer, TemplateAnswerValue::Text(value) if value.trim().is_empty())
        {
            return invalid_template(
                error_path,
                format!("blank required template answer: {}", question.id),
            );
        }
    }
    Ok(())
}

fn render_content(
    content: &str,
    package: &TemplatePackage,
    answers: &BTreeMap<String, TemplateAnswerValue>,
    error_path: &Path,
) -> Result<String> {
    let question_ids = package
        .questions
        .iter()
        .map(|question| question.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut rendered = String::with_capacity(content.len());
    for segment in parse_content(content, error_path)? {
        match segment {
            ContentSegment::Literal(literal) => rendered.push_str(literal),
            ContentSegment::Placeholder(id) => {
                if !question_ids.contains(id) {
                    return invalid_template(
                        error_path,
                        format!("unknown template placeholder: {id}"),
                    );
                }
                let Some(answer) = answers.get(id) else {
                    return invalid_template(
                        error_path,
                        format!("missing template answer for placeholder: {id}"),
                    );
                };
                match answer {
                    TemplateAnswerValue::Text(value) => rendered.push_str(value),
                    TemplateAnswerValue::Boolean(value) => {
                        rendered.push_str(if *value { "true" } else { "false" })
                    }
                }
            }
        }
    }
    Ok(rendered)
}

fn invalid_template<T>(path: &Path, message: impl Into<String>) -> Result<T> {
    Err(FolderbaseError::InvalidRecord {
        path: path.to_path_buf(),
        message: message.into(),
    })
}

fn read_package(path: &Path) -> Result<TemplatePackage> {
    let bytes = fs::read(path).map_err(|source| FolderbaseError::io(path, source))?;
    let package: TemplatePackage =
        serde_json::from_slice(&bytes).map_err(|source| FolderbaseError::json(path, source))?;
    validate_runtime_package(path, &package)?;
    Ok(package)
}

pub(crate) fn validate_runtime_package(path: &Path, package: &TemplatePackage) -> Result<()> {
    if unicode_normalization::UNICODE_VERSION != (17, 0, 0)
        || unicode_casefold::UNICODE_VERSION != (9, 0, 0)
    {
        return invalid_template(
            path,
            "template path policy requires Unicode NFC 17.0.0 and full-default case folding 9.0.0",
        );
    }
    if !supported_protocol_version(&package.protocol_version) {
        return invalid_template(
            path,
            format!(
                "unsupported template protocol {} (supported: valid SemVer 0.2.x)",
                package.protocol_version
            ),
        );
    }
    if !valid_package_id(&package.id) {
        return invalid_template(path, format!("invalid template package id: {}", package.id));
    }
    let package_version =
        Version::parse(&package.version).map_err(|_| FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: format!("invalid template package version: {}", package.version),
        })?;
    if package.name.trim().is_empty() {
        return invalid_template(path, "template name is empty");
    }
    validate_extensions(path, "template package", package.extensions.keys())?;
    let mut question_ids = BTreeSet::new();
    for question in &package.questions {
        validate_extensions(path, "template question", question.extensions.keys())?;
        if !valid_question_id(&question.id) {
            return invalid_template(
                path,
                format!("invalid template question id: {}", question.id),
            );
        }
        if !question_ids.insert(question.id.as_str()) {
            return invalid_template(
                path,
                format!("duplicate template question id: {}", question.id),
            );
        }
        if question.prompt.trim().is_empty() {
            return invalid_template(
                path,
                format!("template question prompt is empty: {}", question.id),
            );
        }
    }
    validate_upgrade_graph(path, package, &package_version)?;
    for edge in &package.upgrade_edges {
        validate_extensions(path, "template upgrade edge", edge.extensions.keys())?;
    }

    let mut targets = BTreeSet::new();
    for artifact in &package.artifacts {
        validate_extensions(path, "template artifact", artifact.extensions.keys())?;
        if !safe_artifact_target(&artifact.target) {
            return invalid_template(
                path,
                format!("unsafe artifact target: {}", artifact.target.display()),
            );
        }
        let target_text = artifact
            .target
            .to_str()
            .expect("safe_artifact_target accepted only UTF-8");
        let folded = target_text
            .nfc()
            .collect::<String>()
            .case_fold()
            .collect::<String>()
            .nfc()
            .collect::<String>();
        if !targets.insert(folded) {
            return invalid_template(
                path,
                format!("duplicate artifact target: {}", artifact.target.display()),
            );
        }
        if artifact.install != "create_if_missing" {
            return invalid_template(path, "unsupported artifact installation mode");
        }
        match (artifact.kind, artifact.content.as_ref()) {
            (TemplateArtifactKind::Text, None) => {
                return invalid_template(path, "text artifact is missing inline content");
            }
            (TemplateArtifactKind::Directory, Some(_)) => {
                return invalid_template(path, "directory artifact cannot contain text");
            }
            _ => {}
        }
        if let Some(content) = artifact.content.as_deref() {
            for segment in parse_content(content, path)? {
                if let ContentSegment::Placeholder(placeholder) = segment
                    && !question_ids.contains(placeholder)
                {
                    return invalid_template(
                        path,
                        format!("unknown template placeholder: {placeholder}"),
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_upgrade_graph(
    path: &Path,
    package: &TemplatePackage,
    package_version: &Version,
) -> Result<()> {
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    let mut parsed_edges = Vec::new();
    for edge in &package.upgrade_edges {
        let from = Version::parse(&edge.from).map_err(|_| FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: format!("invalid upgrade edge version: {}", edge.from),
        })?;
        let to = Version::parse(&edge.to).map_err(|_| FolderbaseError::InvalidRecord {
            path: path.to_path_buf(),
            message: format!("invalid upgrade edge version: {}", edge.to),
        })?;
        graph
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
        parsed_edges.push((edge, from, to));
    }
    if graph_has_cycle(&graph) {
        return invalid_template(path, "template upgrade graph contains a cycle");
    }
    for (edge, from, to) in parsed_edges {
        if from >= to {
            return invalid_template(
                path,
                format!(
                    "upgrade edge does not advance: {} -> {}",
                    edge.from, edge.to
                ),
            );
        }
        if to != *package_version {
            return invalid_template(
                path,
                format!(
                    "upgrade edge does not terminate at package version: {} -> {}",
                    edge.from, edge.to
                ),
            );
        }
    }
    Ok(())
}

fn graph_has_cycle(graph: &BTreeMap<String, Vec<String>>) -> bool {
    fn visit<'a>(
        node: &'a str,
        graph: &'a BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> bool {
        if visited.contains(node) {
            return false;
        }
        if !visiting.insert(node) {
            return true;
        }
        if graph.get(node).is_some_and(|neighbors| {
            neighbors
                .iter()
                .any(|neighbor| visit(neighbor, graph, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(node);
        visited.insert(node);
        false
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    graph
        .keys()
        .any(|node| visit(node, graph, &mut visiting, &mut visited))
}

fn validate_extensions<'a>(
    path: &Path,
    location: &str,
    keys: impl Iterator<Item = &'a String>,
) -> Result<()> {
    if let Some(key) = keys.into_iter().find(|key| !key.starts_with("x-")) {
        return invalid_template(path, format!("unknown {location} property: {key}"));
    }
    Ok(())
}

fn valid_question_id(id: &str) -> bool {
    let mut characters = id.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-')
        })
}

#[derive(Debug, PartialEq, Eq)]
enum ContentSegment<'a> {
    Literal(&'a str),
    Placeholder(&'a str),
}

fn parse_content<'a>(content: &'a str, error_path: &Path) -> Result<Vec<ContentSegment<'a>>> {
    let mut segments = Vec::new();
    let mut remaining = content;
    while let Some(start) = remaining.find("${") {
        if start > 0 {
            segments.push(ContentSegment::Literal(&remaining[..start]));
        }
        let after_open = &remaining[start + 2..];
        let Some(end) = after_open.find('}') else {
            return invalid_template(error_path, "unterminated template placeholder");
        };
        let id = &after_open[..end];
        if !valid_question_id(id) {
            return invalid_template(error_path, format!("invalid template placeholder: {id}"));
        }
        segments.push(ContentSegment::Placeholder(id));
        remaining = &after_open[end + 1..];
    }
    if !remaining.is_empty() {
        segments.push(ContentSegment::Literal(remaining));
    }
    Ok(segments)
}

fn safe_artifact_target(target: &Path) -> bool {
    use std::path::Component;

    let Some(text) = target.to_str() else {
        return false;
    };
    if text.is_empty()
        || text.len() > 4096
        || target.is_absolute()
        || text.contains('\\')
        || text.contains("//")
        || text.ends_with('/')
        || (text.as_bytes().get(1) == Some(&b':')
            && text.as_bytes().first().is_some_and(u8::is_ascii_alphabetic))
    {
        return false;
    }
    let components = target.components().collect::<Vec<_>>();
    if components.len() > 128 {
        return false;
    }
    components.into_iter().all(|component| {
        let Component::Normal(component) = component else {
            return false;
        };
        let Some(component) = component.to_str() else {
            return false;
        };
        if component.is_empty()
            || component.len() > 255
            || component.ends_with(['.', ' '])
            || component
                .chars()
                .any(|character| character <= '\u{1f}' || r#"<>:"|?*"#.contains(character))
        {
            return false;
        }
        let stem = component.split('.').next().unwrap_or(component);
        !matches!(
            stem.to_ascii_uppercase().as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
                | "COM¹"
                | "COM²"
                | "COM³"
                | "LPT¹"
                | "LPT²"
                | "LPT³"
        )
    })
}

fn supported_protocol_version(version: &str) -> bool {
    Version::parse(version).is_ok_and(|version| version.major == 0 && version.minor == 2)
}

fn valid_package_id(id: &str) -> bool {
    let mut characters = id.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
}

fn validate_destination_root(destination_root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(destination_root)
        .map_err(|source| FolderbaseError::io(destination_root, source))?;
    if metadata.file_type().is_symlink() {
        return invalid_template(destination_root, "destination root is a symlink");
    }
    if !metadata.is_dir() {
        return Err(FolderbaseError::InvalidRoot(destination_root.to_path_buf()));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationState {
    Absent,
    Existing,
}

fn inspect_destination(root: &Path, relative: &Path) -> Result<DestinationState> {
    let mut current = root.to_path_buf();
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return invalid_template(
                        &current,
                        format!(
                            "template destination contains a symlink: {}",
                            relative.display()
                        ),
                    );
                }
                if index + 1 < component_count && !metadata.is_dir() {
                    return invalid_template(
                        &current,
                        format!(
                            "template destination ancestor is not a directory: {}",
                            relative.display()
                        ),
                    );
                }
                if index + 1 == component_count {
                    return Ok(DestinationState::Existing);
                }
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {
                return Ok(DestinationState::Absent);
            }
            Err(source) => return Err(FolderbaseError::io(&current, source)),
        }
    }
    Ok(DestinationState::Absent)
}
