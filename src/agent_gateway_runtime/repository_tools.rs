//! Closed, bounded implementations for the built-in read-only repository tools.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{
    MAX_REPOSITORY_FILE_BYTES_V1, MAX_REPOSITORY_SCAN_BYTES_V1, RepositoryOperationV1,
    gateway_workspace_limits_v1, invalid_arguments_v1, path_text_v1, provider_io_v1,
};
use crate::mcp_gateway::{McpError, McpErrorCode, ProviderError, ProviderTool};
use crate::workspace_authority::{
    RepositoryNodeKindV1, RepositoryObservationPlanV1, WorkspaceExecutionEpochV1,
};

const MAX_RESULTS_V1: usize = 500;
const MAX_LINE_BYTES_V1: usize = 4 * 1024;
const MAX_OUTPUT_BYTES_V1: usize = 512 * 1024;
const MAX_PATTERN_BYTES_V1: usize = 4 * 1024;
const MAX_GLOB_BYTES_V1: usize = 512;
const MAX_TREE_DEPTH_V1: usize = 128;
const MAX_EXECUTION_TIME_V1: Duration = Duration::from_secs(5);
const MANIFEST_NAMES_V1: [&str; 6] = [
    "Cargo.toml",
    "go.mod",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "tsconfig.json",
];

pub(super) fn repository_tool_definitions_v1() -> Vec<ProviderTool> {
    vec![
        tool(
            "read",
            json!({
                "type": "object",
                "properties": { "path": bounded_path_schema() },
                "required": ["path"],
                "additionalProperties": false
            }),
        ),
        tool(
            "search",
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "minLength": 1, "maxLength": MAX_PATTERN_BYTES_V1 },
                    "path": bounded_path_schema(),
                    "maxResults": result_limit_schema()
                },
                "required": ["pattern"],
                "additionalProperties": false
            }),
        ),
        tool(
            "list",
            json!({
                "type": "object",
                "properties": { "path": bounded_path_schema(), "maxResults": result_limit_schema() },
                "additionalProperties": false
            }),
        ),
        tool(
            "tree",
            json!({
                "type": "object",
                "properties": {
                    "path": bounded_path_schema(),
                    "maxDepth": { "type": "integer", "minimum": 0, "maximum": MAX_TREE_DEPTH_V1 },
                    "maxResults": result_limit_schema()
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "stat",
            json!({
                "type": "object",
                "properties": { "path": bounded_path_schema() },
                "required": ["path"],
                "additionalProperties": false
            }),
        ),
        tool(
            "glob",
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "minLength": 1, "maxLength": MAX_GLOB_BYTES_V1 },
                    "path": bounded_path_schema(),
                    "maxResults": result_limit_schema()
                },
                "required": ["pattern"],
                "additionalProperties": false
            }),
        ),
        tool(
            "references",
            json!({
                "type": "object",
                "properties": {
                    "symbol": { "type": "string", "minLength": 1, "maxLength": 256 },
                    "path": bounded_path_schema(),
                    "maxResults": result_limit_schema()
                },
                "required": ["symbol"],
                "additionalProperties": false
            }),
        ),
        tool(
            "manifest",
            json!({
                "type": "object",
                "properties": { "path": bounded_path_schema() },
                "additionalProperties": false
            }),
        ),
    ]
}

fn tool(name: &str, schema: Value) -> ProviderTool {
    let mut tool = ProviderTool::new(name, schema);
    tool.description = Some(format!(
        "Bounded, deterministic, read-only repository {name} operation"
    ));
    tool
}

fn bounded_path_schema() -> Value {
    json!({ "type": "string", "minLength": 1, "maxLength": 4096, "default": "." })
}

fn result_limit_schema() -> Value {
    json!({ "type": "integer", "minimum": 1, "maximum": MAX_RESULTS_V1, "default": 200 })
}

pub(super) fn observation_plan_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
    operation: RepositoryOperationV1,
) -> Result<RepositoryObservationPlanV1> {
    if operation == RepositoryOperationV1::Manifest {
        let base = argument_path_v1(arguments, true)?;
        require_directory_v1(epoch, &base)?;
        let mut content = Vec::new();
        let mut negative = Vec::new();
        for name in MANIFEST_NAMES_V1 {
            let candidate = base.join(name);
            match epoch
                .classify_relative(&candidate)
                .map_err(|_| anyhow!("manifest path classification is incomplete"))?
            {
                RepositoryNodeKindV1::Regular => content.push(candidate),
                RepositoryNodeKindV1::Missing => negative.push(candidate),
                RepositoryNodeKindV1::Directory => {
                    bail!("manifest candidate is not a regular file")
                }
            }
        }
        return Ok(RepositoryObservationPlanV1::new(
            content,
            Vec::new(),
            Vec::new(),
            negative,
        ));
    }

    let default_dot = !matches!(
        operation,
        RepositoryOperationV1::Read | RepositoryOperationV1::Stat
    );
    let relative = argument_path_v1(arguments, default_dot)?;
    let kind = epoch
        .classify_relative(&relative)
        .map_err(|_| anyhow!("repository path classification is incomplete"))?;
    match (operation, kind) {
        (RepositoryOperationV1::Read, RepositoryNodeKindV1::Regular)
        | (RepositoryOperationV1::Stat, RepositoryNodeKindV1::Regular) => Ok(
            RepositoryObservationPlanV1::new(vec![relative], vec![], vec![], vec![]),
        ),
        (RepositoryOperationV1::Stat, RepositoryNodeKindV1::Directory)
        | (RepositoryOperationV1::List, RepositoryNodeKindV1::Directory) => Ok(
            RepositoryObservationPlanV1::new(vec![], vec![], vec![relative], vec![]),
        ),
        (
            RepositoryOperationV1::Search
            | RepositoryOperationV1::Tree
            | RepositoryOperationV1::Glob
            | RepositoryOperationV1::References,
            RepositoryNodeKindV1::Directory,
        ) => Ok(
            RepositoryObservationPlanV1::new(vec![], vec![], vec![], vec![])
                .with_source_trees(vec![relative]),
        ),
        (
            RepositoryOperationV1::Search
            | RepositoryOperationV1::Glob
            | RepositoryOperationV1::References,
            RepositoryNodeKindV1::Regular,
        ) => Ok(RepositoryObservationPlanV1::new(
            vec![relative],
            vec![],
            vec![],
            vec![],
        )),
        (_, RepositoryNodeKindV1::Missing) => Ok(RepositoryObservationPlanV1::new(
            vec![],
            vec![],
            vec![],
            vec![relative],
        )),
        _ => bail!("repository path kind is not admitted for this operation"),
    }
}

pub(super) fn execute_repository_tool_v1(
    epoch: &WorkspaceExecutionEpochV1,
    tool_name: &str,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    match tool_name {
        "read" => repository_read_v1(epoch, arguments),
        "search" => repository_search_v1(epoch, arguments),
        "list" => repository_list_v1(epoch, arguments),
        "tree" => repository_tree_v1(epoch, arguments),
        "stat" => repository_stat_v1(epoch, arguments),
        "glob" => repository_glob_v1(epoch, arguments),
        "references" => repository_references_v1(epoch, arguments),
        "manifest" => repository_manifest_v1(epoch, arguments),
        _ => Err(ProviderError(McpError::typed(
            McpErrorCode::MethodNotFound,
            "unknown repository tool",
        ))),
    }
}

fn repository_read_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let relative = argument_path_v1(arguments, false).map_err(invalid_arguments_v1)?;
    require_regular_v1(epoch, &relative).map_err(invalid_arguments_v1)?;
    let bytes = read_file_v1(epoch, &relative)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| invalid_arguments_v1(anyhow!("repository file is not UTF-8")))?;
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "schemaVersion": 1, "path": path_text_v1(&relative), "bytes": text.len() }
    }))
}

fn repository_search_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let pattern = bounded_string_v1(object, "pattern", MAX_PATTERN_BYTES_V1)?;
    let relative = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    let maximum = max_results_v1(object)?;
    let deadline = Instant::now() + MAX_EXECUTION_TIME_V1;
    let files = source_files_v1(epoch, &relative)?;
    let mut matches = Vec::new();
    let mut rendered_bytes = 0_usize;
    let mut truncated = false;
    'files: for file in files {
        ensure_deadline_v1(deadline)?;
        let bytes = read_file_v1(epoch, file.relative_path())?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for (line_index, line) in text.lines().enumerate() {
            if line.contains(pattern) {
                let snippet = bounded_utf8_prefix_v1(line, MAX_LINE_BYTES_V1);
                let path = path_text_v1(file.relative_path());
                charge_output_v1(&mut rendered_bytes, path.len() + snippet.len() + 48)?;
                matches.push(json!({
                    "path": path,
                    "line": line_index + 1,
                    "text": snippet,
                    "lineTruncated": snippet.len() != line.len()
                }));
                if matches.len() == maximum {
                    truncated = true;
                    break 'files;
                }
            }
        }
    }
    let rendered = matches
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}",
                entry["path"].as_str().unwrap_or_default(),
                entry["line"],
                entry["text"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "pattern": pattern, "path": path_text_v1(&relative), "matches": matches, "truncated": truncated }),
    ))
}

fn repository_list_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let relative = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    require_directory_v1(epoch, &relative).map_err(invalid_arguments_v1)?;
    let maximum = max_results_v1(object)?;
    let entries = epoch
        .list_source_directory(&relative, &gateway_workspace_limits_v1())
        .map_err(|_| provider_io_v1("descriptor-bound directory listing failed"))?;
    let truncated = entries.len() > maximum;
    let entries = entries
        .into_iter()
        .take(maximum)
        .map(|entry| {
            json!({
                "path": path_text_v1(entry.relative_path()),
                "kind": node_kind_text_v1(entry.kind()),
                "bytes": entry.bytes()
            })
        })
        .collect::<Vec<_>>();
    let rendered = entries
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}",
                entry["kind"].as_str().unwrap_or_default(),
                entry["path"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ensure_value_bound_v1(&rendered)?;
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "path": path_text_v1(&relative), "entries": entries, "truncated": truncated }),
    ))
}

fn repository_tree_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let relative = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    require_directory_v1(epoch, &relative).map_err(invalid_arguments_v1)?;
    let maximum = max_results_v1(object)?;
    let maximum_depth = object.get("maxDepth").and_then(Value::as_u64).unwrap_or(32);
    let maximum_depth = usize::try_from(maximum_depth)
        .ok()
        .filter(|depth| *depth <= MAX_TREE_DEPTH_V1)
        .ok_or_else(|| invalid_arguments_v1("maxDepth is outside the admitted range"))?;
    let deadline = Instant::now() + MAX_EXECUTION_TIME_V1;
    let mut entries = Vec::new();
    let mut truncated = false;
    collect_tree_v1(
        epoch,
        &relative,
        0,
        maximum_depth,
        maximum,
        deadline,
        &mut entries,
        &mut truncated,
    )?;
    let rendered = entries
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}",
                entry["kind"].as_str().unwrap_or_default(),
                entry["path"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ensure_value_bound_v1(&rendered)?;
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "path": path_text_v1(&relative), "entries": entries, "truncated": truncated }),
    ))
}

#[allow(clippy::too_many_arguments)]
fn collect_tree_v1(
    epoch: &WorkspaceExecutionEpochV1,
    directory: &Path,
    depth: usize,
    maximum_depth: usize,
    maximum_results: usize,
    deadline: Instant,
    output: &mut Vec<Value>,
    truncated: &mut bool,
) -> Result<(), ProviderError> {
    ensure_deadline_v1(deadline)?;
    if depth > maximum_depth || *truncated {
        return Ok(());
    }
    let entries = epoch
        .list_source_directory(directory, &gateway_workspace_limits_v1())
        .map_err(|_| provider_io_v1("descriptor-bound tree traversal failed"))?;
    for entry in entries {
        if output.len() == maximum_results {
            *truncated = true;
            return Ok(());
        }
        output.push(json!({
            "path": path_text_v1(entry.relative_path()),
            "kind": node_kind_text_v1(entry.kind()),
            "bytes": entry.bytes(),
            "depth": depth + 1
        }));
        if entry.kind() == RepositoryNodeKindV1::Directory && depth < maximum_depth {
            collect_tree_v1(
                epoch,
                entry.relative_path(),
                depth + 1,
                maximum_depth,
                maximum_results,
                deadline,
                output,
                truncated,
            )?;
        }
    }
    Ok(())
}

fn repository_stat_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let relative = argument_path_v1(arguments, false).map_err(invalid_arguments_v1)?;
    let kind = epoch
        .classify_relative(&relative)
        .map_err(|_| provider_io_v1("descriptor-bound stat failed"))?;
    let structured = match kind {
        RepositoryNodeKindV1::Missing => json!({
            "schemaVersion": 1, "path": path_text_v1(&relative), "kind": "missing", "exists": false
        }),
        RepositoryNodeKindV1::Regular => {
            let bytes = read_file_v1(epoch, &relative)?;
            json!({
                "schemaVersion": 1,
                "path": path_text_v1(&relative),
                "kind": "file",
                "exists": true,
                "bytes": bytes.len(),
                "digest": blake3::hash(&bytes).to_hex().to_string()
            })
        }
        RepositoryNodeKindV1::Directory => {
            let entries = epoch
                .list_source_directory(&relative, &gateway_workspace_limits_v1())
                .map_err(|_| provider_io_v1("descriptor-bound stat listing failed"))?;
            json!({
                "schemaVersion": 1,
                "path": path_text_v1(&relative),
                "kind": "directory",
                "exists": true,
                "entries": entries.len()
            })
        }
    };
    Ok(tool_result_v1(
        serde_json::to_string(&structured).expect("JSON value"),
        structured,
    ))
}

fn repository_glob_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let pattern = bounded_string_v1(object, "pattern", MAX_GLOB_BYTES_V1)?;
    validate_glob_v1(pattern).map_err(invalid_arguments_v1)?;
    let base = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    let maximum = max_results_v1(object)?;
    let files = source_files_v1(epoch, &base)?;
    let mut paths = Vec::new();
    let mut truncated = false;
    for file in files {
        let candidate = file
            .relative_path()
            .strip_prefix(&base)
            .unwrap_or(file.relative_path());
        let candidate = path_text_v1(candidate);
        if glob_matches_v1(pattern, &candidate) {
            paths.push(path_text_v1(file.relative_path()));
            if paths.len() == maximum {
                truncated = true;
                break;
            }
        }
    }
    let rendered = paths.join("\n");
    ensure_value_bound_v1(&rendered)?;
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "pattern": pattern, "path": path_text_v1(&base), "paths": paths, "truncated": truncated }),
    ))
}

fn repository_references_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let symbol = bounded_string_v1(object, "symbol", 256)?;
    if !symbol.bytes().all(is_identifier_byte_v1) {
        return Err(invalid_arguments_v1("symbol must be an identifier"));
    }
    let base = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    let maximum = max_results_v1(object)?;
    let deadline = Instant::now() + MAX_EXECUTION_TIME_V1;
    let files = source_files_v1(epoch, &base)?;
    let mut references = Vec::new();
    let mut rendered_bytes = 0_usize;
    let mut truncated = false;
    'files: for file in files {
        ensure_deadline_v1(deadline)?;
        let bytes = read_file_v1(epoch, file.relative_path())?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for (line_index, line) in text.lines().enumerate() {
            for (column, _) in line.match_indices(symbol) {
                let before = column
                    .checked_sub(1)
                    .and_then(|index| line.as_bytes().get(index));
                let after = line.as_bytes().get(column + symbol.len());
                if before.is_some_and(|byte| is_identifier_byte_v1(*byte))
                    || after.is_some_and(|byte| is_identifier_byte_v1(*byte))
                {
                    continue;
                }
                let snippet = bounded_utf8_prefix_v1(line, MAX_LINE_BYTES_V1);
                let path = path_text_v1(file.relative_path());
                charge_output_v1(&mut rendered_bytes, path.len() + snippet.len() + 64)?;
                references.push(json!({
                    "path": path,
                    "line": line_index + 1,
                    "column": column + 1,
                    "endColumn": column + symbol.len() + 1,
                    "text": snippet,
                    "lineTruncated": snippet.len() != line.len()
                }));
                if references.len() == maximum {
                    truncated = true;
                    break 'files;
                }
            }
        }
    }
    let rendered = references
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}:{}",
                entry["path"].as_str().unwrap_or_default(),
                entry["line"],
                entry["column"],
                entry["text"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "symbol": symbol, "path": path_text_v1(&base), "references": references, "truncated": truncated }),
    ))
}

fn repository_manifest_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let base = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    require_directory_v1(epoch, &base).map_err(invalid_arguments_v1)?;
    let mut manifests = Vec::new();
    let mut total_bytes = 0_u64;
    for name in MANIFEST_NAMES_V1 {
        let relative = base.join(name);
        match epoch
            .classify_relative(&relative)
            .map_err(|_| provider_io_v1("descriptor-bound manifest classification failed"))?
        {
            RepositoryNodeKindV1::Missing => {}
            RepositoryNodeKindV1::Regular => {
                let bytes = read_file_v1(epoch, &relative)?;
                total_bytes = total_bytes.saturating_add(bytes.len() as u64);
                if total_bytes > MAX_REPOSITORY_SCAN_BYTES_V1 {
                    return Err(limit_error_v1("manifest byte bound exceeded"));
                }
                let text = String::from_utf8(bytes)
                    .map_err(|_| invalid_arguments_v1("manifest is not UTF-8"))?;
                manifests.push(json!({
                    "path": path_text_v1(&relative),
                    "bytes": text.len(),
                    "digest": blake3::hash(text.as_bytes()).to_hex().to_string(),
                    "content": text
                }));
            }
            RepositoryNodeKindV1::Directory => {
                return Err(invalid_arguments_v1("manifest candidate is a directory"));
            }
        }
    }
    let rendered = manifests
        .iter()
        .map(|manifest| {
            format!(
                "{}\t{}",
                manifest["digest"].as_str().unwrap_or_default(),
                manifest["path"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "path": path_text_v1(&base), "manifests": manifests }),
    ))
}

fn source_files_v1(
    epoch: &WorkspaceExecutionEpochV1,
    relative: &Path,
) -> Result<Vec<crate::workspace_authority::RepositoryRegularFileV1>, ProviderError> {
    let files = match epoch
        .classify_relative(relative)
        .map_err(|_| provider_io_v1("descriptor-bound source classification failed"))?
    {
        RepositoryNodeKindV1::Regular => {
            let parent = relative.parent().unwrap_or(Path::new(""));
            let mut files = epoch
                .list_source_files(parent, &gateway_workspace_limits_v1())
                .map_err(|_| provider_io_v1("descriptor-bound source traversal failed"))?;
            files.retain(|file| file.relative_path() == relative);
            files
        }
        RepositoryNodeKindV1::Directory => {
            let mut files = epoch
                .list_source_files(relative, &gateway_workspace_limits_v1())
                .map_err(|_| provider_io_v1("descriptor-bound source traversal failed"))?;
            files.sort_by(|left, right| left.relative_path().cmp(right.relative_path()));
            files
        }
        RepositoryNodeKindV1::Missing => Vec::new(),
    };
    let mut total = 0_u64;
    for file in &files {
        if file.bytes() > MAX_REPOSITORY_FILE_BYTES_V1 {
            return Err(limit_error_v1("repository file byte bound exceeded"));
        }
        total = total
            .checked_add(file.bytes())
            .ok_or_else(|| limit_error_v1("repository scan byte bound exceeded"))?;
        if total > MAX_REPOSITORY_SCAN_BYTES_V1 {
            return Err(limit_error_v1("repository scan byte bound exceeded"));
        }
    }
    Ok(files)
}

fn read_file_v1(
    epoch: &WorkspaceExecutionEpochV1,
    relative: &Path,
) -> Result<Vec<u8>, ProviderError> {
    epoch
        .read_repository_file(relative, MAX_REPOSITORY_FILE_BYTES_V1)
        .map_err(|_| provider_io_v1("descriptor-bound repository read failed"))
}

fn require_regular_v1(epoch: &WorkspaceExecutionEpochV1, path: &Path) -> Result<()> {
    if epoch
        .classify_relative(path)
        .map_err(|_| anyhow!("repository classification failed"))?
        == RepositoryNodeKindV1::Regular
    {
        Ok(())
    } else {
        bail!("path is not a regular file")
    }
}

fn require_directory_v1(epoch: &WorkspaceExecutionEpochV1, path: &Path) -> Result<()> {
    if epoch
        .classify_relative(path)
        .map_err(|_| anyhow!("repository classification failed"))?
        == RepositoryNodeKindV1::Directory
    {
        Ok(())
    } else {
        bail!("path is not a directory")
    }
}

pub(super) fn argument_path_v1(arguments: &Value, default_dot: bool) -> Result<PathBuf> {
    let object = arguments
        .as_object()
        .ok_or_else(|| anyhow!("arguments must be an object"))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .or(default_dot.then_some("."))
        .ok_or_else(|| anyhow!("path is required"))?;
    if path.is_empty() || path.len() > 4096 || path.as_bytes().contains(&0) {
        bail!("path is invalid");
    }
    let path = PathBuf::from(path);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("path must be relative and traversal-free");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        if let Component::Normal(name) = component {
            if normalized.as_os_str().is_empty() && name == ".git" {
                bail!("Git control paths are not repository-source inputs");
            }
            normalized.push(name);
        }
    }
    Ok(normalized)
}

fn object_v1(arguments: &Value) -> Result<&serde_json::Map<String, Value>, ProviderError> {
    arguments
        .as_object()
        .ok_or_else(|| invalid_arguments_v1("arguments must be an object"))
}

fn bounded_string_v1<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
    maximum: usize,
) -> Result<&'a str, ProviderError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= maximum && !value.as_bytes().contains(&0)
        })
        .ok_or_else(|| invalid_arguments_v1("required string is missing or outside its bound"))
}

fn max_results_v1(object: &serde_json::Map<String, Value>) -> Result<usize, ProviderError> {
    let value = object
        .get("maxResults")
        .and_then(Value::as_u64)
        .unwrap_or(200);
    usize::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_RESULTS_V1).contains(value))
        .ok_or_else(|| invalid_arguments_v1("maxResults is outside the admitted range"))
}

fn node_kind_text_v1(kind: RepositoryNodeKindV1) -> &'static str {
    match kind {
        RepositoryNodeKindV1::Missing => "missing",
        RepositoryNodeKindV1::Directory => "directory",
        RepositoryNodeKindV1::Regular => "file",
    }
}

fn tool_result_v1(text: String, structured: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured
    })
}

fn bounded_utf8_prefix_v1(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn charge_output_v1(total: &mut usize, additional: usize) -> Result<(), ProviderError> {
    *total = total
        .checked_add(additional)
        .ok_or_else(|| limit_error_v1("repository output bound exceeded"))?;
    if *total > MAX_OUTPUT_BYTES_V1 {
        return Err(limit_error_v1("repository output bound exceeded"));
    }
    Ok(())
}

fn ensure_value_bound_v1(value: &str) -> Result<(), ProviderError> {
    if value.len() > MAX_OUTPUT_BYTES_V1 {
        Err(limit_error_v1("repository output bound exceeded"))
    } else {
        Ok(())
    }
}

fn ensure_deadline_v1(deadline: Instant) -> Result<(), ProviderError> {
    if Instant::now() > deadline {
        Err(limit_error_v1("repository execution deadline exceeded"))
    } else {
        Ok(())
    }
}

fn limit_error_v1(message: &'static str) -> ProviderError {
    ProviderError(McpError::typed(McpErrorCode::LimitExceeded, message))
}

fn is_identifier_byte_v1(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn validate_glob_v1(pattern: &str) -> Result<()> {
    if pattern.starts_with('/')
        || pattern.split('/').any(|segment| segment == "..")
        || pattern.as_bytes().contains(&0)
    {
        bail!("glob pattern escapes its repository base");
    }
    Ok(())
}

fn glob_matches_v1(pattern: &str, path: &str) -> bool {
    let pattern = pattern.split('/').collect::<Vec<_>>();
    let path = path.split('/').collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    glob_segments_match_v1(&pattern, &path, 0, 0, &mut visited)
}

fn glob_segments_match_v1(
    pattern: &[&str],
    path: &[&str],
    pattern_index: usize,
    path_index: usize,
    visited: &mut BTreeSet<(usize, usize)>,
) -> bool {
    if !visited.insert((pattern_index, path_index)) {
        return false;
    }
    if pattern_index == pattern.len() {
        return path_index == path.len();
    }
    if pattern[pattern_index] == "**" {
        return glob_segments_match_v1(pattern, path, pattern_index + 1, path_index, visited)
            || (path_index < path.len()
                && glob_segments_match_v1(pattern, path, pattern_index, path_index + 1, visited));
    }
    path_index < path.len()
        && glob_segment_match_v1(
            pattern[pattern_index].as_bytes(),
            path[path_index].as_bytes(),
        )
        && glob_segments_match_v1(pattern, path, pattern_index + 1, path_index + 1, visited)
}

fn glob_segment_match_v1(pattern: &[u8], value: &[u8]) -> bool {
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if *token == b'*' {
            current[0] = previous[0];
            for index in 1..=value.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                current[index] =
                    previous[index - 1] && (*token == b'?' || *token == value[index - 1]);
            }
        }
        previous = current;
    }
    previous[value.len()]
}

#[cfg(test)]
mod tests {
    use super::{glob_matches_v1, validate_glob_v1};

    #[test]
    fn bounded_glob_has_stable_segment_semantics() {
        assert!(glob_matches_v1("src/**/*.rs", "src/a/b.rs"));
        assert!(glob_matches_v1("*.toml", "Cargo.toml"));
        assert!(!glob_matches_v1("*.rs", "src/lib.rs"));
        assert!(validate_glob_v1("src/**").is_ok());
        assert!(validate_glob_v1("../secret").is_err());
    }
}
