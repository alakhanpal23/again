//! Closed, bounded implementations for the built-in read-only repository tools.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
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
const MAX_GIT_STDERR_BYTES_V1: usize = 64 * 1024;
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

pub(super) fn git_tool_definitions_v1() -> Vec<ProviderTool> {
    vec![
        tool(
            "status",
            json!({
                "type": "object",
                "properties": { "path": bounded_path_schema(), "maxResults": result_limit_schema() },
                "additionalProperties": false
            }),
        ),
        tool(
            "diff",
            json!({
                "type": "object",
                "properties": {
                    "path": bounded_path_schema(),
                    "staged": { "type": "boolean", "default": false },
                    "revision": { "type": "string", "enum": ["HEAD"] },
                    "contextLines": { "type": "integer", "minimum": 0, "maximum": 20, "default": 3 }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "log",
            json!({
                "type": "object",
                "properties": {
                    "path": bounded_path_schema(),
                    "revision": { "type": "string", "enum": ["HEAD"], "default": "HEAD" },
                    "maxResults": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "show",
            json!({
                "type": "object",
                "properties": {
                    "path": bounded_path_schema(),
                    "revision": { "type": "string", "enum": ["HEAD"], "default": "HEAD" }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "blame",
            json!({
                "type": "object",
                "properties": {
                    "path": bounded_path_schema(),
                    "revision": { "type": "string", "enum": ["HEAD", "WORKTREE"], "default": "WORKTREE" },
                    "startLine": { "type": "integer", "minimum": 1, "maximum": 10000000 },
                    "endLine": { "type": "integer", "minimum": 1, "maximum": 10000000 }
                },
                "required": ["path"],
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
    if matches!(
        operation,
        RepositoryOperationV1::GitLog | RepositoryOperationV1::GitShow
    ) {
        if let Some(path) = arguments
            .as_object()
            .and_then(|object| object.get("path"))
            .and_then(Value::as_str)
        {
            let _ = argument_path_v1(&json!({ "path": path }), false)?;
        }
        return Ok(RepositoryObservationPlanV1::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));
    }
    if operation == RepositoryOperationV1::GitStatus {
        let relative = argument_path_v1(arguments, true)?;
        require_directory_v1(epoch, &relative)?;
        refuse_nested_git_control_v1(epoch, &relative)?;
        return Ok(
            RepositoryObservationPlanV1::new(vec![], vec![], vec![], vec![])
                .with_source_trees(vec![relative]),
        );
    }
    if operation == RepositoryOperationV1::GitBlame {
        let relative = argument_path_v1(arguments, false)?;
        require_regular_v1(epoch, &relative)?;
        return Ok(RepositoryObservationPlanV1::new(
            vec![relative],
            vec![],
            vec![],
            vec![],
        ));
    }
    if operation == RepositoryOperationV1::GitDiff {
        let relative = argument_path_v1(arguments, true)?;
        let plan = match epoch
            .classify_relative(&relative)
            .map_err(|_| anyhow!("Git diff path classification is incomplete"))?
        {
            RepositoryNodeKindV1::Regular => {
                RepositoryObservationPlanV1::new(vec![relative], vec![], vec![], vec![])
            }
            RepositoryNodeKindV1::Directory => {
                refuse_nested_git_control_v1(epoch, &relative)?;
                RepositoryObservationPlanV1::new(vec![], vec![], vec![], vec![])
                    .with_source_trees(vec![relative])
            }
            RepositoryNodeKindV1::Missing => {
                RepositoryObservationPlanV1::new(vec![], vec![], vec![], vec![relative])
            }
        };
        return Ok(plan);
    }
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
                let character_column = line[..column].chars().count() + 1;
                charge_output_v1(&mut rendered_bytes, path.len() + snippet.len() + 64)?;
                references.push(json!({
                    "path": path,
                    "line": line_index + 1,
                    "column": character_column,
                    "endColumn": character_column + symbol.chars().count(),
                    "byteColumn": column + 1,
                    "endByteColumn": column + symbol.len() + 1,
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

pub(super) fn execute_git_tool_v1(
    epoch: &WorkspaceExecutionEpochV1,
    tool_name: &str,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    match tool_name {
        "status" => git_status_v1(epoch, arguments),
        "diff" => git_diff_v1(epoch, arguments),
        "log" => git_log_v1(epoch, arguments),
        "show" => git_show_v1(epoch, arguments),
        "blame" => git_blame_v1(epoch, arguments),
        _ => Err(ProviderError(McpError::typed(
            McpErrorCode::MethodNotFound,
            "unknown Git tool",
        ))),
    }
}

fn git_status_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let maximum = max_results_v1(object)?;
    let path = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    let path_text = path_text_v1(&path);
    let args = vec![
        "status".to_owned(),
        "--porcelain=v2".to_owned(),
        "-z".to_owned(),
        "--untracked-files=all".to_owned(),
        "--".to_owned(),
        path_text.clone(),
    ];
    let bytes = run_git_v1(epoch, &args, MAX_OUTPUT_BYTES_V1)?;
    let fields = split_nul_v1(&bytes)?;
    let mut entries = Vec::new();
    let mut index = 0;
    while index < fields.len() {
        let record = fields[index];
        if record.is_empty() {
            index += 1;
            continue;
        }
        let text = std::str::from_utf8(record)
            .map_err(|_| provider_io_v1("Git status emitted a non-UTF-8 path"))?;
        let mut entry = if let Some(path) = text.strip_prefix("? ") {
            json!({ "kind": "untracked", "status": "??", "path": path })
        } else if let Some(path) = text.strip_prefix("! ") {
            json!({ "kind": "ignored", "status": "!!", "path": path })
        } else {
            let kind = text.split(' ').next().unwrap_or_default();
            let maximum_fields = match kind {
                "1" => 9,
                "2" => 10,
                "u" => 11,
                _ => 0,
            };
            let fields = text.splitn(maximum_fields, ' ').collect::<Vec<_>>();
            let status = fields.get(1).copied().unwrap_or_default();
            let path = fields.last().copied().unwrap_or_default();
            if path.is_empty() || !matches!(kind, "1" | "2" | "u") {
                return Err(provider_io_v1("Git status record is malformed"));
            }
            json!({ "kind": kind, "status": status, "path": path })
        };
        if text.starts_with("2 ") {
            index += 1;
            let original = fields
                .get(index)
                .and_then(|value| std::str::from_utf8(value).ok())
                .ok_or_else(|| provider_io_v1("Git rename status record is malformed"))?;
            entry["originalPath"] = Value::String(original.to_owned());
        }
        entries.push(entry);
        if entries.len() > maximum {
            return Err(limit_error_v1("Git status result bound exceeded"));
        }
        index += 1;
    }
    entries.sort_by(|left, right| {
        left["path"]
            .as_str()
            .cmp(&right["path"].as_str())
            .then_with(|| left["status"].as_str().cmp(&right["status"].as_str()))
    });
    let rendered = entries
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}",
                entry["status"].as_str().unwrap_or_default(),
                entry["path"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "path": path_text, "entries": entries }),
    ))
}

fn git_diff_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let path = argument_path_v1(arguments, true).map_err(invalid_arguments_v1)?;
    let staged = object
        .get("staged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let revision = optional_head_revision_v1(object)?;
    let context = object
        .get("contextLines")
        .and_then(Value::as_u64)
        .unwrap_or(3);
    if context > 20 {
        return Err(invalid_arguments_v1(
            "contextLines is outside the admitted range",
        ));
    }
    let mut args = vec![
        "diff".to_owned(),
        "--no-ext-diff".to_owned(),
        "--no-textconv".to_owned(),
        "--no-color".to_owned(),
        format!("--unified={context}"),
    ];
    if staged {
        args.push("--cached".to_owned());
    }
    if let Some(revision) = revision {
        args.push(revision.to_owned());
    }
    args.push("--".to_owned());
    args.push(path_text_v1(&path));
    let bytes = run_git_v1(epoch, &args, MAX_OUTPUT_BYTES_V1)?;
    let patch = String::from_utf8(bytes)
        .map_err(|_| provider_io_v1("Git diff emitted non-UTF-8 output"))?;
    Ok(tool_result_v1(
        patch.clone(),
        json!({
            "schemaVersion": 1,
            "path": path_text_v1(&path),
            "staged": staged,
            "revision": revision,
            "bytes": patch.len(),
            "patch": patch
        }),
    ))
}

fn git_log_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let revision = head_revision_v1(object)?;
    let maximum = object
        .get("maxResults")
        .and_then(Value::as_u64)
        .unwrap_or(50);
    let maximum = usize::try_from(maximum)
        .ok()
        .filter(|value| (1..=200).contains(value))
        .ok_or_else(|| invalid_arguments_v1("maxResults is outside the Git log bound"))?;
    let mut args = vec![
        "log".to_owned(),
        revision.to_owned(),
        format!("--max-count={maximum}"),
        "-z".to_owned(),
        "--date=iso-strict".to_owned(),
        "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%s".to_owned(),
    ];
    let path = optional_path_v1(arguments)?;
    if let Some(path) = &path {
        args.push("--".to_owned());
        args.push(path_text_v1(path));
    }
    let bytes = run_git_v1(epoch, &args, MAX_OUTPUT_BYTES_V1)?;
    let fields = split_nul_v1(&bytes)?;
    let mut commits = Vec::new();
    for chunk in fields.chunks(6) {
        if chunk.iter().all(|field| field.is_empty()) {
            continue;
        }
        if chunk.len() != 6 {
            return Err(provider_io_v1("Git log record is malformed"));
        }
        let text = chunk
            .iter()
            .map(|field| std::str::from_utf8(field))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| provider_io_v1("Git log emitted non-UTF-8 metadata"))?;
        commits.push(json!({
            "commit": text[0],
            "parents": text[1].split_ascii_whitespace().collect::<Vec<_>>(),
            "authorName": text[2],
            "authorEmail": text[3],
            "authorDate": text[4],
            "subject": text[5]
        }));
    }
    let rendered = commits
        .iter()
        .map(|commit| {
            format!(
                "{}\t{}",
                commit["commit"].as_str().unwrap_or_default(),
                commit["subject"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "revision": revision, "path": path.as_deref().map(path_text_v1), "commits": commits }),
    ))
}

fn git_show_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let revision = head_revision_v1(object)?;
    let path = optional_path_v1(arguments)?;
    let mut args = vec!["show".to_owned()];
    if let Some(path) = &path {
        args.push(format!("{revision}:{}", path_text_v1(path)));
    } else {
        args.extend([
            "--no-ext-diff".to_owned(),
            "--no-textconv".to_owned(),
            "--no-color".to_owned(),
            "--format=fuller".to_owned(),
            revision.to_owned(),
        ]);
    }
    let bytes = run_git_v1(epoch, &args, MAX_OUTPUT_BYTES_V1)?;
    let output = String::from_utf8(bytes)
        .map_err(|_| provider_io_v1("Git show emitted non-UTF-8 output"))?;
    Ok(tool_result_v1(
        output.clone(),
        json!({
            "schemaVersion": 1,
            "revision": revision,
            "path": path.as_deref().map(path_text_v1),
            "bytes": output.len(),
            "output": output
        }),
    ))
}

fn git_blame_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<Value, ProviderError> {
    let object = object_v1(arguments)?;
    let path = argument_path_v1(arguments, false).map_err(invalid_arguments_v1)?;
    require_regular_v1(epoch, &path).map_err(invalid_arguments_v1)?;
    let revision = object
        .get("revision")
        .and_then(Value::as_str)
        .unwrap_or("WORKTREE");
    if !matches!(revision, "HEAD" | "WORKTREE") {
        return Err(invalid_arguments_v1("revision must be HEAD or WORKTREE"));
    }
    let start = optional_line_v1(object, "startLine")?;
    let end = optional_line_v1(object, "endLine")?;
    if let (Some(start), Some(end)) = (start, end)
        && start > end
    {
        return Err(invalid_arguments_v1("startLine must not exceed endLine"));
    }
    let mut args = vec!["blame".to_owned(), "--line-porcelain".to_owned()];
    if start.is_some() || end.is_some() {
        args.push(format!(
            "-L{},{}",
            start.unwrap_or(1),
            end.map_or_else(String::new, |value| value.to_string())
        ));
    }
    if revision == "HEAD" {
        args.push("HEAD".to_owned());
    }
    args.push("--".to_owned());
    args.push(path_text_v1(&path));
    let bytes = run_git_v1(epoch, &args, MAX_OUTPUT_BYTES_V1)?;
    let output = String::from_utf8(bytes)
        .map_err(|_| provider_io_v1("Git blame emitted non-UTF-8 output"))?;
    let mut lines = Vec::new();
    let mut pending: Option<(String, u64, u64)> = None;
    for line in output.lines() {
        if let Some(text) = line.strip_prefix('\t') {
            let (commit, original_line, final_line) = pending
                .take()
                .ok_or_else(|| provider_io_v1("Git blame source line lacks a header"))?;
            lines.push(json!({
                "path": path_text_v1(&path),
                "line": final_line,
                "originalLine": original_line,
                "commit": commit,
                "text": text
            }));
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() >= 3
            && matches!(fields[0].len(), 40 | 64)
            && fields[0].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            let original_line = fields[1]
                .parse::<u64>()
                .map_err(|_| provider_io_v1("Git blame original line is malformed"))?;
            let final_line = fields[2]
                .parse::<u64>()
                .map_err(|_| provider_io_v1("Git blame final line is malformed"))?;
            pending = Some((fields[0].to_owned(), original_line, final_line));
        }
    }
    let rendered = lines
        .iter()
        .map(|line| {
            format!(
                "{}:{}:{}:{}",
                line["path"].as_str().unwrap_or_default(),
                line["line"],
                line["commit"].as_str().unwrap_or_default(),
                line["text"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(tool_result_v1(
        rendered,
        json!({ "schemaVersion": 1, "revision": revision, "path": path_text_v1(&path), "lines": lines }),
    ))
}

fn run_git_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &[String],
    maximum_stdout_bytes: usize,
) -> Result<Vec<u8>, ProviderError> {
    epoch
        .validate_git_execution_safety(&gateway_workspace_limits_v1())
        .map_err(|_| provider_io_v1("Git configuration is not safe for read-only execution"))?;
    epoch
        .validate_current()
        .map_err(|_| provider_io_v1("workspace changed before Git execution"))?;
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .current_dir(epoch.canonical_workspace())
        .args([
            "--no-optional-locks",
            "--literal-pathspecs",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "status.showStash=false",
            "-c",
            "log.showSignature=false",
        ])
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| provider_io_v1("start sanitized Git process failed"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| provider_io_v1("capture Git stdout failed"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| provider_io_v1("capture Git stderr failed"))?;
    let stdout_reader = thread::spawn(move || read_bounded_pipe_v1(stdout, maximum_stdout_bytes));
    let stderr_reader =
        thread::spawn(move || read_bounded_pipe_v1(stderr, MAX_GIT_STDERR_BYTES_V1));
    let deadline = Instant::now() + MAX_EXECUTION_TIME_V1;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(limit_error_v1("Git execution deadline exceeded"));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(provider_io_v1("wait for Git process failed"));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| provider_io_v1("Git stdout reader failed"))?
        .map_err(|_| provider_io_v1("read Git stdout failed"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| provider_io_v1("Git stderr reader failed"))?
        .map_err(|_| provider_io_v1("read Git stderr failed"))?;
    if stdout.overflow || stderr.overflow {
        return Err(limit_error_v1("Git output bound exceeded"));
    }
    if !status.success() {
        let _ = stderr.bytes;
        return Err(provider_io_v1("read-only Git command failed"));
    }
    epoch
        .validate_current()
        .map_err(|_| provider_io_v1("workspace changed during Git execution"))?;
    Ok(stdout.bytes)
}

struct BoundedPipeV1 {
    bytes: Vec<u8>,
    overflow: bool,
}

fn read_bounded_pipe_v1(
    mut reader: impl Read,
    maximum_bytes: usize,
) -> std::io::Result<BoundedPipeV1> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = maximum_bytes.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..read.min(remaining)]);
        overflow |= read > remaining;
    }
    Ok(BoundedPipeV1 { bytes, overflow })
}

fn split_nul_v1(bytes: &[u8]) -> Result<Vec<&[u8]>, ProviderError> {
    if bytes.contains(&b'\n') && !bytes.contains(&0) {
        return Err(provider_io_v1("Git record framing is malformed"));
    }
    let mut fields = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
    while fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    Ok(fields)
}

fn optional_path_v1(arguments: &Value) -> Result<Option<PathBuf>, ProviderError> {
    let object = object_v1(arguments)?;
    if object.get("path").is_none() {
        Ok(None)
    } else {
        argument_path_v1(arguments, false)
            .map(Some)
            .map_err(invalid_arguments_v1)
    }
}

fn head_revision_v1(object: &serde_json::Map<String, Value>) -> Result<&str, ProviderError> {
    let revision = object
        .get("revision")
        .and_then(Value::as_str)
        .unwrap_or("HEAD");
    if revision == "HEAD" {
        Ok(revision)
    } else {
        Err(invalid_arguments_v1(
            "only the authority-bound HEAD revision is admitted",
        ))
    }
}

fn optional_head_revision_v1(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<&str>, ProviderError> {
    object.get("revision").map_or(Ok(None), |revision| {
        revision
            .as_str()
            .filter(|revision| *revision == "HEAD")
            .map(Some)
            .ok_or_else(|| invalid_arguments_v1("only the HEAD revision is admitted"))
    })
}

fn optional_line_v1(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, ProviderError> {
    object.get(field).map_or(Ok(None), |value| {
        value
            .as_u64()
            .filter(|value| (1..=10_000_000).contains(value))
            .map(Some)
            .ok_or_else(|| invalid_arguments_v1("line bound is invalid"))
    })
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

fn refuse_nested_git_control_v1(epoch: &WorkspaceExecutionEpochV1, relative: &Path) -> Result<()> {
    let files = source_files_v1(epoch, relative)
        .map_err(|_| anyhow!("nested Git control inspection is incomplete"))?;
    if files.iter().any(|file| {
        file.relative_path()
            .components()
            .any(|component| matches!(component, Component::Normal(name) if name == ".git"))
    }) {
        bail!("nested Git worktrees or submodules are not admitted for reusable Git queries");
    }
    Ok(())
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
