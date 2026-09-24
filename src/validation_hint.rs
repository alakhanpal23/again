//! Bounded, source-backed validation hints. These never authorize a test skip.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

pub(crate) struct PackageTestSuggestionV1 {
    pub command: &'static str,
    source_digest: String,
    test_script: String,
}

impl PackageTestSuggestionV1 {
    pub fn selector_json(self) -> Value {
        json!({
            "command": self.command,
            "basis": "current_package_test_script",
            "verified": false,
            "source": {
                "path": "package.json",
                "digest": self.source_digest,
                "testScript": self.test_script
            }
        })
    }
}

pub(crate) fn is_javascript_source_v1(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts")
    )
}

pub(crate) fn package_test_suggestion_v1(workspace: &Path) -> Option<PackageTestSuggestionV1> {
    const MAX_MANIFEST_BYTES: u64 = 32 * 1024;
    let workspace = fs::canonicalize(workspace).ok()?;
    let path = workspace.join("package.json");
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return None;
    }
    let manifest: Value = serde_json::from_slice(&bytes).ok()?;
    let script = manifest["scripts"]["test"].as_str()?.trim();
    if script.is_empty()
        || script.len() > 160
        || script.chars().any(char::is_control)
        || script.contains("no test specified")
        || crate::task_lifecycle::screen_sensitive_text_v1(script).is_err()
    {
        return None;
    }
    let declared = manifest["packageManager"].as_str().map(|value| {
        value
            .split_once('@')
            .filter(|(_, version)| !version.is_empty() && version.len() <= 64)
            .map(|(manager, _)| manager)
            .unwrap_or("")
    });
    let lockfiles = [
        (
            "npm",
            ["package-lock.json", "npm-shrinkwrap.json"].as_slice(),
        ),
        ("pnpm", ["pnpm-lock.yaml"].as_slice()),
        ("yarn", ["yarn.lock"].as_slice()),
        ("bun", ["bun.lock", "bun.lockb"].as_slice()),
    ];
    let observed: Vec<&str> = lockfiles
        .iter()
        .filter(|(_, names)| {
            names.iter().any(|name| {
                fs::symlink_metadata(workspace.join(name)).is_ok_and(|metadata| metadata.is_file())
            })
        })
        .map(|(manager, _)| *manager)
        .collect();
    if observed.len() > 1 {
        return None;
    }
    let manager = if let Some(declared) = declared {
        if !matches!(declared, "npm" | "pnpm" | "yarn" | "bun")
            || observed
                .first()
                .is_some_and(|observed| *observed != declared)
        {
            return None;
        }
        declared
    } else {
        observed.first().copied().unwrap_or("npm")
    };
    let command = match manager {
        "npm" => "npm test",
        "pnpm" => "pnpm test",
        "yarn" => "yarn test",
        "bun" => "bun test",
        _ => return None,
    };
    Some(PackageTestSuggestionV1 {
        command,
        source_digest: blake3::hash(&bytes).to_hex().to_string(),
        test_script: script.to_owned(),
    })
}
