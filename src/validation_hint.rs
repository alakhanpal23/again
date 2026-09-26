//! Bounded, source-backed validation hints. These never authorize a test skip.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

pub(crate) struct PackageTestSuggestionV1 {
    pub command: &'static str,
    manifest_path: String,
    working_directory: String,
    source_digest: String,
    test_script: String,
}

impl PackageTestSuggestionV1 {
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    pub fn selector_json(self) -> Value {
        json!({
            "command": self.command,
            "workingDirectory": self.working_directory,
            "basis": "current_package_test_script",
            "verified": false,
            "source": {
                "path": self.manifest_path,
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
    package_test_suggestion_at_v1(workspace, Path::new(""))
}

pub(crate) fn package_test_suggestion_for_source_v1(
    workspace: &Path,
    source_path: &str,
) -> Option<PackageTestSuggestionV1> {
    let source = Path::new(source_path);
    if source_path.is_empty()
        || source_path.len() > 512
        || !source
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return None;
    }
    let root = fs::canonicalize(workspace).ok()?;
    if !fs::symlink_metadata(root.join(source)).ok()?.is_file() {
        return None;
    }
    let mut directory = source.parent()?;
    loop {
        if !directory.as_os_str().is_empty() {
            let package_root = root.join(directory);
            let metadata = fs::symlink_metadata(&package_root).ok()?;
            if !metadata.is_dir() || fs::canonicalize(&package_root).ok()? != package_root {
                return None;
            }
        }
        let manifest = root.join(directory).join("package.json");
        match fs::symlink_metadata(manifest) {
            Ok(metadata) if metadata.is_file() => {
                return package_test_suggestion_at_v1(&root, directory);
            }
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
        if directory.as_os_str().is_empty() {
            return None;
        }
        directory = directory.parent()?;
    }
}

fn package_test_suggestion_at_v1(
    workspace: &Path,
    directory: &Path,
) -> Option<PackageTestSuggestionV1> {
    const MAX_MANIFEST_BYTES: u64 = 32 * 1024;
    let workspace = fs::canonicalize(workspace).ok()?;
    let package_root = workspace.join(directory);
    let path = package_root.join("package.json");
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
    for name in lockfiles.iter().flat_map(|(_, names)| names.iter()) {
        match fs::symlink_metadata(package_root.join(name)) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    let observed: Vec<&str> = lockfiles
        .iter()
        .filter(|(_, names)| {
            names.iter().any(|name| {
                fs::symlink_metadata(package_root.join(name))
                    .is_ok_and(|metadata| metadata.is_file())
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
        observed
            .first()
            .copied()
            .or_else(|| directory.as_os_str().is_empty().then_some("npm"))?
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
        manifest_path: directory
            .join("package.json")
            .to_string_lossy()
            .into_owned(),
        working_directory: if directory.as_os_str().is_empty() {
            ".".to_owned()
        } else {
            directory.to_string_lossy().into_owned()
        },
        source_digest: blake3::hash(&bytes).to_hex().to_string(),
        test_script: script.to_owned(),
    })
}
