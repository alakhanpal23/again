//! Audited executable identities for Again's deliberately small v0 allowlist.
//!
//! PATH resolution is not a trust boundary. Callers must resolve a command and
//! pass its canonical path here before it can be treated as an eligible tool.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A command whose executable has a v0 audit profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    Cat,
    Head,
    Tail,
    Wc,
    Grep,
    Ls,
    Pwd,
    Rg,
}

impl ToolKind {
    fn parse(requested: &str) -> Option<Self> {
        match requested {
            "cat" => Some(Self::Cat),
            "head" => Some(Self::Head),
            "tail" => Some(Self::Tail),
            "wc" => Some(Self::Wc),
            "grep" => Some(Self::Grep),
            "ls" => Some(Self::Ls),
            "pwd" => Some(Self::Pwd),
            "rg" => Some(Self::Rg),
            _ => None,
        }
    }

    fn executable_name(self) -> &'static str {
        match self {
            Self::Cat => "cat",
            Self::Head => "head",
            Self::Tail => "tail",
            Self::Wc => "wc",
            Self::Grep => "grep",
            Self::Ls => "ls",
            Self::Pwd => "pwd",
            Self::Rg => "rg",
        }
    }

    #[cfg(target_os = "macos")]
    fn apple_system_path(self) -> Option<&'static Path> {
        match self {
            Self::Cat => Some(Path::new("/bin/cat")),
            Self::Head => Some(Path::new("/usr/bin/head")),
            Self::Tail => Some(Path::new("/usr/bin/tail")),
            Self::Wc => Some(Path::new("/usr/bin/wc")),
            Self::Grep => Some(Path::new("/usr/bin/grep")),
            Self::Ls => Some(Path::new("/bin/ls")),
            Self::Pwd => Some(Path::new("/bin/pwd")),
            Self::Rg => None,
        }
    }
}

/// Provenance that makes an executable admissible to the v0 runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableProvenance {
    AppleSystem,
    OpenAiCodexBundle,
}

/// Stable executable identity recorded with an admitted invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    pub tool: ToolKind,
    pub canonical_path: PathBuf,
    pub provenance: ExecutableProvenance,
}

/// Stable error codes. Deliberately omit host paths and command output so the
/// value is safe to serialize into policy telemetry and cache diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifyError {
    UnsupportedPlatform,
    UnsupportedTool,
    RequestedNameMismatch,
    BasenameMismatch,
    PathNotCanonical,
    SystemPathMismatch,
    CodexBundlePathMismatch,
    NotRegularExecutable,
    PrivilegedMode,
    ScriptFile,
    SignatureInvalid,
    SignatureIdentityMismatch,
    InspectionFailed,
}

impl VerifyError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::UnsupportedTool => "UNSUPPORTED_TOOL",
            Self::RequestedNameMismatch => "REQUESTED_NAME_MISMATCH",
            Self::BasenameMismatch => "BASENAME_MISMATCH",
            Self::PathNotCanonical => "PATH_NOT_CANONICAL",
            Self::SystemPathMismatch => "SYSTEM_PATH_MISMATCH",
            Self::CodexBundlePathMismatch => "CODEX_BUNDLE_PATH_MISMATCH",
            Self::NotRegularExecutable => "NOT_REGULAR_EXECUTABLE",
            Self::PrivilegedMode => "PRIVILEGED_MODE",
            Self::ScriptFile => "SCRIPT_FILE",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::SignatureIdentityMismatch => "SIGNATURE_IDENTITY_MISMATCH",
            Self::InspectionFailed => "INSPECTION_FAILED",
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for VerifyError {}

/// Verify a requested executable after PATH resolution.
///
/// `canonical_path` must be an absolute, canonical path. On macOS, v0 accepts
/// only Apple system tools at their exact system locations and OpenAI's signed,
/// Codex-bundled `rg`. Every other platform fails closed until a confinement
/// backend can enforce an equivalent executable policy.
pub fn verify_executable(
    requested_argv0: &str,
    canonical_path: &Path,
) -> Result<ExecutableIdentity, VerifyError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (requested_argv0, canonical_path);
        return Err(VerifyError::UnsupportedPlatform);
    }

    #[cfg(target_os = "macos")]
    verify_macos(requested_argv0, canonical_path)
}

#[cfg(target_os = "macos")]
fn verify_macos(
    requested_argv0: &str,
    canonical_path: &Path,
) -> Result<ExecutableIdentity, VerifyError> {
    if requested_argv0.contains('/') || requested_argv0.is_empty() {
        return Err(VerifyError::RequestedNameMismatch);
    }
    let tool = ToolKind::parse(requested_argv0).ok_or(VerifyError::UnsupportedTool)?;
    if canonical_path.file_name().and_then(|name| name.to_str()) != Some(tool.executable_name()) {
        return Err(VerifyError::BasenameMismatch);
    }
    if !canonical_path.is_absolute()
        || std::fs::canonicalize(canonical_path).ok().as_deref() != Some(canonical_path)
    {
        return Err(VerifyError::PathNotCanonical);
    }
    inspect_regular_non_privileged_binary(canonical_path)?;

    if let Some(system_path) = tool.apple_system_path() {
        if canonical_path != system_path {
            return Err(VerifyError::SystemPathMismatch);
        }
        return Ok(ExecutableIdentity {
            tool,
            canonical_path: canonical_path.to_path_buf(),
            provenance: ExecutableProvenance::AppleSystem,
        });
    }

    if !is_codex_bundled_rg(canonical_path) {
        return Err(VerifyError::CodexBundlePathMismatch);
    }
    verify_codex_rg_signature(canonical_path)?;
    Ok(ExecutableIdentity {
        tool,
        canonical_path: canonical_path.to_path_buf(),
        provenance: ExecutableProvenance::OpenAiCodexBundle,
    })
}

#[cfg(target_os = "macos")]
fn inspect_regular_non_privileged_binary(path: &Path) -> Result<(), VerifyError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path).map_err(|_| VerifyError::InspectionFailed)?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o111 == 0 {
        return Err(VerifyError::NotRegularExecutable);
    }
    if metadata.mode() & 0o6000 != 0 {
        return Err(VerifyError::PrivilegedMode);
    }
    let mut prefix = [0_u8; 4];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut prefix))
        .map_err(|_| VerifyError::InspectionFailed)?;
    if prefix.starts_with(b"#!") {
        return Err(VerifyError::ScriptFile);
    }
    if !matches!(
        prefix,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xca, 0xfe, 0xba, 0xbf]
    ) {
        return Err(VerifyError::NotRegularExecutable);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_codex_bundled_rg(path: &Path) -> bool {
    let components: Vec<_> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let has_openai_codex_package = components
        .windows(2)
        .any(|pair| pair[0] == "@openai" && pair[1].starts_with("codex"));
    has_openai_codex_package
        && components.windows(2).any(|pair| pair[0] == "vendor")
        && components.contains(&"codex-path")
        && components.last() == Some(&"rg")
}

#[cfg(target_os = "macos")]
fn verify_codex_rg_signature(path: &Path) -> Result<(), VerifyError> {
    use std::process::Command;

    let verification = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=0"])
        .arg(path)
        .status()
        .map_err(|_| VerifyError::InspectionFailed)?;
    if !verification.success() {
        return Err(VerifyError::SignatureInvalid);
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-dvv"])
        .arg(path)
        .output()
        .map_err(|_| VerifyError::InspectionFailed)?;
    if !details.status.success() {
        return Err(VerifyError::SignatureInvalid);
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&details.stdout),
        String::from_utf8_lossy(&details.stderr)
    );
    let identifier = text
        .lines()
        .find_map(|line| line.strip_prefix("Identifier="));
    let team = text
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="));
    if identifier == Some("com.openai.codex.rg") && team == Some("2DC432GLL2") {
        Ok(())
    } else {
        Err(VerifyError::SignatureIdentityMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn accepts_exact_apple_system_tools() {
        let cases = [
            ("cat", "/bin/cat", ToolKind::Cat),
            ("head", "/usr/bin/head", ToolKind::Head),
            ("tail", "/usr/bin/tail", ToolKind::Tail),
            ("wc", "/usr/bin/wc", ToolKind::Wc),
            ("grep", "/usr/bin/grep", ToolKind::Grep),
            ("ls", "/bin/ls", ToolKind::Ls),
            ("pwd", "/bin/pwd", ToolKind::Pwd),
        ];
        for (requested, path, tool) in cases {
            let path = std::fs::canonicalize(path).expect("system tool exists");
            assert_eq!(
                verify_executable(requested, &path),
                Ok(ExecutableIdentity {
                    tool,
                    canonical_path: path,
                    provenance: ExecutableProvenance::AppleSystem,
                })
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_fake_cat_and_rg() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        for name in ["cat", "rg"] {
            let path = temp.path().join(name);
            std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = std::fs::canonicalize(path).unwrap();
            assert!(verify_executable(name, &path).is_err(), "{name}");
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_is_fail_closed() {
        assert_eq!(
            verify_executable("cat", Path::new("/bin/cat")),
            Err(VerifyError::UnsupportedPlatform)
        );
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(VerifyError::SignatureInvalid.as_str(), "SIGNATURE_INVALID");
        assert_eq!(
            serde_json::to_string(&VerifyError::UnsupportedPlatform).unwrap(),
            "\"UNSUPPORTED_PLATFORM\""
        );
    }
}
