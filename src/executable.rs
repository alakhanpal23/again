//! Audited executable identities for Again's deliberately small v0 allowlist.
//!
//! PATH resolution is not a trust boundary. Callers must resolve a command and
//! pass its canonical path here before it can be treated as an eligible tool.

use std::fmt;
#[cfg(target_os = "macos")]
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
const MACOS_SYSTEM_PROFILE_PATH: &str = "/System/Library/CoreServices/SystemVersion.plist";
#[cfg(target_os = "macos")]
const MACOS_SYSTEM_PROFILE_BLAKE3: &str =
    "5adbd08043e220188b91445787a518ddaa060a56057191707da49b3e91aba10a";
#[cfg(target_os = "macos")]
const MACOS_SYSTEM_PROFILE_ID: &str = "macos-15.6.1-24G90-read-v0";
#[cfg(target_os = "macos")]
const CODEX_RG_BLAKE3: &str = "0dc9090877943cb7bcc35fab4dd2bf501f53c4555a919bf2476fef702f1e5af2";
#[cfg(target_os = "macos")]
const CODEX_RG_PROFILE_ID: &str = "codex-rg-15.2.0-e89fff89ac-arm64-read-v0";
#[cfg(target_os = "macos")]
const MAX_AUDITED_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "macos")]
fn audited_apple_tool_digest(tool: ToolKind) -> Option<&'static str> {
    match tool {
        ToolKind::Cat => Some("30fdc8a74ef975c1d61a6110083490ac43fe0c0c28228a5abd2cd5f88187cf1c"),
        ToolKind::Head => Some("5ce13107571eecfaf6fb128e0f9697f98bade39df715adfd83afd66bbff77f66"),
        ToolKind::Tail => Some("fd4c9cffd139ee86e199c464f71554157ae11eae2809f513aaacade1ab5f2caa"),
        ToolKind::Wc => Some("f34527e367649c6ca0434e0f4a3a083f69cb06325526edd00e418fbdbb73e12b"),
        ToolKind::Grep => Some("46dee6a2c4f69fcaf38aecbc32003bc93ff57903c682b3271e53920e2658a62f"),
        ToolKind::Ls => Some("73d13c2d68c0b93c8cbd18502900d8bd3d8d3472d683c84a06780d0a2b240c77"),
        ToolKind::Pwd => Some("354299ce70bdeafe5a1a74b8063fcad17d785f42db8c0c3d8ebdb157eca572fd"),
        ToolKind::Rg => None,
    }
}

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
    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
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
    /// Exact parser/semantics profile reviewed for this executable.
    pub semantic_profile: String,
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
    SystemProfileMismatch,
    ContentDigestMismatch,
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
            Self::SystemProfileMismatch => "SYSTEM_PROFILE_MISMATCH",
            Self::ContentDigestMismatch => "CONTENT_DIGEST_MISMATCH",
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
        Err(VerifyError::UnsupportedPlatform)
    }

    #[cfg(target_os = "macos")]
    verify_macos(requested_argv0, canonical_path)
}

/// Return the exact complete Apple tool profile available on this host.
///
/// Tests and diagnostics use this to distinguish an intentionally unsupported
/// macOS update from a regression on the one reviewed profile. Individual
/// command admission still verifies its own exact bytes independently.
pub fn host_audited_apple_profile() -> Result<&'static str, VerifyError> {
    #[cfg(not(target_os = "macos"))]
    {
        Err(VerifyError::UnsupportedPlatform)
    }

    #[cfg(target_os = "macos")]
    {
        let profile = verify_macos_system_profile()?;
        for tool in [
            ToolKind::Cat,
            ToolKind::Head,
            ToolKind::Tail,
            ToolKind::Wc,
            ToolKind::Grep,
            ToolKind::Ls,
            ToolKind::Pwd,
        ] {
            let path = tool
                .apple_system_path()
                .ok_or(VerifyError::SystemPathMismatch)?;
            inspect_regular_non_privileged_binary(path)?;
            let expected =
                audited_apple_tool_digest(tool).ok_or(VerifyError::ContentDigestMismatch)?;
            if hash_file_bounded(path)? != expected {
                return Err(VerifyError::ContentDigestMismatch);
            }
        }
        Ok(profile)
    }
}

#[cfg(target_os = "macos")]
fn verify_macos(
    requested_argv0: &str,
    canonical_path: &Path,
) -> Result<ExecutableIdentity, VerifyError> {
    let requested = Path::new(requested_argv0);
    let requested_name = if requested.is_absolute() {
        // Reject aliases, symlinks and merely equivalent spellings. The raw
        // shell command and the wrapper must name the exact audited binary.
        if requested != canonical_path {
            return Err(VerifyError::RequestedNameMismatch);
        }
        requested
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(VerifyError::RequestedNameMismatch)?
    } else {
        if requested_argv0.contains('/') || requested_argv0.is_empty() {
            return Err(VerifyError::RequestedNameMismatch);
        }
        requested_argv0
    };
    let tool = ToolKind::parse(requested_name).ok_or(VerifyError::UnsupportedTool)?;
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
        let semantic_profile = verify_macos_system_profile()?;
        let expected_digest =
            audited_apple_tool_digest(tool).ok_or(VerifyError::ContentDigestMismatch)?;
        if hash_file_bounded(canonical_path)? != expected_digest {
            return Err(VerifyError::ContentDigestMismatch);
        }
        return Ok(ExecutableIdentity {
            tool,
            canonical_path: canonical_path.to_path_buf(),
            provenance: ExecutableProvenance::AppleSystem,
            semantic_profile: semantic_profile.to_owned(),
        });
    }

    if !is_codex_bundled_rg(canonical_path) {
        return Err(VerifyError::CodexBundlePathMismatch);
    }
    let system_profile = verify_macos_system_profile()?;
    verify_codex_rg_signature_identity(canonical_path)?;
    let digest = hash_file_bounded(canonical_path)?;
    if digest != CODEX_RG_BLAKE3 {
        return Err(VerifyError::ContentDigestMismatch);
    }
    Ok(ExecutableIdentity {
        tool,
        canonical_path: canonical_path.to_path_buf(),
        provenance: ExecutableProvenance::OpenAiCodexBundle,
        semantic_profile: format!("{system_profile}+{CODEX_RG_PROFILE_ID}"),
    })
}

#[cfg(target_os = "macos")]
fn verify_macos_system_profile() -> Result<&'static str, VerifyError> {
    let bytes =
        std::fs::read(MACOS_SYSTEM_PROFILE_PATH).map_err(|_| VerifyError::InspectionFailed)?;
    if bytes.len() > 1024 * 1024
        || blake3::hash(&bytes).to_hex().as_str() != MACOS_SYSTEM_PROFILE_BLAKE3
    {
        return Err(VerifyError::SystemProfileMismatch);
    }
    Ok(MACOS_SYSTEM_PROFILE_ID)
}

#[cfg(target_os = "macos")]
fn hash_file_bounded(path: &Path) -> Result<String, VerifyError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| VerifyError::InspectionFailed)?;
    if metadata.len() > MAX_AUDITED_EXECUTABLE_BYTES {
        return Err(VerifyError::ContentDigestMismatch);
    }
    let mut file = std::fs::File::open(path).map_err(|_| VerifyError::InspectionFailed)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| VerifyError::InspectionFailed)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_AUDITED_EXECUTABLE_BYTES {
            return Err(VerifyError::ContentDigestMismatch);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
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
fn verify_codex_rg_signature_identity(path: &Path) -> Result<(), VerifyError> {
    use std::process::Command;

    // Some official npm-distributed Codex bundles retain identifier/team
    // metadata while macOS reports that the extracted nested signature is not
    // strictly verifiable. Runtime integrity and semantics are therefore bound
    // by the exact BLAKE3 allowlist below; these fields are an additional
    // publisher-identity check, not the content trust boundary.
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
        if host_audited_apple_profile().is_err() {
            return;
        }
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
                    semantic_profile: MACOS_SYSTEM_PROFILE_ID.to_owned(),
                })
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn accepts_exact_absolute_apple_system_tools() {
        if host_audited_apple_profile().is_err() {
            return;
        }
        for requested in [
            "/bin/cat",
            "/usr/bin/head",
            "/usr/bin/tail",
            "/usr/bin/wc",
            "/usr/bin/grep",
            "/bin/ls",
            "/bin/pwd",
        ] {
            let canonical = std::fs::canonicalize(requested).expect("system tool exists");
            let exact = canonical.to_str().expect("system path is UTF-8");
            assert!(
                verify_executable(exact, &canonical).is_ok(),
                "absolute audited path should be accepted: {exact}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn codex_bundled_rg_is_accepted_only_when_exact_audited_bytes_are_present() {
        if host_audited_apple_profile().is_err() {
            return;
        }
        let Some(path) = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
            .map(|directory| directory.join("rg"))
            .find(|path| path.is_file() && is_codex_bundled_rg(path))
        else {
            return;
        };
        let path = std::fs::canonicalize(path).unwrap();
        // Keep this expectation independent from `hash_file_bounded`, which is
        // part of the admission implementation under test. The `take` keeps a
        // changed or adversarial fixture from making the test allocate without
        // the executable-size bound.
        let mut audited_candidate = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .take(MAX_AUDITED_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut audited_candidate)
            .unwrap();
        assert!(audited_candidate.len() as u64 <= MAX_AUDITED_EXECUTABLE_BYTES);
        let has_exact_audited_bytes =
            blake3::hash(&audited_candidate).to_hex().as_str() == CODEX_RG_BLAKE3;
        match (has_exact_audited_bytes, verify_executable("rg", &path)) {
            (true, Ok(identity)) => {
                assert_eq!(identity.tool, ToolKind::Rg);
                assert_eq!(identity.provenance, ExecutableProvenance::OpenAiCodexBundle);
                assert_eq!(
                    identity.semantic_profile,
                    format!("{MACOS_SYSTEM_PROFILE_ID}+{CODEX_RG_PROFILE_ID}")
                );
            }
            // Codex may update or re-sign its bundled binary independently of
            // Again. An otherwise recognized bundle with unreviewed bytes must
            // remain an explicit fail-closed negative lane, not make the suite
            // assume that any Codex-bundled `rg` is the audited executable.
            (false, Err(VerifyError::ContentDigestMismatch)) => {}
            (true, Err(error)) => {
                panic!("exact audited Codex rg bytes must verify successfully: {error}")
            }
            (false, Ok(_)) => panic!("unreviewed Codex rg bytes must fail closed"),
            (false, Err(error)) => panic!("unexpected Codex rg verification result: {error}"),
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

    #[cfg(target_os = "macos")]
    #[test]
    fn an_unknown_host_profile_fails_closed_instead_of_becoming_a_success_fixture() {
        if host_audited_apple_profile().is_ok() {
            return;
        }
        let rejected = [
            ("cat", "/bin/cat"),
            ("head", "/usr/bin/head"),
            ("tail", "/usr/bin/tail"),
            ("wc", "/usr/bin/wc"),
            ("grep", "/usr/bin/grep"),
            ("ls", "/bin/ls"),
            ("pwd", "/bin/pwd"),
        ]
        .into_iter()
        .filter_map(|(requested, path)| {
            let canonical = std::fs::canonicalize(path).ok()?;
            verify_executable(requested, &canonical).err()
        })
        .any(|error| {
            matches!(
                error,
                VerifyError::SystemProfileMismatch | VerifyError::ContentDigestMismatch
            )
        });
        assert!(
            rejected,
            "unknown host must reject at least one audited tool"
        );
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
