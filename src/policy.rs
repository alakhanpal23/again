//! Fail-closed admission policy for the deliberately narrow v0 command set.
//!
//! This module classifies the *raw* string supplied to Codex's Bash tool. It
//! is intentionally not a shell interpreter: a command is reusable only when
//! its syntax and operands fit a small, audited subset. Everything uncertain
//! remains executable, but is not admitted to the cache.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Information the hook already has for one Bash tool invocation.
#[derive(Debug, Clone, Copy)]
pub struct PolicyContext<'a> {
    pub workspace: &'a Path,
    pub cwd: &'a Path,
    /// Interactive terminals alter the output/behaviour of common read-only
    /// tools, so their presence is an explicit cache-admission input.
    pub stdin_is_tty: bool,
    pub stdout_is_tty: bool,
}

impl<'a> PolicyContext<'a> {
    pub fn new(workspace: &'a Path, cwd: &'a Path) -> Self {
        Self {
            workspace,
            cwd,
            stdin_is_tty: false,
            stdout_is_tty: false,
        }
    }
}

/// Stable, machine-readable explanations for a non-reuse decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    EmptyCommand,
    Newline,
    ShellComposition,
    ShellExpansion,
    GlobExpansion,
    ParseError,
    AlreadyWrapped,
    TtyDependent,
    StdinDependent,
    AbsolutePath,
    OutsideWorkspace,
    ExcludedRuntimePath,
    MissingOperand,
    UnsafeFlag,
    UnsafeGitSubcommand,
    NetworkCommand,
    MutatingCommand,
    UnsupportedCommand,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyCommand => "EMPTY_COMMAND",
            Self::Newline => "NEWLINE",
            Self::ShellComposition => "SHELL_COMPOSITION",
            Self::ShellExpansion => "SHELL_EXPANSION",
            Self::GlobExpansion => "GLOB_EXPANSION",
            Self::ParseError => "PARSE_ERROR",
            Self::AlreadyWrapped => "ALREADY_WRAPPED",
            Self::TtyDependent => "TTY_DEPENDENT",
            Self::StdinDependent => "STDIN_DEPENDENT",
            Self::AbsolutePath => "ABSOLUTE_PATH",
            Self::OutsideWorkspace => "OUTSIDE_WORKSPACE",
            Self::ExcludedRuntimePath => "EXCLUDED_RUNTIME_PATH",
            Self::MissingOperand => "MISSING_OPERAND",
            Self::UnsafeFlag => "UNSAFE_FLAG",
            Self::UnsafeGitSubcommand => "UNSAFE_GIT_SUBCOMMAND",
            Self::NetworkCommand => "NETWORK_COMMAND",
            Self::MutatingCommand => "MUTATING_COMMAND",
            Self::UnsupportedCommand => "UNSUPPORTED_COMMAND",
        }
    }
}

/// The admission decision consumed by `hook.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Exact result/effect replay is eligible. `argv` is shell-free and may be
    /// passed directly to `Command` (never through another shell).
    ExactReuse {
        argv: Vec<String>,
        access_plan: AccessPlan,
    },
    /// No special hazard was established, but v0 has no proof it is reusable.
    PassThrough { reason: ReasonCode },
    /// A known unsafe operation must bypass Again's store entirely.
    BypassNoStore { reason: ReasonCode },
}

impl Decision {
    pub fn reason(&self) -> Option<ReasonCode> {
        match self {
            Self::ExactReuse { .. } => None,
            Self::PassThrough { reason } | Self::BypassNoStore { reason } => Some(*reason),
        }
    }

    pub fn argv(&self) -> Option<&[String]> {
        match self {
            Self::ExactReuse { argv, .. } => Some(argv),
            _ => None,
        }
    }

    pub fn access_plan(&self) -> Option<&AccessPlan> {
        match self {
            Self::ExactReuse { access_plan, .. } => Some(access_plan),
            _ => None,
        }
    }
}

/// The minimal workspace state that must be fingerprinted for exact reuse.
/// Paths are normalized, relative to the workspace, and retain argv order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPlan {
    pub scopes: Vec<AccessScope>,
}

/// A deterministic scope within an [`AccessPlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessScope {
    IdentityOnly,
    ContentPath(PathBuf),
    RecursiveContentTree(PathBuf),
    DirectoryListing(PathBuf),
    /// Retained for wire/API compatibility; v0 policy no longer emits it.
    WholeWorkspace,
}

/// Classify one raw Codex Bash command. Unknown syntax and executables are
/// deliberately `PassThrough`; known side-effecting constructs are
/// `BypassNoStore`.
pub fn classify(raw: &str, context: PolicyContext<'_>) -> Decision {
    if raw.trim().is_empty() {
        return pass(ReasonCode::EmptyCommand);
    }
    if raw.contains(['\n', '\r']) {
        return bypass(ReasonCode::Newline);
    }
    if context.stdin_is_tty || context.stdout_is_tty {
        return bypass(ReasonCode::TtyDependent);
    }
    if let Some(reason) = reject_shell_syntax(raw) {
        return bypass(reason);
    }

    let argv = match shell_words::split(raw) {
        Ok(argv) if !argv.is_empty() => argv,
        Ok(_) => return pass(ReasonCode::EmptyCommand),
        Err(_) => return pass(ReasonCode::ParseError),
    };
    if argv[0] == "again" || argv[0].ends_with("/again") {
        return bypass(ReasonCode::AlreadyWrapped);
    }
    if Path::new(&argv[0]).is_absolute() {
        return bypass(ReasonCode::AbsolutePath);
    }
    if !cwd_is_in_workspace(context) {
        return bypass(ReasonCode::OutsideWorkspace);
    }
    if is_network_command(&argv[0]) {
        return bypass(ReasonCode::NetworkCommand);
    }
    if is_mutating_command(&argv[0]) {
        return bypass(ReasonCode::MutatingCommand);
    }

    let result = match argv[0].as_str() {
        "cat" => classify_files(&argv, FileOptions::None, true, context),
        "head" | "tail" => classify_files(&argv, FileOptions::HeadTail, true, context),
        "wc" => classify_files(&argv, FileOptions::Wc, true, context),
        "ls" => classify_files(&argv, FileOptions::Ls, false, context),
        "pwd" => classify_pwd(&argv),
        "rg" => classify_search(&argv, true, context),
        "grep" => classify_search(&argv, false, context),
        _ => return pass(ReasonCode::UnsupportedCommand),
    };
    match result {
        Ok(access_plan) => Decision::ExactReuse { argv, access_plan },
        Err(reason) => bypass(reason),
    }
}

fn pass(reason: ReasonCode) -> Decision {
    Decision::PassThrough { reason }
}
fn bypass(reason: ReasonCode) -> Decision {
    Decision::BypassNoStore { reason }
}

fn reject_shell_syntax(raw: &str) -> Option<ReasonCode> {
    // Reject even quoted instances in v0; accepting fewer commands is safer
    // than trying to reproduce Bash quoting/expansion semantics here.
    if raw.contains([';', '|', '&', '<', '>']) || raw.contains("\\\n") {
        return Some(ReasonCode::ShellComposition);
    }
    if raw.contains(['$', '`', '~', '(', ')', '{', '}']) {
        return Some(ReasonCode::ShellExpansion);
    }
    if raw.contains(['*', '?', '[', ']']) {
        return Some(ReasonCode::GlobExpansion);
    }
    None
}

fn cwd_is_in_workspace(context: PolicyContext<'_>) -> bool {
    let workspace = normalize_existing_or_absolute(context.workspace);
    let cwd = normalize_existing_or_absolute(context.cwd);
    workspace.is_some_and(|workspace| cwd.is_some_and(|cwd| cwd.starts_with(workspace)))
}

fn normalize_existing_or_absolute(path: &Path) -> Option<PathBuf> {
    path.is_absolute()
        .then(|| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
}

fn classify_pwd(argv: &[String]) -> Result<AccessPlan, ReasonCode> {
    if argv.len() == 1 || (argv.len() == 2 && matches!(argv[1].as_str(), "-L" | "-P")) {
        Ok(AccessPlan {
            scopes: vec![AccessScope::IdentityOnly],
        })
    } else if argv.get(1).is_some_and(|arg| arg.starts_with('-')) {
        Err(ReasonCode::UnsafeFlag)
    } else {
        Err(ReasonCode::MissingOperand)
    }
}

#[derive(Clone, Copy)]
enum FileOptions {
    None,
    HeadTail,
    Wc,
    Ls,
}

fn classify_files(
    argv: &[String],
    options: FileOptions,
    require_file: bool,
    context: PolicyContext<'_>,
) -> Result<AccessPlan, ReasonCode> {
    let mut index = 1;
    let mut operands = 0;
    let mut options_done = false;
    let mut scopes = Vec::new();
    while index < argv.len() {
        let item = &argv[index];
        if !options_done && item == "--" {
            options_done = true;
            index += 1;
            continue;
        }
        if item == "-" {
            return Err(ReasonCode::StdinDependent);
        }
        if !options_done && item.starts_with('-') {
            index = consume_safe_file_option(argv, index, options)?;
            continue;
        }
        operands += 1;
        validate_path(item, context)?;
        let path = workspace_relative_path(item, context)?;
        scopes.push(match options {
            FileOptions::Ls => AccessScope::DirectoryListing(path),
            FileOptions::None | FileOptions::HeadTail | FileOptions::Wc => {
                AccessScope::ContentPath(path)
            }
        });
        index += 1;
    }
    if require_file && operands == 0 {
        Err(ReasonCode::StdinDependent)
    } else {
        if matches!(options, FileOptions::Ls) && operands == 0 {
            scopes.push(AccessScope::DirectoryListing(workspace_relative_path(
                ".", context,
            )?));
        }
        Ok(AccessPlan { scopes })
    }
}

fn consume_safe_file_option(
    argv: &[String],
    index: usize,
    options: FileOptions,
) -> Result<usize, ReasonCode> {
    let flag = argv[index].as_str();
    let safe = match options {
        FileOptions::None => false,
        FileOptions::HeadTail => matches!(flag, "-q" | "-v"),
        FileOptions::Wc => matches!(
            flag,
            "-c" | "-m"
                | "-l"
                | "-w"
                | "-L"
                | "--bytes"
                | "--chars"
                | "--lines"
                | "--words"
                | "--max-line-length"
        ),
        FileOptions::Ls => safe_ls_flag(flag),
    };
    if safe {
        return Ok(index + 1);
    }
    if matches!(options, FileOptions::HeadTail)
        && matches!(flag, "-n" | "-c" | "--lines" | "--bytes")
    {
        let value = argv.get(index + 1).ok_or(ReasonCode::UnsafeFlag)?;
        if value == "-" || value.starts_with('-') || value.is_empty() {
            return Err(ReasonCode::UnsafeFlag);
        }
        return Ok(index + 2);
    }
    if matches!(options, FileOptions::HeadTail)
        && (flag.starts_with("--lines=") || flag.starts_with("--bytes=") || short_count(flag))
    {
        return Ok(index + 1);
    }
    Err(ReasonCode::UnsafeFlag)
}

fn safe_ls_flag(flag: &str) -> bool {
    matches!(
        flag,
        "-a" | "-A"
            | "-d"
            | "-F"
            | "-r"
            | "-S"
            | "-t"
            | "-U"
            | "-1"
            | "--all"
            | "--almost-all"
            | "--directory"
            | "--classify"
            | "--reverse"
            | "--sort=name"
            | "--sort=time"
            | "--sort=size"
            | "--time=mtime"
            | "--color=never"
    ) || (flag.starts_with('-')
        && flag.len() > 2
        && flag[1..]
            .chars()
            .all(|c| matches!(c, 'a' | 'A' | 'd' | 'F' | 'r' | 'S' | 't' | 'U' | '1')))
}

fn short_count(flag: &str) -> bool {
    let bytes = flag.as_bytes();
    bytes.len() > 2
        && bytes[0] == b'-'
        && (bytes[1] == b'n' || bytes[1] == b'c')
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

fn classify_search(
    argv: &[String],
    is_rg: bool,
    context: PolicyContext<'_>,
) -> Result<AccessPlan, ReasonCode> {
    let mut index = 1;
    let mut no_ignore = false;
    while index < argv.len() {
        let item = &argv[index];
        if item == "--" {
            index += 1;
            break;
        }
        if item.starts_with('-') {
            if safe_search_flag(item, is_rg) {
                no_ignore |= item == "--no-ignore";
                index += 1;
                continue;
            }
            return Err(ReasonCode::UnsafeFlag);
        }
        break;
    }
    let pattern = argv.get(index).ok_or(ReasonCode::MissingOperand)?;
    if pattern == "-" {
        return Err(ReasonCode::StdinDependent);
    }
    index += 1;
    let first_path = index;
    let mut scopes = Vec::new();
    let mut recursive_input = false;
    while index < argv.len() {
        validate_path(&argv[index], context)?;
        recursive_input |= context.cwd.join(&argv[index]).is_dir();
        let path = workspace_relative_path(&argv[index], context)?;
        scopes.push(if is_rg {
            AccessScope::RecursiveContentTree(path)
        } else {
            AccessScope::ContentPath(path)
        });
        index += 1;
    }
    if !is_rg && first_path == argv.len() {
        Err(ReasonCode::StdinDependent)
    } else {
        if is_rg && first_path == argv.len() {
            recursive_input = true;
            scopes.push(AccessScope::RecursiveContentTree(workspace_relative_path(
                ".", context,
            )?));
        }
        // Recursive ripgrep normally consults parent, repository and global ignore
        // files that are not represented by a narrow content scope. Requiring
        // `--no-ignore` removes those ambient filesystem inputs. Explicit regular
        // file operands remain eligible without it.
        if is_rg && recursive_input && !no_ignore {
            return Err(ReasonCode::UnsafeFlag);
        }
        Ok(AccessPlan { scopes })
    }
}

fn safe_search_flag(flag: &str, is_rg: bool) -> bool {
    let common = matches!(
        flag,
        "-i" | "-n"
            | "-H"
            | "-h"
            | "-v"
            | "-w"
            | "-x"
            | "-F"
            | "-E"
            | "--fixed-strings"
            | "--ignore-case"
            | "--line-number"
            | "--with-filename"
            | "--no-filename"
            | "--invert-match"
            | "--word-regexp"
            | "--line-regexp"
    );
    common || (is_rg && matches!(flag, "--no-ignore" | "--no-messages" | "--count" | "-c"))
}

fn validate_path(value: &str, context: PolicyContext<'_>) -> Result<(), ReasonCode> {
    if value == "-" {
        return Err(ReasonCode::StdinDependent);
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(ReasonCode::AbsolutePath);
    }
    if path.components().any(|part| {
        matches!(
            part,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(ReasonCode::OutsideWorkspace);
    }
    if is_excluded_runtime_path(path) {
        return Err(ReasonCode::ExcludedRuntimePath);
    }
    // An existing symlink can escape even when its spelling is relative.
    if let Ok(resolved) = std::fs::canonicalize(context.cwd.join(path)) {
        let workspace = normalize_existing_or_absolute(context.workspace)
            .ok_or(ReasonCode::OutsideWorkspace)?;
        if !resolved.starts_with(workspace) {
            return Err(ReasonCode::OutsideWorkspace);
        }
    }
    Ok(())
}

fn is_excluded_runtime_path(path: &Path) -> bool {
    let parts: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect();
    if parts.contains(&".again") {
        return true;
    }
    if parts
        .windows(2)
        .any(|pair| pair[0] == ".git" && pair[1] == "logs")
    {
        return true;
    }
    parts
        .iter()
        .position(|part| *part == ".git")
        .is_some_and(|git| parts[git + 1..].iter().any(|part| part.ends_with(".lock")))
}

fn workspace_relative_path(value: &str, context: PolicyContext<'_>) -> Result<PathBuf, ReasonCode> {
    validate_path(value, context)?;
    let workspace =
        normalize_existing_or_absolute(context.workspace).ok_or(ReasonCode::OutsideWorkspace)?;
    let cwd = normalize_existing_or_absolute(context.cwd).ok_or(ReasonCode::OutsideWorkspace)?;
    let cwd_relative = cwd
        .strip_prefix(workspace)
        .map_err(|_| ReasonCode::OutsideWorkspace)?;
    let mut relative = PathBuf::new();
    for component in cwd_relative.join(value).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ReasonCode::OutsideWorkspace);
            }
        }
    }
    if relative.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(relative)
    }
}

fn is_network_command(command: &str) -> bool {
    matches!(
        command,
        "curl"
            | "wget"
            | "ssh"
            | "scp"
            | "sftp"
            | "rsync"
            | "nc"
            | "ncat"
            | "netcat"
            | "ping"
            | "telnet"
            | "ftp"
            | "dig"
            | "nslookup"
    )
}

fn is_mutating_command(command: &str) -> bool {
    matches!(
        command,
        "rm" | "mv"
            | "cp"
            | "mkdir"
            | "rmdir"
            | "touch"
            | "tee"
            | "chmod"
            | "chown"
            | "ln"
            | "install"
            | "sed"
            | "perl"
            | "python"
            | "python3"
            | "node"
            | "npm"
            | "pnpm"
            | "yarn"
            | "pip"
            | "pip3"
            | "cargo"
            | "make"
            | "bash"
            | "sh"
            | "zsh"
            | "sudo"
            | "doas"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn context(temp: &TempDir) -> PolicyContext<'_> {
        PolicyContext::new(temp.path(), temp.path())
    }
    fn assert_exact(command: &str, temp: &TempDir, argv: &[&str]) {
        let decision = classify(command, context(temp));
        assert_eq!(
            decision.argv(),
            Some(&argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()[..]),
            "{command}"
        );
        assert!(decision.access_plan().is_some(), "{command}");
    }
    fn assert_bypass(command: &str, temp: &TempDir, reason: ReasonCode) {
        assert_eq!(
            classify(command, context(temp)),
            Decision::BypassNoStore { reason },
            "{command}"
        );
    }

    #[test]
    fn admits_only_simple_read_only_commands() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("readme.txt"), "hello\n").unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        let cases: &[(&str, &[&str])] = &[
            ("cat readme.txt", &["cat", "readme.txt"]),
            ("head -n 1 readme.txt", &["head", "-n", "1", "readme.txt"]),
            (
                "tail --lines=1 readme.txt",
                &["tail", "--lines=1", "readme.txt"],
            ),
            ("wc -l readme.txt", &["wc", "-l", "readme.txt"]),
            ("ls -a src", &["ls", "-a", "src"]),
            ("pwd -P", &["pwd", "-P"]),
            (
                "rg --no-ignore needle .",
                &["rg", "--no-ignore", "needle", "."],
            ),
            (
                "grep -n needle readme.txt",
                &["grep", "-n", "needle", "readme.txt"],
            ),
        ];
        for (command, argv) in cases {
            assert_exact(command, &temp, argv);
        }
    }

    #[test]
    fn exact_reuse_has_minimal_deterministic_access_plans() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("a.txt"), "a").unwrap();
        std::fs::write(temp.path().join("b.txt"), "b").unwrap();
        let cases: &[(&str, Vec<AccessScope>)] = &[
            ("pwd", vec![AccessScope::IdentityOnly]),
            (
                "cat a.txt b.txt",
                vec![
                    AccessScope::ContentPath(PathBuf::from("a.txt")),
                    AccessScope::ContentPath(PathBuf::from("b.txt")),
                ],
            ),
            (
                "grep needle a.txt",
                vec![AccessScope::ContentPath(PathBuf::from("a.txt"))],
            ),
            (
                "rg --no-ignore needle src",
                vec![AccessScope::RecursiveContentTree(PathBuf::from("src"))],
            ),
            (
                "rg --no-ignore needle",
                vec![AccessScope::RecursiveContentTree(PathBuf::from("."))],
            ),
            (
                "ls src",
                vec![AccessScope::DirectoryListing(PathBuf::from("src"))],
            ),
            (
                "ls",
                vec![AccessScope::DirectoryListing(PathBuf::from("."))],
            ),
        ];
        for (command, scopes) in cases {
            let decision = classify(command, context(&temp));
            assert_eq!(
                decision.access_plan(),
                Some(&AccessPlan {
                    scopes: scopes.clone()
                }),
                "{command}"
            );
        }
    }

    #[test]
    fn all_git_commands_pass_through_without_cache_admission() {
        let temp = TempDir::new().unwrap();
        let commands = [
            "git status --short",
            "git diff --cached --no-color",
            "git show HEAD",
            "git log main",
            "git rev-parse --show-toplevel",
            "git cat-file -t HEAD",
            "git push origin main",
            "git config --get user.name",
        ];
        for command in commands {
            assert_eq!(
                classify(command, context(&temp)),
                Decision::PassThrough {
                    reason: ReasonCode::UnsupportedCommand
                },
                "{command}"
            );
        }
    }

    #[test]
    fn bypasses_shell_syntax_and_expansion() {
        let temp = TempDir::new().unwrap();
        let cases = [
            ("cat a; cat b", ReasonCode::ShellComposition),
            ("cat a && cat b", ReasonCode::ShellComposition),
            ("cat a | wc -l", ReasonCode::ShellComposition),
            ("cat < a", ReasonCode::ShellComposition),
            ("cat a > out", ReasonCode::ShellComposition),
            ("cat $(pwd)/a", ReasonCode::ShellExpansion),
            ("cat `pwd`/a", ReasonCode::ShellExpansion),
            ("cat $HOME/a", ReasonCode::ShellExpansion),
            ("cat *.rs", ReasonCode::GlobExpansion),
            ("rg 'foo?' .", ReasonCode::GlobExpansion),
            ("cat a\ncat b", ReasonCode::Newline),
        ];
        for (command, reason) in cases {
            assert_bypass(command, &temp, reason);
        }
    }

    #[test]
    fn rejects_paths_stdin_flags_and_wrappers() {
        let temp = TempDir::new().unwrap();
        let cases = [
            ("cat /etc/passwd", ReasonCode::AbsolutePath),
            ("cat ../secret", ReasonCode::OutsideWorkspace),
            ("cat -", ReasonCode::StdinDependent),
            ("head", ReasonCode::StdinDependent),
            ("grep needle", ReasonCode::StdinDependent),
            ("cat --help", ReasonCode::UnsafeFlag),
            ("ls -l", ReasonCode::UnsafeFlag),
            ("rg needle .", ReasonCode::UnsafeFlag),
            ("rg --hidden --no-ignore needle .", ReasonCode::UnsafeFlag),
            ("cat .again/cache", ReasonCode::ExcludedRuntimePath),
            ("cat .git/logs/HEAD", ReasonCode::ExcludedRuntimePath),
            ("cat .git/index.lock", ReasonCode::ExcludedRuntimePath),
            ("again cat readme.txt", ReasonCode::AlreadyWrapped),
            ("/usr/bin/cat readme.txt", ReasonCode::AbsolutePath),
        ];
        for (command, reason) in cases {
            assert_bypass(command, &temp, reason);
        }
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "no").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), temp.path().join("escape"))
            .unwrap();
        assert_bypass("cat escape", &temp, ReasonCode::OutsideWorkspace);
    }

    #[test]
    fn known_effectful_commands_bypass_and_unknowns_pass_through() {
        let temp = TempDir::new().unwrap();
        let bypasses = [
            ("curl https://example.com", ReasonCode::NetworkCommand),
            ("wget https://example.com", ReasonCode::NetworkCommand),
            ("rm readme.txt", ReasonCode::MutatingCommand),
            ("npm install", ReasonCode::MutatingCommand),
        ];
        for (command, reason) in bypasses {
            assert_bypass(command, &temp, reason);
        }
        assert_eq!(
            classify("echo harmless", context(&temp)),
            Decision::PassThrough {
                reason: ReasonCode::UnsupportedCommand
            }
        );
        assert_eq!(
            classify("'unterminated", context(&temp)),
            Decision::PassThrough {
                reason: ReasonCode::ParseError
            }
        );
        assert_eq!(
            classify("   ", context(&temp)),
            Decision::PassThrough {
                reason: ReasonCode::EmptyCommand
            }
        );
    }

    #[test]
    fn refuses_tty_or_cwd_outside_workspace() {
        let temp = TempDir::new().unwrap();
        let mut tty = context(&temp);
        tty.stdout_is_tty = true;
        assert_eq!(
            classify("pwd", tty),
            Decision::BypassNoStore {
                reason: ReasonCode::TtyDependent
            }
        );
        let outside = tempfile::tempdir().unwrap();
        assert_eq!(
            classify("pwd", PolicyContext::new(temp.path(), outside.path())),
            Decision::BypassNoStore {
                reason: ReasonCode::OutsideWorkspace
            }
        );
    }

    #[test]
    fn reason_codes_are_stable() {
        assert_eq!(ReasonCode::UnsafeFlag.as_str(), "UNSAFE_FLAG");
        assert_eq!(
            serde_json::to_string(&ReasonCode::NetworkCommand).unwrap(),
            "\"NETWORK_COMMAND\""
        );
    }
}
