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
    /// Automatic shell-hook rewriting must not change how argv[0] resolves.
    /// When set, only an explicit absolute executable path is admissible;
    /// bare names could resolve through aliases, functions, or shell startup
    /// files that a direct wrapper execution cannot observe.
    pub require_explicit_executable: bool,
}

impl<'a> PolicyContext<'a> {
    pub fn new(workspace: &'a Path, cwd: &'a Path) -> Self {
        Self {
            workspace,
            cwd,
            stdin_is_tty: false,
            stdout_is_tty: false,
            require_explicit_executable: false,
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
    ShellResolutionAmbiguous,
    TtyDependent,
    StdinDependent,
    AbsolutePath,
    OutsideWorkspace,
    ExcludedRuntimePath,
    UnsupportedPath,
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
            Self::ShellResolutionAmbiguous => "SHELL_RESOLUTION_AMBIGUOUS",
            Self::TtyDependent => "TTY_DEPENDENT",
            Self::StdinDependent => "STDIN_DEPENDENT",
            Self::AbsolutePath => "ABSOLUTE_PATH",
            Self::OutsideWorkspace => "OUTSIDE_WORKSPACE",
            Self::ExcludedRuntimePath => "EXCLUDED_RUNTIME_PATH",
            Self::UnsupportedPath => "UNSUPPORTED_PATH",
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
    let program_path = Path::new(&argv[0]);
    let program = if context.require_explicit_executable {
        if !program_path.is_absolute() {
            return bypass(ReasonCode::ShellResolutionAmbiguous);
        }
        match program_path.file_name().and_then(|name| name.to_str()) {
            Some(name) if !name.is_empty() => name,
            _ => return bypass(ReasonCode::ShellResolutionAmbiguous),
        }
    } else {
        if program_path.is_absolute() {
            return bypass(ReasonCode::AbsolutePath);
        }
        argv[0].as_str()
    };
    if !cwd_is_in_workspace(context) {
        return bypass(ReasonCode::OutsideWorkspace);
    }
    if is_network_command(program) {
        return bypass(ReasonCode::NetworkCommand);
    }
    if is_mutating_command(program) {
        return bypass(ReasonCode::MutatingCommand);
    }

    let result = match program {
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
    if argv.len() == 2 && argv[1] == "-P" {
        Ok(AccessPlan {
            scopes: vec![AccessScope::IdentityOnly],
        })
    } else {
        // Default pwd and -L consult logical PWD resolution. V0 does not bind
        // the filesystem identity of every component in that environment path.
        Err(ReasonCode::UnsafeFlag)
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
    if matches!(options, FileOptions::Ls)
        && (!ls_explicitly_disables_color(argv) || !ls_option_mix_supported(argv))
    {
        return Err(ReasonCode::UnsafeFlag);
    }
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
        if matches!(options, FileOptions::HeadTail)
            && argv
                .first()
                .is_some_and(|program| program.ends_with("tail"))
            && !options_done
            && operands == 0
            && item.starts_with('+')
        {
            // BSD tail's legacy +N/+Nc forms are options that read stdin, not
            // filenames. An explicit preceding `--` remains an unambiguous
            // filename escape.
            return Err(ReasonCode::UnsafeFlag);
        }
        if !options_done && item.starts_with('-') {
            index = consume_safe_file_option(argv, index, options)?;
            continue;
        }
        operands += 1;
        validate_path(item, context)?;
        if matches!(options, FileOptions::Ls)
            && std::fs::symlink_metadata(context.cwd.join(item))
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            // Default ls follows a command-line symlink to a directory, while
            // -d observes the link itself. V0 deliberately models neither
            // branch until its access plan carries that option-dependent
            // distinction. The fingerprinter independently rejects this case
            // to close the classify/fingerprint race.
            return Err(ReasonCode::UnsupportedPath);
        }
        let path = workspace_relative_path(item, context)?;
        scopes.push(match options {
            FileOptions::Ls => AccessScope::DirectoryListing(path),
            FileOptions::None | FileOptions::HeadTail | FileOptions::Wc => {
                AccessScope::ContentPath(path)
            }
        });
        // The audited macOS file utilities stop option parsing at the first
        // operand. Every later token, including `--` or a leading dash, is a
        // filename and must therefore be represented in the access plan.
        options_done = true;
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
            .all(|c| matches!(c, 'a' | 'A' | 'd' | 'F' | 'r' | 'S' | 't' | '1')))
}

fn ls_explicitly_disables_color(argv: &[String]) -> bool {
    for value in argv.iter().skip(1) {
        if value == "--" || !value.starts_with('-') || value == "-" {
            break;
        }
        if value == "--color=never" {
            return true;
        }
    }
    false
}

/// `ls -a` includes the synthetic `.` and `..` entries. Sorting those entries by
/// time or size observes parent-directory metadata outside a narrow listing
/// scope, so that option combination must pass through until it is modeled.
fn ls_option_mix_supported(argv: &[String]) -> bool {
    let mut includes_dot_and_dotdot = false;
    let mut metadata_sort = false;

    for flag in argv.iter().skip(1) {
        if flag == "--" || !flag.starts_with('-') || flag == "-" {
            break;
        }
        includes_dot_and_dotdot |= flag == "-a"
            || flag == "--all"
            || (flag.starts_with('-') && !flag.starts_with("--") && flag[1..].contains('a'));
        metadata_sort |= matches!(flag.as_str(), "-t" | "-S" | "--sort=time" | "--sort=size")
            || (flag.starts_with('-')
                && !flag.starts_with("--")
                && flag[1..].chars().any(|value| matches!(value, 't' | 'S')));
    }

    !(includes_dot_and_dotdot && metadata_sort)
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
    let mut sort_path = false;
    let mut options_done = false;
    while index < argv.len() {
        let item = &argv[index];
        if item == "--" {
            options_done = true;
            index += 1;
            break;
        }
        if item.starts_with('-') {
            if safe_search_flag(item, is_rg) {
                no_ignore |= item == "--no-ignore";
                sort_path |= item == "--sort=path";
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
    while index < argv.len() {
        // GNU grep and ripgrep accept options after the pattern. Treating such
        // a token as a path can omit the command's real recursive input from
        // the access plan (for example `rg needle -n`). An explicit pre-pattern
        // `--` is the only case in which a dash-prefixed token is unambiguously
        // positional in this deliberately small parser.
        if !options_done && argv[index].starts_with('-') {
            return Err(ReasonCode::UnsafeFlag);
        }
        validate_path(&argv[index], context)?;
        let operand_is_directory = context.cwd.join(&argv[index]).is_dir();
        let path = workspace_relative_path(&argv[index], context)?;
        if is_rg
            && operand_is_directory
            && recursive_rg_directory_targets_git(&argv[index], &path, context)
        {
            return Err(ReasonCode::UnsupportedPath);
        }
        scopes.push(if is_rg {
            AccessScope::RecursiveContentTree(path)
        } else {
            AccessScope::ContentPath(path)
        });
        index += 1;
    }
    if first_path == argv.len() {
        // Both grep and rg can switch to stdin when it is readable. V0 does
        // not model stdin source/content, so require at least one explicit
        // path even though interactive rg often defaults to the current tree.
        Err(ReasonCode::StdinDependent)
    } else {
        // Every ripgrep request must disable ambient ignore files and select
        // deterministic path ordering. Requiring both even for a currently
        // regular-file operand closes the race where it becomes a directory
        // between classification and fingerprinting.
        if is_rg && (!no_ignore || !sort_path) {
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
            | "-v"
            | "-w"
            | "-x"
            | "-F"
            | "--fixed-strings"
            | "--ignore-case"
            | "--line-number"
            | "--with-filename"
            | "--no-filename"
            | "--invert-match"
            | "--word-regexp"
            | "--line-regexp"
    );
    common
        || (!is_rg && matches!(flag, "-E" | "-h"))
        || (is_rg
            && matches!(
                flag,
                "--no-ignore" | "--no-messages" | "--count" | "-c" | "--sort=path"
            ))
}

fn recursive_rg_directory_targets_git(
    spelling: &str,
    relative: &Path,
    context: PolicyContext<'_>,
) -> bool {
    if first_normal_component_is_git(relative) {
        return true;
    }
    let Ok(workspace) = std::fs::canonicalize(context.workspace) else {
        return true;
    };
    let Ok(canonical) = std::fs::canonicalize(context.cwd.join(spelling)) else {
        return false;
    };
    canonical
        .strip_prefix(workspace)
        .is_ok_and(first_normal_component_is_git)
}

fn first_normal_component_is_git(path: &Path) -> bool {
    path.components().find_map(|component| match component {
        Component::Normal(value) => Some(value == ".git"),
        Component::CurDir => None,
        Component::ParentDir | Component::RootDir | Component::Prefix(_) => Some(false),
    }) == Some(true)
}

fn validate_path(value: &str, context: PolicyContext<'_>) -> Result<(), ReasonCode> {
    if value.is_empty() {
        return Err(ReasonCode::UnsupportedPath);
    }
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
            (
                "ls --color=never -a src",
                &["ls", "--color=never", "-a", "src"],
            ),
            ("pwd -P", &["pwd", "-P"]),
            (
                "rg --no-ignore --sort=path needle .",
                &["rg", "--no-ignore", "--sort=path", "needle", "."],
            ),
            (
                "grep -n needle readme.txt",
                &["grep", "-n", "needle", "readme.txt"],
            ),
            ("grep '' readme.txt", &["grep", "", "readme.txt"]),
        ];
        for (command, argv) in cases {
            assert_exact(command, &temp, argv);
        }
    }

    #[test]
    fn hook_mode_requires_an_explicit_absolute_executable() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("readme.txt"), "hello\n").unwrap();
        let mut hook_context = context(&temp);
        hook_context.require_explicit_executable = true;

        assert_eq!(
            classify("cat readme.txt", hook_context),
            Decision::BypassNoStore {
                reason: ReasonCode::ShellResolutionAmbiguous
            }
        );
        assert_eq!(
            classify("bin/cat readme.txt", hook_context),
            Decision::BypassNoStore {
                reason: ReasonCode::ShellResolutionAmbiguous
            }
        );
        assert_eq!(
            classify("/bin/cat readme.txt", hook_context).argv(),
            Some(&["/bin/cat".to_owned(), "readme.txt".to_owned()][..])
        );
        assert_eq!(
            classify("/usr/bin/curl https://example.invalid", hook_context),
            Decision::BypassNoStore {
                reason: ReasonCode::NetworkCommand
            }
        );
        assert_eq!(
            classify("/bin/rm readme.txt", hook_context),
            Decision::BypassNoStore {
                reason: ReasonCode::MutatingCommand
            }
        );
    }

    #[test]
    fn exact_reuse_has_minimal_deterministic_access_plans() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("a.txt"), "a").unwrap();
        std::fs::write(temp.path().join("b.txt"), "b").unwrap();
        let cases: &[(&str, Vec<AccessScope>)] = &[
            ("pwd -P", vec![AccessScope::IdentityOnly]),
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
                "rg --no-ignore --sort=path needle src",
                vec![AccessScope::RecursiveContentTree(PathBuf::from("src"))],
            ),
            (
                "ls --color=never src",
                vec![AccessScope::DirectoryListing(PathBuf::from("src"))],
            ),
            (
                "ls --color=never",
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
            ("cat '' readme.txt", ReasonCode::UnsupportedPath),
            ("cat ../secret", ReasonCode::OutsideWorkspace),
            ("cat -", ReasonCode::StdinDependent),
            ("head", ReasonCode::StdinDependent),
            ("tail +1", ReasonCode::UnsafeFlag),
            ("tail +1c", ReasonCode::UnsafeFlag),
            ("grep needle", ReasonCode::StdinDependent),
            ("cat --help", ReasonCode::UnsafeFlag),
            ("ls -l", ReasonCode::UnsafeFlag),
            ("rg needle .", ReasonCode::UnsafeFlag),
            (
                "rg --no-ignore --sort=path needle",
                ReasonCode::StdinDependent,
            ),
            ("rg --hidden --no-ignore needle .", ReasonCode::UnsafeFlag),
            ("rg --no-ignore needle .", ReasonCode::UnsafeFlag),
            ("rg needle -n", ReasonCode::UnsafeFlag),
            ("rg needle --no-ignore", ReasonCode::UnsafeFlag),
            ("rg -E utf-8 needle", ReasonCode::UnsafeFlag),
            ("rg -h needle readme.txt", ReasonCode::UnsafeFlag),
            ("grep needle -n readme.txt", ReasonCode::UnsafeFlag),
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
    fn rejects_ls_symlink_operands_until_follow_semantics_are_modeled() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir(temp.path().join("target")).unwrap();
        std::os::unix::fs::symlink("target", temp.path().join("linked")).unwrap();

        assert_bypass(
            "ls --color=never linked",
            &temp,
            ReasonCode::UnsupportedPath,
        );
        assert_bypass(
            "ls --color=never -d linked",
            &temp,
            ReasonCode::UnsupportedPath,
        );
    }

    #[test]
    fn rejects_ls_all_with_parent_metadata_sorting() {
        let temp = TempDir::new().unwrap();
        for command in [
            "ls --color=never -at",
            "ls --color=never -aS",
            "ls --color=never --all --sort=time",
            "ls --color=never --all --sort=size",
        ] {
            assert_bypass(command, &temp, ReasonCode::UnsafeFlag);
        }
        assert_exact(
            "ls --color=never -ar",
            &temp,
            &["ls", "--color=never", "-ar"],
        );
        assert_exact(
            "ls --color=never -At",
            &temp,
            &["ls", "--color=never", "-At"],
        );
    }

    #[test]
    fn recursive_rg_rejects_git_directories_and_requires_path_sorting() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir(temp.path().join(".git")).unwrap();
        std::fs::create_dir_all(temp.path().join(".git/refs")).unwrap();
        std::fs::create_dir(temp.path().join("tree")).unwrap();
        std::os::unix::fs::symlink(".git", temp.path().join("git-alias")).unwrap();

        assert_bypass(
            "rg --no-ignore --sort=path needle .git",
            &temp,
            ReasonCode::UnsupportedPath,
        );
        assert_bypass(
            "rg --no-ignore --sort=path needle .git/refs",
            &temp,
            ReasonCode::UnsupportedPath,
        );
        assert_bypass(
            "rg --no-ignore --sort=path needle git-alias",
            &temp,
            ReasonCode::UnsupportedPath,
        );
        assert_bypass("rg --no-ignore needle tree", &temp, ReasonCode::UnsafeFlag);
        assert_exact(
            "rg --no-ignore --sort=path needle tree",
            &temp,
            &["rg", "--no-ignore", "--sort=path", "needle", "tree"],
        );
    }

    #[test]
    fn macos_file_options_stop_at_the_first_operand() {
        let temp = TempDir::new().unwrap();
        let cases = [
            (
                "cat readme.txt --",
                vec![
                    AccessScope::ContentPath(PathBuf::from("readme.txt")),
                    AccessScope::ContentPath(PathBuf::from("--")),
                ],
            ),
            (
                "head readme.txt -n 1",
                vec![
                    AccessScope::ContentPath(PathBuf::from("readme.txt")),
                    AccessScope::ContentPath(PathBuf::from("-n")),
                    AccessScope::ContentPath(PathBuf::from("1")),
                ],
            ),
            (
                "wc readme.txt -l",
                vec![
                    AccessScope::ContentPath(PathBuf::from("readme.txt")),
                    AccessScope::ContentPath(PathBuf::from("-l")),
                ],
            ),
            (
                "ls --color=never src -1",
                vec![
                    AccessScope::DirectoryListing(PathBuf::from("src")),
                    AccessScope::DirectoryListing(PathBuf::from("-1")),
                ],
            ),
        ];

        for (command, scopes) in cases {
            assert_eq!(
                classify(command, context(&temp)).access_plan(),
                Some(&AccessPlan { scopes }),
                "{command}"
            );
        }
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
