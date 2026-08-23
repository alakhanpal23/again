//! Content-derived request fingerprints for the conservative macOS v0.
//!
//! The legacy whole-workspace fingerprint ignores access, creation, and modification
//! times. The scoped execution proof additionally binds Unix identity/change epochs
//! so a byte-for-byte ABA mutation between validation runs cannot look unchanged.
//! Callers must provide the complete environment visible to the child process; the
//! returned value contains only digests of environment names and values.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use blake3::{Hash, Hasher};
use thiserror::Error;

const FORMAT_VERSION: &[u8] = b"again-fingerprint-v2";

/// All execution inputs needed to construct a cache request fingerprint.
///
/// `executable` must be the executable selected after `PATH` resolution. `argv`
/// remains the exact argument vector supplied to that executable. `environment`
/// must be the complete environment, rather than an overlay on the parent process.
/// The slice may be in any order, but duplicate names are rejected.
///
/// This type intentionally does not implement `Debug`, preventing accidental logs
/// from printing plaintext environment values.
pub struct FingerprintInput<'a> {
    pub argv: &'a [OsString],
    pub cwd: &'a Path,
    pub workspace: &'a Path,
    pub environment: &'a [(OsString, OsString)],
    pub executable: &'a Path,
}

/// Stable component fingerprints consumed by the execution engine and cache index.
///
/// Every digest is lower-case BLAKE3 hex. Environment plaintext is never retained in
/// this result. Canonical paths are returned so the engine can execute against the
/// same identities that were fingerprinted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FingerprintResult {
    pub request_digest: String,
    pub workspace_digest: String,
    pub workspace_tree_digest: String,
    pub environment_digest: String,
    pub executable_digest: String,
    pub canonical_workspace: PathBuf,
    pub canonical_cwd: PathBuf,
    pub canonical_executable: PathBuf,
    /// Number of included filesystem nodes, including the workspace root.
    pub workspace_entries: u64,
}

/// A conservative description of the workspace state visible to one command.
///
/// Paths are always workspace-relative. `ContentPath` follows in-workspace
/// symlinks and hashes the resolved file/tree. `DirectoryListing` observes one
/// directory level without opening regular-file contents. `WholeWorkspace` is
/// useful as a fail-safe fallback and subsumes every other entry in the slice.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ScopeEntry {
    /// Only canonical workspace and cwd identity affect the request.
    IdentityOnly,
    /// Hash a regular file's content, or a directory recursively.
    ContentPath(PathBuf),
    /// Explicit recursive-tree form used by recursive search commands.
    RecursiveContentTree(PathBuf),
    /// Hash one directory listing, or only a file operand's metadata.
    DirectoryListing(PathBuf),
    /// Hash the complete workspace using scoped (mtime-sensitive) metadata.
    WholeWorkspace,
}

/// The complete Unix identity/change tuple used to validate a memoized file digest.
///
/// A cache hit is permitted only when every field matches. In particular, inode and
/// ctime prevent the common unsafe shortcuts of trusting only size and mtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    /// Full Unix mode, including the file-type bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.len(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime_sec: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    /// Reject impossible timestamps before consulting persistent state.
    pub fn is_valid(&self) -> bool {
        (0..1_000_000_000).contains(&self.mtime_nsec)
            && (0..1_000_000_000).contains(&self.ctime_nsec)
    }
}

/// Optional optimization for content hashing.
///
/// Implementations must treat any storage or validation problem as a miss. The
/// fingerprinting layer independently re-stats paths around both hits and reads,
/// and records a digest only after a stable byte read.
pub trait FileDigestCache {
    fn lookup(&mut self, identity: &FileIdentity) -> Option<[u8; 32]>;
    fn record(&mut self, identity: &FileIdentity, digest: [u8; 32]);
}

#[derive(Default)]
struct NoFileDigestCache;

impl FileDigestCache for NoFileDigestCache {
    fn lookup(&mut self, _identity: &FileIdentity) -> Option<[u8; 32]> {
        None
    }

    fn record(&mut self, _identity: &FileIdentity, _digest: [u8; 32]) {}
}

#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("command argv must contain argv[0]")]
    EmptyArgv,

    #[error("at least one fingerprint scope entry is required")]
    EmptyScope,

    #[error("scope path must be relative to the workspace: {0}")]
    AbsoluteScopePath(PathBuf),

    #[error("scope path is inside an excluded runtime path: {0}")]
    ExcludedScopePath(PathBuf),

    #[error("symlink cycle encountered while hashing scoped content: {0}")]
    SymlinkCycle(PathBuf),

    #[error("directory-listing symlink operands require option-aware semantics: {0}")]
    SymlinkListingOperand(PathBuf),

    #[error("workspace is not a directory: {0}")]
    WorkspaceNotDirectory(PathBuf),

    #[error("working directory is not a directory: {0}")]
    WorkingDirectoryNotDirectory(PathBuf),

    #[error("executable is not a regular file: {0}")]
    ExecutableNotRegular(PathBuf),

    #[error("{kind} path escapes workspace `{workspace}`: {path}")]
    PathEscapesWorkspace {
        kind: &'static str,
        path: PathBuf,
        workspace: PathBuf,
    },

    #[error("working directory is inside an excluded runtime path: {0}")]
    ExcludedWorkingDirectory(PathBuf),

    #[error("symlink targets an excluded runtime path: {0}")]
    SymlinkTargetsExcludedPath(PathBuf),

    #[error("special filesystem entry is not fingerprintable: {0}")]
    SpecialFile(PathBuf),

    #[error("filesystem entry changed while fingerprinting `{path}`")]
    ConcurrentMutation { path: PathBuf },

    #[error("environment contains a duplicate name (name digest {name_digest})")]
    DuplicateEnvironmentName { name_digest: String },

    #[error("cannot {operation} `{path}`")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Fingerprint a complete request and its workspace.
pub fn fingerprint(input: &FingerprintInput<'_>) -> Result<FingerprintResult, FingerprintError> {
    if input.argv.is_empty() {
        return Err(FingerprintError::EmptyArgv);
    }

    let canonical_workspace = canonicalize(input.workspace, "canonicalize workspace")?;
    let workspace_metadata = metadata(&canonical_workspace, "inspect workspace")?;
    if !workspace_metadata.is_dir() {
        return Err(FingerprintError::WorkspaceNotDirectory(canonical_workspace));
    }

    let canonical_cwd = canonicalize(input.cwd, "canonicalize working directory")?;
    let cwd_metadata = metadata(&canonical_cwd, "inspect working directory")?;
    if !cwd_metadata.is_dir() {
        return Err(FingerprintError::WorkingDirectoryNotDirectory(
            canonical_cwd,
        ));
    }
    ensure_within(&canonical_cwd, &canonical_workspace, "working directory")?;
    let cwd_relative = canonical_cwd
        .strip_prefix(&canonical_workspace)
        .expect("ensure_within established prefix");
    if is_excluded_namespace(cwd_relative) {
        return Err(FingerprintError::ExcludedWorkingDirectory(canonical_cwd));
    }

    let canonical_executable = canonicalize(input.executable, "canonicalize executable")?;
    let executable_fingerprint = fingerprint_executable(&canonical_executable)?;
    let environment_fingerprint = fingerprint_environment(input.environment)?;
    let command_fingerprint = fingerprint_argv(input.argv);
    let cwd_fingerprint = hash_fields(
        "again.cwd.v1",
        [
            canonical_workspace.as_os_str().as_bytes(),
            cwd_relative.as_os_str().as_bytes(),
        ],
    );

    let mut walker = WorkspaceWalker {
        root: &canonical_workspace,
    };
    let workspace_tree = walker.walk(&canonical_workspace, Path::new(""))?;
    let workspace_fingerprint = hash_fields(
        "again.workspace.identity.v1",
        [
            canonical_workspace.as_os_str().as_bytes(),
            workspace_tree.digest.as_bytes(),
        ],
    );

    let request_fingerprint = hash_fields(
        "again.request.v1",
        [
            FORMAT_VERSION,
            command_fingerprint.as_bytes(),
            cwd_fingerprint.as_bytes(),
            workspace_fingerprint.as_bytes(),
            environment_fingerprint.as_bytes(),
            executable_fingerprint.as_bytes(),
        ],
    );

    Ok(FingerprintResult {
        request_digest: hex(request_fingerprint),
        workspace_digest: hex(workspace_fingerprint),
        workspace_tree_digest: hex(workspace_tree.digest),
        environment_digest: hex(environment_fingerprint),
        executable_digest: hex(executable_fingerprint),
        canonical_workspace,
        canonical_cwd,
        canonical_executable,
        workspace_entries: workspace_tree.entries,
    })
}

/// Fingerprint only the workspace state described by `scopes`.
///
/// This preserves the command, cwd, environment, executable, and request component
/// encodings used by [`fingerprint`], while replacing its expensive generic tree
/// with an explicit scope Merkle root. Unlike the legacy whole-workspace walker,
/// scoped filesystem metadata includes device, inode, size, ownership, and
/// nanosecond mtime/ctime because commands such as `ls -l` and `ls -t` expose
/// metadata while the identity/ctime epoch prevents byte-for-byte ABA mutations
/// from reusing an observation made against a different filesystem object. A missing path is a
/// valid, deterministic observation tied to its nearest existing in-workspace
/// ancestor, allowing the wrapped command to produce its normal nonzero result.
pub fn fingerprint_scoped(
    input: &FingerprintInput<'_>,
    scopes: &[ScopeEntry],
) -> Result<FingerprintResult, FingerprintError> {
    let mut cache = NoFileDigestCache;
    fingerprint_scoped_with_cache(input, scopes, &mut cache)
}

/// Fingerprint scoped inputs while reusing only strongly validated file digests.
///
/// This is identical to [`fingerprint_scoped`] except for the explicit optimization
/// interface. Cache errors are represented by misses, never by unverified hits.
pub fn fingerprint_scoped_with_cache(
    input: &FingerprintInput<'_>,
    scopes: &[ScopeEntry],
    cache: &mut dyn FileDigestCache,
) -> Result<FingerprintResult, FingerprintError> {
    if input.argv.is_empty() {
        return Err(FingerprintError::EmptyArgv);
    }
    if scopes.is_empty() {
        return Err(FingerprintError::EmptyScope);
    }

    let canonical_workspace = canonicalize(input.workspace, "canonicalize workspace")?;
    let workspace_metadata = metadata(&canonical_workspace, "inspect workspace")?;
    if !workspace_metadata.is_dir() {
        return Err(FingerprintError::WorkspaceNotDirectory(canonical_workspace));
    }

    let canonical_cwd = canonicalize(input.cwd, "canonicalize working directory")?;
    let cwd_metadata = metadata(&canonical_cwd, "inspect working directory")?;
    if !cwd_metadata.is_dir() {
        return Err(FingerprintError::WorkingDirectoryNotDirectory(
            canonical_cwd,
        ));
    }
    ensure_within(&canonical_cwd, &canonical_workspace, "working directory")?;
    let cwd_relative = canonical_cwd
        .strip_prefix(&canonical_workspace)
        .expect("ensure_within established prefix");
    if is_excluded_namespace(cwd_relative) {
        return Err(FingerprintError::ExcludedWorkingDirectory(canonical_cwd));
    }

    let canonical_executable = canonicalize(input.executable, "canonicalize executable")?;
    let executable_fingerprint = fingerprint_executable_with_cache(&canonical_executable, cache)?;
    let environment_fingerprint = fingerprint_environment(input.environment)?;
    let command_fingerprint = fingerprint_argv(input.argv);
    let cwd_fingerprint = hash_fields(
        "again.cwd.v1",
        [
            canonical_workspace.as_os_str().as_bytes(),
            cwd_relative.as_os_str().as_bytes(),
        ],
    );

    let mut walker = ScopedWalker {
        root: &canonical_workspace,
        cache,
    };
    let mut components: Vec<(Vec<u8>, Hash, u64)> = Vec::new();

    if scopes
        .iter()
        .any(|scope| matches!(scope, ScopeEntry::WholeWorkspace))
    {
        // WholeWorkspace is the set-theoretic superset of every other scope, so do
        // not waste time hashing redundant operands.
        let mut active = HashSet::new();
        let tree = walker.walk_content(&canonical_workspace, Path::new(""), &mut active)?;
        let component = hash_fields(
            "again.scope.whole-workspace.v1",
            [&tree.digest.as_bytes()[..]],
        );
        components.push((vec![3], component, tree.entries));
    } else {
        for scope in scopes {
            let (key, component, entries) = match scope {
                ScopeEntry::IdentityOnly => (
                    vec![0],
                    hash_fields("again.scope.identity-only.v1", std::iter::empty()),
                    0,
                ),
                ScopeEntry::ContentPath(relative) => {
                    let resolved = resolve_scope_operand(&canonical_workspace, relative)?;
                    let mut active = HashSet::new();
                    let tree =
                        walker.walk_content(&resolved.path, &resolved.relative, &mut active)?;
                    let component = hash_fields(
                        "again.scope.content-path.v1",
                        [
                            resolved.relative.as_os_str().as_bytes(),
                            tree.digest.as_bytes(),
                        ],
                    );
                    (scope_key(1, &resolved.relative), component, tree.entries)
                }
                ScopeEntry::RecursiveContentTree(relative) => {
                    let resolved = resolve_scope_operand(&canonical_workspace, relative)?;
                    reject_recursive_git_directory(&canonical_workspace, &resolved)?;
                    let mut active = HashSet::new();
                    let tree =
                        walker.walk_content(&resolved.path, &resolved.relative, &mut active)?;
                    let component = hash_fields(
                        "again.scope.recursive-content-tree.v1",
                        [
                            resolved.relative.as_os_str().as_bytes(),
                            tree.digest.as_bytes(),
                        ],
                    );
                    (scope_key(4, &resolved.relative), component, tree.entries)
                }
                ScopeEntry::DirectoryListing(relative) => {
                    let resolved = resolve_scope_operand(&canonical_workspace, relative)?;
                    let listing = walker.walk_listing(&resolved.path, &resolved.relative)?;
                    let component = hash_fields(
                        "again.scope.directory-listing.v1",
                        [
                            resolved.relative.as_os_str().as_bytes(),
                            listing.digest.as_bytes(),
                        ],
                    );
                    (scope_key(2, &resolved.relative), component, listing.entries)
                }
                ScopeEntry::WholeWorkspace => unreachable!("handled above"),
            };
            components.push((key, component, entries));
        }
        components.sort_by(|left, right| left.0.cmp(&right.0));
        components.dedup_by(|left, right| left.0 == right.0);
    }

    let mut scope_hasher = domain_hasher("again.workspace.scope-set.v1");
    put_u64(&mut scope_hasher, components.len() as u64);
    let mut workspace_entries = 0_u64;
    for (key, component, entries) in components {
        put_bytes(&mut scope_hasher, &key);
        scope_hasher.update(component.as_bytes());
        workspace_entries = workspace_entries.checked_add(entries).ok_or_else(|| {
            io_error(
                "count scoped workspace entries",
                &canonical_workspace,
                io::Error::other("workspace entry count overflow"),
            )
        })?;
    }
    let workspace_tree_fingerprint = scope_hasher.finalize();
    let workspace_fingerprint = hash_fields(
        "again.workspace.scoped-identity.v1",
        [
            canonical_workspace.as_os_str().as_bytes(),
            workspace_tree_fingerprint.as_bytes(),
        ],
    );

    let request_fingerprint = hash_fields(
        "again.request.v1",
        [
            FORMAT_VERSION,
            command_fingerprint.as_bytes(),
            cwd_fingerprint.as_bytes(),
            workspace_fingerprint.as_bytes(),
            environment_fingerprint.as_bytes(),
            executable_fingerprint.as_bytes(),
        ],
    );

    Ok(FingerprintResult {
        request_digest: hex(request_fingerprint),
        workspace_digest: hex(workspace_fingerprint),
        workspace_tree_digest: hex(workspace_tree_fingerprint),
        environment_digest: hex(environment_fingerprint),
        executable_digest: hex(executable_fingerprint),
        canonical_workspace,
        canonical_cwd,
        canonical_executable,
        workspace_entries,
    })
}

struct ResolvedScopePath {
    path: PathBuf,
    relative: PathBuf,
}

fn reject_recursive_git_directory(
    workspace: &Path,
    resolved: &ResolvedScopePath,
) -> Result<(), FingerprintError> {
    let metadata = match fs::metadata(&resolved.path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(io_error(
                "inspect recursive scope operand",
                &resolved.path,
                source,
            ));
        }
    };
    if !metadata.is_dir() {
        return Ok(());
    }
    let canonical = canonicalize(&resolved.path, "canonicalize recursive scope operand")?;
    ensure_within(&canonical, workspace, "recursive scope operand")?;
    let relative = canonical
        .strip_prefix(workspace)
        .expect("ensure_within established recursive scope prefix");
    if is_git_namespace(relative) {
        return Err(FingerprintError::ExcludedScopePath(canonical));
    }
    Ok(())
}

fn resolve_scope_operand(
    workspace: &Path,
    relative: &Path,
) -> Result<ResolvedScopePath, FingerprintError> {
    if relative.is_absolute() {
        return Err(FingerprintError::AbsoluteScopePath(relative.to_path_buf()));
    }
    let candidate = workspace.join(relative);
    let normalized =
        lexical_normalize(&candidate).ok_or_else(|| FingerprintError::PathEscapesWorkspace {
            kind: "scope",
            path: candidate.clone(),
            workspace: workspace.to_path_buf(),
        })?;
    ensure_within(&normalized, workspace, "scope")?;
    let normalized_relative = normalized
        .strip_prefix(workspace)
        .expect("ensure_within established prefix")
        .to_path_buf();
    if is_excluded_namespace(&normalized_relative) {
        return Err(FingerprintError::ExcludedScopePath(normalized));
    }

    // Resolve every existing component, including a final symlink, solely to
    // validate confinement. Missing operands are valid observations: validating
    // their nearest existing ancestor catches an intermediate escaping symlink.
    match fs::canonicalize(&normalized) {
        Ok(canonical) => {
            ensure_within(&canonical, workspace, "scope")?;
            let canonical_relative = canonical
                .strip_prefix(workspace)
                .expect("ensure_within established prefix");
            if is_excluded_namespace(canonical_relative) {
                return Err(FingerprintError::ExcludedScopePath(canonical));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            nearest_existing_ancestor(&normalized, workspace)?;
        }
        Err(source) => return Err(io_error("resolve scope path", &normalized, source)),
    }

    Ok(ResolvedScopePath {
        path: normalized,
        relative: normalized_relative,
    })
}

fn scope_key(tag: u8, relative: &Path) -> Vec<u8> {
    let path = relative.as_os_str().as_bytes();
    let mut key = Vec::with_capacity(path.len() + 1);
    key.push(tag);
    key.extend_from_slice(path);
    key
}

fn fingerprint_argv(argv: &[OsString]) -> Hash {
    let mut hasher = domain_hasher("again.argv.v1");
    put_u64(&mut hasher, argv.len() as u64);
    for argument in argv {
        put_bytes(&mut hasher, argument.as_os_str().as_bytes());
    }
    hasher.finalize()
}

fn fingerprint_environment(environment: &[(OsString, OsString)]) -> Result<Hash, FingerprintError> {
    let mut entries: Vec<_> = environment.iter().collect();
    entries.sort_by(|(left, _), (right, _)| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });

    for pair in entries.windows(2) {
        if pair[0].0.as_os_str().as_bytes() == pair[1].0.as_os_str().as_bytes() {
            return Err(FingerprintError::DuplicateEnvironmentName {
                name_digest: hex(hash_fields(
                    "again.environment.name.v1",
                    [pair[0].0.as_os_str().as_bytes()],
                )),
            });
        }
    }

    let mut hasher = domain_hasher("again.environment.v1");
    put_u64(&mut hasher, entries.len() as u64);
    for (name, value) in entries {
        let name_digest = hash_fields("again.environment.name.v1", [name.as_os_str().as_bytes()]);
        // Bind the value digest to its name to avoid correlating the same secret
        // when it appears under different variables.
        let value_digest = hash_fields(
            "again.environment.value.v1",
            [name.as_os_str().as_bytes(), value.as_os_str().as_bytes()],
        );
        hasher.update(name_digest.as_bytes());
        hasher.update(value_digest.as_bytes());
    }
    Ok(hasher.finalize())
}

fn fingerprint_executable(path: &Path) -> Result<Hash, FingerprintError> {
    let mut cache = NoFileDigestCache;
    fingerprint_executable_with_cache(path, &mut cache)
}

fn fingerprint_executable_with_cache(
    path: &Path,
    cache: &mut dyn FileDigestCache,
) -> Result<Hash, FingerprintError> {
    let initial_metadata = metadata(path, "inspect executable")?;
    if !initial_metadata.is_file() {
        return Err(FingerprintError::ExecutableNotRegular(path.to_path_buf()));
    }
    let content = hash_file_with_cache(path, "read executable", cache)?;
    let after_hash = metadata(path, "inspect executable after hashing")?;
    if !same_metadata(&initial_metadata, &after_hash) {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    let mut hasher = domain_hasher("again.executable.v1");
    put_bytes(&mut hasher, path.as_os_str().as_bytes());
    put_u64(&mut hasher, initial_metadata.dev());
    put_u64(&mut hasher, initial_metadata.ino());
    put_u32(&mut hasher, relevant_mode(&initial_metadata));
    put_i64(&mut hasher, initial_metadata.ctime());
    put_i64(&mut hasher, initial_metadata.ctime_nsec());
    hasher.update(content.as_bytes());
    Ok(hasher.finalize())
}

struct ScopedWalker<'a, 'cache> {
    root: &'a Path,
    cache: &'cache mut dyn FileDigestCache,
}

impl ScopedWalker<'_, '_> {
    fn walk_content(
        &mut self,
        path: &Path,
        relative: &Path,
        active_directories: &mut HashSet<PathBuf>,
    ) -> Result<WalkResult, FingerprintError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return fingerprint_absent_path(path, relative, self.root);
            }
            Err(source) => {
                return Err(io_error("inspect scoped content entry", path, source));
            }
        };
        let kind = scoped_file_kind(path, &metadata)?;

        if metadata.file_type().is_symlink() {
            let resolved = resolve_scoped_symlink(path, self.root)?;
            if !same_metadata(&metadata, &resolved.metadata) {
                return Err(FingerprintError::ConcurrentMutation {
                    path: path.to_path_buf(),
                });
            }
            let target =
                self.walk_content(&resolved.canonical, &resolved.relative, active_directories)?;
            let after_target = symlink_metadata(path, "inspect scoped content symlink")?;
            if !same_metadata(&metadata, &after_target) {
                return Err(FingerprintError::ConcurrentMutation {
                    path: path.to_path_buf(),
                });
            }
            let mut hasher = domain_hasher("again.scoped-content.symlink.v1");
            put_rich_metadata(&mut hasher, &metadata, kind);
            put_bytes(&mut hasher, resolved.raw_target.as_os_str().as_bytes());
            put_bytes(&mut hasher, resolved.relative.as_os_str().as_bytes());
            hasher.update(target.digest.as_bytes());
            return Ok(WalkResult {
                digest: hasher.finalize(),
                entries: target.entries.checked_add(1).ok_or_else(|| {
                    io_error(
                        "count scoped symlink entries",
                        path,
                        io::Error::other("workspace entry count overflow"),
                    )
                })?,
            });
        }

        let canonical = canonicalize(path, "canonicalize scoped content entry")?;
        ensure_within(&canonical, self.root, "scoped content entry")?;

        if metadata.is_file() {
            let content = hash_file_with_cache(path, "read scoped content file", self.cache)?;
            let after_hash = symlink_metadata(path, "inspect scoped content file")?;
            if !same_metadata(&metadata, &after_hash) {
                return Err(FingerprintError::ConcurrentMutation {
                    path: path.to_path_buf(),
                });
            }
            let mut hasher = domain_hasher("again.scoped-content.file.v1");
            put_rich_metadata(&mut hasher, &metadata, kind);
            hasher.update(content.as_bytes());
            return Ok(WalkResult {
                digest: hasher.finalize(),
                entries: 1,
            });
        }

        if !active_directories.insert(canonical.clone()) {
            return Err(FingerprintError::SymlinkCycle(canonical));
        }
        let result = self.walk_content_directory(path, relative, &metadata, active_directories);
        active_directories.remove(&canonical);
        result
    }

    fn walk_content_directory(
        &mut self,
        path: &Path,
        relative: &Path,
        metadata: &Metadata,
        active_directories: &mut HashSet<PathBuf>,
    ) -> Result<WalkResult, FingerprintError> {
        let iterator = fs::read_dir(path)
            .map_err(|source| io_error("read scoped content directory", path, source))?;
        let mut children = Vec::new();
        for entry in iterator {
            let entry = entry
                .map_err(|source| io_error("read scoped content directory entry", path, source))?;
            children.push(entry.file_name());
        }
        children.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let after_read = symlink_metadata(path, "inspect scoped content directory")?;
        if !same_metadata(metadata, &after_read) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }

        let mut included = Vec::new();
        let mut entries = 1_u64;
        for name in children {
            let child_path = path.join(&name);
            let child_relative = relative.join(&name);
            let child_metadata = symlink_metadata(&child_path, "inspect scoped content entry")?;
            if is_excluded(&child_relative, &child_metadata) {
                continue;
            }
            let child = self.walk_content(&child_path, &child_relative, active_directories)?;
            entries = entries.checked_add(child.entries).ok_or_else(|| {
                io_error(
                    "count scoped content entries",
                    self.root,
                    io::Error::other("workspace entry count overflow"),
                )
            })?;
            included.push((name, child.digest));
        }
        let after_children = symlink_metadata(path, "inspect scoped content directory")?;
        if !same_metadata(metadata, &after_children) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }

        let mut hasher = domain_hasher("again.scoped-content.directory.v1");
        put_rich_metadata(&mut hasher, metadata, b'd');
        put_u64(&mut hasher, included.len() as u64);
        for (name, digest) in included {
            put_bytes(&mut hasher, name.as_bytes());
            hasher.update(digest.as_bytes());
        }
        Ok(WalkResult {
            digest: hasher.finalize(),
            entries,
        })
    }

    fn walk_listing(
        &mut self,
        path: &Path,
        relative: &Path,
    ) -> Result<WalkResult, FingerprintError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return fingerprint_absent_path(path, relative, self.root);
            }
            Err(source) => return Err(io_error("inspect listing operand", path, source)),
        };
        let kind = scoped_file_kind(path, &metadata)?;

        if metadata.file_type().is_symlink() {
            // `ls link` follows a command-line directory symlink, whereas
            // `ls -d link` observes the link entry. DirectoryListing does not
            // encode that argv distinction, so accepting either here would be
            // an incomplete proof. This guard also closes a race after policy
            // classification but before fingerprinting.
            return Err(FingerprintError::SymlinkListingOperand(path.to_path_buf()));
        }

        let canonical = canonicalize(path, "canonicalize listing operand")?;
        ensure_within(&canonical, self.root, "listing operand")?;

        if metadata.is_file() {
            let after_metadata = symlink_metadata(path, "inspect listing file operand")?;
            if !same_metadata(&metadata, &after_metadata) {
                return Err(FingerprintError::ConcurrentMutation {
                    path: path.to_path_buf(),
                });
            }
            let mut hasher = domain_hasher("again.directory-listing.file-operand.v1");
            put_rich_metadata(&mut hasher, &metadata, kind);
            return Ok(WalkResult {
                digest: hasher.finalize(),
                entries: 1,
            });
        }

        let iterator = fs::read_dir(path)
            .map_err(|source| io_error("read scoped directory listing", path, source))?;
        let mut names = Vec::new();
        for entry in iterator {
            let entry =
                entry.map_err(|source| io_error("read scoped directory entry", path, source))?;
            names.push(entry.file_name());
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let after_read = symlink_metadata(path, "inspect scoped directory listing")?;
        if !same_metadata(&metadata, &after_read) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }

        let mut members = Vec::new();
        for name in names {
            let child_path = path.join(&name);
            let child_metadata = symlink_metadata(&child_path, "inspect listing member")?;
            // A one-level `ls` can print excluded runtime names and can sort or
            // classify them from metadata. Include the entry metadata without
            // recursing into or opening its contents. Content/tree scopes still
            // exclude these volatile namespaces.
            let child_kind = scoped_file_kind(&child_path, &child_metadata)?;
            let mut child_hasher = domain_hasher("again.directory-listing.member.v1");
            put_rich_metadata(&mut child_hasher, &child_metadata, child_kind);
            if child_metadata.file_type().is_symlink() {
                let resolved = resolve_scoped_symlink(&child_path, self.root)?;
                if !same_metadata(&child_metadata, &resolved.metadata) {
                    return Err(FingerprintError::ConcurrentMutation { path: child_path });
                }
                put_bytes(
                    &mut child_hasher,
                    resolved.raw_target.as_os_str().as_bytes(),
                );
                put_bytes(&mut child_hasher, resolved.relative.as_os_str().as_bytes());
            }
            let child_after = symlink_metadata(&child_path, "inspect listing member")?;
            if !same_metadata(&child_metadata, &child_after) {
                return Err(FingerprintError::ConcurrentMutation { path: child_path });
            }
            members.push((name, child_hasher.finalize()));
        }
        let after_members = symlink_metadata(path, "inspect scoped directory listing")?;
        if !same_metadata(&metadata, &after_members) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }

        let mut hasher = domain_hasher("again.directory-listing.directory.v1");
        put_rich_metadata(&mut hasher, &metadata, kind);
        put_u64(&mut hasher, members.len() as u64);
        for (name, digest) in &members {
            put_bytes(&mut hasher, name.as_bytes());
            hasher.update(digest.as_bytes());
        }
        Ok(WalkResult {
            digest: hasher.finalize(),
            entries: members.len() as u64 + 1,
        })
    }
}

struct ExistingAncestor {
    spelled_relative: PathBuf,
    canonical_relative: PathBuf,
    metadata: Metadata,
}

fn fingerprint_absent_path(
    path: &Path,
    relative: &Path,
    workspace: &Path,
) -> Result<WalkResult, FingerprintError> {
    // An absent observation is only safe if it remains absent while its nearest
    // existing ancestor is sampled.  Otherwise a concurrent creator could make
    // the child observe a different state than the fingerprint records.
    if fs::symlink_metadata(path).is_ok() {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    let ancestor = nearest_existing_ancestor(path, workspace)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    let after_ancestor = nearest_existing_ancestor(path, workspace)?;
    if ancestor.spelled_relative != after_ancestor.spelled_relative
        || ancestor.canonical_relative != after_ancestor.canonical_relative
        || !same_metadata(&ancestor.metadata, &after_ancestor.metadata)
    {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    let kind = scoped_file_kind(path, &ancestor.metadata)?;
    let mut hasher = domain_hasher("again.scoped.absent-path.v1");
    put_bytes(&mut hasher, relative.as_os_str().as_bytes());
    put_bytes(
        &mut hasher,
        ancestor.spelled_relative.as_os_str().as_bytes(),
    );
    put_bytes(
        &mut hasher,
        ancestor.canonical_relative.as_os_str().as_bytes(),
    );
    put_rich_metadata(&mut hasher, &ancestor.metadata, kind);
    Ok(WalkResult {
        digest: hasher.finalize(),
        entries: 1,
    })
}

fn nearest_existing_ancestor(
    path: &Path,
    workspace: &Path,
) -> Result<ExistingAncestor, FingerprintError> {
    let mut probe = path.to_path_buf();
    loop {
        match fs::canonicalize(&probe) {
            Ok(canonical) => {
                ensure_within(&canonical, workspace, "scope ancestor")?;
                let spelled_relative = probe
                    .strip_prefix(workspace)
                    .expect("lexical scope confinement established prefix")
                    .to_path_buf();
                let canonical_relative = canonical
                    .strip_prefix(workspace)
                    .expect("ensure_within established prefix")
                    .to_path_buf();
                if is_excluded_namespace(&spelled_relative)
                    || is_excluded_namespace(&canonical_relative)
                {
                    return Err(FingerprintError::ExcludedScopePath(canonical));
                }
                let metadata = metadata(&canonical, "inspect nearest scope ancestor")?;
                return Ok(ExistingAncestor {
                    spelled_relative,
                    canonical_relative,
                    metadata,
                });
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                if !probe.pop() {
                    return Err(io_error("resolve nearest scope ancestor", path, source));
                }
            }
            Err(source) => {
                return Err(io_error("resolve nearest scope ancestor", &probe, source));
            }
        }
    }
}

struct ResolvedSymlink {
    raw_target: PathBuf,
    canonical: PathBuf,
    relative: PathBuf,
    metadata: Metadata,
}

fn resolve_scoped_symlink(
    path: &Path,
    workspace: &Path,
) -> Result<ResolvedSymlink, FingerprintError> {
    let (raw_target, before) = read_symlink_consistent(path, "read scoped symlink")?;
    let canonical = canonicalize(path, "resolve scoped symlink")?;
    let after = symlink_metadata(path, "inspect resolved scoped symlink")?;
    if !same_metadata(&before, &after) {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    ensure_within(&canonical, workspace, "scoped symlink target")?;
    let relative = canonical
        .strip_prefix(workspace)
        .expect("ensure_within established prefix")
        .to_path_buf();
    if is_excluded_namespace(&relative) {
        return Err(FingerprintError::SymlinkTargetsExcludedPath(canonical));
    }
    Ok(ResolvedSymlink {
        raw_target,
        canonical,
        relative,
        metadata: after,
    })
}

fn scoped_file_kind(path: &Path, metadata: &Metadata) -> Result<u8, FingerprintError> {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        Ok(b'f')
    } else if file_type.is_dir() {
        Ok(b'd')
    } else if file_type.is_symlink() {
        Ok(b'l')
    } else {
        Err(FingerprintError::SpecialFile(path.to_path_buf()))
    }
}

fn put_rich_metadata(hasher: &mut Hasher, metadata: &Metadata, kind: u8) {
    hasher.update(&[kind]);
    put_u64(hasher, metadata.dev());
    put_u64(hasher, metadata.ino());
    put_u32(hasher, relevant_mode(metadata));
    put_u64(hasher, metadata.len());
    put_u32(hasher, metadata.uid());
    put_u32(hasher, metadata.gid());
    put_i64(hasher, metadata.mtime());
    put_i64(hasher, metadata.mtime_nsec());
    put_i64(hasher, metadata.ctime());
    put_i64(hasher, metadata.ctime_nsec());
}

fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    FileIdentity::from_metadata(left) == FileIdentity::from_metadata(right)
}

fn read_symlink_consistent(
    path: &Path,
    operation: &'static str,
) -> Result<(PathBuf, Metadata), FingerprintError> {
    let before = symlink_metadata(path, operation)?;
    if !before.file_type().is_symlink() {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    let target = fs::read_link(path).map_err(|source| io_error(operation, path, source))?;
    let after = symlink_metadata(path, operation)?;
    if !same_metadata(&before, &after) {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    Ok((target, after))
}

struct WorkspaceWalker<'a> {
    root: &'a Path,
}

#[derive(Debug)]
struct WalkResult {
    digest: Hash,
    entries: u64,
}

impl WorkspaceWalker<'_> {
    fn walk(&mut self, path: &Path, relative: &Path) -> Result<WalkResult, FingerprintError> {
        let metadata = symlink_metadata(path, "inspect workspace entry")?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            return self.walk_symlink(path, &metadata);
        }

        // Canonicalization is intentionally done for every followed object, not only
        // for the root. It catches directory components replaced by escaping links.
        let canonical = canonicalize(path, "canonicalize workspace entry")?;
        ensure_within(&canonical, self.root, "workspace entry")?;

        if file_type.is_file() {
            let content = hash_file(path, "read workspace file")?;
            let after_hash = symlink_metadata(path, "inspect workspace file")?;
            if !same_metadata(&metadata, &after_hash) {
                return Err(FingerprintError::ConcurrentMutation {
                    path: path.to_path_buf(),
                });
            }
            let mut hasher = domain_hasher("again.workspace.file.v1");
            put_u32(&mut hasher, relevant_mode(&metadata));
            hasher.update(content.as_bytes());
            return Ok(WalkResult {
                digest: hasher.finalize(),
                entries: 1,
            });
        }

        if file_type.is_dir() {
            return self.walk_directory(path, relative, &metadata);
        }

        Err(FingerprintError::SpecialFile(path.to_path_buf()))
    }

    fn walk_directory(
        &mut self,
        path: &Path,
        relative: &Path,
        metadata: &Metadata,
    ) -> Result<WalkResult, FingerprintError> {
        let iterator =
            fs::read_dir(path).map_err(|source| io_error("read directory", path, source))?;
        let mut children = Vec::new();
        for entry in iterator {
            let entry = entry.map_err(|source| io_error("read directory entry", path, source))?;
            children.push(entry.file_name());
        }
        children.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let after_read = symlink_metadata(path, "inspect directory")?;
        if !same_metadata(metadata, &after_read) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }

        let mut included = Vec::new();
        let mut entries = 1_u64;
        for name in children {
            let child_path = path.join(&name);
            let child_relative = relative.join(&name);
            let child_metadata = symlink_metadata(&child_path, "inspect workspace entry")?;
            if is_excluded(&child_relative, &child_metadata) {
                continue;
            }
            let child = self.walk(&child_path, &child_relative)?;
            entries = entries.checked_add(child.entries).ok_or_else(|| {
                io_error(
                    "count workspace entries",
                    self.root,
                    io::Error::other("workspace entry count overflow"),
                )
            })?;
            included.push((name, child.digest));
        }
        let after_children = symlink_metadata(path, "inspect directory")?;
        if !same_metadata(metadata, &after_children) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }

        let mut hasher = domain_hasher("again.workspace.directory.v1");
        put_u32(&mut hasher, relevant_mode(metadata));
        put_u64(&mut hasher, included.len() as u64);
        for (name, digest) in included {
            put_bytes(&mut hasher, name.as_bytes());
            hasher.update(digest.as_bytes());
        }
        Ok(WalkResult {
            digest: hasher.finalize(),
            entries,
        })
    }

    fn walk_symlink(
        &self,
        path: &Path,
        metadata: &Metadata,
    ) -> Result<WalkResult, FingerprintError> {
        let (target, observed) = read_symlink_consistent(path, "read symlink")?;
        if !same_metadata(metadata, &observed) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }
        self.validate_symlink_target(path, &target)?;
        let after_validation = symlink_metadata(path, "inspect validated symlink")?;
        if !same_metadata(&observed, &after_validation) {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }

        let mut hasher = domain_hasher("again.workspace.symlink.v1");
        put_u32(&mut hasher, relevant_mode(metadata));
        put_bytes(&mut hasher, target.as_os_str().as_bytes());
        Ok(WalkResult {
            digest: hasher.finalize(),
            entries: 1,
        })
    }

    fn validate_symlink_target(&self, link: &Path, target: &Path) -> Result<(), FingerprintError> {
        let candidate = if target.is_absolute() {
            target.to_path_buf()
        } else {
            link.parent().unwrap_or(self.root).join(target)
        };
        let normalized = lexical_normalize(&candidate).ok_or_else(|| {
            FingerprintError::PathEscapesWorkspace {
                kind: "symlink target",
                path: candidate.clone(),
                workspace: self.root.to_path_buf(),
            }
        })?;
        ensure_within(&normalized, self.root, "symlink target")?;

        let relative = normalized
            .strip_prefix(self.root)
            .expect("ensure_within established prefix");
        if is_excluded_namespace(relative) {
            return Err(FingerprintError::SymlinkTargetsExcludedPath(normalized));
        }

        // For a dangling target, canonicalize its longest existing ancestor. This
        // detects an intermediate symlink that leaves the workspace without rejecting
        // ordinary in-workspace dangling symlinks.
        let mut existing = normalized.clone();
        loop {
            match fs::canonicalize(&existing) {
                Ok(canonical) => {
                    ensure_within(&canonical, self.root, "symlink target")?;
                    break;
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    if !existing.pop() {
                        return Err(io_error("resolve symlink target", &normalized, source));
                    }
                }
                Err(source) => {
                    return Err(io_error("resolve symlink target", &normalized, source));
                }
            }
        }
        Ok(())
    }
}

fn is_excluded(relative: &Path, metadata: &Metadata) -> bool {
    if is_again_path(relative) || is_git_log_path(relative) {
        return true;
    }
    metadata.is_file() && is_git_lock_path(relative)
}

fn is_excluded_namespace(relative: &Path) -> bool {
    is_again_path(relative) || is_git_log_path(relative) || is_git_lock_path(relative)
}

fn is_again_path(relative: &Path) -> bool {
    normal_components(relative)
        .first()
        .is_some_and(|component| *component == b".again")
}

fn is_git_log_path(relative: &Path) -> bool {
    let components = normal_components(relative);
    components.len() >= 2 && components[0] == b".git" && components[1] == b"logs"
}

fn is_git_namespace(relative: &Path) -> bool {
    normal_components(relative)
        .first()
        .is_some_and(|component| *component == b".git")
}

fn is_git_lock_path(relative: &Path) -> bool {
    let components = normal_components(relative);
    components
        .first()
        .is_some_and(|component| *component == b".git")
        && components
            .last()
            .is_some_and(|component| component.ends_with(b".lock"))
}

fn normal_components(path: &Path) -> Vec<&[u8]> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.as_bytes()),
            _ => None,
        })
        .collect()
}

fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn ensure_within(
    path: &Path,
    workspace: &Path,
    kind: &'static str,
) -> Result<(), FingerprintError> {
    if path.starts_with(workspace) {
        Ok(())
    } else {
        Err(FingerprintError::PathEscapesWorkspace {
            kind,
            path: path.to_path_buf(),
            workspace: workspace.to_path_buf(),
        })
    }
}

fn hash_file(path: &Path, operation: &'static str) -> Result<Hash, FingerprintError> {
    let mut cache = NoFileDigestCache;
    hash_file_with_cache(path, operation, &mut cache)
}

fn hash_file_with_cache(
    path: &Path,
    operation: &'static str,
    cache: &mut dyn FileDigestCache,
) -> Result<Hash, FingerprintError> {
    let path_before = symlink_metadata(path, operation)?;
    if !path_before.is_file() {
        return Err(FingerprintError::SpecialFile(path.to_path_buf()));
    }
    let identity = FileIdentity::from_metadata(&path_before);
    if identity.is_valid()
        && let Some(bytes) = cache.lookup(&identity)
    {
        // A persistent digest proves prior content, not current authority to
        // read it. Re-open and fstat on every hit so credential/sandbox changes
        // cannot turn an unreadable native input into a cached success.
        let file = File::open(path).map_err(|source| io_error(operation, path, source))?;
        let opened_metadata = file
            .metadata()
            .map_err(|source| io_error("inspect opened cached file", path, source))?;
        if !opened_metadata.is_file() {
            return Err(FingerprintError::SpecialFile(path.to_path_buf()));
        }
        let path_after = symlink_metadata(path, operation)?;
        if !same_metadata(&path_before, &opened_metadata)
            || !same_metadata(&path_before, &path_after)
            || !same_metadata(&opened_metadata, &path_after)
        {
            return Err(FingerprintError::ConcurrentMutation {
                path: path.to_path_buf(),
            });
        }
        return Ok(Hash::from_bytes(bytes));
    }

    let mut file = File::open(path).map_err(|source| io_error(operation, path, source))?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| io_error("inspect opened file", path, source))?;
    if !opened_metadata.is_file() {
        return Err(FingerprintError::SpecialFile(path.to_path_buf()));
    }
    if !same_metadata(&path_before, &opened_metadata) {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }

    let mut hasher = domain_hasher("again.file.content.v1");
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error(operation, path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let path_after = symlink_metadata(path, operation)?;
    if !same_metadata(&path_before, &path_after) || !same_metadata(&opened_metadata, &path_after) {
        return Err(FingerprintError::ConcurrentMutation {
            path: path.to_path_buf(),
        });
    }
    let digest = hasher.finalize();
    if identity.is_valid() {
        cache.record(&identity, *digest.as_bytes());
    }
    Ok(digest)
}

fn relevant_mode(metadata: &Metadata) -> u32 {
    metadata.mode() & 0o7777
}

fn canonicalize(path: &Path, operation: &'static str) -> Result<PathBuf, FingerprintError> {
    fs::canonicalize(path).map_err(|source| io_error(operation, path, source))
}

fn metadata(path: &Path, operation: &'static str) -> Result<Metadata, FingerprintError> {
    fs::metadata(path).map_err(|source| io_error(operation, path, source))
}

fn symlink_metadata(path: &Path, operation: &'static str) -> Result<Metadata, FingerprintError> {
    fs::symlink_metadata(path).map_err(|source| io_error(operation, path, source))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> FingerprintError {
    FingerprintError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn domain_hasher(domain: &'static str) -> Hasher {
    Hasher::new_derive_key(domain)
}

fn hash_fields<'a>(domain: &'static str, fields: impl IntoIterator<Item = &'a [u8]>) -> Hash {
    let mut hasher = domain_hasher(domain);
    for field in fields {
        put_bytes(&mut hasher, field);
    }
    hasher.finalize()
}

fn put_bytes(hasher: &mut Hasher, bytes: &[u8]) {
    put_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn put_u64(hasher: &mut Hasher, value: u64) {
    hasher.update(&value.to_be_bytes());
}

fn put_u32(hasher: &mut Hasher, value: u32) {
    hasher.update(&value.to_be_bytes());
}

fn put_i64(hasher: &mut Hasher, value: i64) {
    hasher.update(&value.to_be_bytes());
}

fn hex(hash: Hash) -> String {
    hash.to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::{self, FileTimes, OpenOptions};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, SystemTime};

    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        _temp: TempDir,
        workspace: PathBuf,
        executable: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let workspace = temp.path().join("workspace");
            fs::create_dir(&workspace).expect("workspace");
            fs::create_dir(workspace.join("src")).expect("src");
            fs::write(workspace.join("src/main.rs"), b"fn main() {}\n").expect("source");

            let executable = temp.path().join("tool");
            fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("executable");
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
                .expect("executable mode");

            Self {
                _temp: temp,
                workspace,
                executable,
            }
        }

        fn fingerprint(&self, environment: &[(OsString, OsString)]) -> FingerprintResult {
            let argv = vec![OsString::from("tool"), OsString::from("--check")];
            fingerprint(&FingerprintInput {
                argv: &argv,
                cwd: &self.workspace,
                workspace: &self.workspace,
                environment,
                executable: &self.executable,
            })
            .expect("fingerprint")
        }

        fn fingerprint_scoped(&self, scopes: &[ScopeEntry]) -> FingerprintResult {
            let argv = vec![OsString::from("tool"), OsString::from("--check")];
            super::fingerprint_scoped(
                &FingerprintInput {
                    argv: &argv,
                    cwd: &self.workspace,
                    workspace: &self.workspace,
                    environment: &environment(),
                    executable: &self.executable,
                },
                scopes,
            )
            .expect("scoped fingerprint")
        }

        fn fingerprint_scoped_cached(
            &self,
            scopes: &[ScopeEntry],
            cache: &mut dyn FileDigestCache,
        ) -> FingerprintResult {
            let argv = vec![OsString::from("tool"), OsString::from("--check")];
            super::fingerprint_scoped_with_cache(
                &FingerprintInput {
                    argv: &argv,
                    cwd: &self.workspace,
                    workspace: &self.workspace,
                    environment: &environment(),
                    executable: &self.executable,
                },
                scopes,
                cache,
            )
            .expect("cached scoped fingerprint")
        }
    }

    #[derive(Default)]
    struct CountingCache {
        digests: HashMap<FileIdentity, [u8; 32]>,
        hits: usize,
        records: usize,
    }

    impl FileDigestCache for CountingCache {
        fn lookup(&mut self, identity: &FileIdentity) -> Option<[u8; 32]> {
            let digest = self.digests.get(identity).copied();
            if digest.is_some() {
                self.hits += 1;
            }
            digest
        }

        fn record(&mut self, identity: &FileIdentity, digest: [u8; 32]) {
            self.records += 1;
            self.digests.insert(*identity, digest);
        }
    }

    fn environment() -> Vec<(OsString, OsString)> {
        vec![
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("LANG"), OsString::from("C")),
        ]
    }

    #[test]
    fn is_deterministic_and_environment_order_independent() {
        let fixture = Fixture::new();
        let mut first_environment = environment();
        let first = fixture.fingerprint(&first_environment);
        first_environment.reverse();
        let second = fixture.fingerprint(&first_environment);

        assert_eq!(first, second);
        assert_eq!(first.request_digest.len(), 64);
    }

    #[test]
    fn warm_scoped_fingerprint_reuses_file_digests() {
        let fixture = Fixture::new();
        let selected = fixture.workspace.join("large.bin");
        fs::write(&selected, vec![0x5a; 1024 * 1024]).expect("large fixture");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("large.bin"))];
        let mut cache = CountingCache::default();

        let first = fixture.fingerprint_scoped_cached(&scope, &mut cache);
        assert_eq!(cache.records, 2, "executable and selected file were read");
        let second = fixture.fingerprint_scoped_cached(&scope, &mut cache);

        assert_eq!(first, second);
        assert_eq!(cache.records, 2, "warm hit must not re-read either file");
        assert_eq!(cache.hits, 2);
    }

    #[test]
    fn memoized_digest_still_requires_current_read_authority() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("input");
        fs::write(&path, b"previously readable").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let identity = FileIdentity::from_metadata(&metadata);
        let mut cache = CountingCache::default();
        cache
            .digests
            .insert(identity, *blake3::hash(b"previously readable").as_bytes());

        assert!(hash_file_with_cache(&path, "test read", &mut cache).is_err());
    }

    #[test]
    fn restored_mtime_cannot_hide_content_mutation_from_cache() {
        let fixture = Fixture::new();
        let selected = fixture.workspace.join("selected");
        fs::write(&selected, b"before").expect("selected file");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("selected"))];
        let mut cache = CountingCache::default();
        let original = fs::metadata(&selected).expect("original metadata");
        let first = fixture.fingerprint_scoped_cached(&scope, &mut cache);

        fs::write(&selected, b"after!").expect("same-size mutation");
        OpenOptions::new()
            .write(true)
            .open(&selected)
            .expect("open selected")
            .set_times(FileTimes::new().set_modified(original.modified().expect("original mtime")))
            .expect("restore mtime");
        let changed = fs::metadata(&selected).expect("changed metadata");
        assert_eq!(original.len(), changed.len());
        assert_eq!(original.mtime(), changed.mtime());
        assert_eq!(original.mtime_nsec(), changed.mtime_nsec());
        assert_ne!(
            (original.ctime(), original.ctime_nsec()),
            (changed.ctime(), changed.ctime_nsec())
        );

        let second = fixture.fingerprint_scoped_cached(&scope, &mut cache);
        assert_ne!(first.request_digest, second.request_digest);
        assert_eq!(cache.records, 3, "changed ctime must force a byte read");
    }

    #[test]
    fn inode_replacement_with_identical_bytes_changes_the_request_epoch() {
        let fixture = Fixture::new();
        let selected = fixture.workspace.join("selected");
        let replacement = fixture.workspace.join("replacement");
        fs::write(&selected, b"stable").expect("selected file");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("selected"))];
        let mut cache = CountingCache::default();
        let original = fs::metadata(&selected).expect("original metadata");
        let first = fixture.fingerprint_scoped_cached(&scope, &mut cache);

        fs::write(&replacement, b"stable").expect("replacement file");
        fs::set_permissions(&replacement, original.permissions()).expect("replacement mode");
        OpenOptions::new()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .set_times(FileTimes::new().set_modified(original.modified().expect("original mtime")))
            .expect("replacement mtime");
        fs::rename(&replacement, &selected).expect("replace selected");
        let changed = fs::metadata(&selected).expect("replacement metadata");
        assert_ne!(original.ino(), changed.ino());

        let second = fixture.fingerprint_scoped_cached(&scope, &mut cache);
        assert_ne!(first.request_digest, second.request_digest);
        assert_eq!(cache.records, 3, "changed inode must force a byte read");
    }

    #[test]
    fn byte_for_byte_restore_cannot_hide_an_aba_mutation() {
        let fixture = Fixture::new();
        let selected = fixture.workspace.join("selected");
        fs::write(&selected, b"stable").expect("selected file");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("selected"))];
        let mut cache = CountingCache::default();
        let original = fs::metadata(&selected).expect("original metadata");
        let first = fixture.fingerprint_scoped_cached(&scope, &mut cache);

        fs::write(&selected, b"changed").expect("transient mutation");
        fs::write(&selected, b"stable").expect("restore original bytes");
        OpenOptions::new()
            .write(true)
            .open(&selected)
            .expect("open selected")
            .set_times(FileTimes::new().set_modified(original.modified().expect("original mtime")))
            .expect("restore mtime");
        let restored = fs::metadata(&selected).expect("restored metadata");
        assert_eq!(original.len(), restored.len());
        assert_eq!(original.mtime(), restored.mtime());
        assert_eq!(original.mtime_nsec(), restored.mtime_nsec());
        assert_ne!(
            (original.ctime(), original.ctime_nsec()),
            (restored.ctime(), restored.ctime_nsec())
        );

        let second = fixture.fingerprint_scoped_cached(&scope, &mut cache);
        assert_ne!(first.request_digest, second.request_digest);
    }

    #[test]
    fn file_content_invalidates_workspace_and_request() {
        let fixture = Fixture::new();
        let before = fixture.fingerprint(&environment());
        fs::write(fixture.workspace.join("src/main.rs"), b"fn changed() {}\n")
            .expect("change source");
        let after = fixture.fingerprint(&environment());

        assert_ne!(before.workspace_tree_digest, after.workspace_tree_digest);
        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn directory_membership_invalidates_workspace_and_request() {
        let fixture = Fixture::new();
        let before = fixture.fingerprint(&environment());
        fs::write(fixture.workspace.join("src/new.rs"), b"").expect("new member");
        let after = fixture.fingerprint(&environment());

        assert_ne!(before.workspace_tree_digest, after.workspace_tree_digest);
        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn symlink_target_invalidates_workspace_and_request() {
        let fixture = Fixture::new();
        fs::write(fixture.workspace.join("first"), b"same").expect("first target");
        fs::write(fixture.workspace.join("second"), b"same").expect("second target");
        let link = fixture.workspace.join("selected");
        symlink("first", &link).expect("first link");
        let before = fixture.fingerprint(&environment());
        fs::remove_file(&link).expect("remove link");
        symlink("second", &link).expect("second link");
        let after = fixture.fingerprint(&environment());

        assert_ne!(before.workspace_tree_digest, after.workspace_tree_digest);
        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn executable_content_invalidates_request() {
        let fixture = Fixture::new();
        let before = fixture.fingerprint(&environment());
        fs::write(&fixture.executable, b"#!/bin/sh\nexit 1\n").expect("change executable");
        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o755))
            .expect("restore executable mode");
        let after = fixture.fingerprint(&environment());

        assert_ne!(before.executable_digest, after.executable_digest);
        assert_ne!(before.request_digest, after.request_digest);
        assert_eq!(before.workspace_tree_digest, after.workspace_tree_digest);
    }

    #[test]
    fn environment_value_invalidates_request_without_touching_workspace() {
        let fixture = Fixture::new();
        let before_environment = environment();
        let mut after_environment = environment();
        after_environment[1].1 = OsString::from("en_US.UTF-8");
        let before = fixture.fingerprint(&before_environment);
        let after = fixture.fingerprint(&after_environment);

        assert_ne!(before.environment_digest, after.environment_digest);
        assert_ne!(before.request_digest, after.request_digest);
        assert_eq!(before.workspace_tree_digest, after.workspace_tree_digest);
    }

    #[test]
    fn git_index_is_included() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.workspace.join(".git")).expect("git directory");
        fs::write(
            fixture.workspace.join(".git/HEAD"),
            b"ref: refs/heads/main\n",
        )
        .expect("HEAD");
        fs::write(fixture.workspace.join(".git/index"), b"index-v1").expect("index");
        let before = fixture.fingerprint(&environment());
        fs::write(fixture.workspace.join(".git/index"), b"index-v2").expect("change index");
        let after = fixture.fingerprint(&environment());

        assert_ne!(before.workspace_tree_digest, after.workspace_tree_digest);
        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn mtimes_alone_are_ignored() {
        let fixture = Fixture::new();
        let source = fixture.workspace.join("src/main.rs");
        let before = fixture.fingerprint(&environment());
        let file = OpenOptions::new()
            .write(true)
            .open(&source)
            .expect("open source");
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800);
        file.set_times(FileTimes::new().set_modified(modified))
            .expect("set mtime");
        let after = fixture.fingerprint(&environment());

        assert_eq!(before.workspace_tree_digest, after.workspace_tree_digest);
        assert_eq!(before.request_digest, after.request_digest);
    }

    #[test]
    fn escaping_symlink_fails_closed() {
        let fixture = Fixture::new();
        symlink("../../outside", fixture.workspace.join("escape")).expect("escaping link");
        let argv = vec![OsString::from("tool")];
        let error = fingerprint(&FingerprintInput {
            argv: &argv,
            cwd: &fixture.workspace,
            workspace: &fixture.workspace,
            environment: &environment(),
            executable: &fixture.executable,
        })
        .expect_err("escaping link must fail");

        assert!(matches!(
            error,
            FingerprintError::PathEscapesWorkspace { .. }
        ));
    }

    #[test]
    fn special_file_fails_closed() {
        let root = fs::canonicalize("/dev").expect("canonical /dev");
        let special = fs::canonicalize("/dev/null").expect("canonical /dev/null");
        let mut walker = WorkspaceWalker { root: &root };
        let error = walker
            .walk(&special, Path::new("null"))
            .expect_err("character device must fail");

        assert!(matches!(error, FingerprintError::SpecialFile(path) if path == special));
    }

    #[test]
    fn unreadable_file_fails_closed() {
        let fixture = Fixture::new();
        let unreadable = fixture.workspace.join("unreadable");
        fs::write(&unreadable, b"hidden input").expect("unreadable fixture");
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
            .expect("remove read permission");
        let argv = vec![OsString::from("tool")];
        let result = fingerprint(&FingerprintInput {
            argv: &argv,
            cwd: &fixture.workspace,
            workspace: &fixture.workspace,
            environment: &environment(),
            executable: &fixture.executable,
        });
        // Restore access before asserting so TempDir cleanup remains reliable.
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))
            .expect("restore read permission");

        assert!(matches!(result, Err(FingerprintError::Io { .. })));
    }

    #[test]
    fn volatile_again_and_git_lock_log_paths_are_excluded() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.workspace.join(".again")).expect("again dir");
        fs::create_dir(fixture.workspace.join(".git")).expect("git dir");
        fs::create_dir(fixture.workspace.join(".git/logs")).expect("git logs");
        fs::write(fixture.workspace.join(".again/cache"), b"one").expect("again cache");
        fs::write(fixture.workspace.join(".git/index.lock"), b"one").expect("git lock");
        fs::write(fixture.workspace.join(".git/logs/HEAD"), b"one").expect("git log");
        let before = fixture.fingerprint(&environment());

        fs::write(fixture.workspace.join(".again/cache"), b"two").expect("change cache");
        fs::write(fixture.workspace.join(".git/index.lock"), b"two").expect("change lock");
        fs::write(fixture.workspace.join(".git/logs/HEAD"), b"two").expect("change log");
        let after = fixture.fingerprint(&environment());

        assert_eq!(before.workspace_tree_digest, after.workspace_tree_digest);
        assert_eq!(before.request_digest, after.request_digest);
    }

    #[test]
    fn duplicate_environment_names_fail_without_exposing_plaintext() {
        let fixture = Fixture::new();
        let environment = vec![
            (OsString::from("SECRET"), OsString::from("first")),
            (OsString::from("SECRET"), OsString::from("second")),
        ];
        let argv = vec![OsString::from("tool")];
        let error = fingerprint(&FingerprintInput {
            argv: &argv,
            cwd: &fixture.workspace,
            workspace: &fixture.workspace,
            environment: &environment,
            executable: &fixture.executable,
        })
        .expect_err("duplicate environment names must fail");
        let message = error.to_string();

        assert!(matches!(
            error,
            FingerprintError::DuplicateEnvironmentName { .. }
        ));
        assert!(!message.contains("SECRET"));
        assert!(!message.contains("first"));
        assert!(!message.contains("second"));
    }

    #[test]
    fn identity_only_does_not_walk_or_invalidate_on_workspace_changes() {
        let fixture = Fixture::new();
        let unreadable = fixture.workspace.join("unrelated-large-input");
        fs::write(&unreadable, vec![b'x'; 256 * 1024]).expect("unrelated file");
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
            .expect("make unrelated file unreadable");

        let before = fixture.fingerprint_scoped(&[ScopeEntry::IdentityOnly]);
        fs::write(fixture.workspace.join("src/main.rs"), b"changed\n").expect("change source");
        let after = fixture.fingerprint_scoped(&[ScopeEntry::IdentityOnly]);
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))
            .expect("restore unrelated file");

        assert_eq!(before.request_digest, after.request_digest);
        assert_eq!(before.workspace_entries, 0);
    }

    #[test]
    fn content_path_reads_only_the_selected_file_and_invalidates_on_content() {
        let fixture = Fixture::new();
        let unrelated = fixture.workspace.join("unrelated");
        fs::write(&unrelated, vec![b'x'; 256 * 1024]).expect("unrelated file");
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o000))
            .expect("make unrelated file unreadable");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("src/main.rs"))];

        let before = fixture.fingerprint_scoped(&scope);
        assert_eq!(before.workspace_entries, 1);
        fs::write(fixture.workspace.join("src/main.rs"), b"fn selected() {}\n")
            .expect("change selected file");
        let after = fixture.fingerprint_scoped(&scope);
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600))
            .expect("restore unrelated file");

        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn missing_content_and_listing_operands_are_stable_until_created() {
        let fixture = Fixture::new();
        let cases = [
            ScopeEntry::ContentPath(PathBuf::from("src/missing-content")),
            ScopeEntry::DirectoryListing(PathBuf::from("src/missing-listing")),
        ];

        for scope in cases {
            let before = fixture.fingerprint_scoped(std::slice::from_ref(&scope));
            let repeated = fixture.fingerprint_scoped(std::slice::from_ref(&scope));
            assert_eq!(before.request_digest, repeated.request_digest);
            assert_eq!(before.workspace_entries, 1);

            let relative = match &scope {
                ScopeEntry::ContentPath(path) | ScopeEntry::DirectoryListing(path) => path,
                _ => unreachable!("test cases are path scopes"),
            };
            fs::write(fixture.workspace.join(relative), b"now present")
                .expect("create missing operand");
            let present = fixture.fingerprint_scoped(std::slice::from_ref(&scope));
            assert_ne!(before.request_digest, present.request_digest);
        }
    }

    #[test]
    fn content_tree_follows_in_workspace_symlink_targets() {
        let fixture = Fixture::new();
        let shared = fixture.workspace.join("shared.conf");
        fs::write(&shared, b"first\n").expect("shared config");
        symlink("../shared.conf", fixture.workspace.join("src/shared.conf"))
            .expect("config symlink");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("src"))];
        let before = fixture.fingerprint_scoped(&scope);
        fs::write(&shared, b"second\n").expect("change symlink target");
        let after = fixture.fingerprint_scoped(&scope);

        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn directory_listing_conservatively_changes_after_a_member_content_mutation() {
        let fixture = Fixture::new();
        let source = fixture.workspace.join("src/main.rs");
        let original_mtime = fs::metadata(&source)
            .expect("source metadata")
            .modified()
            .expect("source mtime");
        let scope = [ScopeEntry::DirectoryListing(PathBuf::from("src"))];
        let before = fixture.fingerprint_scoped(&scope);

        // Although a plain listing does not expose member contents, changing a
        // member advances its ctime. Binding the listing observation to that
        // epoch is intentionally conservative: it closes same-size/restored-
        // mtime ABA holes at the cost of a safe miss.
        fs::write(&source, b"fn nope() {}\n").expect("same-size content change");
        OpenOptions::new()
            .write(true)
            .open(&source)
            .expect("open source")
            .set_times(FileTimes::new().set_modified(original_mtime))
            .expect("restore mtime");
        let content_changed = fixture.fingerprint_scoped(&scope);
        assert_ne!(before.request_digest, content_changed.request_digest);

        fs::write(fixture.workspace.join("src/member.rs"), b"").expect("new member");
        let member_added = fixture.fingerprint_scoped(&scope);
        assert_ne!(before.request_digest, member_added.request_digest);
    }

    #[test]
    fn directory_listing_is_non_recursive() {
        let fixture = Fixture::new();
        let nested = fixture.workspace.join("src/nested");
        fs::create_dir(&nested).expect("nested directory");
        let nested_file = nested.join("value");
        fs::write(&nested_file, b"one").expect("nested file");
        let scope = [ScopeEntry::DirectoryListing(PathBuf::from("src"))];
        let before = fixture.fingerprint_scoped(&scope);
        fs::write(&nested_file, b"two").expect("change nested content");
        let after = fixture.fingerprint_scoped(&scope);

        assert_eq!(before.request_digest, after.request_digest);
    }

    #[test]
    fn scoped_fingerprints_include_mtime() {
        let fixture = Fixture::new();
        let source = fixture.workspace.join("src/main.rs");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("src/main.rs"))];
        let before = fixture.fingerprint_scoped(&scope);
        OpenOptions::new()
            .write(true)
            .open(&source)
            .expect("open source")
            .set_times(
                FileTimes::new()
                    .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567_890)),
            )
            .expect("set scoped mtime");
        let after = fixture.fingerprint_scoped(&scope);

        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn scoped_content_includes_permission_changes() {
        let fixture = Fixture::new();
        let source = fixture.workspace.join("src/main.rs");
        let scope = [ScopeEntry::ContentPath(PathBuf::from("src/main.rs"))];
        let before = fixture.fingerprint_scoped(&scope);
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))
            .expect("change scoped permission");
        let after = fixture.fingerprint_scoped(&scope);
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644))
            .expect("restore scoped permission");

        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn scoped_directory_listing_rejects_special_members() {
        let fixture = Fixture::new();
        let workspace_alias = fixture.workspace.with_file_name("workspace-alias");
        symlink(&fixture.workspace, &workspace_alias).expect("workspace alias");
        let socket = workspace_alias.join("src/socket");
        let _listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("create unix socket: {error}"),
        };
        // Scoped operands are walked below the canonical workspace. On macOS,
        // temporary directories are commonly spelled below `/var` while
        // canonicalization returns the `/private/var` alias. Compare the error
        // against the same canonical identity used by the walker.
        let canonical_socket = fs::canonicalize(&socket).expect("canonical socket path");
        let result = super::fingerprint_scoped(
            &FingerprintInput {
                argv: &[OsString::from("tool")],
                cwd: &workspace_alias,
                workspace: &workspace_alias,
                environment: &environment(),
                executable: &fixture.executable,
            },
            &[ScopeEntry::DirectoryListing(PathBuf::from("src"))],
        );

        assert!(
            matches!(result, Err(FingerprintError::SpecialFile(ref path)) if path == &canonical_socket),
            "directory listing must fail closed on Unix socket member: {result:?}"
        );
    }

    #[test]
    fn scoped_directory_listing_rejects_a_symlink_operand() {
        let fixture = Fixture::new();
        symlink("src", fixture.workspace.join("linked-src")).expect("directory symlink");
        let result = super::fingerprint_scoped(
            &FingerprintInput {
                argv: &[OsString::from("ls"), OsString::from("linked-src")],
                cwd: &fixture.workspace,
                workspace: &fixture.workspace,
                environment: &environment(),
                executable: &fixture.executable,
            },
            &[ScopeEntry::DirectoryListing(PathBuf::from("linked-src"))],
        );

        assert!(
            matches!(result, Err(FingerprintError::SymlinkListingOperand(ref path)) if path.ends_with("linked-src")),
            "listing symlink operand must fail closed: {result:?}"
        );
    }

    #[test]
    fn directory_listing_includes_excluded_member_metadata() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.workspace.join(".git")).expect("git directory");
        let lock = fixture.workspace.join(".git/index.lock");
        fs::write(&lock, b"one").expect("git lock");
        let scope = [ScopeEntry::DirectoryListing(PathBuf::from(".git"))];
        let before = fixture.fingerprint_scoped(&scope);

        fs::write(&lock, b"a larger lock file").expect("change excluded member metadata");
        let after = fixture.fingerprint_scoped(&scope);

        assert_ne!(before.request_digest, after.request_digest);
    }

    #[test]
    fn recursive_scope_rejects_git_directory_and_symlink_alias() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.workspace.join(".git")).expect("git directory");
        fs::create_dir_all(fixture.workspace.join(".git/refs")).expect("git refs");
        symlink(".git", fixture.workspace.join("git-alias")).expect("git alias");
        let input = FingerprintInput {
            argv: &[OsString::from("rg")],
            cwd: &fixture.workspace,
            workspace: &fixture.workspace,
            environment: &environment(),
            executable: &fixture.executable,
        };

        for scope in [
            ScopeEntry::RecursiveContentTree(PathBuf::from(".git")),
            ScopeEntry::RecursiveContentTree(PathBuf::from(".git/refs")),
            ScopeEntry::RecursiveContentTree(PathBuf::from("git-alias")),
        ] {
            let result = super::fingerprint_scoped(&input, &[scope]);
            assert!(
                matches!(result, Err(FingerprintError::ExcludedScopePath(_))),
                "recursive Git scope must fail closed: {result:?}"
            );
        }

        // A direct regular file remains a complete content observation even
        // when it lives under `.git`; only recursive directory traversal has
        // excluded descendants that make a narrow proof incomplete.
        fs::write(
            fixture.workspace.join(".git/HEAD"),
            b"ref: refs/heads/main\n",
        )
        .expect("git HEAD");
        assert!(
            super::fingerprint_scoped(
                &input,
                &[ScopeEntry::RecursiveContentTree(PathBuf::from(".git/HEAD"))]
            )
            .is_ok()
        );
    }

    #[test]
    fn scoped_symlink_cycles_fail_closed() {
        let fixture = Fixture::new();
        symlink("cycle-b", fixture.workspace.join("cycle-a")).expect("cycle a");
        symlink("cycle-a", fixture.workspace.join("cycle-b")).expect("cycle b");
        let result = super::fingerprint_scoped(
            &FingerprintInput {
                argv: &[OsString::from("tool")],
                cwd: &fixture.workspace,
                workspace: &fixture.workspace,
                environment: &environment(),
                executable: &fixture.executable,
            },
            &[ScopeEntry::ContentPath(PathBuf::from("cycle-a"))],
        );

        assert!(result.is_err());
    }

    #[test]
    fn scoped_symlink_to_special_target_fails_closed() {
        let fixture = Fixture::new();
        symlink("/dev/null", fixture.workspace.join("src/null")).expect("special target symlink");
        let result = super::fingerprint_scoped(
            &FingerprintInput {
                argv: &[OsString::from("tool")],
                cwd: &fixture.workspace,
                workspace: &fixture.workspace,
                environment: &environment(),
                executable: &fixture.executable,
            },
            &[ScopeEntry::ContentPath(PathBuf::from("src/null"))],
        );

        assert!(matches!(
            result,
            Err(FingerprintError::PathEscapesWorkspace { .. })
        ));
    }

    #[test]
    fn scope_order_and_duplicates_do_not_affect_the_digest() {
        let fixture = Fixture::new();
        let content = ScopeEntry::ContentPath(PathBuf::from("src/main.rs"));
        let first = fixture.fingerprint_scoped(&[ScopeEntry::IdentityOnly, content.clone()]);
        let second =
            fixture.fingerprint_scoped(&[content.clone(), ScopeEntry::IdentityOnly, content]);

        assert_eq!(first.request_digest, second.request_digest);
        assert_eq!(first.workspace_entries, second.workspace_entries);
    }

    #[test]
    fn whole_workspace_scope_is_mtime_sensitive_and_subsumes_other_scopes() {
        let fixture = Fixture::new();
        let whole = fixture.fingerprint_scoped(&[ScopeEntry::WholeWorkspace]);
        let redundant = fixture.fingerprint_scoped(&[
            ScopeEntry::ContentPath(PathBuf::from("src/main.rs")),
            ScopeEntry::WholeWorkspace,
            ScopeEntry::IdentityOnly,
        ]);
        assert_eq!(whole, redundant);

        let source = fixture.workspace.join("src/main.rs");
        OpenOptions::new()
            .write(true)
            .open(&source)
            .expect("open source")
            .set_times(
                FileTimes::new()
                    .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_111_111_111)),
            )
            .expect("set mtime");
        let changed = fixture.fingerprint_scoped(&[ScopeEntry::WholeWorkspace]);
        assert_ne!(whole.request_digest, changed.request_digest);
    }

    #[test]
    fn scoped_paths_and_symlinks_cannot_escape_workspace() {
        let fixture = Fixture::new();
        let argv = vec![OsString::from("tool")];
        let input = FingerprintInput {
            argv: &argv,
            cwd: &fixture.workspace,
            workspace: &fixture.workspace,
            environment: &environment(),
            executable: &fixture.executable,
        };
        let relative_escape =
            fingerprint_scoped(&input, &[ScopeEntry::ContentPath(PathBuf::from("../tool"))])
                .expect_err("relative escape must fail");
        assert!(matches!(
            relative_escape,
            FingerprintError::PathEscapesWorkspace { .. }
        ));

        symlink("../tool", fixture.workspace.join("escape")).expect("escaping symlink");
        let symlink_escape =
            fingerprint_scoped(&input, &[ScopeEntry::ContentPath(PathBuf::from("escape"))])
                .expect_err("symlink escape must fail");
        assert!(matches!(
            symlink_escape,
            FingerprintError::PathEscapesWorkspace { .. }
        ));
    }
}
