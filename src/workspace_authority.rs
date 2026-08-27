//! Bounded, read-only authority over the state on which one tool result depends.
//!
//! An authority is minted only from an explicit observation plan. Paths outside
//! that plan are deliberately unobserved and therefore cannot be claimed as
//! dependencies. Filesystem notifications may tell a caller when to re-run an
//! observation, but they are never accepted as evidence by this module.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use blake3::Hasher;

pub const WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1: u16 = 1;

/// Hard limits applied before an observation can mint authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceAuthorityLimitsV1 {
    pub max_plan_entries: usize,
    pub max_path_bytes: usize,
    pub max_total_path_bytes: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_tree_entries: u64,
    pub max_tree_depth: usize,
    pub max_directory_entries: u64,
    pub max_environment_entries: usize,
    pub max_environment_name_bytes: usize,
    pub max_environment_value_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_task_field_bytes: usize,
    pub max_external_dependencies: usize,
    pub max_external_token_bytes: usize,
}

impl Default for WorkspaceAuthorityLimitsV1 {
    fn default() -> Self {
        Self {
            max_plan_entries: 1_024,
            max_path_bytes: 4_096,
            max_total_path_bytes: 16 * 1024 * 1024,
            max_file_bytes: 256 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            max_tree_entries: 100_000,
            max_tree_depth: 256,
            max_directory_entries: 16_384,
            max_environment_entries: 256,
            max_environment_name_bytes: 256,
            max_environment_value_bytes: 1024 * 1024,
            max_identity_bytes: 16 * 1024,
            max_task_field_bytes: 64 * 1024,
            max_external_dependencies: 256,
            max_external_token_bytes: 1024 * 1024,
        }
    }
}

/// A deterministic, domain-separated BLAKE3 state digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateDigestV1([u8; 32]);

impl StateDigestV1 {
    pub fn from_domain_and_bytes(domain: &'static [u8], value: &[u8]) -> Self {
        let mut encoder = CanonicalEncoder::new(domain);
        encoder.bytes(value);
        encoder.finish()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StateDimensionV1 {
    Repository,
    RepositoryGit,
    RepositoryIndex,
    RepositoryContent,
    OperatingSystem,
    Architecture,
    Kernel,
    Executables,
    WorkingDirectory,
    EnvironmentValues,
    ResourceProfile,
    SandboxBackend,
    McpProviderToolSchema,
    AuthorizationScope,
    Task,
    ExternalFreshness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompleteReasonCodeV1 {
    UnknownRelevantState,
    UnreadableRelevantState,
    InvalidObservationPlan,
    InputLimitExceeded,
    SymlinkRefused,
    SpecialFileRefused,
    SparseCheckoutAmbiguous,
    ConcurrentMutation,
    RepositoryReplaced,
    GitStateChanged,
}

#[derive(Clone, Eq, PartialEq)]
pub struct IncompleteReasonV1 {
    code: IncompleteReasonCodeV1,
    dimension: StateDimensionV1,
    path: Option<PathBuf>,
    operation: &'static str,
}

impl std::fmt::Debug for IncompleteReasonV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IncompleteReasonV1")
            .field("code", &self.code)
            .field("dimension", &self.dimension)
            .field("path", &self.path.as_ref().map(|_| "<redacted>"))
            .field("operation", &self.operation)
            .finish()
    }
}

impl IncompleteReasonV1 {
    pub fn code(&self) -> IncompleteReasonCodeV1 {
        self.code
    }

    pub fn dimension(&self) -> StateDimensionV1 {
        self.dimension
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn operation(&self) -> &'static str {
        self.operation
    }
}

/// A fail-closed result. This type intentionally has no authority-producing
/// method; only [`CompleteToolStateV1`] can mint reusable authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncompleteToolStateV1 {
    schema_version: u16,
    reasons: Vec<IncompleteReasonV1>,
}

impl IncompleteToolStateV1 {
    fn single(
        code: IncompleteReasonCodeV1,
        dimension: StateDimensionV1,
        path: Option<PathBuf>,
        operation: &'static str,
    ) -> Self {
        Self {
            schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
            reasons: vec![IncompleteReasonV1 {
                code,
                dimension,
                path,
                operation,
            }],
        }
    }

    pub fn unknown(dimension: StateDimensionV1, operation: &'static str) -> Self {
        Self::single(
            IncompleteReasonCodeV1::UnknownRelevantState,
            dimension,
            None,
            operation,
        )
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn reasons(&self) -> &[IncompleteReasonV1] {
        &self.reasons
    }

    pub fn primary_code(&self) -> IncompleteReasonCodeV1 {
        self.reasons[0].code
    }
}

pub type AuthorityResult<T> = Result<T, IncompleteToolStateV1>;

fn incomplete_io(
    dimension: StateDimensionV1,
    path: &Path,
    operation: &'static str,
    _error: io::Error,
) -> IncompleteToolStateV1 {
    IncompleteToolStateV1::single(
        IncompleteReasonCodeV1::UnreadableRelevantState,
        dimension,
        Some(path.to_path_buf()),
        operation,
    )
}

fn incomplete_limit(
    dimension: StateDimensionV1,
    path: Option<&Path>,
    operation: &'static str,
) -> IncompleteToolStateV1 {
    IncompleteToolStateV1::single(
        IncompleteReasonCodeV1::InputLimitExceeded,
        dimension,
        path.map(Path::to_path_buf),
        operation,
    )
}

fn incomplete_plan(
    dimension: StateDimensionV1,
    path: Option<&Path>,
    operation: &'static str,
) -> IncompleteToolStateV1 {
    IncompleteToolStateV1::single(
        IncompleteReasonCodeV1::InvalidObservationPlan,
        dimension,
        path.map(Path::to_path_buf),
        operation,
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct RepositoryObservationPlanV1 {
    /// Exact regular files whose metadata and content are relevant.
    content_paths: Vec<PathBuf>,
    /// Exact recursive trees. Every entry is included regardless of Git
    /// tracking or ignore status, so relevant untracked inputs are bound.
    recursive_trees: Vec<PathBuf>,
    /// One-level directory name, type, and metadata observations.
    directory_listings: Vec<PathBuf>,
    /// Existence observations, including an explicit absent state.
    negative_dependencies: Vec<PathBuf>,
}
impl std::fmt::Debug for RepositoryObservationPlanV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryObservationPlanV1")
            .field("content_paths", &self.content_paths.len())
            .field("recursive_trees", &self.recursive_trees.len())
            .field("directory_listings", &self.directory_listings.len())
            .field("negative_dependencies", &self.negative_dependencies.len())
            .finish()
    }
}

impl RepositoryObservationPlanV1 {
    pub fn new(
        content_paths: Vec<PathBuf>,
        recursive_trees: Vec<PathBuf>,
        directory_listings: Vec<PathBuf>,
        negative_dependencies: Vec<PathBuf>,
    ) -> Self {
        Self {
            content_paths,
            recursive_trees,
            directory_listings,
            negative_dependencies,
        }
    }

    pub fn content_paths(&self) -> &[PathBuf] {
        &self.content_paths
    }

    pub fn recursive_trees(&self) -> &[PathBuf] {
        &self.recursive_trees
    }

    pub fn directory_listings(&self) -> &[PathBuf] {
        &self.directory_listings
    }

    pub fn negative_dependencies(&self) -> &[PathBuf] {
        &self.negative_dependencies
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryObservationKindV1 {
    ContentPath,
    RecursiveTree,
    DirectoryListing,
    NegativeDependency,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RepositoryObservationV1 {
    kind: RepositoryObservationKindV1,
    path: PathBuf,
    digest: StateDigestV1,
    entries: u64,
    bytes: u64,
    present: bool,
}
impl std::fmt::Debug for RepositoryObservationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryObservationV1")
            .field("kind", &self.kind)
            .field("path", &"<redacted>")
            .field("digest", &self.digest)
            .field("entries", &self.entries)
            .field("bytes", &self.bytes)
            .field("present", &self.present)
            .finish()
    }
}

impl RepositoryObservationV1 {
    pub fn kind(&self) -> RepositoryObservationKindV1 {
        self.kind
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }

    pub fn entries(&self) -> u64 {
        self.entries
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn is_present(&self) -> bool {
        self.present
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum RepositoryGitStateV1 {
    NotGitRepository,
    Git {
        worktree_root: PathBuf,
        git_directory: PathBuf,
        head_ref: Option<String>,
        head_object: Option<String>,
        head_digest: StateDigestV1,
        index_digest: Option<StateDigestV1>,
    },
}
impl std::fmt::Debug for RepositoryGitStateV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGitRepository => f.write_str("NotGitRepository"),
            Self::Git {
                head_ref,
                head_object,
                head_digest,
                index_digest,
                ..
            } => f
                .debug_struct("Git")
                .field("paths", &"<redacted>")
                .field("head_ref", &head_ref.as_ref().map(|_| "<redacted>"))
                .field("head_object", &head_object.as_ref().map(|_| "<redacted>"))
                .field("head_digest", head_digest)
                .field("index_digest", index_digest)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RepositoryEpochV1 {
    schema_version: u16,
    canonical_workspace: PathBuf,
    workspace_identity: FilesystemIdentityV1,
    git: RepositoryGitStateV1,
    plan: RepositoryObservationPlanV1,
    observations: Vec<RepositoryObservationV1>,
    digest: StateDigestV1,
}
impl std::fmt::Debug for RepositoryEpochV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryEpochV1")
            .field("schema_version", &self.schema_version)
            .field("workspace", &"<redacted>")
            .field("git", &self.git)
            .field("observation_count", &self.observations.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl RepositoryEpochV1 {
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn canonical_workspace(&self) -> &Path {
        &self.canonical_workspace
    }

    pub fn workspace_identity_digest(&self) -> StateDigestV1 {
        let mut encoder = CanonicalEncoder::new(b"again.workspace-identity.v1");
        encoder.path(&self.canonical_workspace);
        self.workspace_identity.encode_authority(&mut encoder);
        encoder.finish()
    }

    pub fn git_state(&self) -> &RepositoryGitStateV1 {
        &self.git
    }

    pub fn plan(&self) -> &RepositoryObservationPlanV1 {
        &self.plan
    }

    pub fn observations(&self) -> &[RepositoryObservationV1] {
        &self.observations
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_repository_epoch(self)
    }
}

/// One descriptor-retained repository identity for a complete provider call.
///
/// The owned root descriptor is deliberately private and this type is neither
/// cloneable nor serializable. Repository observations, provider reads, and
/// final validation performed through this value therefore remain attached to
/// the exact directory opened at issuance even if its pathname is replaced and
/// later restored.
pub(crate) struct WorkspaceExecutionEpochV1 {
    requested_workspace: PathBuf,
    canonical_workspace: PathBuf,
    root_handle: File,
    root_identity: FilesystemIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryNodeKindV1 {
    Missing,
    Directory,
    Regular,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RepositoryRegularFileV1 {
    relative_path: PathBuf,
    bytes: u64,
}

impl RepositoryRegularFileV1 {
    pub(crate) fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FilesystemIdentityV1 {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

impl FilesystemIdentityV1 {
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

    fn encode_full(self, encoder: &mut CanonicalEncoder) {
        self.encode_authority(encoder);
        encoder.u64(self.size);
        encoder.i64(self.mtime_sec);
        encoder.i64(self.mtime_nsec);
        encoder.i64(self.ctime_sec);
        encoder.i64(self.ctime_nsec);
    }

    fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }

    fn same_authority(self, other: Self) -> bool {
        self.same_object(other)
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
    }

    /// Stable identity omits mutable timestamps and directory size. Those are
    /// still checked at every pre/open/post race boundary, but excluding them
    /// from the authority lets explicitly unobserved paths remain irrelevant.
    fn encode_authority(self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.device);
        encoder.u64(self.inode);
        encoder.u32(self.mode);
        encoder.u32(self.uid);
        encoder.u32(self.gid);
    }
}

#[derive(Clone, Copy)]
enum ExpectedNodeV1 {
    Directory,
    Regular,
}

fn secure_open_path(
    path: &Path,
    expected: ExpectedNodeV1,
    dimension: StateDimensionV1,
    operation: &'static str,
) -> AuthorityResult<File> {
    let mut current = if path.is_absolute() {
        File::open("/").map_err(|error| incomplete_io(dimension, path, operation, error))?
    } else {
        File::open(".").map_err(|error| incomplete_io(dimension, path, operation, error))?
    };
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            Component::ParentDir => components.push(OsString::from("..")),
            Component::Prefix(_) => return Err(incomplete_plan(dimension, Some(path), operation)),
        }
    }
    let component_count = components.len();
    for (index, name) in components.into_iter().enumerate() {
        let final_component = index + 1 == component_count;
        let require_directory = !final_component || matches!(expected, ExpectedNodeV1::Directory);
        current = openat_no_follow(
            current.as_raw_fd(),
            &name,
            require_directory,
            dimension,
            path,
            operation,
        )?;
    }
    let metadata = current
        .metadata()
        .map_err(|error| incomplete_io(dimension, path, operation, error))?;
    let valid = match expected {
        ExpectedNodeV1::Directory => metadata.is_dir(),
        ExpectedNodeV1::Regular => metadata.is_file(),
    };
    if !valid {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SpecialFileRefused,
            dimension,
            Some(path.to_path_buf()),
            operation,
        ));
    }
    Ok(current)
}

fn duplicate_descriptor(
    file: &File,
    dimension: StateDimensionV1,
    display_path: &Path,
    operation: &'static str,
) -> AuthorityResult<File> {
    // SAFETY: fcntl duplicates a live descriptor and returns unique ownership.
    let descriptor = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(incomplete_io(
            dimension,
            display_path,
            operation,
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn secure_open_relative(
    anchor: &File,
    relative: &Path,
    expected: ExpectedNodeV1,
    dimension: StateDimensionV1,
    display_path: &Path,
    operation: &'static str,
) -> AuthorityResult<File> {
    let mut current = duplicate_descriptor(anchor, dimension, display_path, operation)?;
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(incomplete_plan(dimension, Some(display_path), operation));
            }
        }
    }
    let count = components.len();
    for (index, name) in components.into_iter().enumerate() {
        let final_component = index + 1 == count;
        current = openat_no_follow(
            current.as_raw_fd(),
            &name,
            !final_component || matches!(expected, ExpectedNodeV1::Directory),
            dimension,
            display_path,
            operation,
        )?;
    }
    let metadata = current
        .metadata()
        .map_err(|error| incomplete_io(dimension, display_path, operation, error))?;
    let valid = match expected {
        ExpectedNodeV1::Directory => metadata.is_dir(),
        ExpectedNodeV1::Regular => metadata.is_file(),
    };
    if !valid {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SpecialFileRefused,
            dimension,
            Some(display_path.to_path_buf()),
            operation,
        ));
    }
    Ok(current)
}

fn secure_node_kind_relative(
    anchor: &File,
    relative: &Path,
    dimension: StateDimensionV1,
    display_path: &Path,
    operation: &'static str,
) -> AuthorityResult<Option<SecureNodeKindV1>> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let parent_handle = secure_open_relative(
        anchor,
        parent,
        ExpectedNodeV1::Directory,
        dimension,
        display_path,
        operation,
    )?;
    let Some(name) = relative.file_name() else {
        return Ok(Some(SecureNodeKindV1::Directory));
    };
    let name = CString::new(name.as_bytes())
        .map_err(|_| incomplete_plan(dimension, Some(display_path), operation))?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            parent_handle.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(incomplete_io(dimension, display_path, operation, error));
    }
    let kind = stat.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SymlinkRefused,
            dimension,
            Some(display_path.to_path_buf()),
            operation,
        ));
    }
    if kind == libc::S_IFDIR {
        Ok(Some(SecureNodeKindV1::Directory))
    } else if kind == libc::S_IFREG {
        Ok(Some(SecureNodeKindV1::Regular))
    } else {
        Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SpecialFileRefused,
            dimension,
            Some(display_path.to_path_buf()),
            operation,
        ))
    }
}

impl WorkspaceExecutionEpochV1 {
    pub(crate) fn begin(
        workspace: &Path,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        validate_limits(limits)?;
        let root_handle = secure_open_path(
            workspace,
            ExpectedNodeV1::Directory,
            StateDimensionV1::Repository,
            "open provider workspace epoch",
        )?;
        let canonical_workspace = descriptor_path(
            &root_handle,
            workspace,
            StateDimensionV1::Repository,
            "resolve provider workspace epoch",
        )?;
        check_path_bound(&canonical_workspace, limits, StateDimensionV1::Repository)?;
        let root_identity =
            FilesystemIdentityV1::from_metadata(&root_handle.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::Repository,
                    &canonical_workspace,
                    "inspect provider workspace epoch",
                    error,
                )
            })?);
        let epoch = Self {
            requested_workspace: workspace.to_path_buf(),
            canonical_workspace,
            root_handle,
            root_identity,
        };
        epoch.verify_current_path()?;
        Ok(epoch)
    }

    pub(crate) fn canonical_workspace(&self) -> &Path {
        &self.canonical_workspace
    }

    pub(crate) fn classify_relative(
        &self,
        relative: &Path,
    ) -> AuthorityResult<RepositoryNodeKindV1> {
        let display = self.canonical_workspace.join(relative);
        let kind = secure_node_kind_relative(
            &self.root_handle,
            relative,
            StateDimensionV1::RepositoryContent,
            &display,
            "classify provider repository path",
        )?;
        Ok(match kind {
            None => RepositoryNodeKindV1::Missing,
            Some(SecureNodeKindV1::Directory) => RepositoryNodeKindV1::Directory,
            Some(SecureNodeKindV1::Regular) => RepositoryNodeKindV1::Regular,
        })
    }

    pub(crate) fn observe_repository(
        &self,
        plan: &RepositoryObservationPlanV1,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<RepositoryEpochV1> {
        observe_repository_epoch_inner(self, plan, limits, || {})
    }

    pub(crate) fn read_repository_file(
        &self,
        relative: &Path,
        maximum_bytes: u64,
    ) -> AuthorityResult<Vec<u8>> {
        self.read_repository_file_inner(relative, maximum_bytes, || {})
    }

    fn read_repository_file_inner<F>(
        &self,
        relative: &Path,
        maximum_bytes: u64,
        before_final_validation: F,
    ) -> AuthorityResult<Vec<u8>>
    where
        F: FnOnce(),
    {
        if maximum_bytes == 0 {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "bound repository provider read",
            ));
        }
        let mut file = secure_open_relative(
            &self.root_handle,
            relative,
            ExpectedNodeV1::Regular,
            StateDimensionV1::RepositoryContent,
            relative,
            "open repository provider input",
        )?;
        let before = FilesystemIdentityV1::from_metadata(&file.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                relative,
                "inspect repository provider input",
                error,
            )
        })?);
        if before.size > maximum_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "read repository provider input",
            ));
        }
        let capacity = usize::try_from(before.size).map_err(|_| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "allocate repository provider input",
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "allocate repository provider input",
            )
        })?;
        file.by_ref()
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                incomplete_io(
                    StateDimensionV1::RepositoryContent,
                    relative,
                    "read repository provider input",
                    error,
                )
            })?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "read repository provider input",
            ));
        }
        let after = FilesystemIdentityV1::from_metadata(&file.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                relative,
                "reinspect repository provider input",
                error,
            )
        })?);
        let reopened = secure_open_relative(
            &self.root_handle,
            relative,
            ExpectedNodeV1::Regular,
            StateDimensionV1::RepositoryContent,
            relative,
            "reopen repository provider input",
        )?;
        let path_after =
            FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::RepositoryContent,
                    relative,
                    "inspect reopened repository provider input",
                    error,
                )
            })?);
        before_final_validation();
        self.verify_current_path()?;
        if before != after || after != path_after {
            return Err(concurrent(
                StateDimensionV1::RepositoryContent,
                relative,
                "authenticate repository provider read",
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn list_regular_files(
        &self,
        start: &Path,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Vec<RepositoryRegularFileV1>> {
        validate_limits(limits)?;
        let normalized = normalize_provider_relative_path(start, limits)?;
        let mut files = Vec::new();
        let mut ledger = ProviderTraversalLedgerV1::default();
        collect_provider_regular_files_v1(self, &normalized, 0, limits, &mut ledger, &mut files)?;
        self.verify_current_path()?;
        Ok(files)
    }

    fn verify_current_path(&self) -> AuthorityResult<()> {
        let handle_identity =
            FilesystemIdentityV1::from_metadata(&self.root_handle.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::Repository,
                    &self.canonical_workspace,
                    "reinspect provider workspace epoch",
                    error,
                )
            })?);
        let reopened = secure_open_path(
            &self.requested_workspace,
            ExpectedNodeV1::Directory,
            StateDimensionV1::Repository,
            "reopen provider workspace epoch",
        )?;
        let path_identity =
            FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::Repository,
                    &self.canonical_workspace,
                    "inspect reopened provider workspace epoch",
                    error,
                )
            })?);
        let canonical_after = descriptor_path(
            &reopened,
            &self.requested_workspace,
            StateDimensionV1::Repository,
            "resolve reopened provider workspace epoch",
        )?;
        if !self.root_identity.same_authority(handle_identity)
            || !self.root_identity.same_authority(path_identity)
            || self.canonical_workspace != canonical_after
        {
            return Err(IncompleteToolStateV1::single(
                IncompleteReasonCodeV1::RepositoryReplaced,
                StateDimensionV1::Repository,
                Some(self.canonical_workspace.clone()),
                "verify provider workspace epoch",
            ));
        }
        Ok(())
    }
}

fn openat_no_follow(
    parent: RawFd,
    name: &OsStr,
    directory: bool,
    dimension: StateDimensionV1,
    display_path: &Path,
    operation: &'static str,
) -> AuthorityResult<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| incomplete_plan(dimension, Some(display_path), operation))?;
    let mut before: libc::stat = unsafe { std::mem::zeroed() };
    let inspected = unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            &mut before,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if inspected < 0 {
        return Err(incomplete_io(
            dimension,
            display_path,
            operation,
            io::Error::last_os_error(),
        ));
    }
    let kind = before.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SymlinkRefused,
            dimension,
            Some(display_path.to_path_buf()),
            operation,
        ));
    }
    if (directory && kind != libc::S_IFDIR) || (!directory && kind != libc::S_IFREG) {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SpecialFileRefused,
            dimension,
            Some(display_path.to_path_buf()),
            operation,
        ));
    }
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if directory {
        flags |= libc::O_DIRECTORY;
    } else {
        // Avoid blocking if an attacker substitutes a FIFO before the final
        // descriptor authentication. Regular files ignore O_NONBLOCK.
        flags |= libc::O_NONBLOCK;
    }
    // SAFETY: `parent` is an owned live directory descriptor, `name` is NUL
    // terminated, and successful ownership is transferred immediately to File.
    let descriptor = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ELOOP)) {
            return Err(IncompleteToolStateV1::single(
                IncompleteReasonCodeV1::SymlinkRefused,
                dimension,
                Some(display_path.to_path_buf()),
                operation,
            ));
        }
        if matches!(error.raw_os_error(), Some(libc::ENOTDIR)) {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: the parent descriptor and name remain live; this only
            // classifies the refused final component without following it.
            let classified = unsafe {
                libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
            };
            if classified == 0 && stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(IncompleteToolStateV1::single(
                    IncompleteReasonCodeV1::SymlinkRefused,
                    dimension,
                    Some(display_path.to_path_buf()),
                    operation,
                ));
            }
            return Err(IncompleteToolStateV1::single(
                IncompleteReasonCodeV1::SpecialFileRefused,
                dimension,
                Some(display_path.to_path_buf()),
                operation,
            ));
        }
        return Err(incomplete_io(dimension, display_path, operation, error));
    }
    let mut after: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: descriptor is newly opened and after is writable.
    if unsafe { libc::fstat(descriptor, &mut after) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(descriptor) };
        return Err(incomplete_io(dimension, display_path, operation, error));
    }
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode
    {
        unsafe { libc::close(descriptor) };
        return Err(concurrent(dimension, display_path, operation));
    }
    // SAFETY: `descriptor` is newly returned and uniquely owned.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SecureNodeKindV1 {
    Directory,
    Regular,
}

fn secure_node_kind(
    path: &Path,
    dimension: StateDimensionV1,
    operation: &'static str,
) -> AuthorityResult<Option<SecureNodeKindV1>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let Some(name) = path.file_name() else {
        let handle = secure_open_path(path, ExpectedNodeV1::Directory, dimension, operation)?;
        drop(handle);
        return Ok(Some(SecureNodeKindV1::Directory));
    };
    let parent_handle = secure_open_path(parent, ExpectedNodeV1::Directory, dimension, operation)?;
    let name = CString::new(name.as_bytes())
        .map_err(|_| incomplete_plan(dimension, Some(path), operation))?;
    // SAFETY: parent_handle is a live directory descriptor and stat points to
    // initialized writable storage. AT_SYMLINK_NOFOLLOW prevents traversal.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            parent_handle.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(incomplete_io(dimension, path, operation, error));
    }
    let file_type = stat.st_mode & libc::S_IFMT;
    if file_type == libc::S_IFLNK {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SymlinkRefused,
            dimension,
            Some(path.to_path_buf()),
            operation,
        ));
    }
    if file_type == libc::S_IFDIR {
        Ok(Some(SecureNodeKindV1::Directory))
    } else if file_type == libc::S_IFREG {
        Ok(Some(SecureNodeKindV1::Regular))
    } else {
        Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::SpecialFileRefused,
            dimension,
            Some(path.to_path_buf()),
            operation,
        ))
    }
}

#[cfg(target_os = "linux")]
fn descriptor_path(
    file: &File,
    display_path: &Path,
    dimension: StateDimensionV1,
    operation: &'static str,
) -> AuthorityResult<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|error| incomplete_io(dimension, display_path, operation, error))
}

#[cfg(target_os = "macos")]
fn descriptor_path(
    file: &File,
    display_path: &Path,
    dimension: StateDimensionV1,
    operation: &'static str,
) -> AuthorityResult<PathBuf> {
    let mut bytes = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the buffer is writable for PATH_MAX bytes and F_GETPATH writes a
    // NUL-terminated path without taking ownership of the descriptor.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, bytes.as_mut_ptr()) };
    if result < 0 {
        return Err(incomplete_io(
            dimension,
            display_path,
            operation,
            io::Error::last_os_error(),
        ));
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| incomplete_limit(dimension, Some(display_path), "bound descriptor path"))?;
    bytes.truncate(end);
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn descriptor_path(
    _file: &File,
    display_path: &Path,
    dimension: StateDimensionV1,
    operation: &'static str,
) -> AuthorityResult<PathBuf> {
    Err(IncompleteToolStateV1::single(
        IncompleteReasonCodeV1::UnreadableRelevantState,
        dimension,
        Some(display_path.to_path_buf()),
        operation,
    ))
}

struct DirectoryStreamV1(*mut libc::DIR);

impl Drop for DirectoryStreamV1 {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the DIR pointer returned by
        // fdopendir and closes it exactly once.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn directory_names_from_handle(
    handle: &File,
    path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<Vec<OsString>> {
    // SAFETY: fcntl duplicates a live descriptor; the duplicate is transferred
    // to fdopendir below or closed on its failure path.
    let duplicate = unsafe { libc::fcntl(handle.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(incomplete_io(
            StateDimensionV1::RepositoryContent,
            path,
            "duplicate directory descriptor",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: duplicate is a directory descriptor and ownership transfers to
    // the returned DIR stream on success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and therefore did not take ownership.
        unsafe { libc::close(duplicate) };
        return Err(incomplete_io(
            StateDimensionV1::RepositoryContent,
            path,
            "open directory stream",
            io::Error::last_os_error(),
        ));
    }
    let stream = DirectoryStreamV1(stream);
    // SAFETY: stream owns a live DIR. A duplicated descriptor shares the open
    // file description offset, so every sample must explicitly rewind it.
    unsafe { libc::rewinddir(stream.0) };
    let mut names = Vec::new();
    let mut total_name_bytes = 0_usize;
    loop {
        set_errno_zero();
        // SAFETY: stream owns a live DIR pointer. The entry remains valid until
        // the next readdir call and is copied before then.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = errno_value();
            if error != 0 {
                return Err(incomplete_io(
                    StateDimensionV1::RepositoryContent,
                    path,
                    "read directory stream",
                    io::Error::from_raw_os_error(error),
                ));
            }
            break;
        }
        // SAFETY: POSIX dirent d_name is NUL terminated for a successful entry.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if names.len() as u64 >= limits.max_directory_entries {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "bound directory entries",
            ));
        }
        if bytes.len() > limits.max_path_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "bound directory entry name",
            ));
        }
        total_name_bytes = total_name_bytes.checked_add(bytes.len()).ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "sum directory entry name bytes",
            )
        })?;
        if total_name_bytes > limits.max_total_path_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "bound directory entry name bytes",
            ));
        }
        names.try_reserve(1).map_err(|_| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "allocate directory entry name",
            )
        })?;
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

#[derive(Default)]
struct ProviderTraversalLedgerV1 {
    entries: u64,
    path_bytes: usize,
}

impl ProviderTraversalLedgerV1 {
    fn charge(
        &mut self,
        relative: &Path,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<()> {
        self.entries = self.entries.checked_add(1).ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "sum provider traversal entries",
            )
        })?;
        if self.entries > limits.max_tree_entries {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "bound provider traversal entries",
            ));
        }
        let bytes = relative.as_os_str().as_bytes().len();
        if bytes > limits.max_path_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "bound provider traversal path",
            ));
        }
        self.path_bytes = self.path_bytes.checked_add(bytes).ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "sum provider traversal path bytes",
            )
        })?;
        if self.path_bytes > limits.max_total_path_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(relative),
                "bound provider traversal path bytes",
            ));
        }
        Ok(())
    }
}

fn normalize_provider_relative_path(
    path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(incomplete_plan(
                    StateDimensionV1::RepositoryContent,
                    Some(path),
                    "normalize provider traversal path",
                ));
            }
        }
    }
    check_path_bound(&normalized, limits, StateDimensionV1::RepositoryContent)?;
    Ok(normalized)
}

fn collect_provider_regular_files_v1(
    epoch: &WorkspaceExecutionEpochV1,
    relative: &Path,
    depth: usize,
    limits: &WorkspaceAuthorityLimitsV1,
    ledger: &mut ProviderTraversalLedgerV1,
    files: &mut Vec<RepositoryRegularFileV1>,
) -> AuthorityResult<()> {
    if depth > limits.max_tree_depth {
        return Err(incomplete_limit(
            StateDimensionV1::RepositoryContent,
            Some(relative),
            "bound provider traversal depth",
        ));
    }
    ledger.charge(relative, limits)?;
    let display = epoch.canonical_workspace.join(relative);
    match secure_node_kind_relative(
        &epoch.root_handle,
        relative,
        StateDimensionV1::RepositoryContent,
        &display,
        "inspect provider traversal entry",
    )? {
        None => Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::UnreadableRelevantState,
            StateDimensionV1::RepositoryContent,
            Some(display),
            "require provider traversal entry",
        )),
        Some(SecureNodeKindV1::Regular) => {
            let file = secure_open_relative(
                &epoch.root_handle,
                relative,
                ExpectedNodeV1::Regular,
                StateDimensionV1::RepositoryContent,
                &display,
                "open provider traversal file",
            )?;
            let before =
                FilesystemIdentityV1::from_metadata(&file.metadata().map_err(|error| {
                    incomplete_io(
                        StateDimensionV1::RepositoryContent,
                        &display,
                        "inspect provider traversal file",
                        error,
                    )
                })?);
            let reopened = secure_open_relative(
                &epoch.root_handle,
                relative,
                ExpectedNodeV1::Regular,
                StateDimensionV1::RepositoryContent,
                &display,
                "reopen provider traversal file",
            )?;
            let after =
                FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
                    incomplete_io(
                        StateDimensionV1::RepositoryContent,
                        &display,
                        "reinspect provider traversal file",
                        error,
                    )
                })?);
            if before != after {
                return Err(concurrent(
                    StateDimensionV1::RepositoryContent,
                    &display,
                    "authenticate provider traversal file",
                ));
            }
            files.try_reserve(1).map_err(|_| {
                incomplete_limit(
                    StateDimensionV1::RepositoryContent,
                    Some(&display),
                    "allocate provider traversal result",
                )
            })?;
            files.push(RepositoryRegularFileV1 {
                relative_path: relative.to_path_buf(),
                bytes: before.size,
            });
            Ok(())
        }
        Some(SecureNodeKindV1::Directory) => {
            let (_identity, names) =
                stable_directory_listing_relative(&epoch.root_handle, relative, &display, limits)?;
            for name in names {
                let child_bytes = relative
                    .as_os_str()
                    .as_bytes()
                    .len()
                    .checked_add(name.as_bytes().len())
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| {
                        incomplete_limit(
                            StateDimensionV1::RepositoryContent,
                            Some(relative),
                            "sum provider child path bytes",
                        )
                    })?;
                if child_bytes > limits.max_path_bytes {
                    return Err(incomplete_limit(
                        StateDimensionV1::RepositoryContent,
                        Some(relative),
                        "bound provider child path",
                    ));
                }
                let child = relative.join(name);
                collect_provider_regular_files_v1(epoch, &child, depth + 1, limits, ledger, files)?;
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn errno_value() -> i32 {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "linux")]
fn set_errno_zero() {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(target_os = "macos")]
fn errno_value() -> i32 {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() }
}

#[cfg(target_os = "macos")]
fn set_errno_zero() {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() = 0 }
}

#[derive(Default)]
struct ObservationLedger {
    bytes: u64,
    entries: u64,
}

impl ObservationLedger {
    fn add_bytes(
        &mut self,
        amount: u64,
        limits: &WorkspaceAuthorityLimitsV1,
        dimension: StateDimensionV1,
        path: &Path,
    ) -> AuthorityResult<()> {
        self.bytes = self
            .bytes
            .checked_add(amount)
            .ok_or_else(|| incomplete_limit(dimension, Some(path), "sum observed bytes"))?;
        if self.bytes > limits.max_total_bytes {
            return Err(incomplete_limit(
                dimension,
                Some(path),
                "observe total bytes",
            ));
        }
        Ok(())
    }

    fn add_entry(
        &mut self,
        limits: &WorkspaceAuthorityLimitsV1,
        path: &Path,
    ) -> AuthorityResult<()> {
        self.entries = self.entries.checked_add(1).ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "sum observed entries",
            )
        })?;
        if self.entries > limits.max_tree_entries {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "observe tree entries",
            ));
        }
        Ok(())
    }
}

/// Observe a repository without writing to it. The same plan is sampled twice
/// and all path, Git, index, and workspace identities must remain stable.
pub fn observe_repository_v1(
    workspace: &Path,
    plan: &RepositoryObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<RepositoryEpochV1> {
    observe_repository_inner(workspace, plan, limits, || {})
}

fn observe_repository_inner<F>(
    workspace: &Path,
    plan: &RepositoryObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
    between_samples: F,
) -> AuthorityResult<RepositoryEpochV1>
where
    F: FnOnce(),
{
    let epoch = WorkspaceExecutionEpochV1::begin(workspace, limits)?;
    observe_repository_epoch_inner(&epoch, plan, limits, between_samples)
}

fn observe_repository_epoch_inner<F>(
    execution_epoch: &WorkspaceExecutionEpochV1,
    plan: &RepositoryObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
    between_samples: F,
) -> AuthorityResult<RepositoryEpochV1>
where
    F: FnOnce(),
{
    validate_limits(limits)?;
    let plan = normalize_plan(plan, limits)?;
    execution_epoch.verify_current_path()?;
    let canonical_workspace = execution_epoch.canonical_workspace.clone();
    let root_before = FilesystemIdentityV1::from_metadata(
        &execution_epoch.root_handle.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::Repository,
                &canonical_workspace,
                "inspect retained workspace",
                error,
            )
        })?,
    );
    if !execution_epoch.root_identity.same_authority(root_before) {
        return Err(concurrent(
            StateDimensionV1::Repository,
            &canonical_workspace,
            "authenticate retained workspace",
        ));
    }

    let git_before = observe_git_state(&canonical_workspace, limits)?;
    let observations_before = observe_plan_once(
        &canonical_workspace,
        &execution_epoch.root_handle,
        &plan,
        limits,
    )?;
    between_samples();
    execution_epoch.verify_current_path()?;
    let observations_after = observe_plan_once(
        &canonical_workspace,
        &execution_epoch.root_handle,
        &plan,
        limits,
    )?;
    if observations_before != observations_after {
        return Err(concurrent(
            StateDimensionV1::RepositoryContent,
            &canonical_workspace,
            "compare retained repository observation samples",
        ));
    }
    let git_after = observe_git_state(&canonical_workspace, limits)?;
    if git_before != git_after {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::GitStateChanged,
            StateDimensionV1::RepositoryGit,
            Some(canonical_workspace.join(".git")),
            "compare retained Git samples",
        ));
    }
    execution_epoch.verify_current_path()?;
    let root_after = FilesystemIdentityV1::from_metadata(
        &execution_epoch.root_handle.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::Repository,
                &canonical_workspace,
                "reinspect retained workspace",
                error,
            )
        })?,
    );
    if !root_before.same_authority(root_after) {
        return Err(concurrent(
            StateDimensionV1::Repository,
            &canonical_workspace,
            "verify retained repository authority identity",
        ));
    }

    let mut repository_epoch = RepositoryEpochV1 {
        schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
        canonical_workspace,
        workspace_identity: root_before,
        git: git_before,
        plan,
        observations: observations_before,
        digest: StateDigestV1([0; 32]),
    };
    repository_epoch.digest = digest_encoded(
        b"again.repository-epoch.v1",
        &encode_repository_epoch(&repository_epoch),
    );
    Ok(repository_epoch)
}

#[cfg(test)]
pub fn observe_repository_with_test_hook_v1<F>(
    workspace: &Path,
    plan: &RepositoryObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
    between_samples: F,
) -> AuthorityResult<RepositoryEpochV1>
where
    F: FnOnce(),
{
    observe_repository_inner(workspace, plan, limits, between_samples)
}

fn validate_limits(limits: &WorkspaceAuthorityLimitsV1) -> AuthorityResult<()> {
    let valid = limits.max_plan_entries > 0
        && limits.max_path_bytes > 0
        && limits.max_total_path_bytes >= limits.max_path_bytes
        && limits.max_file_bytes > 0
        && limits.max_total_bytes > 0
        && limits.max_tree_entries > 0
        && limits.max_tree_depth > 0
        && limits.max_directory_entries > 0
        && limits.max_environment_entries > 0
        && limits.max_environment_name_bytes > 0
        && limits.max_environment_value_bytes > 0
        && limits.max_identity_bytes > 0
        && limits.max_task_field_bytes > 0
        && limits.max_external_dependencies > 0
        && limits.max_external_token_bytes > 0;
    if !valid || limits.max_file_bytes > limits.max_total_bytes {
        return Err(incomplete_plan(
            StateDimensionV1::Repository,
            None,
            "validate authority limits",
        ));
    }
    Ok(())
}

fn normalize_plan(
    plan: &RepositoryObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<RepositoryObservationPlanV1> {
    let total = plan
        .content_paths
        .len()
        .checked_add(plan.recursive_trees.len())
        .and_then(|value| value.checked_add(plan.directory_listings.len()))
        .and_then(|value| value.checked_add(plan.negative_dependencies.len()))
        .ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                None,
                "count observation plan entries",
            )
        })?;
    if total > limits.max_plan_entries {
        return Err(incomplete_limit(
            StateDimensionV1::RepositoryContent,
            None,
            "bound observation plan entries",
        ));
    }

    Ok(RepositoryObservationPlanV1 {
        content_paths: normalize_path_set(&plan.content_paths, false, limits)?,
        recursive_trees: normalize_path_set(&plan.recursive_trees, true, limits)?,
        directory_listings: normalize_path_set(&plan.directory_listings, true, limits)?,
        negative_dependencies: normalize_path_set(&plan.negative_dependencies, false, limits)?,
    })
}

fn normalize_path_set(
    paths: &[PathBuf],
    allow_empty: bool,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<Vec<PathBuf>> {
    let mut normalized = Vec::new();
    normalized.try_reserve_exact(paths.len()).map_err(|_| {
        incomplete_limit(
            StateDimensionV1::RepositoryContent,
            None,
            "allocate normalized observation paths",
        )
    })?;
    for path in paths {
        if path.as_os_str().as_bytes().len() > limits.max_path_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "bound observation path",
            ));
        }
        let mut value = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(component) => value.push(component),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(incomplete_plan(
                        StateDimensionV1::RepositoryContent,
                        Some(path),
                        "normalize observation path",
                    ));
                }
            }
        }
        if !allow_empty && value.as_os_str().is_empty() {
            return Err(incomplete_plan(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "require nonempty observation path",
            ));
        }
        normalized.push(value);
    }
    normalized.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(incomplete_plan(
            StateDimensionV1::RepositoryContent,
            None,
            "reject duplicate observation paths",
        ));
    }
    Ok(normalized)
}

fn observe_plan_once(
    root: &Path,
    root_handle: &File,
    plan: &RepositoryObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<Vec<RepositoryObservationV1>> {
    let mut ledger = ObservationLedger::default();
    let mut observations = Vec::new();
    for relative in &plan.content_paths {
        observations.push(observe_content_path(
            root,
            root_handle,
            relative,
            limits,
            &mut ledger,
        )?);
    }
    for relative in &plan.recursive_trees {
        observations.push(observe_recursive_tree(
            root,
            root_handle,
            relative,
            limits,
            &mut ledger,
        )?);
    }
    for relative in &plan.directory_listings {
        observations.push(observe_directory_listing(
            root,
            root_handle,
            relative,
            limits,
            &mut ledger,
        )?);
    }
    for relative in &plan.negative_dependencies {
        observations.push(observe_negative_dependency(
            root,
            root_handle,
            relative,
            limits,
            &mut ledger,
        )?);
    }
    observations.sort_by(|left, right| {
        observation_kind_tag(left.kind)
            .cmp(&observation_kind_tag(right.kind))
            .then_with(|| {
                left.path
                    .as_os_str()
                    .as_bytes()
                    .cmp(right.path.as_os_str().as_bytes())
            })
    });
    Ok(observations)
}

fn observe_content_path(
    root: &Path,
    root_handle: &File,
    relative: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    ledger: &mut ObservationLedger,
) -> AuthorityResult<RepositoryObservationV1> {
    let path = root.join(relative);
    if secure_node_kind_relative(
        root_handle,
        relative,
        StateDimensionV1::RepositoryContent,
        &path,
        "inspect selected content",
    )? != Some(SecureNodeKindV1::Regular)
    {
        return Err(special(&path, "observe selected content"));
    }
    let file = observe_regular_file_relative(root_handle, relative, &path, limits, ledger)?;
    let mut encoder = CanonicalEncoder::new(b"again.repository-content-path.v1");
    encoder.path(relative);
    file.encode(&mut encoder);
    Ok(RepositoryObservationV1 {
        kind: RepositoryObservationKindV1::ContentPath,
        path: relative.to_path_buf(),
        digest: encoder.finish(),
        entries: 1,
        bytes: file.bytes,
        present: true,
    })
}

fn observe_recursive_tree(
    root: &Path,
    root_handle: &File,
    relative: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    ledger: &mut ObservationLedger,
) -> AuthorityResult<RepositoryObservationV1> {
    let tree_root = root.join(relative);
    if secure_node_kind_relative(
        root_handle,
        relative,
        StateDimensionV1::RepositoryContent,
        &tree_root,
        "inspect recursive tree",
    )? != Some(SecureNodeKindV1::Directory)
    {
        return Err(special(&tree_root, "observe recursive tree"));
    }

    let entries_before = ledger.entries;
    let bytes_before = ledger.bytes;
    let mut encoder = CanonicalEncoder::new(b"again.repository-recursive-tree.v1");
    encoder.path(relative);
    let context = TreeObservationContextV1 {
        repository_root: root,
        root_handle,
        tree_base: relative,
        limits,
    };
    encode_tree(&context, Path::new(""), 0, ledger, &mut encoder)?;
    Ok(RepositoryObservationV1 {
        kind: RepositoryObservationKindV1::RecursiveTree,
        path: relative.to_path_buf(),
        digest: encoder.finish(),
        entries: ledger.entries - entries_before,
        bytes: ledger.bytes - bytes_before,
        present: true,
    })
}

struct TreeObservationContextV1<'a> {
    repository_root: &'a Path,
    root_handle: &'a File,
    tree_base: &'a Path,
    limits: &'a WorkspaceAuthorityLimitsV1,
}

fn encode_tree(
    context: &TreeObservationContextV1<'_>,
    tree_relative: &Path,
    depth: usize,
    ledger: &mut ObservationLedger,
    encoder: &mut CanonicalEncoder,
) -> AuthorityResult<()> {
    let repository_relative = context.tree_base.join(tree_relative);
    let path = context.repository_root.join(&repository_relative);
    if depth > context.limits.max_tree_depth {
        return Err(incomplete_limit(
            StateDimensionV1::RepositoryContent,
            Some(&path),
            "bound recursive tree depth",
        ));
    }
    ledger.add_entry(context.limits, &path)?;
    let (identity, names) = stable_directory_listing_relative(
        context.root_handle,
        &repository_relative,
        &path,
        context.limits,
    )?;
    encoder.u8(1);
    encoder.path(tree_relative);
    identity.encode_full(encoder);
    encoder.u64(names.len() as u64);
    for name in names {
        let child_relative = tree_relative.join(&name);
        let child_repository_relative = context.tree_base.join(&child_relative);
        let child = context.repository_root.join(&child_repository_relative);
        check_path_bound(
            child
                .strip_prefix(context.repository_root)
                .unwrap_or(&child),
            context.limits,
            StateDimensionV1::RepositoryContent,
        )?;
        let kind = secure_node_kind_relative(
            context.root_handle,
            &child_repository_relative,
            StateDimensionV1::RepositoryContent,
            &child,
            "inspect recursive tree entry",
        )?
        .ok_or_else(|| {
            concurrent(
                StateDimensionV1::RepositoryContent,
                &child,
                "inspect recursive tree entry",
            )
        })?;
        if kind == SecureNodeKindV1::Directory {
            encode_tree(context, &child_relative, depth + 1, ledger, encoder)?;
        } else {
            ledger.add_entry(context.limits, &child)?;
            let observed = observe_regular_file_relative(
                context.root_handle,
                &child_repository_relative,
                &child,
                context.limits,
                ledger,
            )?;
            encoder.u8(2);
            encoder.path(&child_relative);
            observed.encode(encoder);
        }
    }
    Ok(())
}

fn observe_directory_listing(
    root: &Path,
    root_handle: &File,
    relative: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    ledger: &mut ObservationLedger,
) -> AuthorityResult<RepositoryObservationV1> {
    let path = root.join(relative);
    let entries_before = ledger.entries;
    let (identity, names) =
        stable_directory_listing_relative(root_handle, relative, &path, limits)?;
    ledger.add_entry(limits, &path)?;
    let mut encoder = CanonicalEncoder::new(b"again.repository-directory-listing.v1");
    encoder.path(relative);
    identity.encode_full(&mut encoder);
    encoder.u64(names.len() as u64);
    for name in names {
        let child = path.join(&name);
        ledger.add_entry(limits, &child)?;
        let child_relative = relative.join(&name);
        let kind = secure_node_kind_relative(
            root_handle,
            &child_relative,
            StateDimensionV1::RepositoryContent,
            &child,
            "inspect directory entry",
        )?
        .ok_or_else(|| {
            concurrent(
                StateDimensionV1::RepositoryContent,
                &child,
                "inspect directory entry",
            )
        })?;
        let expected = if kind == SecureNodeKindV1::Directory {
            ExpectedNodeV1::Directory
        } else {
            ExpectedNodeV1::Regular
        };
        let first = secure_open_relative(
            root_handle,
            &child_relative,
            expected,
            StateDimensionV1::RepositoryContent,
            &child,
            "open directory entry",
        )?;
        let identity_before =
            FilesystemIdentityV1::from_metadata(&first.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::RepositoryContent,
                    &child,
                    "inspect open directory entry",
                    error,
                )
            })?);
        let second = secure_open_relative(
            root_handle,
            &child_relative,
            expected,
            StateDimensionV1::RepositoryContent,
            &child,
            "reopen directory entry",
        )?;
        let identity_after =
            FilesystemIdentityV1::from_metadata(&second.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::RepositoryContent,
                    &child,
                    "inspect reopened directory entry",
                    error,
                )
            })?);
        if identity_before != identity_after {
            return Err(concurrent(
                StateDimensionV1::RepositoryContent,
                &child,
                "observe directory entry",
            ));
        }
        encoder.os_str(&name);
        encoder.u8(if kind == SecureNodeKindV1::Directory {
            1
        } else {
            2
        });
        identity_before.encode_full(&mut encoder);
    }
    Ok(RepositoryObservationV1 {
        kind: RepositoryObservationKindV1::DirectoryListing,
        path: relative.to_path_buf(),
        digest: encoder.finish(),
        entries: ledger.entries - entries_before,
        bytes: 0,
        present: true,
    })
}

fn observe_negative_dependency(
    root: &Path,
    root_handle: &File,
    relative: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    ledger: &mut ObservationLedger,
) -> AuthorityResult<RepositoryObservationV1> {
    let path = root.join(relative);
    let parent = path.parent().unwrap_or(root);
    let relative_parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let (parent_identity_before, names_before) =
        stable_directory_listing_relative(root_handle, relative_parent, parent, limits)?;
    let first_kind = secure_node_kind_relative(
        root_handle,
        relative,
        StateDimensionV1::RepositoryContent,
        &path,
        "inspect negative dependency",
    )?;
    let mut encoder = CanonicalEncoder::new(b"again.repository-negative-dependency.v1");
    encoder.path(relative);
    parent_identity_before.encode_authority(&mut encoder);
    let present = if let Some(kind) = first_kind {
        let expected = if kind == SecureNodeKindV1::Directory {
            ExpectedNodeV1::Directory
        } else {
            ExpectedNodeV1::Regular
        };
        let handle = secure_open_relative(
            root_handle,
            relative,
            expected,
            StateDimensionV1::RepositoryContent,
            &path,
            "open negative dependency",
        )?;
        let identity =
            FilesystemIdentityV1::from_metadata(&handle.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::RepositoryContent,
                    &path,
                    "inspect open negative dependency",
                    error,
                )
            })?);
        let reopened = secure_open_relative(
            root_handle,
            relative,
            expected,
            StateDimensionV1::RepositoryContent,
            &path,
            "reopen negative dependency",
        )?;
        let after = FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                &path,
                "inspect reopened negative dependency",
                error,
            )
        })?);
        if identity != after {
            return Err(concurrent(
                StateDimensionV1::RepositoryContent,
                &path,
                "observe negative dependency",
            ));
        }
        encoder.bool(true);
        encoder.u8(if kind == SecureNodeKindV1::Directory {
            1
        } else {
            2
        });
        identity.encode_full(&mut encoder);
        true
    } else {
        encoder.bool(false);
        false
    };
    let (parent_identity_after, names_after) =
        stable_directory_listing_relative(root_handle, relative_parent, parent, limits)?;
    let second_kind = secure_node_kind_relative(
        root_handle,
        relative,
        StateDimensionV1::RepositoryContent,
        &path,
        "reinspect negative dependency",
    )?;
    if parent_identity_before != parent_identity_after
        || names_before != names_after
        || first_kind != second_kind
    {
        return Err(concurrent(
            StateDimensionV1::RepositoryContent,
            &path,
            "observe negative dependency",
        ));
    }
    ledger.add_entry(limits, &path)?;
    Ok(RepositoryObservationV1 {
        kind: RepositoryObservationKindV1::NegativeDependency,
        path: relative.to_path_buf(),
        digest: encoder.finish(),
        entries: 1,
        bytes: 0,
        present,
    })
}

#[allow(dead_code)]
fn stable_directory_listing(
    path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<(FilesystemIdentityV1, Vec<OsString>)> {
    let handle = secure_open_path(
        path,
        ExpectedNodeV1::Directory,
        StateDimensionV1::RepositoryContent,
        "open directory",
    )?;
    let before = FilesystemIdentityV1::from_metadata(&handle.metadata().map_err(|error| {
        incomplete_io(
            StateDimensionV1::RepositoryContent,
            path,
            "inspect open directory",
            error,
        )
    })?);
    let names = directory_names_from_handle(&handle, path, limits)?;
    let names_again = directory_names_from_handle(&handle, path, limits)?;
    let after_handle =
        FilesystemIdentityV1::from_metadata(&handle.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                path,
                "reinspect open directory",
                error,
            )
        })?);
    let reopened = secure_open_path(
        path,
        ExpectedNodeV1::Directory,
        StateDimensionV1::RepositoryContent,
        "reopen directory",
    )?;
    let after_path =
        FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                path,
                "inspect reopened directory",
                error,
            )
        })?);
    if before != after_handle || before != after_path || names != names_again {
        return Err(concurrent(
            StateDimensionV1::RepositoryContent,
            path,
            "list directory",
        ));
    }
    Ok((before, names))
}

fn stable_directory_listing_relative(
    anchor: &File,
    relative: &Path,
    display_path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<(FilesystemIdentityV1, Vec<OsString>)> {
    let handle = secure_open_relative(
        anchor,
        relative,
        ExpectedNodeV1::Directory,
        StateDimensionV1::RepositoryContent,
        display_path,
        "open anchored directory",
    )?;
    let before = FilesystemIdentityV1::from_metadata(&handle.metadata().map_err(|error| {
        incomplete_io(
            StateDimensionV1::RepositoryContent,
            display_path,
            "inspect anchored directory",
            error,
        )
    })?);
    let names = directory_names_from_handle(&handle, display_path, limits)?;
    let names_again = directory_names_from_handle(&handle, display_path, limits)?;
    let after_handle =
        FilesystemIdentityV1::from_metadata(&handle.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                display_path,
                "reinspect anchored directory",
                error,
            )
        })?);
    let reopened = secure_open_relative(
        anchor,
        relative,
        ExpectedNodeV1::Directory,
        StateDimensionV1::RepositoryContent,
        display_path,
        "reopen anchored directory",
    )?;
    let after_path =
        FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                display_path,
                "inspect reopened anchored directory",
                error,
            )
        })?);
    if before != after_handle || before != after_path || names != names_again {
        return Err(concurrent(
            StateDimensionV1::RepositoryContent,
            display_path,
            "list anchored directory",
        ));
    }
    Ok((before, names))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedFileV1 {
    identity: FilesystemIdentityV1,
    content_digest: StateDigestV1,
    bytes: u64,
}

impl ObservedFileV1 {
    fn encode(self, encoder: &mut CanonicalEncoder) {
        self.identity.encode_full(encoder);
        encoder.digest(self.content_digest);
        encoder.u64(self.bytes);
    }
}

fn observe_regular_file(
    path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    ledger: &mut ObservationLedger,
) -> AuthorityResult<ObservedFileV1> {
    let mut file = secure_open_path(
        path,
        ExpectedNodeV1::Regular,
        StateDimensionV1::RepositoryContent,
        "open regular file",
    )?;
    let before_metadata = file.metadata().map_err(|error| {
        incomplete_io(
            StateDimensionV1::RepositoryContent,
            path,
            "inspect open regular file",
            error,
        )
    })?;
    if before_metadata.len() > limits.max_file_bytes {
        return Err(incomplete_limit(
            StateDimensionV1::RepositoryContent,
            Some(path),
            "bound regular file",
        ));
    }
    let before = FilesystemIdentityV1::from_metadata(&before_metadata);
    let mut hasher = Hasher::new();
    hasher.update(b"again.observed-file.v1");
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                path,
                "read regular file",
                error,
            )
        })?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "sum regular file bytes",
            )
        })?;
        if bytes > limits.max_file_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(path),
                "read bounded regular file",
            ));
        }
        ledger.add_bytes(
            read as u64,
            limits,
            StateDimensionV1::RepositoryContent,
            path,
        )?;
        hasher.update(&buffer[..read]);
    }
    let after_handle = FilesystemIdentityV1::from_metadata(&file.metadata().map_err(|error| {
        incomplete_io(
            StateDimensionV1::RepositoryContent,
            path,
            "reinspect open regular file",
            error,
        )
    })?);
    let reopened = secure_open_path(
        path,
        ExpectedNodeV1::Regular,
        StateDimensionV1::RepositoryContent,
        "reopen regular file",
    )?;
    let after_path =
        FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                path,
                "inspect reopened regular file",
                error,
            )
        })?);
    if before != after_handle || before != after_path || before.size != bytes {
        return Err(concurrent(
            StateDimensionV1::RepositoryContent,
            path,
            "read regular file",
        ));
    }
    Ok(ObservedFileV1 {
        identity: before,
        content_digest: StateDigestV1(*hasher.finalize().as_bytes()),
        bytes,
    })
}

fn observe_regular_file_relative(
    anchor: &File,
    relative: &Path,
    display_path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    ledger: &mut ObservationLedger,
) -> AuthorityResult<ObservedFileV1> {
    let mut file = secure_open_relative(
        anchor,
        relative,
        ExpectedNodeV1::Regular,
        StateDimensionV1::RepositoryContent,
        display_path,
        "open anchored regular file",
    )?;
    let before_metadata = file.metadata().map_err(|error| {
        incomplete_io(
            StateDimensionV1::RepositoryContent,
            display_path,
            "inspect anchored regular file",
            error,
        )
    })?;
    if before_metadata.len() > limits.max_file_bytes {
        return Err(incomplete_limit(
            StateDimensionV1::RepositoryContent,
            Some(display_path),
            "bound anchored regular file",
        ));
    }
    let before = FilesystemIdentityV1::from_metadata(&before_metadata);
    let mut hasher = Hasher::new();
    hasher.update(b"again.observed-file.v1");
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                display_path,
                "read anchored regular file",
                error,
            )
        })?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(display_path),
                "sum anchored regular file bytes",
            )
        })?;
        if bytes > limits.max_file_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::RepositoryContent,
                Some(display_path),
                "read bounded anchored regular file",
            ));
        }
        ledger.add_bytes(
            read as u64,
            limits,
            StateDimensionV1::RepositoryContent,
            display_path,
        )?;
        hasher.update(&buffer[..read]);
    }
    let after_handle = FilesystemIdentityV1::from_metadata(&file.metadata().map_err(|error| {
        incomplete_io(
            StateDimensionV1::RepositoryContent,
            display_path,
            "reinspect anchored regular file",
            error,
        )
    })?);
    let reopened = secure_open_relative(
        anchor,
        relative,
        ExpectedNodeV1::Regular,
        StateDimensionV1::RepositoryContent,
        display_path,
        "reopen anchored regular file",
    )?;
    let after_path =
        FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::RepositoryContent,
                display_path,
                "inspect reopened anchored regular file",
                error,
            )
        })?);
    if before != after_handle || before != after_path || before.size != bytes {
        return Err(concurrent(
            StateDimensionV1::RepositoryContent,
            display_path,
            "read anchored regular file",
        ));
    }
    Ok(ObservedFileV1 {
        identity: before,
        content_digest: StateDigestV1(*hasher.finalize().as_bytes()),
        bytes,
    })
}

#[allow(dead_code)]
fn symlink(path: &Path, operation: &'static str) -> IncompleteToolStateV1 {
    IncompleteToolStateV1::single(
        IncompleteReasonCodeV1::SymlinkRefused,
        StateDimensionV1::RepositoryContent,
        Some(path.to_path_buf()),
        operation,
    )
}

fn special(path: &Path, operation: &'static str) -> IncompleteToolStateV1 {
    IncompleteToolStateV1::single(
        IncompleteReasonCodeV1::SpecialFileRefused,
        StateDimensionV1::RepositoryContent,
        Some(path.to_path_buf()),
        operation,
    )
}

fn concurrent(
    dimension: StateDimensionV1,
    path: &Path,
    operation: &'static str,
) -> IncompleteToolStateV1 {
    IncompleteToolStateV1::single(
        IncompleteReasonCodeV1::ConcurrentMutation,
        dimension,
        Some(path.to_path_buf()),
        operation,
    )
}

fn observe_git_state(
    workspace: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<RepositoryGitStateV1> {
    let Some((worktree_root, dot_git, dot_git_kind)) = find_git_marker(workspace)? else {
        return Ok(RepositoryGitStateV1::NotGitRepository);
    };
    check_path_bound(&worktree_root, limits, StateDimensionV1::RepositoryGit)?;
    let git_directory = if dot_git_kind == SecureNodeKindV1::Directory {
        dot_git
    } else {
        let bytes = read_bounded_stable_file(
            &dot_git,
            limits.max_path_bytes as u64 + 16,
            StateDimensionV1::RepositoryGit,
        )?;
        let prefix = b"gitdir: ";
        let trimmed = trim_ascii_space(&bytes);
        let raw = trimmed.strip_prefix(prefix).ok_or_else(|| {
            incomplete_plan(
                StateDimensionV1::RepositoryGit,
                Some(&dot_git),
                "parse Git worktree pointer",
            )
        })?;
        if raw.is_empty() || raw.contains(&0) {
            return Err(incomplete_plan(
                StateDimensionV1::RepositoryGit,
                Some(&dot_git),
                "parse Git worktree pointer",
            ));
        }
        let pointed = PathBuf::from(OsString::from_vec(raw.to_vec()));
        if pointed.is_absolute() {
            pointed
        } else {
            worktree_root.join(pointed)
        }
    };

    let git_directory = canonical_directory(
        &git_directory,
        limits,
        StateDimensionV1::RepositoryGit,
        "canonicalize Git directory",
    )?;
    let common_directory = observe_common_git_directory(&git_directory, limits)?;
    refuse_sparse_checkout(&git_directory, &common_directory, limits)?;

    let head_path = git_directory.join("HEAD");
    let head_bytes = read_bounded_stable_file(
        &head_path,
        limits.max_identity_bytes as u64,
        StateDimensionV1::RepositoryGit,
    )?;
    let head_digest = digest_encoded(b"again.git-head-file.v1", &head_bytes);
    let head_text = std::str::from_utf8(trim_ascii_space(&head_bytes)).map_err(|_| {
        incomplete_plan(
            StateDimensionV1::RepositoryGit,
            Some(&head_path),
            "parse Git HEAD",
        )
    })?;
    let (head_ref, head_object) = if let Some(reference) = head_text.strip_prefix("ref: ") {
        validate_git_reference(reference, &head_path, limits)?;
        let object = resolve_git_reference(&git_directory, &common_directory, reference, limits)?;
        (Some(reference.to_owned()), object)
    } else {
        validate_git_object(head_text, &head_path)?;
        (None, Some(head_text.to_owned()))
    };

    let index_path = git_directory.join("index");
    let index_digest = match secure_node_kind(
        &index_path,
        StateDimensionV1::RepositoryIndex,
        "inspect Git index",
    )? {
        Some(kind) => {
            if kind != SecureNodeKindV1::Regular {
                return Err(IncompleteToolStateV1::single(
                    IncompleteReasonCodeV1::SpecialFileRefused,
                    StateDimensionV1::RepositoryIndex,
                    Some(index_path),
                    "observe Git index",
                ));
            }
            let bytes = read_bounded_stable_file(
                &index_path,
                limits.max_file_bytes,
                StateDimensionV1::RepositoryIndex,
            )?;
            Some(digest_encoded(b"again.git-index.v1", &bytes))
        }
        None => None,
    };

    Ok(RepositoryGitStateV1::Git {
        worktree_root,
        git_directory,
        head_ref,
        head_object,
        head_digest,
        index_digest,
    })
}

fn find_git_marker(
    workspace: &Path,
) -> AuthorityResult<Option<(PathBuf, PathBuf, SecureNodeKindV1)>> {
    let mut current = Some(workspace);
    while let Some(directory) = current {
        let marker = directory.join(".git");
        if let Some(kind) = secure_node_kind(
            &marker,
            StateDimensionV1::RepositoryGit,
            "discover Git worktree",
        )? {
            return Ok(Some((directory.to_path_buf(), marker, kind)));
        }
        current = directory.parent();
    }
    Ok(None)
}

fn observe_common_git_directory(
    git_directory: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<PathBuf> {
    let commondir_path = git_directory.join("commondir");
    match secure_node_kind(
        &commondir_path,
        StateDimensionV1::RepositoryGit,
        "inspect common Git directory",
    )? {
        Some(kind) => {
            if kind != SecureNodeKindV1::Regular {
                return Err(IncompleteToolStateV1::single(
                    IncompleteReasonCodeV1::SpecialFileRefused,
                    StateDimensionV1::RepositoryGit,
                    Some(commondir_path),
                    "resolve common Git directory",
                ));
            }
            let bytes = read_bounded_stable_file(
                &commondir_path,
                limits.max_path_bytes as u64,
                StateDimensionV1::RepositoryGit,
            )?;
            let raw = trim_ascii_space(&bytes);
            if raw.is_empty() || raw.contains(&0) {
                return Err(incomplete_plan(
                    StateDimensionV1::RepositoryGit,
                    Some(&commondir_path),
                    "parse common Git directory",
                ));
            }
            let path = PathBuf::from(OsString::from_vec(raw.to_vec()));
            let path = if path.is_absolute() {
                path
            } else {
                git_directory.join(path)
            };
            canonical_directory(
                &path,
                limits,
                StateDimensionV1::RepositoryGit,
                "canonicalize common Git directory",
            )
        }
        None => Ok(git_directory.to_path_buf()),
    }
}

fn refuse_sparse_checkout(
    git_directory: &Path,
    common_directory: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<()> {
    let mut candidates = vec![
        git_directory.join("info/sparse-checkout"),
        common_directory.join("info/sparse-checkout"),
    ];
    candidates.sort();
    candidates.dedup();
    for path in candidates {
        if secure_node_kind(
            &path,
            StateDimensionV1::RepositoryGit,
            "inspect sparse checkout marker",
        )?
        .is_some()
        {
            return Err(IncompleteToolStateV1::single(
                IncompleteReasonCodeV1::SparseCheckoutAmbiguous,
                StateDimensionV1::RepositoryGit,
                Some(path),
                "reject sparse checkout",
            ));
        }
    }

    for path in [
        common_directory.join("config"),
        git_directory.join("config.worktree"),
    ] {
        let bytes = match secure_node_kind(
            &path,
            StateDimensionV1::RepositoryGit,
            "inspect Git configuration",
        )? {
            Some(kind) => {
                if kind != SecureNodeKindV1::Regular {
                    return Err(IncompleteToolStateV1::single(
                        IncompleteReasonCodeV1::SpecialFileRefused,
                        StateDimensionV1::RepositoryGit,
                        Some(path),
                        "inspect Git configuration",
                    ));
                }
                read_bounded_stable_file(
                    &path,
                    limits
                        .max_file_bytes
                        .min(limits.max_identity_bytes as u64 * 16),
                    StateDimensionV1::RepositoryGit,
                )?
            }
            None => continue,
        };
        if git_config_enables_sparse(&bytes) {
            return Err(IncompleteToolStateV1::single(
                IncompleteReasonCodeV1::SparseCheckoutAmbiguous,
                StateDimensionV1::RepositoryGit,
                Some(path),
                "reject sparse Git configuration",
            ));
        }
    }
    Ok(())
}

fn git_config_enables_sparse(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let mut core = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            core = section == "core";
            continue;
        }
        if !core || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        if matches!(key.as_str(), "sparsecheckout" | "sparseindex")
            && matches!(value.as_str(), "true" | "yes" | "on" | "1")
        {
            return true;
        }
    }
    false
}

fn validate_git_reference(
    reference: &str,
    head_path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<()> {
    let valid = reference.starts_with("refs/")
        && reference.len() <= limits.max_path_bytes
        && !reference.as_bytes().contains(&0)
        && !reference.contains("..")
        && !reference.contains("//")
        && !reference.starts_with('/')
        && !reference.ends_with('/');
    if !valid {
        return Err(incomplete_plan(
            StateDimensionV1::RepositoryGit,
            Some(head_path),
            "validate Git HEAD reference",
        ));
    }
    Ok(())
}

fn validate_git_object(object: &str, path: &Path) -> AuthorityResult<()> {
    if !matches!(object.len(), 40 | 64) || !object.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(incomplete_plan(
            StateDimensionV1::RepositoryGit,
            Some(path),
            "validate Git object identity",
        ));
    }
    Ok(())
}

fn resolve_git_reference(
    git_directory: &Path,
    common_directory: &Path,
    reference: &str,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<Option<String>> {
    let mut loose_candidates = vec![
        git_directory.join(reference),
        common_directory.join(reference),
    ];
    loose_candidates.sort();
    loose_candidates.dedup();
    for path in loose_candidates {
        if let Some(kind) = secure_node_kind(
            &path,
            StateDimensionV1::RepositoryGit,
            "inspect loose Git reference",
        )? {
            if kind != SecureNodeKindV1::Regular {
                return Err(IncompleteToolStateV1::single(
                    IncompleteReasonCodeV1::SpecialFileRefused,
                    StateDimensionV1::RepositoryGit,
                    Some(path),
                    "resolve loose Git reference",
                ));
            }
            let bytes = read_bounded_stable_file(
                &path,
                limits.max_identity_bytes as u64,
                StateDimensionV1::RepositoryGit,
            )?;
            let object = std::str::from_utf8(trim_ascii_space(&bytes)).map_err(|_| {
                incomplete_plan(
                    StateDimensionV1::RepositoryGit,
                    Some(&path),
                    "parse loose Git reference",
                )
            })?;
            validate_git_object(object, &path)?;
            return Ok(Some(object.to_owned()));
        }
    }

    let packed_path = common_directory.join("packed-refs");
    let bytes = match secure_node_kind(
        &packed_path,
        StateDimensionV1::RepositoryGit,
        "inspect packed Git references",
    )? {
        Some(kind) => {
            if kind != SecureNodeKindV1::Regular {
                return Err(IncompleteToolStateV1::single(
                    IncompleteReasonCodeV1::SpecialFileRefused,
                    StateDimensionV1::RepositoryGit,
                    Some(packed_path),
                    "resolve packed Git reference",
                ));
            }
            read_bounded_stable_file(
                &packed_path,
                limits.max_file_bytes,
                StateDimensionV1::RepositoryGit,
            )?
        }
        None => return Ok(None),
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        incomplete_plan(
            StateDimensionV1::RepositoryGit,
            Some(&packed_path),
            "parse packed Git references",
        )
    })?;
    for line in text.lines() {
        if line.starts_with('#') || line.starts_with('^') || line.trim().is_empty() {
            continue;
        }
        let Some((object, name)) = line.split_once(' ') else {
            return Err(incomplete_plan(
                StateDimensionV1::RepositoryGit,
                Some(&packed_path),
                "parse packed Git reference",
            ));
        };
        if name == reference {
            validate_git_object(object, &packed_path)?;
            return Ok(Some(object.to_owned()));
        }
    }
    Ok(None)
}

fn canonical_directory(
    path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    dimension: StateDimensionV1,
    operation: &'static str,
) -> AuthorityResult<PathBuf> {
    let handle = secure_open_path(path, ExpectedNodeV1::Directory, dimension, operation)?;
    let before = FilesystemIdentityV1::from_metadata(
        &handle
            .metadata()
            .map_err(|error| incomplete_io(dimension, path, operation, error))?,
    );
    let canonical = descriptor_path(&handle, path, dimension, operation)?;
    check_path_bound(&canonical, limits, dimension)?;
    let reopened = secure_open_path(path, ExpectedNodeV1::Directory, dimension, operation)?;
    let after = FilesystemIdentityV1::from_metadata(
        &reopened
            .metadata()
            .map_err(|error| incomplete_io(dimension, path, operation, error))?,
    );
    if before != after {
        return Err(concurrent(dimension, path, operation));
    }
    Ok(canonical)
}

fn read_bounded_stable_file(
    path: &Path,
    max_bytes: u64,
    dimension: StateDimensionV1,
) -> AuthorityResult<Vec<u8>> {
    let mut file = secure_open_path(
        path,
        ExpectedNodeV1::Regular,
        dimension,
        "open bounded state file",
    )?;
    let before_metadata = file.metadata().map_err(|error| {
        incomplete_io(dimension, path, "inspect open bounded state file", error)
    })?;
    if before_metadata.len() > max_bytes {
        return Err(incomplete_limit(dimension, Some(path), "bound state file"));
    }
    let before = FilesystemIdentityV1::from_metadata(&before_metadata);
    let capacity = usize::try_from(before.size)
        .map_err(|_| incomplete_limit(dimension, Some(path), "allocate bounded state file"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| incomplete_limit(dimension, Some(path), "allocate bounded state file"))?;
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| incomplete_io(dimension, path, "read bounded state file", error))?;
    if bytes.len() as u64 > max_bytes {
        return Err(incomplete_limit(
            dimension,
            Some(path),
            "read bounded state file",
        ));
    }
    let after_handle = FilesystemIdentityV1::from_metadata(&file.metadata().map_err(|error| {
        incomplete_io(dimension, path, "reinspect open bounded state file", error)
    })?);
    let reopened = secure_open_path(
        path,
        ExpectedNodeV1::Regular,
        dimension,
        "reopen bounded state file",
    )?;
    let after_path =
        FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
            incomplete_io(
                dimension,
                path,
                "inspect reopened bounded state file",
                error,
            )
        })?);
    if before != after_handle || before != after_path || before.size != bytes.len() as u64 {
        return Err(concurrent(dimension, path, "read bounded state file"));
    }
    Ok(bytes)
}

fn trim_ascii_space(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

/// One allowlisted environment value. Plaintext is digested immediately and
/// is never retained by this type or by an authority.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentValueDigestV1 {
    name: OsString,
    value_digest: StateDigestV1,
}
impl std::fmt::Debug for EnvironmentValueDigestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentValueDigestV1")
            .field("name", &"<redacted>")
            .field("value_digest", &self.value_digest)
            .finish()
    }
}

impl EnvironmentValueDigestV1 {
    pub fn from_value(
        name: &OsStr,
        value: &OsStr,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        if name.as_bytes().len() > limits.max_environment_name_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::EnvironmentValues,
                None,
                "bound allowlisted environment name",
            ));
        }
        if name.as_bytes().is_empty()
            || name.as_bytes().contains(&b'=')
            || name.as_bytes().contains(&0)
        {
            return Err(incomplete_plan(
                StateDimensionV1::EnvironmentValues,
                None,
                "validate allowlisted environment name",
            ));
        }
        if value.as_bytes().len() > limits.max_environment_value_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::EnvironmentValues,
                None,
                "bound allowlisted environment value",
            ));
        }
        let mut encoder = CanonicalEncoder::new(b"again.environment-value.v1");
        encoder.os_str(name);
        encoder.os_str(value);
        Ok(Self {
            name: name.to_os_string(),
            value_digest: encoder.finish(),
        })
    }

    pub fn name(&self) -> &OsStr {
        &self.name
    }

    pub fn value_digest(&self) -> StateDigestV1 {
        self.value_digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableObservationRequestV1 {
    label: String,
    path: PathBuf,
    version_identity_digest: StateDigestV1,
}
impl std::fmt::Debug for ExecutableObservationRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutableObservationRequestV1")
            .field("label", &"<redacted>")
            .field("path", &"<redacted>")
            .field("version_identity_digest", &self.version_identity_digest)
            .finish()
    }
}

impl ExecutableObservationRequestV1 {
    /// `version_identity` is hashed immediately. It should be obtained by the
    /// caller through the same declared tool-selection boundary used for the
    /// eventual invocation.
    pub fn new(
        label: impl Into<String>,
        path: impl Into<PathBuf>,
        version_identity: &[u8],
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        let label = label.into();
        let path = path.into();
        check_identity_text(
            &label,
            limits,
            StateDimensionV1::Executables,
            "validate executable label",
        )?;
        check_path_bound(&path, limits, StateDimensionV1::Executables)?;
        if version_identity.is_empty() || version_identity.len() > limits.max_identity_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::Executables,
                Some(&path),
                "bound executable version identity",
            ));
        }
        Ok(Self {
            label,
            path,
            version_identity_digest: StateDigestV1::from_domain_and_bytes(
                b"again.executable-version-identity.v1",
                version_identity,
            ),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpIdentityV1 {
    provider_id: String,
    tool_schema_version: String,
}
impl std::fmt::Debug for McpIdentityV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("McpIdentityV1(<redacted>)")
    }
}

/// A bounded declaration of environment dimensions proven irrelevant by the
/// caller's tool schema. Evidence bytes are digested immediately and retained
/// only as a deterministic proof commitment.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentRelevanceProofV1 {
    exclusions: Vec<(StateDimensionV1, StateDigestV1)>,
    digest: StateDigestV1,
}

impl EnvironmentRelevanceProofV1 {
    pub fn from_exclusions(
        exclusions: Vec<(StateDimensionV1, Vec<u8>)>,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        if exclusions.len() > environment_dimensions().len() {
            return Err(incomplete_limit(
                StateDimensionV1::EnvironmentValues,
                None,
                "bound relevance exclusions",
            ));
        }
        let mut committed = Vec::new();
        committed.try_reserve_exact(exclusions.len()).map_err(|_| {
            incomplete_limit(
                StateDimensionV1::EnvironmentValues,
                None,
                "allocate relevance exclusions",
            )
        })?;
        for (dimension, evidence) in exclusions {
            if !environment_dimensions().contains(&dimension) {
                return Err(incomplete_plan(
                    dimension,
                    None,
                    "reject non-environment relevance exclusion",
                ));
            }
            if evidence.is_empty() || evidence.len() > limits.max_identity_bytes {
                return Err(incomplete_limit(
                    dimension,
                    None,
                    "bound relevance exclusion evidence",
                ));
            }
            committed.push((
                dimension,
                StateDigestV1::from_domain_and_bytes(
                    b"again.environment-relevance-evidence.v1",
                    &evidence,
                ),
            ));
        }
        committed.sort_by_key(|(dimension, _)| dimension_tag(*dimension));
        if committed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(incomplete_plan(
                StateDimensionV1::EnvironmentValues,
                None,
                "reject duplicate relevance exclusion",
            ));
        }
        let mut encoder = CanonicalEncoder::new(b"again.environment-relevance-proof.v1");
        encoder.u64(committed.len() as u64);
        for (dimension, evidence) in &committed {
            encoder.u8(dimension_tag(*dimension));
            encoder.digest(*evidence);
        }
        Ok(Self {
            exclusions: committed,
            digest: encoder.finish(),
        })
    }

    fn excludes(&self, dimension: StateDimensionV1) -> bool {
        self.exclusions
            .iter()
            .any(|(candidate, _)| *candidate == dimension)
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }
}

impl std::fmt::Debug for EnvironmentRelevanceProofV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentRelevanceProofV1")
            .field("exclusion_count", &self.exclusions.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl McpIdentityV1 {
    pub fn new(provider_id: impl Into<String>, tool_schema_version: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            tool_schema_version: tool_schema_version.into(),
        }
    }
}

/// Declares the only environment dimensions that may influence the authority.
/// A dimension absent from both the observed fields and `unknown_dimensions`
/// is explicitly excluded. A declared unknown makes observation incomplete.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentObservationPlanV1 {
    include_operating_system: bool,
    include_architecture: bool,
    kernel_identity: Option<String>,
    executables: Vec<ExecutableObservationRequestV1>,
    cwd: Option<PathBuf>,
    environment_values: Vec<EnvironmentValueDigestV1>,
    resource_profile_id: Option<String>,
    sandbox_backend_id: Option<String>,
    mcp_identity: Option<McpIdentityV1>,
    authorization_scope_digest: Option<StateDigestV1>,
    unknown_dimensions: BTreeSet<StateDimensionV1>,
    relevance_proof: Option<EnvironmentRelevanceProofV1>,
}
impl std::fmt::Debug for EnvironmentObservationPlanV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentObservationPlanV1")
            .field("executable_count", &self.executables.len())
            .field("environment_value_count", &self.environment_values.len())
            .field("unknown_dimensions", &self.unknown_dimensions)
            .field("has_relevance_proof", &self.relevance_proof.is_some())
            .finish()
    }
}

impl EnvironmentObservationPlanV1 {
    pub fn new() -> Self {
        Self {
            include_operating_system: false,
            include_architecture: false,
            kernel_identity: None,
            executables: Vec::new(),
            cwd: None,
            environment_values: Vec::new(),
            resource_profile_id: None,
            sandbox_backend_id: None,
            mcp_identity: None,
            authorization_scope_digest: None,
            unknown_dimensions: BTreeSet::new(),
            relevance_proof: None,
        }
    }

    pub fn with_operating_system(mut self) -> Self {
        self.include_operating_system = true;
        self
    }

    pub fn with_architecture(mut self) -> Self {
        self.include_architecture = true;
        self
    }

    pub fn with_kernel_identity(mut self, identity: impl Into<String>) -> Self {
        self.kernel_identity = Some(identity.into());
        self
    }

    pub fn with_executable(mut self, executable: ExecutableObservationRequestV1) -> Self {
        self.executables.push(executable);
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn with_environment_value(mut self, value: EnvironmentValueDigestV1) -> Self {
        self.environment_values.push(value);
        self
    }

    pub fn with_resource_profile_id(mut self, identity: impl Into<String>) -> Self {
        self.resource_profile_id = Some(identity.into());
        self
    }

    pub fn with_sandbox_backend_id(mut self, identity: impl Into<String>) -> Self {
        self.sandbox_backend_id = Some(identity.into());
        self
    }

    pub fn with_mcp_identity(mut self, identity: McpIdentityV1) -> Self {
        self.mcp_identity = Some(identity);
        self
    }

    /// The identifier is domain-separated and immediately digested so this
    /// structure cannot accidentally persist a credential or bearer token.
    pub fn with_authorization_scope_identifier(
        mut self,
        identifier: &[u8],
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        if identifier.is_empty() || identifier.len() > limits.max_identity_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::AuthorizationScope,
                None,
                "bound authorization-scope identifier",
            ));
        }
        self.authorization_scope_digest = Some(StateDigestV1::from_domain_and_bytes(
            b"again.authorization-scope.v1",
            identifier,
        ));
        Ok(self)
    }

    pub fn with_unknown_dimension(mut self, dimension: StateDimensionV1) -> Self {
        self.unknown_dimensions.insert(dimension);
        self
    }

    pub fn with_relevance_proof(mut self, proof: EnvironmentRelevanceProofV1) -> Self {
        self.relevance_proof = Some(proof);
        self
    }
}

impl Default for EnvironmentObservationPlanV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentObservationV1 {
    dimension: StateDimensionV1,
    label: Vec<u8>,
    digest: StateDigestV1,
}
impl std::fmt::Debug for EnvironmentObservationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentObservationV1")
            .field("dimension", &self.dimension)
            .field("label", &"<redacted>")
            .field("digest", &self.digest)
            .finish()
    }
}

impl EnvironmentObservationV1 {
    pub fn dimension(&self) -> StateDimensionV1 {
        self.dimension
    }

    pub fn label(&self) -> &[u8] {
        &self.label
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentAuthorityV1 {
    schema_version: u16,
    observed_dimensions: Vec<StateDimensionV1>,
    explicitly_excluded_dimensions: Vec<StateDimensionV1>,
    observations: Vec<EnvironmentObservationV1>,
    relevance_proof_digest: StateDigestV1,
    digest: StateDigestV1,
}
impl std::fmt::Debug for EnvironmentAuthorityV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentAuthorityV1")
            .field("schema_version", &self.schema_version)
            .field("observed_dimensions", &self.observed_dimensions)
            .field(
                "explicitly_excluded_dimensions",
                &self.explicitly_excluded_dimensions,
            )
            .field("observation_count", &self.observations.len())
            .field("relevance_proof_digest", &self.relevance_proof_digest)
            .field("digest", &self.digest)
            .finish()
    }
}

impl EnvironmentAuthorityV1 {
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn observed_dimensions(&self) -> &[StateDimensionV1] {
        &self.observed_dimensions
    }

    pub fn explicitly_excluded_dimensions(&self) -> &[StateDimensionV1] {
        &self.explicitly_excluded_dimensions
    }

    pub fn observations(&self) -> &[EnvironmentObservationV1] {
        &self.observations
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_environment_authority(self)
    }
}

pub fn observe_environment_v1(
    plan: &EnvironmentObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<EnvironmentAuthorityV1> {
    validate_limits(limits)?;
    validate_environment_plan(plan, limits)?;
    if let Some(dimension) = plan.unknown_dimensions.iter().next().copied() {
        return Err(IncompleteToolStateV1::unknown(
            dimension,
            "observe declared environment dimension",
        ));
    }

    let before = observe_environment_once(plan, limits)?;
    let after = observe_environment_once(plan, limits)?;
    if before != after {
        return Err(IncompleteToolStateV1::single(
            IncompleteReasonCodeV1::ConcurrentMutation,
            StateDimensionV1::Executables,
            None,
            "compare environment samples",
        ));
    }
    let mut observed_dimensions = before
        .iter()
        .map(|observation| observation.dimension)
        .collect::<Vec<_>>();
    observed_dimensions.sort();
    observed_dimensions.dedup();
    let proof = plan.relevance_proof.as_ref().ok_or_else(|| {
        IncompleteToolStateV1::unknown(
            StateDimensionV1::EnvironmentValues,
            "require environment relevance proof",
        )
    })?;
    let explicitly_excluded_dimensions = proof
        .exclusions
        .iter()
        .map(|(dimension, _)| *dimension)
        .collect();
    let mut authority = EnvironmentAuthorityV1 {
        schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
        observed_dimensions,
        explicitly_excluded_dimensions,
        observations: before,
        relevance_proof_digest: proof.digest,
        digest: StateDigestV1([0; 32]),
    };
    authority.digest = digest_encoded(
        b"again.environment-authority.v1",
        &encode_environment_authority(&authority),
    );
    Ok(authority)
}

fn validate_environment_plan(
    plan: &EnvironmentObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<()> {
    let proof = plan.relevance_proof.as_ref().ok_or_else(|| {
        IncompleteToolStateV1::unknown(
            StateDimensionV1::EnvironmentValues,
            "validate environment relevance proof",
        )
    })?;
    let entry_count = plan
        .executables
        .len()
        .checked_add(plan.environment_values.len())
        .ok_or_else(|| {
            incomplete_limit(
                StateDimensionV1::EnvironmentValues,
                None,
                "count environment observations",
            )
        })?;
    if entry_count > limits.max_environment_entries {
        return Err(incomplete_limit(
            StateDimensionV1::EnvironmentValues,
            None,
            "bound environment observations",
        ));
    }
    for (dimension, observed) in [
        (
            StateDimensionV1::OperatingSystem,
            plan.include_operating_system,
        ),
        (StateDimensionV1::Architecture, plan.include_architecture),
        (StateDimensionV1::Kernel, plan.kernel_identity.is_some()),
        (StateDimensionV1::Executables, !plan.executables.is_empty()),
        (StateDimensionV1::WorkingDirectory, plan.cwd.is_some()),
        (
            StateDimensionV1::EnvironmentValues,
            !plan.environment_values.is_empty(),
        ),
        (
            StateDimensionV1::ResourceProfile,
            plan.resource_profile_id.is_some(),
        ),
        (
            StateDimensionV1::SandboxBackend,
            plan.sandbox_backend_id.is_some(),
        ),
        (
            StateDimensionV1::McpProviderToolSchema,
            plan.mcp_identity.is_some(),
        ),
        (
            StateDimensionV1::AuthorizationScope,
            plan.authorization_scope_digest.is_some(),
        ),
    ] {
        if observed && plan.unknown_dimensions.contains(&dimension) {
            return Err(incomplete_plan(
                dimension,
                None,
                "reject observed and unknown environment dimension",
            ));
        }
        if observed && proof.excludes(dimension) {
            return Err(incomplete_plan(
                dimension,
                None,
                "reject observed and excluded environment dimension",
            ));
        }
        if plan.unknown_dimensions.contains(&dimension) && proof.excludes(dimension) {
            return Err(incomplete_plan(
                dimension,
                None,
                "reject unknown and excluded environment dimension",
            ));
        }
        if !observed && !plan.unknown_dimensions.contains(&dimension) && !proof.excludes(dimension)
        {
            return Err(IncompleteToolStateV1::unknown(
                dimension,
                "classify relevant environment dimension",
            ));
        }
    }
    if plan
        .unknown_dimensions
        .iter()
        .any(|dimension| !environment_dimensions().contains(dimension))
    {
        return Err(incomplete_plan(
            StateDimensionV1::EnvironmentValues,
            None,
            "reject non-environment unknown dimension",
        ));
    }
    for value in [
        plan.kernel_identity.as_deref(),
        plan.resource_profile_id.as_deref(),
        plan.sandbox_backend_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        check_identity_text(
            value,
            limits,
            StateDimensionV1::EnvironmentValues,
            "validate environment identity",
        )?;
    }
    if let Some(mcp) = &plan.mcp_identity {
        check_identity_text(
            &mcp.provider_id,
            limits,
            StateDimensionV1::McpProviderToolSchema,
            "validate MCP provider identity",
        )?;
        check_identity_text(
            &mcp.tool_schema_version,
            limits,
            StateDimensionV1::McpProviderToolSchema,
            "validate MCP tool schema version",
        )?;
    }

    let mut labels = BTreeSet::new();
    for executable in &plan.executables {
        if !labels.insert(executable.label.as_bytes()) {
            return Err(incomplete_plan(
                StateDimensionV1::Executables,
                Some(&executable.path),
                "reject duplicate executable label",
            ));
        }
    }
    let mut names = BTreeSet::new();
    for value in &plan.environment_values {
        if !names.insert(value.name.as_bytes()) {
            return Err(incomplete_plan(
                StateDimensionV1::EnvironmentValues,
                None,
                "reject duplicate allowlisted environment name",
            ));
        }
    }
    Ok(())
}

fn observe_environment_once(
    plan: &EnvironmentObservationPlanV1,
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<Vec<EnvironmentObservationV1>> {
    let mut observations = Vec::new();
    if plan.include_operating_system {
        observations.push(environment_identity_observation(
            StateDimensionV1::OperatingSystem,
            b"os",
            std::env::consts::OS.as_bytes(),
        ));
    }
    if plan.include_architecture {
        observations.push(environment_identity_observation(
            StateDimensionV1::Architecture,
            b"architecture",
            std::env::consts::ARCH.as_bytes(),
        ));
    }
    if let Some(kernel) = &plan.kernel_identity {
        observations.push(environment_identity_observation(
            StateDimensionV1::Kernel,
            b"kernel",
            kernel.as_bytes(),
        ));
    }

    let mut executables = plan.executables.iter().collect::<Vec<_>>();
    executables.sort_by(|left, right| left.label.as_bytes().cmp(right.label.as_bytes()));
    let mut ledger = ObservationLedger::default();
    for executable in executables {
        let executable_handle = secure_open_path(
            &executable.path,
            ExpectedNodeV1::Regular,
            StateDimensionV1::Executables,
            "open executable",
        )?;
        let executable_identity = FilesystemIdentityV1::from_metadata(
            &executable_handle.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::Executables,
                    &executable.path,
                    "inspect open executable",
                    error,
                )
            })?,
        );
        let canonical = descriptor_path(
            &executable_handle,
            &executable.path,
            StateDimensionV1::Executables,
            "resolve executable descriptor",
        )?;
        check_path_bound(&canonical, limits, StateDimensionV1::Executables)?;
        let observed =
            observe_regular_file(&canonical, limits, &mut ledger).map_err(|mut state| {
                for reason in &mut state.reasons {
                    reason.dimension = StateDimensionV1::Executables;
                }
                state
            })?;
        if !executable_identity.same_object(observed.identity) {
            return Err(concurrent(
                StateDimensionV1::Executables,
                &executable.path,
                "observe executable identity",
            ));
        }
        let mut encoder = CanonicalEncoder::new(b"again.environment-executable.v1");
        encoder.bytes(executable.label.as_bytes());
        encoder.path(&canonical);
        observed.encode(&mut encoder);
        encoder.digest(executable.version_identity_digest);
        observations.push(EnvironmentObservationV1 {
            dimension: StateDimensionV1::Executables,
            label: executable.label.as_bytes().to_vec(),
            digest: encoder.finish(),
        });
    }

    if let Some(cwd) = &plan.cwd {
        let handle = secure_open_path(
            cwd,
            ExpectedNodeV1::Directory,
            StateDimensionV1::WorkingDirectory,
            "open working directory",
        )?;
        let canonical = descriptor_path(
            &handle,
            cwd,
            StateDimensionV1::WorkingDirectory,
            "resolve working directory descriptor",
        )?;
        check_path_bound(&canonical, limits, StateDimensionV1::WorkingDirectory)?;
        let opened = FilesystemIdentityV1::from_metadata(&handle.metadata().map_err(|error| {
            incomplete_io(
                StateDimensionV1::WorkingDirectory,
                &canonical,
                "inspect open working directory",
                error,
            )
        })?);
        let reopened = secure_open_path(
            cwd,
            ExpectedNodeV1::Directory,
            StateDimensionV1::WorkingDirectory,
            "reopen working directory",
        )?;
        let path_identity =
            FilesystemIdentityV1::from_metadata(&reopened.metadata().map_err(|error| {
                incomplete_io(
                    StateDimensionV1::WorkingDirectory,
                    cwd,
                    "inspect reopened working directory",
                    error,
                )
            })?);
        if opened != path_identity {
            return Err(concurrent(
                StateDimensionV1::WorkingDirectory,
                &canonical,
                "observe working directory",
            ));
        }
        let mut encoder = CanonicalEncoder::new(b"again.environment-cwd.v1");
        encoder.path(&canonical);
        opened.encode_authority(&mut encoder);
        observations.push(EnvironmentObservationV1 {
            dimension: StateDimensionV1::WorkingDirectory,
            label: b"cwd".to_vec(),
            digest: encoder.finish(),
        });
    }

    let mut environment_values = plan.environment_values.iter().collect::<Vec<_>>();
    environment_values.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    for value in environment_values {
        let mut encoder = CanonicalEncoder::new(b"again.environment-allowlisted.v1");
        encoder.os_str(&value.name);
        encoder.digest(value.value_digest);
        observations.push(EnvironmentObservationV1 {
            dimension: StateDimensionV1::EnvironmentValues,
            label: value.name.as_bytes().to_vec(),
            digest: encoder.finish(),
        });
    }
    if let Some(identity) = &plan.resource_profile_id {
        observations.push(environment_identity_observation(
            StateDimensionV1::ResourceProfile,
            b"resource-profile",
            identity.as_bytes(),
        ));
    }
    if let Some(identity) = &plan.sandbox_backend_id {
        observations.push(environment_identity_observation(
            StateDimensionV1::SandboxBackend,
            b"sandbox-backend",
            identity.as_bytes(),
        ));
    }
    if let Some(identity) = &plan.mcp_identity {
        let mut encoder = CanonicalEncoder::new(b"again.environment-mcp.v1");
        encoder.bytes(identity.provider_id.as_bytes());
        encoder.bytes(identity.tool_schema_version.as_bytes());
        observations.push(EnvironmentObservationV1 {
            dimension: StateDimensionV1::McpProviderToolSchema,
            label: b"mcp".to_vec(),
            digest: encoder.finish(),
        });
    }
    if let Some(scope) = plan.authorization_scope_digest {
        let mut encoder = CanonicalEncoder::new(b"again.environment-authorization-scope.v1");
        encoder.digest(scope);
        observations.push(EnvironmentObservationV1 {
            dimension: StateDimensionV1::AuthorizationScope,
            label: b"authorization-scope".to_vec(),
            digest: encoder.finish(),
        });
    }
    observations.sort_by(|left, right| {
        dimension_tag(left.dimension)
            .cmp(&dimension_tag(right.dimension))
            .then_with(|| left.label.cmp(&right.label))
    });
    Ok(observations)
}

fn environment_identity_observation(
    dimension: StateDimensionV1,
    label: &[u8],
    value: &[u8],
) -> EnvironmentObservationV1 {
    let mut encoder = CanonicalEncoder::new(b"again.environment-identity.v1");
    encoder.u8(dimension_tag(dimension));
    encoder.bytes(label);
    encoder.bytes(value);
    EnvironmentObservationV1 {
        dimension,
        label: label.to_vec(),
        digest: encoder.finish(),
    }
}

fn environment_dimensions() -> [StateDimensionV1; 10] {
    [
        StateDimensionV1::OperatingSystem,
        StateDimensionV1::Architecture,
        StateDimensionV1::Kernel,
        StateDimensionV1::Executables,
        StateDimensionV1::WorkingDirectory,
        StateDimensionV1::EnvironmentValues,
        StateDimensionV1::ResourceProfile,
        StateDimensionV1::SandboxBackend,
        StateDimensionV1::McpProviderToolSchema,
        StateDimensionV1::AuthorizationScope,
    ]
}

#[derive(Clone, Eq, PartialEq)]
pub struct TaskStateInputV1 {
    pub task_id: String,
    pub task_revision: u64,
    pub user_goal_digest: StateDigestV1,
    pub accepted_constraints_digest: StateDigestV1,
    pub branch_identity: String,
    pub worktree_identity: String,
    pub patch_digest: StateDigestV1,
    pub plan_revision: u64,
    pub compaction_epoch: u64,
}
impl std::fmt::Debug for TaskStateInputV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskStateInputV1")
            .field("identities", &"<redacted>")
            .field("task_revision", &self.task_revision)
            .field("plan_revision", &self.plan_revision)
            .field("compaction_epoch", &self.compaction_epoch)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TaskStateV1 {
    schema_version: u16,
    task_id: String,
    task_revision: u64,
    user_goal_digest: StateDigestV1,
    accepted_constraints_digest: StateDigestV1,
    branch_identity: String,
    worktree_identity: String,
    patch_digest: StateDigestV1,
    plan_revision: u64,
    compaction_epoch: u64,
    digest: StateDigestV1,
}
impl std::fmt::Debug for TaskStateV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskStateV1")
            .field("schema_version", &self.schema_version)
            .field("identities", &"<redacted>")
            .field("task_revision", &self.task_revision)
            .field("plan_revision", &self.plan_revision)
            .field("compaction_epoch", &self.compaction_epoch)
            .field("digest", &self.digest)
            .finish()
    }
}

impl TaskStateV1 {
    pub(crate) fn from_input(
        input: TaskStateInputV1,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        for value in [
            input.task_id.as_str(),
            input.branch_identity.as_str(),
            input.worktree_identity.as_str(),
        ] {
            if value.is_empty() || value.len() > limits.max_task_field_bytes {
                return Err(incomplete_limit(
                    StateDimensionV1::Task,
                    None,
                    "bound task identity field",
                ));
            }
        }
        let mut state = Self {
            schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
            task_id: input.task_id,
            task_revision: input.task_revision,
            user_goal_digest: input.user_goal_digest,
            accepted_constraints_digest: input.accepted_constraints_digest,
            branch_identity: input.branch_identity,
            worktree_identity: input.worktree_identity,
            patch_digest: input.patch_digest,
            plan_revision: input.plan_revision,
            compaction_epoch: input.compaction_epoch,
            digest: StateDigestV1([0; 32]),
        };
        state.digest = digest_encoded(b"again.task-state.v1", &encode_task_state(&state));
        Ok(state)
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn task_revision(&self) -> u64 {
        self.task_revision
    }

    pub fn user_goal_digest(&self) -> StateDigestV1 {
        self.user_goal_digest
    }

    pub fn accepted_constraints_digest(&self) -> StateDigestV1 {
        self.accepted_constraints_digest
    }

    pub fn branch_identity(&self) -> &str {
        &self.branch_identity
    }

    pub fn worktree_identity(&self) -> &str {
        &self.worktree_identity
    }

    pub fn patch_digest(&self) -> StateDigestV1 {
        self.patch_digest
    }

    pub fn plan_revision(&self) -> u64 {
        self.plan_revision
    }

    pub fn compaction_epoch(&self) -> u64 {
        self.compaction_epoch
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_task_state(self)
    }
}

/// A freshness token supplied by the named external provider. Token bytes and
/// authorization material are never retained; only domain-separated digests
/// are stored. This binds the observed token but does not independently claim
/// that a provider omitted a mutation.
#[derive(Clone, Eq, PartialEq)]
pub struct ExternalDependencyObservationV1 {
    provider_id: String,
    resource_id_digest: StateDigestV1,
    freshness_token_digest: StateDigestV1,
}
impl std::fmt::Debug for ExternalDependencyObservationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalDependencyObservationV1")
            .field("provider_id", &"<redacted>")
            .field("resource_id_digest", &self.resource_id_digest)
            .field("freshness_token_digest", &self.freshness_token_digest)
            .finish()
    }
}

impl ExternalDependencyObservationV1 {
    #[allow(dead_code)]
    pub(crate) fn from_token(
        provider_id: impl Into<String>,
        resource_identifier: &[u8],
        freshness_token: &[u8],
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        let provider_id = provider_id.into();
        check_identity_text(
            &provider_id,
            limits,
            StateDimensionV1::ExternalFreshness,
            "validate external provider identity",
        )?;
        if resource_identifier.is_empty() || resource_identifier.len() > limits.max_identity_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::ExternalFreshness,
                None,
                "bound external resource identity",
            ));
        }
        if freshness_token.is_empty() || freshness_token.len() > limits.max_external_token_bytes {
            return Err(incomplete_limit(
                StateDimensionV1::ExternalFreshness,
                None,
                "bound external freshness token",
            ));
        }
        Ok(Self {
            provider_id,
            resource_id_digest: StateDigestV1::from_domain_and_bytes(
                b"again.external-resource-id.v1",
                resource_identifier,
            ),
            freshness_token_digest: StateDigestV1::from_domain_and_bytes(
                b"again.external-freshness-token.v1",
                freshness_token,
            ),
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn resource_id_digest(&self) -> StateDigestV1 {
        self.resource_id_digest
    }

    pub fn freshness_token_digest(&self) -> StateDigestV1 {
        self.freshness_token_digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExternalFreshnessV1 {
    schema_version: u16,
    external_state_explicitly_excluded: bool,
    dependencies: Vec<ExternalDependencyObservationV1>,
    no_dependencies_proof_digest: Option<StateDigestV1>,
    digest: StateDigestV1,
}
impl std::fmt::Debug for ExternalFreshnessV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalFreshnessV1")
            .field("schema_version", &self.schema_version)
            .field(
                "external_state_explicitly_excluded",
                &self.external_state_explicitly_excluded,
            )
            .field("dependency_count", &self.dependencies.len())
            .field("digest", &self.digest)
            .finish()
    }
}

/// Opaque proof issued only by the trusted integration boundary after it has
/// validated that the call schema has no external dependencies.
#[derive(Eq, PartialEq)]
pub struct ValidatedNoExternalDependenciesProofV1 {
    digest: StateDigestV1,
}

impl std::fmt::Debug for ValidatedNoExternalDependenciesProofV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValidatedNoExternalDependenciesProofV1(<redacted>)")
    }
}

#[cfg(test)]
pub fn validated_no_external_dependencies_for_test_v1(
    evidence: &[u8],
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<ValidatedNoExternalDependenciesProofV1> {
    if evidence.is_empty() || evidence.len() > limits.max_identity_bytes {
        return Err(incomplete_limit(
            StateDimensionV1::ExternalFreshness,
            None,
            "bound no-external-dependencies proof",
        ));
    }
    Ok(ValidatedNoExternalDependenciesProofV1 {
        digest: StateDigestV1::from_domain_and_bytes(
            b"again.validated-no-external-dependencies.v1",
            evidence,
        ),
    })
}

/// Crate-trusted issuance boundary for tool implementations whose closed
/// schema was reviewed to have no external dependencies. The evidence is
/// committed immediately and the opaque proof cannot be constructed by SDK
/// callers or deserialized from an MCP request.
pub(crate) fn issue_no_external_dependencies_v1(
    evidence: &[u8],
    limits: &WorkspaceAuthorityLimitsV1,
) -> AuthorityResult<ValidatedNoExternalDependenciesProofV1> {
    if evidence.is_empty() || evidence.len() > limits.max_identity_bytes {
        return Err(incomplete_limit(
            StateDimensionV1::ExternalFreshness,
            None,
            "bound trusted no-external-dependencies proof",
        ));
    }
    Ok(ValidatedNoExternalDependenciesProofV1 {
        digest: StateDigestV1::from_domain_and_bytes(
            b"again.validated-no-external-dependencies.v1",
            evidence,
        ),
    })
}

impl ExternalFreshnessV1 {
    pub fn no_external_dependencies(proof: ValidatedNoExternalDependenciesProofV1) -> Self {
        let mut value = Self {
            schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
            external_state_explicitly_excluded: true,
            dependencies: Vec::new(),
            no_dependencies_proof_digest: Some(proof.digest),
            digest: StateDigestV1([0; 32]),
        };
        value.digest = digest_encoded(
            b"again.external-freshness.v1",
            &encode_external_freshness(&value),
        );
        value
    }

    pub fn from_observations(
        mut dependencies: Vec<ExternalDependencyObservationV1>,
        limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<Self> {
        if dependencies.is_empty() {
            return Err(incomplete_plan(
                StateDimensionV1::ExternalFreshness,
                None,
                "require observed external dependencies",
            ));
        }
        if dependencies.len() > limits.max_external_dependencies {
            return Err(incomplete_limit(
                StateDimensionV1::ExternalFreshness,
                None,
                "bound external dependencies",
            ));
        }
        dependencies.sort_by(|left, right| {
            left.provider_id
                .as_bytes()
                .cmp(right.provider_id.as_bytes())
                .then_with(|| left.resource_id_digest.cmp(&right.resource_id_digest))
        });
        if dependencies.windows(2).any(|pair| {
            pair[0].provider_id == pair[1].provider_id
                && pair[0].resource_id_digest == pair[1].resource_id_digest
        }) {
            return Err(incomplete_plan(
                StateDimensionV1::ExternalFreshness,
                None,
                "reject duplicate external dependency",
            ));
        }
        let mut value = Self {
            schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
            external_state_explicitly_excluded: false,
            dependencies,
            no_dependencies_proof_digest: None,
            digest: StateDigestV1([0; 32]),
        };
        value.digest = digest_encoded(
            b"again.external-freshness.v1",
            &encode_external_freshness(&value),
        );
        Ok(value)
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn external_state_explicitly_excluded(&self) -> bool {
        self.external_state_explicitly_excluded
    }

    pub fn dependencies(&self) -> &[ExternalDependencyObservationV1] {
        &self.dependencies
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentContextEpochV1 {
    schema_version: u16,
    repository: RepositoryEpochV1,
    environment: EnvironmentAuthorityV1,
    task: TaskStateV1,
    digest: StateDigestV1,
}
impl std::fmt::Debug for AgentContextEpochV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentContextEpochV1")
            .field("schema_version", &self.schema_version)
            .field("digest", &self.digest)
            .finish()
    }
}

impl AgentContextEpochV1 {
    pub fn new(
        repository: RepositoryEpochV1,
        environment: EnvironmentAuthorityV1,
        task: TaskStateV1,
    ) -> Self {
        let mut value = Self {
            schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
            repository,
            environment,
            task,
            digest: StateDigestV1([0; 32]),
        };
        value.digest = digest_encoded(
            b"again.agent-context-epoch.v1",
            &encode_agent_context(&value),
        );
        value
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn repository(&self) -> &RepositoryEpochV1 {
        &self.repository
    }

    pub fn environment(&self) -> &EnvironmentAuthorityV1 {
        &self.environment
    }

    pub fn task(&self) -> &TaskStateV1 {
        &self.task
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }
}

/// Capability handed to a reuse decision. Its private field prevents callers
/// from minting one out of an incomplete state or an arbitrary digest.
#[derive(Debug, Eq, PartialEq)]
pub struct ReusableToolAuthorityV1 {
    complete_state_digest: StateDigestV1,
}

impl ReusableToolAuthorityV1 {
    pub fn complete_state_digest(&self) -> StateDigestV1 {
        self.complete_state_digest
    }
}

#[derive(Eq, PartialEq)]
pub struct CompleteToolStateV1 {
    schema_version: u16,
    agent_context: AgentContextEpochV1,
    external_freshness: ExternalFreshnessV1,
    digest: StateDigestV1,
}
impl std::fmt::Debug for CompleteToolStateV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompleteToolStateV1")
            .field("schema_version", &self.schema_version)
            .field("digest", &self.digest)
            .finish()
    }
}

impl CompleteToolStateV1 {
    pub fn new(
        repository: RepositoryEpochV1,
        environment: EnvironmentAuthorityV1,
        task: TaskStateV1,
        external_freshness: ExternalFreshnessV1,
    ) -> Self {
        let mut value = Self {
            schema_version: WORKSPACE_AUTHORITY_SCHEMA_VERSION_V1,
            agent_context: AgentContextEpochV1::new(repository, environment, task),
            external_freshness,
            digest: StateDigestV1([0; 32]),
        };
        value.digest = digest_encoded(
            b"again.complete-tool-state.v1",
            &encode_complete_tool_state(&value),
        );
        value
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn agent_context(&self) -> &AgentContextEpochV1 {
        &self.agent_context
    }

    pub fn external_freshness(&self) -> &ExternalFreshnessV1 {
        &self.external_freshness
    }

    pub fn digest(&self) -> StateDigestV1 {
        self.digest
    }

    pub fn into_reusable_authority(self) -> ReusableToolAuthorityV1 {
        ReusableToolAuthorityV1 {
            complete_state_digest: self.digest,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_complete_tool_state(self)
    }
}

fn check_identity_text(
    value: &str,
    limits: &WorkspaceAuthorityLimitsV1,
    dimension: StateDimensionV1,
    operation: &'static str,
) -> AuthorityResult<()> {
    if value.is_empty() || value.len() > limits.max_identity_bytes || value.as_bytes().contains(&0)
    {
        return Err(incomplete_limit(dimension, None, operation));
    }
    Ok(())
}

fn check_path_bound(
    path: &Path,
    limits: &WorkspaceAuthorityLimitsV1,
    dimension: StateDimensionV1,
) -> AuthorityResult<()> {
    if path.as_os_str().as_bytes().len() > limits.max_path_bytes {
        return Err(incomplete_limit(
            dimension,
            Some(path),
            "bound filesystem path",
        ));
    }
    Ok(())
}

fn encode_repository_epoch(epoch: &RepositoryEpochV1) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new(b"again.repository-epoch-encoding.v1");
    encoder.u16(epoch.schema_version);
    encoder.path(&epoch.canonical_workspace);
    epoch.workspace_identity.encode_authority(&mut encoder);
    match &epoch.git {
        RepositoryGitStateV1::NotGitRepository => encoder.u8(0),
        RepositoryGitStateV1::Git {
            worktree_root,
            git_directory,
            head_ref,
            head_object,
            head_digest,
            index_digest,
        } => {
            encoder.u8(1);
            encoder.path(worktree_root);
            encoder.path(git_directory);
            encoder.optional_bytes(head_ref.as_ref().map(String::as_bytes));
            encoder.optional_bytes(head_object.as_ref().map(String::as_bytes));
            encoder.digest(*head_digest);
            encoder.optional_digest(*index_digest);
        }
    }
    encode_repository_plan(&epoch.plan, &mut encoder);
    encoder.u64(epoch.observations.len() as u64);
    for observation in &epoch.observations {
        encoder.u8(observation_kind_tag(observation.kind));
        encoder.path(&observation.path);
        encoder.digest(observation.digest);
        encoder.u64(observation.entries);
        encoder.u64(observation.bytes);
        encoder.bool(observation.present);
    }
    encoder.into_bytes()
}

fn encode_repository_plan(plan: &RepositoryObservationPlanV1, encoder: &mut CanonicalEncoder) {
    for paths in [
        &plan.content_paths,
        &plan.recursive_trees,
        &plan.directory_listings,
        &plan.negative_dependencies,
    ] {
        encoder.u64(paths.len() as u64);
        for path in paths {
            encoder.path(path);
        }
    }
}

fn encode_environment_authority(authority: &EnvironmentAuthorityV1) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new(b"again.environment-authority-encoding.v1");
    encoder.u16(authority.schema_version);
    encoder.u64(authority.observed_dimensions.len() as u64);
    for dimension in &authority.observed_dimensions {
        encoder.u8(dimension_tag(*dimension));
    }
    encoder.u64(authority.explicitly_excluded_dimensions.len() as u64);
    for dimension in &authority.explicitly_excluded_dimensions {
        encoder.u8(dimension_tag(*dimension));
    }
    encoder.digest(authority.relevance_proof_digest);
    encoder.u64(authority.observations.len() as u64);
    for observation in &authority.observations {
        encoder.u8(dimension_tag(observation.dimension));
        encoder.bytes(&observation.label);
        encoder.digest(observation.digest);
    }
    encoder.into_bytes()
}

fn encode_task_state(task: &TaskStateV1) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new(b"again.task-state-encoding.v1");
    encoder.u16(task.schema_version);
    encoder.bytes(task.task_id.as_bytes());
    encoder.u64(task.task_revision);
    encoder.digest(task.user_goal_digest);
    encoder.digest(task.accepted_constraints_digest);
    encoder.bytes(task.branch_identity.as_bytes());
    encoder.bytes(task.worktree_identity.as_bytes());
    encoder.digest(task.patch_digest);
    encoder.u64(task.plan_revision);
    encoder.u64(task.compaction_epoch);
    encoder.into_bytes()
}

fn encode_external_freshness(external: &ExternalFreshnessV1) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new(b"again.external-freshness-encoding.v1");
    encoder.u16(external.schema_version);
    encoder.bool(external.external_state_explicitly_excluded);
    encoder.bool(external.no_dependencies_proof_digest.is_some());
    if let Some(proof) = external.no_dependencies_proof_digest {
        encoder.digest(proof);
    }
    encoder.u64(external.dependencies.len() as u64);
    for dependency in &external.dependencies {
        encoder.bytes(dependency.provider_id.as_bytes());
        encoder.digest(dependency.resource_id_digest);
        encoder.digest(dependency.freshness_token_digest);
    }
    encoder.into_bytes()
}

fn encode_agent_context(context: &AgentContextEpochV1) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new(b"again.agent-context-encoding.v1");
    encoder.u16(context.schema_version);
    encoder.digest(context.repository.digest());
    encoder.digest(context.environment.digest());
    encoder.digest(context.task.digest());
    encoder.into_bytes()
}

fn encode_complete_tool_state(state: &CompleteToolStateV1) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new(b"again.complete-tool-state-encoding.v1");
    encoder.u16(state.schema_version);
    encoder.digest(state.agent_context.digest());
    encoder.digest(state.external_freshness.digest());
    encoder.into_bytes()
}

fn observation_kind_tag(kind: RepositoryObservationKindV1) -> u8 {
    match kind {
        RepositoryObservationKindV1::ContentPath => 1,
        RepositoryObservationKindV1::RecursiveTree => 2,
        RepositoryObservationKindV1::DirectoryListing => 3,
        RepositoryObservationKindV1::NegativeDependency => 4,
    }
}

fn dimension_tag(dimension: StateDimensionV1) -> u8 {
    match dimension {
        StateDimensionV1::Repository => 1,
        StateDimensionV1::RepositoryGit => 2,
        StateDimensionV1::RepositoryIndex => 3,
        StateDimensionV1::RepositoryContent => 4,
        StateDimensionV1::OperatingSystem => 5,
        StateDimensionV1::Architecture => 6,
        StateDimensionV1::Kernel => 7,
        StateDimensionV1::Executables => 8,
        StateDimensionV1::WorkingDirectory => 9,
        StateDimensionV1::EnvironmentValues => 10,
        StateDimensionV1::ResourceProfile => 11,
        StateDimensionV1::SandboxBackend => 12,
        StateDimensionV1::McpProviderToolSchema => 13,
        StateDimensionV1::AuthorizationScope => 14,
        StateDimensionV1::Task => 15,
        StateDimensionV1::ExternalFreshness => 16,
    }
}

fn digest_encoded(domain: &'static [u8], bytes: &[u8]) -> StateDigestV1 {
    StateDigestV1::from_domain_and_bytes(domain, bytes)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod retained_epoch_tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn retained_epoch_reads_original_repository_across_aba_path_swap() {
        let temporary = TempDir::new().unwrap();
        let base = fs::canonicalize(temporary.path()).unwrap();
        let repository = base.join("repository");
        let retained = base.join("retained");
        fs::create_dir(&repository).unwrap();
        fs::write(repository.join("input.txt"), b"original").unwrap();
        let limits = WorkspaceAuthorityLimitsV1::default();
        let epoch = WorkspaceExecutionEpochV1::begin(&repository, &limits).unwrap();

        fs::rename(&repository, &retained).unwrap();
        fs::create_dir(&repository).unwrap();
        fs::write(repository.join("input.txt"), b"replacement").unwrap();
        let bytes = epoch
            .read_repository_file_inner(Path::new("input.txt"), 64, || {
                fs::remove_file(repository.join("input.txt")).unwrap();
                fs::remove_dir(&repository).unwrap();
                fs::rename(&retained, &repository).unwrap();
            })
            .unwrap();

        assert_eq!(bytes, b"original");
    }

    #[test]
    fn retained_traversal_refuses_intermediate_symlinks() {
        let temporary = TempDir::new().unwrap();
        let base = fs::canonicalize(temporary.path()).unwrap();
        let repository = base.join("repository");
        let external = base.join("external");
        fs::create_dir(&repository).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(external.join("secret.txt"), b"secret").unwrap();
        std::os::unix::fs::symlink(&external, repository.join("linked")).unwrap();
        let limits = WorkspaceAuthorityLimitsV1::default();
        let epoch = WorkspaceExecutionEpochV1::begin(&repository, &limits).unwrap();

        let error = epoch
            .list_regular_files(Path::new(""), &limits)
            .unwrap_err();
        assert_eq!(error.primary_code(), IncompleteReasonCodeV1::SymlinkRefused);
    }

    #[test]
    fn retained_traversal_enforces_depth_directory_and_path_byte_bounds() {
        let temporary = TempDir::new().unwrap();
        let base = fs::canonicalize(temporary.path()).unwrap();

        let depth_root = base.join("depth");
        fs::create_dir_all(depth_root.join("a/b/c")).unwrap();
        fs::write(depth_root.join("a/b/c/input"), b"x").unwrap();
        let depth_limits = WorkspaceAuthorityLimitsV1 {
            max_tree_depth: 2,
            ..WorkspaceAuthorityLimitsV1::default()
        };
        let depth_epoch = WorkspaceExecutionEpochV1::begin(&depth_root, &depth_limits).unwrap();
        assert_eq!(
            depth_epoch
                .list_regular_files(Path::new(""), &depth_limits)
                .unwrap_err()
                .primary_code(),
            IncompleteReasonCodeV1::InputLimitExceeded
        );

        let directory_root = base.join("directory");
        fs::create_dir(&directory_root).unwrap();
        for name in ["one", "two", "three"] {
            fs::write(directory_root.join(name), b"x").unwrap();
        }
        let directory_limits = WorkspaceAuthorityLimitsV1 {
            max_directory_entries: 2,
            ..WorkspaceAuthorityLimitsV1::default()
        };
        let directory_epoch =
            WorkspaceExecutionEpochV1::begin(&directory_root, &directory_limits).unwrap();
        assert_eq!(
            directory_epoch
                .list_regular_files(Path::new(""), &directory_limits)
                .unwrap_err()
                .primary_code(),
            IncompleteReasonCodeV1::InputLimitExceeded
        );

        let byte_root = base.join("bytes");
        fs::create_dir(&byte_root).unwrap();
        for index in 0..24 {
            fs::write(byte_root.join(format!("file{index:04}")), b"x").unwrap();
        }
        let max_path_bytes = byte_root.as_os_str().as_bytes().len() + 16;
        let byte_limits = WorkspaceAuthorityLimitsV1 {
            max_path_bytes,
            max_total_path_bytes: max_path_bytes,
            ..WorkspaceAuthorityLimitsV1::default()
        };
        let byte_epoch = WorkspaceExecutionEpochV1::begin(&byte_root, &byte_limits).unwrap();
        assert_eq!(
            byte_epoch
                .list_regular_files(Path::new(""), &byte_limits)
                .unwrap_err()
                .primary_code(),
            IncompleteReasonCodeV1::InputLimitExceeded
        );
    }
}

struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn new(domain: &'static [u8]) -> Self {
        let mut value = Self { bytes: Vec::new() };
        value.bytes(domain);
        value
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn os_str(&mut self, value: &OsStr) {
        self.bytes(value.as_bytes());
    }

    fn path(&mut self, value: &Path) {
        self.os_str(value.as_os_str());
    }

    fn digest(&mut self, value: StateDigestV1) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn optional_digest(&mut self, value: Option<StateDigestV1>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.digest(value);
            }
            None => self.u8(0),
        }
    }

    fn optional_bytes(&mut self, value: Option<&[u8]>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.bytes(value);
            }
            None => self.u8(0),
        }
    }

    fn finish(self) -> StateDigestV1 {
        let mut hasher = Hasher::new();
        hasher.update(&self.bytes);
        StateDigestV1(*hasher.finalize().as_bytes())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
