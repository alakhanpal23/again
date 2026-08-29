//! Private, process-local sharing of sealed workspace observations.
//!
//! Nothing in this module is persistent or independently authoritative. Every
//! returned repository epoch was produced behind the manifest's fresh fence.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use serde_json::Value;

use super::{RepositoryOperationV1, repository_tools};
use crate::workspace_authority::{
    ObservedManifestAccountingV1, ObservedManifestV1, RepositoryEpochV1,
    RepositoryObservationPlanV1, WorkspaceAuthorityLimitsV1, WorkspaceExecutionEpochV1,
};

const MAX_CACHED_RESOLUTION_PLANS_V1: usize = 128;
const MANIFEST_LOCK_WAIT_V1: Duration = Duration::from_secs(5);
const MANIFEST_LOCK_POLL_V1: Duration = Duration::from_millis(1);

pub(super) struct ObservedWorkspaceRequestV1 {
    pub(super) execution_epoch: Arc<WorkspaceExecutionEpochV1>,
    pub(super) repository_epoch: RepositoryEpochV1,
}

struct WorkspaceObservationSessionV1 {
    execution_epoch: Arc<WorkspaceExecutionEpochV1>,
    state: Mutex<WorkspaceObservationStateV1>,
}

struct WorkspaceObservationStateV1 {
    manifest: ObservedManifestV1,
    plans: BTreeMap<(u8, Vec<u8>), RepositoryObservationPlanV1>,
}

#[derive(Default)]
struct WorkspaceObservationCountersV1 {
    sessions_created: AtomicU64,
    session_rotations: AtomicU64,
    physical_content_hashes: AtomicU64,
    physical_directory_listings: AtomicU64,
    content_hashes_avoided: AtomicU64,
    directory_listings_avoided: AtomicU64,
    resolver_executions: AtomicU64,
    resolver_calls_avoided: AtomicU64,
    bounded_lock_refusals: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct WorkspaceObservationMetricsV1 {
    pub(super) sessions_created: u64,
    pub(super) session_rotations: u64,
    pub(super) physical_content_hashes: u64,
    pub(super) physical_directory_listings: u64,
    pub(super) content_hashes_avoided: u64,
    pub(super) directory_listings_avoided: u64,
    pub(super) resolver_executions: u64,
    pub(super) resolver_calls_avoided: u64,
    pub(super) bounded_lock_refusals: u64,
}

pub(super) struct WorkspaceObservationManagerV1 {
    workspace: PathBuf,
    limits: WorkspaceAuthorityLimitsV1,
    current: Mutex<Arc<WorkspaceObservationSessionV1>>,
    counters: WorkspaceObservationCountersV1,
}

enum SessionObservationErrorV1 {
    Busy,
    Plan(anyhow::Error),
    Manifest(anyhow::Error),
}

impl WorkspaceObservationSessionV1 {
    fn begin(workspace: &Path, limits: &WorkspaceAuthorityLimitsV1) -> Result<Arc<Self>> {
        let execution_epoch = Arc::new(
            WorkspaceExecutionEpochV1::begin(workspace, limits)
                .map_err(|_| anyhow!("descriptor-retained workspace issuance failed"))?,
        );
        let manifest = execution_epoch
            .begin_observed_manifest(limits)
            .map_err(|_| anyhow!("sealed workspace observation issuance failed"))?;
        Ok(Arc::new(Self {
            execution_epoch,
            state: Mutex::new(WorkspaceObservationStateV1 {
                manifest,
                plans: BTreeMap::new(),
            }),
        }))
    }

    fn bounded_state_lock(
        &self,
    ) -> std::result::Result<MutexGuard<'_, WorkspaceObservationStateV1>, SessionObservationErrorV1>
    {
        let deadline = Instant::now() + MANIFEST_LOCK_WAIT_V1;
        loop {
            match self.state.try_lock() {
                Ok(state) => return Ok(state),
                Err(TryLockError::Poisoned(poison)) => return Ok(poison.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(MANIFEST_LOCK_POLL_V1);
                }
                Err(TryLockError::WouldBlock) => return Err(SessionObservationErrorV1::Busy),
            }
        }
    }

    fn observe(
        &self,
        arguments: &Value,
        operation: RepositoryOperationV1,
        counters: &WorkspaceObservationCountersV1,
    ) -> std::result::Result<ObservedWorkspaceRequestV1, SessionObservationErrorV1> {
        let key = (
            operation.cache_tag(),
            serde_json::to_vec(arguments)
                .map_err(|error| SessionObservationErrorV1::Plan(error.into()))?,
        );
        let mut state = self.bounded_state_lock()?;
        let plan = if let Some(plan) = state.plans.get(&key) {
            counters
                .resolver_calls_avoided
                .fetch_add(1, Ordering::Relaxed);
            plan.clone()
        } else {
            let plan =
                repository_tools::observation_plan_v1(&self.execution_epoch, arguments, operation)
                    .map_err(SessionObservationErrorV1::Plan)?;
            counters.resolver_executions.fetch_add(1, Ordering::Relaxed);
            if state.plans.len() < MAX_CACHED_RESOLUTION_PLANS_V1 {
                state.plans.insert(key, plan.clone());
            }
            plan
        };
        let before = state.manifest.accounting();
        let observed = state.manifest.observe_repository(&plan);
        let after = state.manifest.accounting();
        record_accounting_delta(counters, before, after);
        let repository_epoch = observed.map_err(|error| {
            SessionObservationErrorV1::Manifest(anyhow!(
                "sealed repository observation failed: {:?}",
                error.primary_code()
            ))
        })?;
        Ok(ObservedWorkspaceRequestV1 {
            execution_epoch: Arc::clone(&self.execution_epoch),
            repository_epoch,
        })
    }
}

impl WorkspaceObservationManagerV1 {
    pub(super) fn begin(workspace: &Path, limits: WorkspaceAuthorityLimitsV1) -> Result<Self> {
        let session = WorkspaceObservationSessionV1::begin(workspace, &limits)?;
        let counters = WorkspaceObservationCountersV1::default();
        counters.sessions_created.store(1, Ordering::Relaxed);
        Ok(Self {
            workspace: workspace.to_path_buf(),
            limits,
            current: Mutex::new(session),
            counters,
        })
    }

    pub(super) fn observe(
        &self,
        arguments: &Value,
        operation: RepositoryOperationV1,
    ) -> Result<ObservedWorkspaceRequestV1> {
        let session = self.current_session()?;
        match session.observe(arguments, operation, &self.counters) {
            Ok(observed) => Ok(observed),
            Err(SessionObservationErrorV1::Busy) => {
                self.counters
                    .bounded_lock_refusals
                    .fetch_add(1, Ordering::Relaxed);
                Err(anyhow!("workspace observation session is busy"))
            }
            Err(SessionObservationErrorV1::Plan(error)) => Err(error),
            Err(SessionObservationErrorV1::Manifest(_error)) => {
                let replacement = self.rotate_if_current(&session)?;
                match replacement.observe(arguments, operation, &self.counters) {
                    Ok(observed) => Ok(observed),
                    Err(SessionObservationErrorV1::Busy) => {
                        self.counters
                            .bounded_lock_refusals
                            .fetch_add(1, Ordering::Relaxed);
                        Err(anyhow!("replacement workspace observation session is busy"))
                    }
                    Err(SessionObservationErrorV1::Plan(error))
                    | Err(SessionObservationErrorV1::Manifest(error)) => Err(error),
                }
            }
        }
    }

    fn current_session(&self) -> Result<Arc<WorkspaceObservationSessionV1>> {
        let current = self.bounded_current_lock()?;
        Ok(Arc::clone(&*current))
    }

    fn bounded_current_lock(&self) -> Result<MutexGuard<'_, Arc<WorkspaceObservationSessionV1>>> {
        let deadline = Instant::now() + MANIFEST_LOCK_WAIT_V1;
        loop {
            match self.current.try_lock() {
                Ok(current) => return Ok(current),
                Err(TryLockError::Poisoned(poison)) => return Ok(poison.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(MANIFEST_LOCK_POLL_V1);
                }
                Err(TryLockError::WouldBlock) => {
                    self.counters
                        .bounded_lock_refusals
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(anyhow!("workspace observation rotation is busy"));
                }
            }
        }
    }

    fn rotate_if_current(
        &self,
        failed: &Arc<WorkspaceObservationSessionV1>,
    ) -> Result<Arc<WorkspaceObservationSessionV1>> {
        let replacement = WorkspaceObservationSessionV1::begin(&self.workspace, &self.limits)?;
        let mut current = self.bounded_current_lock()?;
        if Arc::ptr_eq(&current, failed) {
            *current = replacement;
            self.counters
                .sessions_created
                .fetch_add(1, Ordering::Relaxed);
            self.counters
                .session_rotations
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(Arc::clone(&current))
    }

    pub(super) fn metrics(&self) -> WorkspaceObservationMetricsV1 {
        WorkspaceObservationMetricsV1 {
            sessions_created: self.counters.sessions_created.load(Ordering::Relaxed),
            session_rotations: self.counters.session_rotations.load(Ordering::Relaxed),
            physical_content_hashes: self
                .counters
                .physical_content_hashes
                .load(Ordering::Relaxed),
            physical_directory_listings: self
                .counters
                .physical_directory_listings
                .load(Ordering::Relaxed),
            content_hashes_avoided: self.counters.content_hashes_avoided.load(Ordering::Relaxed),
            directory_listings_avoided: self
                .counters
                .directory_listings_avoided
                .load(Ordering::Relaxed),
            resolver_executions: self.counters.resolver_executions.load(Ordering::Relaxed),
            resolver_calls_avoided: self.counters.resolver_calls_avoided.load(Ordering::Relaxed),
            bounded_lock_refusals: self.counters.bounded_lock_refusals.load(Ordering::Relaxed),
        }
    }
}

fn record_accounting_delta(
    counters: &WorkspaceObservationCountersV1,
    before: ObservedManifestAccountingV1,
    after: ObservedManifestAccountingV1,
) {
    counters.physical_content_hashes.fetch_add(
        after
            .physical_content_hashes()
            .saturating_sub(before.physical_content_hashes()),
        Ordering::Relaxed,
    );
    counters.physical_directory_listings.fetch_add(
        after
            .physical_directory_listings()
            .saturating_sub(before.physical_directory_listings()),
        Ordering::Relaxed,
    );
    counters.content_hashes_avoided.fetch_add(
        after
            .avoided_content_hashes()
            .saturating_sub(before.avoided_content_hashes()),
        Ordering::Relaxed,
    );
    counters.directory_listings_avoided.fetch_add(
        after
            .avoided_directory_listings()
            .saturating_sub(before.avoided_directory_listings()),
        Ordering::Relaxed,
    );
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::{FileTimes, OpenOptions};
    use std::process::Command;
    use std::sync::Barrier;
    use std::thread;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    fn manager(workspace: &Path) -> Arc<WorkspaceObservationManagerV1> {
        let workspace = fs::canonicalize(workspace).unwrap();
        Arc::new(
            WorkspaceObservationManagerV1::begin(
                &workspace,
                super::super::gateway_workspace_limits_v1(),
            )
            .unwrap(),
        )
    }

    fn git(workspace: &Path, arguments: &[&str]) {
        let output = Command::new("/usr/bin/git")
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-c", "commit.gpgsign=false"])
            .args(arguments)
            .current_dir(workspace)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn sequential_overlapping_operations_share_hashes_directories_and_resolver_plans() {
        let temporary = TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("src")).unwrap();
        fs::write(
            temporary.path().join("src/lib.rs"),
            b"pub fn shared_needle() {}\n",
        )
        .unwrap();
        fs::write(
            temporary.path().join("src/other.rs"),
            b"pub fn other() {}\n",
        )
        .unwrap();
        let manager = manager(temporary.path());
        let search = manager
            .observe(
                &json!({"pattern":"shared_needle","path":"."}),
                RepositoryOperationV1::Search,
            )
            .unwrap();
        let tree = manager
            .observe(&json!({"path":"."}), RepositoryOperationV1::Tree)
            .unwrap();
        let references = manager
            .observe(
                &json!({"symbol":"shared_needle","path":"."}),
                RepositoryOperationV1::References,
            )
            .unwrap();
        assert_eq!(
            search.repository_epoch.digest(),
            tree.repository_epoch.digest()
        );
        assert_eq!(
            tree.repository_epoch.digest(),
            references.repository_epoch.digest()
        );

        let before_repeat = manager.metrics();
        manager
            .observe(
                &json!({"pattern":"shared_needle","path":"."}),
                RepositoryOperationV1::Search,
            )
            .unwrap();
        let metrics = manager.metrics();
        assert_eq!(metrics.sessions_created, 1);
        assert_eq!(metrics.physical_content_hashes, 2);
        assert!(metrics.content_hashes_avoided >= 6);
        assert!(metrics.directory_listings_avoided >= 6);
        assert_eq!(metrics.resolver_executions, 3);
        assert_eq!(metrics.resolver_calls_avoided, 1);
        assert_eq!(
            metrics.physical_content_hashes,
            before_repeat.physical_content_hashes
        );
    }

    #[test]
    fn relevant_mutation_rotates_once_while_irrelevant_mutation_preserves_session() {
        let temporary = TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("src")).unwrap();
        fs::create_dir(temporary.path().join("docs")).unwrap();
        fs::write(temporary.path().join("src/lib.rs"), b"before\n").unwrap();
        fs::write(temporary.path().join("docs/note"), b"before\n").unwrap();
        let manager = manager(temporary.path());
        let arguments = json!({"pattern":"before","path":"src"});
        let first = manager
            .observe(&arguments, RepositoryOperationV1::Search)
            .unwrap();

        fs::write(temporary.path().join("docs/note"), b"changed\n").unwrap();
        let irrelevant = manager
            .observe(&arguments, RepositoryOperationV1::Search)
            .unwrap();
        assert_eq!(
            first.repository_epoch.digest(),
            irrelevant.repository_epoch.digest()
        );
        assert_eq!(manager.metrics().session_rotations, 0);

        fs::write(temporary.path().join("src/lib.rs"), b"after!\n").unwrap();
        let relevant = manager
            .observe(&arguments, RepositoryOperationV1::Search)
            .unwrap();
        assert_ne!(
            first.repository_epoch.digest(),
            relevant.repository_epoch.digest()
        );
        let metrics = manager.metrics();
        assert_eq!(metrics.sessions_created, 2);
        assert_eq!(metrics.session_rotations, 1);
        assert_eq!(metrics.physical_content_hashes, 2);
    }

    #[test]
    fn read_then_source_tree_and_listing_then_negative_dependencies_share_nodes() {
        let temporary = TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("src")).unwrap();
        fs::write(temporary.path().join("src/lib.rs"), b"shared_needle\n").unwrap();
        fs::write(temporary.path().join("src/other.rs"), b"other\n").unwrap();
        fs::write(
            temporary.path().join("Cargo.toml"),
            b"[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        let manager = manager(temporary.path());
        manager
            .observe(&json!({"path":"src/lib.rs"}), RepositoryOperationV1::Read)
            .unwrap();
        manager
            .observe(
                &json!({"pattern":"shared_needle","path":"src"}),
                RepositoryOperationV1::Search,
            )
            .unwrap();
        let after_tree = manager.metrics();
        assert_eq!(after_tree.physical_content_hashes, 2);
        assert!(after_tree.content_hashes_avoided >= 1);

        manager
            .observe(&json!({"path":"."}), RepositoryOperationV1::List)
            .unwrap();
        let before_manifest = manager.metrics();
        manager
            .observe(&json!({"path":"."}), RepositoryOperationV1::Manifest)
            .unwrap();
        let after_manifest = manager.metrics();
        assert_eq!(
            before_manifest.physical_directory_listings,
            after_manifest.physical_directory_listings
        );
        assert!(
            after_manifest.directory_listings_avoided > before_manifest.directory_listings_avoided
        );
    }

    #[test]
    fn directory_membership_change_rotates_before_new_tree_can_be_observed() {
        let temporary = TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("src")).unwrap();
        fs::write(temporary.path().join("src/one.rs"), b"one\n").unwrap();
        let manager = manager(temporary.path());
        let arguments = json!({"path":"src"});
        let first = manager
            .observe(&arguments, RepositoryOperationV1::Tree)
            .unwrap();
        fs::write(temporary.path().join("src/two.rs"), b"two\n").unwrap();
        let second = manager
            .observe(&arguments, RepositoryOperationV1::Tree)
            .unwrap();
        assert_ne!(
            first.repository_epoch.digest(),
            second.repository_epoch.digest()
        );
        assert_eq!(manager.metrics().session_rotations, 1);
    }

    #[test]
    fn concurrent_identical_observations_do_not_duplicate_physical_manifest_work() {
        let temporary = TempDir::new().unwrap();
        fs::create_dir(temporary.path().join("src")).unwrap();
        fs::write(temporary.path().join("src/lib.rs"), b"shared_needle\n").unwrap();
        let manager = manager(temporary.path());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                manager
                    .observe(
                        &json!({"pattern":"shared_needle","path":"src"}),
                        RepositoryOperationV1::Search,
                    )
                    .unwrap()
                    .repository_epoch
                    .digest()
            }));
        }
        barrier.wait();
        let first = workers.remove(0).join().unwrap();
        let second = workers.remove(0).join().unwrap();
        assert_eq!(first, second);
        let metrics = manager.metrics();
        assert_eq!(metrics.physical_content_hashes, 1);
        assert!(metrics.content_hashes_avoided >= 1);
        assert_eq!(metrics.resolver_executions, 1);
        assert_eq!(metrics.resolver_calls_avoided, 1);
        assert_eq!(metrics.bounded_lock_refusals, 0);
    }

    #[test]
    fn same_size_restored_mtime_replacement_rotates_and_never_reuses_old_nodes() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("input");
        fs::write(&path, b"before").unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let manager = manager(temporary.path());
        let arguments = json!({"path":"input"});
        let first = manager
            .observe(&arguments, RepositoryOperationV1::Read)
            .unwrap();

        fs::remove_file(&path).unwrap();
        fs::write(&path, b"after!").unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(modified))
            .unwrap();
        let second = manager
            .observe(&arguments, RepositoryOperationV1::Read)
            .unwrap();
        assert_ne!(
            first.repository_epoch.digest(),
            second.repository_epoch.digest()
        );
        let metrics = manager.metrics();
        assert_eq!(metrics.session_rotations, 1);
        assert_eq!(metrics.physical_content_hashes, 2);
        assert_eq!(metrics.content_hashes_avoided, 0);
    }

    #[test]
    fn git_state_change_and_workspace_replacement_each_rotate_the_session() {
        let temporary = TempDir::new().unwrap();
        let repository = temporary.path().join("repository");
        let moved = temporary.path().join("moved");
        fs::create_dir(&repository).unwrap();
        fs::write(repository.join("input"), b"same").unwrap();
        git(&repository, &["init", "-q"]);
        git(&repository, &["config", "user.name", "Hot Reuse Test"]);
        git(
            &repository,
            &["config", "user.email", "hot-reuse@example.invalid"],
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-q", "-m", "initial"]);
        let manager = manager(&repository);
        let arguments = json!({"maxResults":10});
        let first = manager
            .observe(&arguments, RepositoryOperationV1::GitLog)
            .unwrap();

        git(&repository, &["config", "diff.algorithm", "histogram"]);
        let configured = manager
            .observe(&arguments, RepositoryOperationV1::GitLog)
            .unwrap();
        assert_ne!(
            first.repository_epoch.digest(),
            configured.repository_epoch.digest()
        );
        assert_eq!(manager.metrics().session_rotations, 1);

        fs::rename(&repository, &moved).unwrap();
        fs::create_dir(&repository).unwrap();
        fs::write(repository.join("input"), b"same").unwrap();
        let replacement = manager
            .observe(&json!({"path":"input"}), RepositoryOperationV1::Read)
            .unwrap();
        assert_ne!(
            configured.repository_epoch.workspace_identity_digest(),
            replacement.repository_epoch.workspace_identity_digest()
        );
        assert_eq!(manager.metrics().session_rotations, 2);
    }
}
