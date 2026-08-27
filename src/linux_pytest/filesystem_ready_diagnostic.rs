//! Fixed, command-free Gate 3 filesystem-ready diagnostic.
//!
//! The diagnostic is intentionally narrower than an execution profile. It
//! constructs two deterministic inert publications on a provisioned `noatime`
//! working filesystem, proves one successful two-root attachment followed by
//! cancellation, and proves one fixed runtime-`open_tree` refusal after the
//! workspace attachment. It never accepts or releases a workload command and
//! returns only redacted cleanup facts.

use super::RefusalCode;

pub(crate) enum FixedFilesystemReadyProbeDiagnosticV1 {
    Completed {
        successful_attachment_count: u8,
        injected_refusal_count: u8,
        terminal_reap_count: u8,
        cleanup_complete: bool,
    },
    Refused {
        code: RefusalCode,
        stage: &'static str,
        reason: &'static str,
        errno: Option<i32>,
        cleanup_complete: bool,
        expected_unavailable: bool,
    },
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
mod supported {
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::{self, File};
    use std::io;
    use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use super::{FixedFilesystemReadyProbeDiagnosticV1, RefusalCode};
    use crate::linux_pytest::execute_only_admission::{
        FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1, parse_first_execute_only_argv_v1,
    };
    use crate::linux_pytest::execute_only_connector::{
        CommandFreeCancellationPrimaryV1, CommandFreeSetupPrimaryV1,
        prepare_first_execute_only_filesystem_ready_checkpoint_v1,
    };
    use crate::linux_pytest::execute_only_runtime::{
        inventory_first_execute_only_runtime_structure_v1,
        project_first_execute_only_runtime_retained_root_pair_v1,
        qualify_first_execute_only_runtime_checkpoint_v1,
        split_first_execute_only_runtime_filesystem_roots_v1,
    };
    use crate::linux_pytest::execute_only_stdio::open_profile_owned_stdio_v1;
    use crate::linux_pytest::snapshot_connector::connect_snapshot_pipeline;
    use crate::linux_pytest::snapshot_policy::{
        SnapshotPipelineResourcesV1, SnapshotResourcePolicyV1,
    };
    use crate::linux_pytest::snapshot_tree::qualify_fixed_diagnostic_no_atime_source_view_v1;

    const ELF64_HEADER_BYTES: usize = 64;
    const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
    const ELF64_DYNAMIC_ENTRY_BYTES: usize = 16;
    const RUNTIME_FIXTURE_BASE: u64 = 0x40_0000;
    const RUNTIME_FIXTURE_INTERPRETER_OFFSET: usize = 0x200;
    const RUNTIME_FIXTURE_DYNAMIC_OFFSET: usize = 0x400;
    const RUNTIME_FIXTURE_STRING_TABLE_OFFSET: usize = 0x1000;
    const ELF64_LOAD_PAGE_BYTES: u64 = 4096;

    #[derive(Clone, Copy)]
    enum DiagnosticCaseV1 {
        ReadyThenCancel,
        RuntimeOpenRefusal,
    }

    struct DiagnosticDirectoryV1 {
        parent: File,
        directory: File,
        name: CString,
        identity: DiagnosticDirectoryIdentityV1,
        path: PathBuf,
        armed: bool,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct DiagnosticDirectoryIdentityV1 {
        device: libc::dev_t,
        inode: libc::ino_t,
    }

    impl DiagnosticDirectoryV1 {
        fn create(label: &str) -> Result<Self, FixedDiagnosticFailureV1> {
            let parent = File::open(".").map_err(|error| {
                FixedDiagnosticFailureV1::io("open_fixture_parent", "io", error, true, false)
            })?;
            for _ in 0..16 {
                let name = random_diagnostic_directory_name_v1(label)?;
                if unsafe {
                    libc::mkdirat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::S_IRWXU as libc::mode_t,
                    )
                } != 0
                {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EEXIST) {
                        continue;
                    }
                    return Err(FixedDiagnosticFailureV1::io(
                        "create_fixture",
                        "io",
                        error,
                        true,
                        false,
                    ));
                }
                let raw = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw < 0 {
                    let error = io::Error::last_os_error();
                    let _ = unsafe {
                        libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                    };
                    return Err(FixedDiagnosticFailureV1::io(
                        "open_fixture",
                        "io",
                        error,
                        false,
                        false,
                    ));
                }
                let directory = unsafe { File::from_raw_fd(raw) };
                let identity =
                    diagnostic_directory_identity_v1(directory.as_raw_fd()).map_err(|error| {
                        FixedDiagnosticFailureV1::io(
                            "authenticate_fixture",
                            "io",
                            error,
                            false,
                            false,
                        )
                    })?;
                if diagnostic_named_directory_identity_v1(parent.as_raw_fd(), &name)
                    .ok()
                    .flatten()
                    != Some(identity)
                {
                    return Err(FixedDiagnosticFailureV1::new(
                        RefusalCode::SnapshotConstructionFailed,
                        "authenticate_fixture",
                        "identity_drift",
                        None,
                        false,
                        false,
                    ));
                }
                return Ok(Self {
                    parent,
                    directory,
                    path: PathBuf::from(OsStr::from_bytes(name.to_bytes())),
                    name,
                    identity,
                    armed: true,
                });
            }
            Err(FixedDiagnosticFailureV1::new(
                RefusalCode::SnapshotConstructionFailed,
                "create_fixture",
                "name_collision",
                None,
                true,
                false,
            ))
        }

        fn finish(mut self) -> bool {
            let removed = cleanup_diagnostic_directory_v1(
                self.parent.as_raw_fd(),
                self.directory.as_raw_fd(),
                &self.name,
                self.identity,
            );
            self.armed = !removed;
            removed
        }

        /// Preserve the descriptor-pinned fixture when child cleanup is not
        /// proven. Deleting or chmodding publication backing storage while an
        /// un-reaped child may still hold it would defeat the runtime's
        /// deliberate lifetime quarantine.
        fn quarantine(mut self) {
            self.armed = false;
        }
    }

    impl Drop for DiagnosticDirectoryV1 {
        fn drop(&mut self) {
            if self.armed {
                let _ = cleanup_diagnostic_directory_v1(
                    self.parent.as_raw_fd(),
                    self.directory.as_raw_fd(),
                    &self.name,
                    self.identity,
                );
            }
        }
    }

    struct FixedDiagnosticFailureV1 {
        code: RefusalCode,
        stage: &'static str,
        reason: &'static str,
        errno: Option<i32>,
        cleanup_complete: bool,
        expected_unavailable: bool,
    }

    impl FixedDiagnosticFailureV1 {
        const fn new(
            code: RefusalCode,
            stage: &'static str,
            reason: &'static str,
            errno: Option<i32>,
            cleanup_complete: bool,
            expected_unavailable: bool,
        ) -> Self {
            Self {
                code,
                stage,
                reason,
                errno,
                cleanup_complete,
                expected_unavailable,
            }
        }

        fn io(
            stage: &'static str,
            reason: &'static str,
            error: io::Error,
            cleanup_complete: bool,
            expected_unavailable: bool,
        ) -> Self {
            Self::new(
                RefusalCode::SnapshotConstructionFailed,
                stage,
                reason,
                error.raw_os_error(),
                cleanup_complete,
                expected_unavailable,
            )
        }

        fn with_fixture_cleanup(mut self, complete: bool) -> Self {
            self.cleanup_complete &= complete;
            self
        }

        fn erase(self) -> FixedFilesystemReadyProbeDiagnosticV1 {
            FixedFilesystemReadyProbeDiagnosticV1::Refused {
                code: self.code,
                stage: self.stage,
                reason: self.reason,
                errno: self.errno,
                cleanup_complete: self.cleanup_complete,
                expected_unavailable: self.expected_unavailable,
            }
        }
    }

    pub(super) fn diagnose_v1() -> FixedFilesystemReadyProbeDiagnosticV1 {
        if unsafe { libc::getuid() } == 0 {
            return FixedDiagnosticFailureV1::new(
                RefusalCode::IsolationPreflightFailed,
                "dedicated_helper",
                "host_uid_zero",
                None,
                true,
                true,
            )
            .erase();
        }
        let group_count = unsafe {
            libc::syscall(
                libc::SYS_getgroups,
                0_usize,
                std::ptr::null_mut::<libc::gid_t>(),
            )
        };
        if group_count < 0 {
            return FixedDiagnosticFailureV1::io(
                "dedicated_helper",
                "group_readback",
                io::Error::last_os_error(),
                true,
                false,
            )
            .erase();
        }
        if group_count != 0 {
            return FixedDiagnosticFailureV1::new(
                RefusalCode::IsolationPreflightFailed,
                "dedicated_helper",
                "host_supplementary_groups",
                None,
                true,
                true,
            )
            .erase();
        }
        if let Err(failure) = run_case_v1(
            ".again-filesystem-ready-probe-success-v1",
            DiagnosticCaseV1::ReadyThenCancel,
        ) {
            return failure.erase();
        }
        if let Err(failure) = run_case_v1(
            ".again-filesystem-ready-probe-refusal-v1",
            DiagnosticCaseV1::RuntimeOpenRefusal,
        ) {
            return failure.erase();
        }
        FixedFilesystemReadyProbeDiagnosticV1::Completed {
            successful_attachment_count: 1,
            injected_refusal_count: 1,
            terminal_reap_count: 2,
            cleanup_complete: true,
        }
    }

    fn run_case_v1(name: &str, case: DiagnosticCaseV1) -> Result<(), FixedDiagnosticFailureV1> {
        let directory = DiagnosticDirectoryV1::create(name)?;
        let result = run_case_inner_v1(&directory.path, case);
        match result {
            Ok(()) => {
                if directory.finish() {
                    Ok(())
                } else {
                    Err(FixedDiagnosticFailureV1::new(
                        RefusalCode::SnapshotConstructionFailed,
                        "fixture_cleanup",
                        "cleanup_incomplete",
                        None,
                        false,
                        false,
                    ))
                }
            }
            Err(failure) if failure.cleanup_complete => {
                let fixture_cleanup_complete = directory.finish();
                Err(failure.with_fixture_cleanup(fixture_cleanup_complete))
            }
            Err(failure) => {
                directory.quarantine();
                Err(failure.with_fixture_cleanup(false))
            }
        }
    }

    fn run_case_inner_v1(
        base: &Path,
        case: DiagnosticCaseV1,
    ) -> Result<(), FixedDiagnosticFailureV1> {
        let workspace_source = base.join("workspace-source");
        let runtime_source = base.join("runtime-source");
        let workspace_publication = base.join("workspace-publication");
        let runtime_publication = base.join("runtime-publication");
        for path in [
            &workspace_source,
            &runtime_source,
            &workspace_publication,
            &runtime_publication,
        ] {
            create_private_directory_v1(path)?;
        }
        create_workspace_source_v1(&workspace_source)?;
        create_runtime_source_v1(&runtime_source)?;
        create_qualification_probes_v1(&workspace_source)?;
        create_qualification_probes_v1(&runtime_source)?;

        let workspace_source_fd = File::open(&workspace_source).map_err(|error| {
            FixedDiagnosticFailureV1::io("open_workspace_source", "io", error, true, false)
        })?;
        let runtime_source_fd = File::open(&runtime_source).map_err(|error| {
            FixedDiagnosticFailureV1::io("open_runtime_source", "io", error, true, false)
        })?;
        let workspace_publication_fd = File::open(&workspace_publication).map_err(|error| {
            FixedDiagnosticFailureV1::io("open_workspace_publication", "io", error, true, false)
        })?;
        let runtime_publication_fd = File::open(&runtime_publication).map_err(|error| {
            FixedDiagnosticFailureV1::io("open_runtime_publication", "io", error, true, false)
        })?;
        let workspace_s1 = qualify_fixed_diagnostic_no_atime_source_view_v1(
            workspace_source_fd.as_fd(),
        )
        .map_err(|failure| {
            FixedDiagnosticFailureV1::new(
                failure.code(),
                "workspace_source_qualification",
                failure.reason(),
                failure.errno(),
                true,
                failure.is_expected_unavailable(),
            )
        })?;
        let workspace_s2 = qualify_fixed_diagnostic_no_atime_source_view_v1(
            workspace_source_fd.as_fd(),
        )
        .map_err(|failure| {
            FixedDiagnosticFailureV1::new(
                failure.code(),
                "workspace_source_requalification",
                failure.reason(),
                failure.errno(),
                true,
                failure.is_expected_unavailable(),
            )
        })?;
        let runtime_s1 = qualify_fixed_diagnostic_no_atime_source_view_v1(
            runtime_source_fd.as_fd(),
        )
        .map_err(|failure| {
            FixedDiagnosticFailureV1::new(
                failure.code(),
                "runtime_source_qualification",
                failure.reason(),
                failure.errno(),
                true,
                failure.is_expected_unavailable(),
            )
        })?;
        let runtime_s2 = qualify_fixed_diagnostic_no_atime_source_view_v1(
            runtime_source_fd.as_fd(),
        )
        .map_err(|failure| {
            FixedDiagnosticFailureV1::new(
                failure.code(),
                "runtime_source_requalification",
                failure.reason(),
                failure.errno(),
                true,
                failure.is_expected_unavailable(),
            )
        })?;

        let workspace_connector = connect_snapshot_pipeline(publication_resources_v1())
            .map_err(|_| snapshot_failure_v1("workspace_connector", "policy_projection"))?;
        let runtime_connector = connect_snapshot_pipeline(publication_resources_v1())
            .map_err(|_| snapshot_failure_v1("runtime_connector", "policy_projection"))?;
        let argv = [
            b".venv/bin/python".as_slice(),
            b"-I",
            b"-m",
            b"pytest",
            b"tests/test_smoke.py::test_smoke",
        ];
        let lexical = parse_first_execute_only_argv_v1(&argv)
            .map_err(|_| snapshot_failure_v1("lexical_admission", "fixed_argv_refused"))?;
        let workspace_binding = workspace_connector
            .materialize_first_execute_only_workspace_tree_and_publish_at(
                lexical,
                workspace_publication_fd.as_fd(),
                c".again-snapshot-stage-11111111111111111111111111111111",
                c"workspace-final",
                workspace_s1,
                workspace_s2,
                c"root",
            )
            .map_err(|_| snapshot_failure_v1("workspace_publication", "pipeline_refused"))?;
        let checkpoint = qualify_first_execute_only_runtime_checkpoint_v1(workspace_binding)
            .map_err(|_| snapshot_failure_v1("workspace_checkpoint", "runtime_refused"))?;
        let runtime_publication_token = runtime_connector
            .materialize_first_execute_only_runtime_inventory_tree_and_publish_at(
                runtime_publication_fd.as_fd(),
                c".again-snapshot-stage-22222222222222222222222222222222",
                c"runtime-final",
                runtime_s1,
                runtime_s2,
                c"root",
            )
            .map_err(|_| snapshot_failure_v1("runtime_publication", "pipeline_refused"))?;
        let inventory = inventory_first_execute_only_runtime_structure_v1(
            checkpoint,
            runtime_publication_token,
        )
        .map_err(|_| snapshot_failure_v1("runtime_inventory", "inventory_refused"))?;
        let roots = project_first_execute_only_runtime_retained_root_pair_v1(inventory)
            .map_err(|_| snapshot_failure_v1("root_projection", "projection_refused"))?;

        match case {
            DiagnosticCaseV1::ReadyThenCancel => run_ready_then_cancel_v1(roots),
            DiagnosticCaseV1::RuntimeOpenRefusal => run_runtime_open_refusal_v1(roots),
        }
    }

    fn run_ready_then_cancel_v1(
        roots: crate::linux_pytest::execute_only_runtime::FirstExecuteOnlyRuntimeRetainedRootPairV1<
            '_,
        >,
    ) -> Result<(), FixedDiagnosticFailureV1> {
        let ready = prepare_first_execute_only_filesystem_ready_checkpoint_v1(roots).map_err(
            |failure| match failure.primary() {
                CommandFreeSetupPrimaryV1::Isolation(primary) => FixedDiagnosticFailureV1::new(
                    primary.code(),
                    primary.stage(),
                    primary.reason(),
                    primary.primary_errno(),
                    primary.cleanup_complete() && failure.stdio_cleanup_complete(),
                    primary.cleanup_complete()
                        && failure.stdio_cleanup_complete()
                        && primary.is_expected_unavailable(),
                ),
                CommandFreeSetupPrimaryV1::Stdio(_) => FixedDiagnosticFailureV1::new(
                    RefusalCode::IsolationPreflightFailed,
                    "stdio_setup",
                    "refused",
                    None,
                    failure.cleanup_complete(),
                    false,
                ),
                CommandFreeSetupPrimaryV1::Runtime(_) => {
                    snapshot_failure_v1("filesystem_root_split", "root_projection_refused")
                }
            },
        )?;
        let report = ready.cancel_and_finish_v1().map_err(|failure| {
            let reason = match failure.primary() {
                CommandFreeCancellationPrimaryV1::Isolation(_) => "isolation_cancellation",
                CommandFreeCancellationPrimaryV1::Stdio(_) => "stdio_drain",
            };
            FixedDiagnosticFailureV1::new(
                RefusalCode::IsolationPreflightFailed,
                "cancel_and_finish",
                reason,
                None,
                failure.cleanup_complete(),
                false,
            )
        })?;
        if !report.capture_complete() || report.requires_execute_only_classification() {
            return Err(FixedDiagnosticFailureV1::new(
                RefusalCode::IsolationPreflightFailed,
                "cancel_and_finish",
                "stdio_invariant",
                None,
                true,
                false,
            ));
        }
        Ok(())
    }

    fn run_runtime_open_refusal_v1(
        roots: crate::linux_pytest::execute_only_runtime::FirstExecuteOnlyRuntimeRetainedRootPairV1<
            '_,
        >,
    ) -> Result<(), FixedDiagnosticFailureV1> {
        let stdio = open_profile_owned_stdio_v1().map_err(|failure| {
            FixedDiagnosticFailureV1::new(
                RefusalCode::IsolationPreflightFailed,
                "stdio_setup",
                "refused",
                None,
                failure.cleanup_complete(),
                false,
            )
        })?;
        let (parent_stdio, child_stdio) = stdio.split_for_isolation_v1().map_err(|failure| {
            FixedDiagnosticFailureV1::new(
                RefusalCode::IsolationPreflightFailed,
                "stdio_split",
                "refused",
                None,
                failure.cleanup_complete(),
                false,
            )
        })?;
        let split = split_first_execute_only_runtime_filesystem_roots_v1(roots)
            .map_err(|_| snapshot_failure_v1("filesystem_root_split", "projection_refused"))?;
        let blocked = match split.begin_with_profile_stdio_fixed_runtime_refusal_v1(child_stdio) {
            Ok(blocked) => blocked,
            Err(primary) => {
                let parent_cleanup = parent_stdio.close_without_capture_v1();
                return Err(FixedDiagnosticFailureV1::new(
                    primary.code(),
                    primary.stage(),
                    primary.reason(),
                    primary.primary_errno(),
                    primary.cleanup_complete() && parent_cleanup,
                    primary.cleanup_complete()
                        && parent_cleanup
                        && primary.is_expected_unavailable(),
                ));
            }
        };
        let failure = match blocked.continue_to_filesystem_ready_v1() {
            Err(failure) => failure,
            Ok(ready) => {
                let child_cleanup = ready.cancel_and_reap_v1().is_ok();
                let parent_cleanup = parent_stdio.close_without_capture_v1();
                return Err(FixedDiagnosticFailureV1::new(
                    RefusalCode::IsolationPreflightFailed,
                    "fixed_runtime_refusal",
                    "unexpected_success",
                    None,
                    child_cleanup && parent_cleanup,
                    false,
                ));
            }
        };
        let parent_cleanup = parent_stdio.close_without_capture_v1();
        if failure.stage() != "child_filesystem_attachment"
            || failure.reason() != "fixed_runtime_open_tree_refusal"
            || failure.primary_errno() != Some(libc::EIO)
            || !failure.cleanup_complete()
            || !parent_cleanup
        {
            return Err(FixedDiagnosticFailureV1::new(
                failure.code(),
                failure.stage(),
                failure.reason(),
                failure.primary_errno(),
                failure.cleanup_complete() && parent_cleanup,
                false,
            ));
        }
        Ok(())
    }

    fn create_private_directory_v1(path: &Path) -> Result<(), FixedDiagnosticFailureV1> {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path).map_err(|error| {
            FixedDiagnosticFailureV1::io("create_fixture", "io", error, true, false)
        })
    }

    fn create_workspace_source_v1(path: &Path) -> Result<(), FixedDiagnosticFailureV1> {
        fs::create_dir_all(path.join("root/.venv/bin"))
            .and_then(|()| fs::create_dir_all(path.join("root/tests")))
            .and_then(|()| {
                fs::write(
                    path.join("root/.venv/bin/python"),
                    forest_elf_fixture_v1(DiagnosticElfRoleV1::RootExecutable, &[b"libc.so.6"]),
                )
            })
            .and_then(|()| {
                fs::set_permissions(
                    path.join("root/.venv/bin/python"),
                    fs::Permissions::from_mode(0o755),
                )
            })
            .and_then(|()| {
                fs::write(
                    path.join("root/tests/test_smoke.py"),
                    FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1,
                )
            })
            .map_err(|error| {
                FixedDiagnosticFailureV1::io("create_workspace_fixture", "io", error, true, false)
            })
    }

    fn create_runtime_source_v1(path: &Path) -> Result<(), FixedDiagnosticFailureV1> {
        fs::create_dir_all(path.join("root/lib64"))
            .and_then(|()| {
                fs::write(
                    path.join("root/lib64/ld-linux-x86-64.so.2"),
                    forest_elf_fixture_v1(DiagnosticElfRoleV1::Interpreter, &[]),
                )
            })
            .and_then(|()| {
                fs::write(
                    path.join("root/lib64/libc.so.6"),
                    forest_elf_fixture_v1(DiagnosticElfRoleV1::DependencyDso, &[]),
                )
            })
            .map_err(|error| {
                FixedDiagnosticFailureV1::io("create_runtime_fixture", "io", error, true, false)
            })
    }

    fn create_qualification_probes_v1(path: &Path) -> Result<(), FixedDiagnosticFailureV1> {
        fs::create_dir(path.join("probe-directory"))
            .and_then(|()| fs::write(path.join("probe-regular"), b"again-source-view-probe-v1"))
            .and_then(|()| symlink("probe-regular", path.join("probe-symlink")))
            .map_err(|error| {
                FixedDiagnosticFailureV1::io("create_source_probes", "io", error, true, false)
            })?;
        let regular = File::open(path.join("probe-regular")).map_err(|error| {
            FixedDiagnosticFailureV1::io("open_source_probe", "io", error, true, false)
        })?;
        let value = b"again-source-view-probe-value-v1";
        let result = unsafe {
            libc::fsetxattr(
                regular.as_raw_fd(),
                c"user.again.source-view-probe-v1".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if result != 0 {
            return Err(FixedDiagnosticFailureV1::io(
                "create_source_probe_xattr",
                "io",
                io::Error::last_os_error(),
                true,
                true,
            ));
        }
        Ok(())
    }

    fn publication_resources_v1() -> SnapshotPipelineResourcesV1 {
        let policy = SnapshotResourcePolicyV1::checked(
            8,
            NonZeroU32::new(64).expect("nonzero"),
            NonZeroU16::new(255).expect("nonzero"),
            16 * 1024,
            16 * 1024,
            16 * 1024 * 1024,
            64 * 1024 * 1024,
            64,
            4_096,
            64,
            4_096,
            255,
            64 * 1024,
            64 * 1024,
            1024 * 1024,
            NonZeroU64::new(8 * 1024 * 1024).expect("nonzero"),
            16 * 1024 * 1024,
            1024 * 1024,
            NonZeroU64::new(1_000_000).expect("nonzero"),
            NonZeroU8::new(4).expect("nonzero"),
            NonZeroU8::new(3).expect("nonzero"),
            NonZeroU8::new(4).expect("nonzero"),
        )
        .expect("fixed diagnostic resource policy is valid");
        SnapshotPipelineResourcesV1::preflight(policy, 0, u64::MAX, u64::MAX)
            .expect("fixed diagnostic resource ledger is valid")
    }

    fn snapshot_failure_v1(stage: &'static str, reason: &'static str) -> FixedDiagnosticFailureV1 {
        FixedDiagnosticFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            stage,
            reason,
            None,
            true,
            false,
        )
    }

    fn random_diagnostic_directory_name_v1(
        label: &str,
    ) -> Result<CString, FixedDiagnosticFailureV1> {
        let mut random = [0_u8; 16];
        let result = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                random.as_mut_ptr(),
                random.len(),
                0_u32,
            )
        };
        if usize::try_from(result).ok() != Some(random.len()) {
            return Err(FixedDiagnosticFailureV1::io(
                "create_fixture",
                "randomness",
                io::Error::last_os_error(),
                true,
                false,
            ));
        }
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut suffix, "{byte:02x}").expect("writing to a String cannot fail");
        }
        CString::new(format!(".again-fs-ready-{label}-{suffix}"))
            .map_err(|_| snapshot_failure_v1("create_fixture", "invalid_name"))
    }

    fn diagnostic_directory_identity_v1(
        descriptor: libc::c_int,
    ) -> io::Result<DiagnosticDirectoryIdentityV1> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(descriptor, status.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe { status.assume_init() };
        if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        Ok(DiagnosticDirectoryIdentityV1 {
            device: status.st_dev,
            inode: status.st_ino,
        })
    }

    fn diagnostic_named_directory_identity_v1(
        parent: libc::c_int,
        name: &CStr,
    ) -> io::Result<Option<DiagnosticDirectoryIdentityV1>> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::zeroed();
        if unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let status = unsafe { status.assume_init() };
        if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Ok(None);
        }
        Ok(Some(DiagnosticDirectoryIdentityV1 {
            device: status.st_dev,
            inode: status.st_ino,
        }))
    }

    fn cleanup_diagnostic_directory_v1(
        parent: libc::c_int,
        directory: libc::c_int,
        name: &CStr,
        identity: DiagnosticDirectoryIdentityV1,
    ) -> bool {
        let mut remaining = 4096_usize;
        let contents_removed = cleanup_diagnostic_contents_v1(directory, 0, &mut remaining);
        if !contents_removed
            || diagnostic_directory_identity_v1(directory).ok() != Some(identity)
            || diagnostic_named_directory_identity_v1(parent, name)
                .ok()
                .flatten()
                != Some(identity)
        {
            return false;
        }
        if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return false;
        }
        diagnostic_named_directory_identity_v1(parent, name).ok() == Some(None)
    }

    fn cleanup_diagnostic_contents_v1(
        directory: libc::c_int,
        depth: usize,
        remaining: &mut usize,
    ) -> bool {
        if depth >= 32 || unsafe { libc::fchmod(directory, libc::S_IRWXU as libc::mode_t) } != 0 {
            return false;
        }
        let duplicate = unsafe { libc::fcntl(directory, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return false;
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let _ = unsafe { libc::close(duplicate) };
            return false;
        }
        let mut complete = true;
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                if unsafe { *libc::__errno_location() } != 0 {
                    complete = false;
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            if *remaining == 0 {
                complete = false;
                continue;
            }
            *remaining -= 1;
            let name = match CString::new(name.to_bytes()) {
                Ok(name) => name,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let mut status = std::mem::MaybeUninit::<libc::stat>::zeroed();
            if unsafe {
                libc::fstatat(
                    directory,
                    name.as_ptr(),
                    status.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                complete = false;
                continue;
            }
            let status = unsafe { status.assume_init() };
            if status.st_mode & libc::S_IFMT == libc::S_IFDIR {
                let child = unsafe {
                    libc::openat(
                        directory,
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if child < 0 {
                    complete = false;
                    continue;
                }
                let expected = DiagnosticDirectoryIdentityV1 {
                    device: status.st_dev,
                    inode: status.st_ino,
                };
                let child_complete = diagnostic_directory_identity_v1(child).ok() == Some(expected)
                    && cleanup_diagnostic_contents_v1(child, depth + 1, remaining);
                let close_complete = unsafe { libc::close(child) } == 0;
                if !child_complete
                    || !close_complete
                    || diagnostic_named_directory_identity_v1(directory, &name)
                        .ok()
                        .flatten()
                        != Some(expected)
                    || unsafe { libc::unlinkat(directory, name.as_ptr(), libc::AT_REMOVEDIR) } != 0
                {
                    complete = false;
                }
            } else if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } != 0 {
                complete = false;
            }
        }
        let close_complete = unsafe { libc::closedir(stream) } == 0;
        complete && close_complete
    }

    #[cfg(test)]
    mod cleanup_tests {
        use super::*;

        #[test]
        fn substituted_fixture_name_is_not_deleted_or_reported_complete() {
            let directory = DiagnosticDirectoryV1::create("cleanup-race")
                .unwrap_or_else(|_| panic!("fixture creation failed"));
            let original = directory.path.clone();
            let displaced = PathBuf::from(format!("{}-displaced", original.to_string_lossy()));
            fs::rename(&original, &displaced).unwrap();
            fs::create_dir(&original).unwrap();
            fs::write(original.join("do-not-delete"), b"substitute").unwrap();

            assert!(!directory.finish());
            assert_eq!(
                fs::read(original.join("do-not-delete")).unwrap(),
                b"substitute"
            );

            fs::remove_dir_all(&original).unwrap();
            fs::remove_dir_all(&displaced).unwrap();
        }

        #[test]
        fn explicit_quarantine_preserves_fixture_tree() {
            let directory = DiagnosticDirectoryV1::create("cleanup-quarantine")
                .unwrap_or_else(|_| panic!("fixture creation failed"));
            let path = directory.path.clone();
            fs::write(path.join("retained"), b"uncertain-child-lifetime").unwrap();
            directory.quarantine();
            assert!(path.join("retained").is_file());
            fs::remove_dir_all(path).unwrap();
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum DiagnosticElfRoleV1 {
        RootExecutable,
        Interpreter,
        DependencyDso,
    }

    #[allow(clippy::too_many_arguments)]
    fn write_program_header_v1(
        bytes: &mut [u8],
        index: usize,
        kind: u32,
        flags: u32,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        let start = ELF64_HEADER_BYTES + index * ELF64_PROGRAM_HEADER_BYTES;
        let program = &mut bytes[start..start + ELF64_PROGRAM_HEADER_BYTES];
        program[0..4].copy_from_slice(&kind.to_le_bytes());
        program[4..8].copy_from_slice(&flags.to_le_bytes());
        program[8..16].copy_from_slice(&offset.to_le_bytes());
        program[16..24].copy_from_slice(&virtual_address.to_le_bytes());
        program[32..40].copy_from_slice(&file_size.to_le_bytes());
        program[40..48].copy_from_slice(&memory_size.to_le_bytes());
        program[48..56].copy_from_slice(&alignment.to_le_bytes());
    }

    fn write_dynamic_entry_v1(bytes: &mut [u8], index: usize, tag: u64, value: u64) {
        let start = RUNTIME_FIXTURE_DYNAMIC_OFFSET + index * ELF64_DYNAMIC_ENTRY_BYTES;
        bytes[start..start + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn forest_elf_fixture_v1(role: DiagnosticElfRoleV1, needed: &[&[u8]]) -> Vec<u8> {
        const INTERPRETER: &[u8] = b"/lib64/ld-linux-x86-64.so.2";
        let mut string_table = vec![0_u8];
        let mut offsets = Vec::new();
        for name in needed {
            offsets.push(string_table.len());
            string_table.extend_from_slice(name);
            string_table.push(0);
        }
        let dynamic_count = needed.len() + 3;
        let dynamic_bytes = dynamic_count * ELF64_DYNAMIC_ENTRY_BYTES;
        let interpreter = (role == DiagnosticElfRoleV1::RootExecutable).then_some(INTERPRETER);
        let interpreter_bytes = interpreter.map_or(0, |path| path.len() + 1);
        let file_bytes = 8192_usize
            .max(RUNTIME_FIXTURE_DYNAMIC_OFFSET + dynamic_bytes)
            .max(RUNTIME_FIXTURE_STRING_TABLE_OFFSET + string_table.len())
            .max(RUNTIME_FIXTURE_INTERPRETER_OFFSET + interpreter_bytes);
        let program_count = if interpreter.is_some() { 3 } else { 2 };
        let mut bytes = vec![0_u8; file_bytes];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[7] = 0;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        let entry = if matches!(
            role,
            DiagnosticElfRoleV1::RootExecutable | DiagnosticElfRoleV1::Interpreter
        ) {
            RUNTIME_FIXTURE_BASE + 0x100
        } else {
            0
        };
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF64_HEADER_BYTES as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(program_count as u16).to_le_bytes());
        write_program_header_v1(
            &mut bytes,
            0,
            1,
            5,
            0,
            RUNTIME_FIXTURE_BASE,
            file_bytes as u64,
            file_bytes as u64,
            ELF64_LOAD_PAGE_BYTES,
        );
        let dynamic_index = if let Some(interpreter) = interpreter {
            let mut value = interpreter.to_vec();
            value.push(0);
            bytes[RUNTIME_FIXTURE_INTERPRETER_OFFSET
                ..RUNTIME_FIXTURE_INTERPRETER_OFFSET + value.len()]
                .copy_from_slice(&value);
            write_program_header_v1(
                &mut bytes,
                1,
                3,
                4,
                RUNTIME_FIXTURE_INTERPRETER_OFFSET as u64,
                RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_INTERPRETER_OFFSET as u64,
                value.len() as u64,
                value.len() as u64,
                1,
            );
            2
        } else {
            1
        };
        write_program_header_v1(
            &mut bytes,
            dynamic_index,
            2,
            4,
            RUNTIME_FIXTURE_DYNAMIC_OFFSET as u64,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_DYNAMIC_OFFSET as u64,
            dynamic_bytes as u64,
            dynamic_bytes as u64,
            8,
        );
        bytes[RUNTIME_FIXTURE_STRING_TABLE_OFFSET
            ..RUNTIME_FIXTURE_STRING_TABLE_OFFSET + string_table.len()]
            .copy_from_slice(&string_table);
        for (index, offset) in offsets.into_iter().enumerate() {
            write_dynamic_entry_v1(&mut bytes, index, 1, offset as u64);
        }
        write_dynamic_entry_v1(
            &mut bytes,
            needed.len(),
            5,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_STRING_TABLE_OFFSET as u64,
        );
        write_dynamic_entry_v1(&mut bytes, needed.len() + 1, 10, string_table.len() as u64);
        write_dynamic_entry_v1(&mut bytes, needed.len() + 2, 0, 0);
        bytes
    }
}

pub(crate) fn diagnose_fixed_filesystem_ready_v1() -> FixedFilesystemReadyProbeDiagnosticV1 {
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    {
        supported::diagnose_v1()
    }
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    )))]
    {
        let (code, stage, reason) = if !cfg!(target_os = "linux") {
            (RefusalCode::UnsupportedOs, "platform", "unsupported_os")
        } else {
            (
                RefusalCode::UnsupportedArchitecture,
                "platform",
                "unsupported_architecture",
            )
        };
        FixedFilesystemReadyProbeDiagnosticV1::Refused {
            code,
            stage,
            reason,
            errno: None,
            cleanup_complete: true,
            expected_unavailable: true,
        }
    }
}
