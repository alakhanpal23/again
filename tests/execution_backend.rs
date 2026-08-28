use again::execution_backend::{
    AuditedLocalRead, AuditedReadRequest, AuditedReadResult, BackendError, BackendKind,
    ExactReadAdapter, Firecracker, GVisor, Qualification, RemoteMcp, RootlessLinux,
    UnsupportedReason,
};

#[test]
fn authority_matrix_is_minimal_and_explicit() {
    let local = AuditedLocalRead.descriptor();
    assert!(local.is_available());
    assert_eq!(local.qualification(), Qualification::Composable);
    assert!(local.authority().permits_exact_local_read());
    assert!(!local.authority().permits_local_command_execution());
    assert!(!local.authority().permits_remote_tool_forwarding());
    assert!(!local.is_authoritative());

    let rootless = RootlessLinux.descriptor();
    assert_eq!(rootless.kind(), BackendKind::RootlessLinux);
    assert!(!rootless.is_available());
    assert!(!rootless.authority().permits_local_command_execution());

    let gvisor = GVisor {
        runtime_name: "runsc".into(),
    }
    .descriptor();
    let firecracker = Firecracker {
        profile_name: "future-profile".into(),
    }
    .descriptor();
    assert_eq!(gvisor.qualification(), Qualification::DescriptorOnly);
    assert_eq!(firecracker.qualification(), Qualification::DescriptorOnly);
    assert_eq!(gvisor.authority(), rootless.authority());
    assert_eq!(firecracker.authority(), rootless.authority());
    assert!(!gvisor.authority().permits_local_command_execution());

    let remote = RemoteMcp {
        provider_identity: "provider-identity".into(),
    }
    .descriptor();
    assert!(remote.is_available());
    assert!(remote.authority().permits_remote_tool_forwarding());
    assert!(!remote.authority().permits_local_command_execution());
}

#[test]
fn unavailable_sandbox_backends_return_typed_unsupported() {
    assert_eq!(
        RootlessLinux.require_available(),
        Err(BackendError::Unsupported {
            backend: BackendKind::RootlessLinux,
            reason: UnsupportedReason::RootlessLinuxIsCommandFree,
        })
    );
    assert_eq!(
        GVisor {
            runtime_name: "runsc".into()
        }
        .require_available(),
        Err(BackendError::Unsupported {
            backend: BackendKind::GVisor,
            reason: UnsupportedReason::DescriptorOnly,
        })
    );
    assert_eq!(
        Firecracker {
            profile_name: "microvm".into()
        }
        .require_available(),
        Err(BackendError::Unsupported {
            backend: BackendKind::Firecracker,
            reason: UnsupportedReason::DescriptorOnly,
        })
    );
}

#[test]
fn rootless_linux_cannot_accidentally_gain_command_authority() {
    let descriptor = RootlessLinux.descriptor();
    assert!(!descriptor.is_available());
    assert!(!descriptor.authority().permits_local_command_execution());
    assert_eq!(descriptor.qualification(), Qualification::CommandFree);

    // Its public API accepts no command, argv, environment, closure, or adapter.
    let refusal = RootlessLinux.require_available().unwrap_err();
    assert!(matches!(
        refusal,
        BackendError::Unsupported {
            reason: UnsupportedReason::RootlessLinuxIsCommandFree,
            ..
        }
    ));
}

struct ExactReadFixture;

impl ExactReadAdapter for ExactReadFixture {
    fn read_exact(&self, request: &AuditedReadRequest) -> Result<AuditedReadResult, BackendError> {
        assert_eq!(request.canonical_path, "/safe/input");
        Ok(AuditedReadResult {
            bytes: b"exact".to_vec(),
            observed_fingerprint: request.expected_fingerprint.clone(),
        })
    }
}

#[test]
fn audited_local_read_has_a_narrow_exact_read_seam() {
    let request = AuditedReadRequest {
        logical_call_id: "logical-7".into(),
        canonical_path: "/safe/input".into(),
        expected_fingerprint: "b3:expected".into(),
    };
    let result = AuditedLocalRead
        .execute(&ExactReadFixture, &request)
        .unwrap();
    assert_eq!(result.bytes, b"exact");
    assert_eq!(result.observed_fingerprint, "b3:expected");
}

#[test]
fn remote_mcp_preserves_success_and_error_exactly() {
    #[derive(Debug, Eq, PartialEq)]
    struct UpstreamError {
        code: i64,
        data: Vec<u8>,
    }

    let remote = RemoteMcp {
        provider_identity: "stable".into(),
    };
    let success: Result<Vec<u8>, UpstreamError> = Ok(vec![0, 1, 2, 255]);
    assert_eq!(remote.preserve(success), Ok(vec![0, 1, 2, 255]));

    let error = Err::<Vec<u8>, _>(UpstreamError {
        code: -32_001,
        data: vec![9, 8, 7],
    });
    assert_eq!(
        remote.preserve(error),
        Err(UpstreamError {
            code: -32_001,
            data: vec![9, 8, 7],
        })
    );
}

#[test]
fn backend_kind_serialization_is_stable() {
    let kinds = [
        (BackendKind::AuditedLocalRead, "\"audited_local_read\""),
        (BackendKind::RootlessLinux, "\"rootless_linux\""),
        (BackendKind::GVisor, "\"g_visor\""),
        (BackendKind::Firecracker, "\"firecracker\""),
        (BackendKind::RemoteMcp, "\"remote_mcp\""),
    ];
    for (kind, expected) in kinds {
        assert_eq!(serde_json::to_string(&kind).unwrap(), expected);
    }
}

#[test]
fn audited_read_adapter_failure_remains_typed() {
    struct Failure;
    impl ExactReadAdapter for Failure {
        fn read_exact(
            &self,
            _request: &AuditedReadRequest,
        ) -> Result<AuditedReadResult, BackendError> {
            Err(BackendError::AuditedRead {
                message: "fingerprint mismatch".into(),
            })
        }
    }

    let request = AuditedReadRequest {
        logical_call_id: "logical-failure".into(),
        canonical_path: "/safe/input".into(),
        expected_fingerprint: "b3:expected".into(),
    };
    assert_eq!(
        AuditedLocalRead.execute(&Failure, &request),
        Err(BackendError::AuditedRead {
            message: "fingerprint mismatch".into(),
        })
    );
}
