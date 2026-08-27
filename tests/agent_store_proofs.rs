use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use again::agent_gateway::{
    AgentCallIdentityV1, CanonicalArguments, DigestReferenceV1, EffectClass,
    FreshnessRequirementV1, GatewayDecision, GatewayToolCallInputV1, GatewayToolCallV1,
    ModelIdentityV1, PermissionClass, PresentationMode, ProviderIdentityV1,
    RepositoryEnvironmentStateV1, RoutingCandidatesV1, StateDigestReferenceV1, ToolIdentityV1,
    WorkspaceIdentityV1, route,
};
use again::store::{
    GatewayCallAcquisition, GatewayCompletion, GatewayCoordinatorInputV1, GatewayDependencyV1,
    GatewayExecutionStart, GatewayFreshnessEvidenceV1, GatewayOperationDispositionV1,
    GatewayRouteProofObservationV1, GatewayRouteProofUnavailableV1, Store, StoredResult,
    ValidatedGatewayReadV1, gateway_policy_digest,
};
use rusqlite::Connection;
use tempfile::TempDir;

const POLICY: &str = "store-proof-v1";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn digest(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn digest_ref(value: &str) -> DigestReferenceV1 {
    DigestReferenceV1::new("blake3", digest(value)).unwrap()
}

fn make_call(
    effect: EffectClass,
    freshness: FreshnessRequirementV1,
    suffix: &str,
) -> GatewayToolCallV1 {
    GatewayToolCallV1::from_input(GatewayToolCallInputV1 {
        schema_version: 1,
        provider: ProviderIdentityV1 {
            id: "provider".to_owned(),
            version: "1".to_owned(),
        },
        model: ModelIdentityV1 {
            id: "model".to_owned(),
            version: "1".to_owned(),
        },
        tool: ToolIdentityV1 {
            id: "read".to_owned(),
            version: "1".to_owned(),
        },
        arguments: CanonicalArguments::from_json_str(&format!(r#"{{"suffix":"{suffix}"}}"#))
            .unwrap(),
        workspace: WorkspaceIdentityV1 {
            workspace_id: "workspace".to_owned(),
            cwd: ".".to_owned(),
        },
        call: AgentCallIdentityV1 {
            agent_id: "agent".to_owned(),
            session_id: "session".to_owned(),
            turn_id: "turn".to_owned(),
            call_id: format!("call-{suffix}"),
        },
        task: None,
        state: RepositoryEnvironmentStateV1::Known {
            reference: StateDigestReferenceV1 {
                schema_version: 1,
                repository: digest_ref("repository"),
                environment: digest_ref("environment"),
            },
        },
        permission_class: PermissionClass::Preapproved,
        effect_class: effect,
        freshness,
        presentation: PresentationMode::Exact,
    })
    .unwrap()
}

fn binding(call: &GatewayToolCallV1) -> ValidatedGatewayReadV1 {
    let state_digest = digest("state");
    ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
        request_digest: call.request_digest().as_str().to_owned(),
        state_digest: state_digest.clone(),
        policy_digest: gateway_policy_digest(POLICY),
        operation: GatewayOperationDispositionV1::ReplayEligibleRead,
        freshness: GatewayFreshnessEvidenceV1 {
            snapshot_digest: state_digest,
            observed_at_ms: now_ms().saturating_sub(10),
            valid_until_ms: now_ms().saturating_add(60_000),
        },
        dependencies: vec![GatewayDependencyV1 {
            key_digest: digest("dependency-key"),
            value_digest: digest("dependency-value"),
        }],
    })
    .unwrap()
}

fn leader(acquisition: GatewayCallAcquisition) -> String {
    match acquisition {
        GatewayCallAcquisition::Leader { lease_id, .. } => lease_id,
        other => panic!("expected leader, got {other:?}"),
    }
}

fn stored_result(store: &mut Store, binding: &ValidatedGatewayReadV1) -> StoredResult {
    store
        .insert_result(
            binding.request_digest(),
            b"stdout",
            b"stderr",
            0,
            5,
            POLICY,
            r#"{"proof":"store"}"#,
        )
        .unwrap()
}

fn complete(store: &mut Store, lease: &str, binding: &ValidatedGatewayReadV1) -> String {
    assert_eq!(
        store.start_gateway_execution(lease, "owner").unwrap(),
        GatewayExecutionStart::Started
    );
    let result = stored_result(store, binding);
    match store.complete_gateway_call(lease, &result.id).unwrap() {
        GatewayCompletion::Completed {
            gateway_result_id, ..
        } => gateway_result_id,
        other => panic!("expected completion, got {other:?}"),
    }
}

#[test]
fn exact_store_transaction_proof_is_the_only_exact_serve_input() {
    let temp = TempDir::new().unwrap();
    let mut store = Store::open(temp.path().join("state")).unwrap();
    let call = make_call(
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
        "exact",
    );
    let binding = binding(&call);
    let lease = leader(store.acquire_gateway_call(&binding, "owner").unwrap());
    let gateway_result_id = complete(&mut store, &lease, &binding);

    let proof = match store
        .observe_gateway_route_proof_v1(&binding, &call)
        .unwrap()
    {
        GatewayRouteProofObservationV1::Exact(proof) => proof,
        other => panic!("expected exact proof, got {other:?}"),
    };
    assert_eq!(proof.gateway_result_id(), gateway_result_id);
    assert_eq!(proof.lifecycle_generation(), 1);
    assert!(format!("{proof:?}").contains("<redacted>"));
    let candidates = RoutingCandidatesV1::default().with_store_exact_proof(proof);
    assert_eq!(route(&call, &candidates), GatewayDecision::ServeExact);
    assert_eq!(route(&call, &candidates), GatewayDecision::Execute);
}

#[test]
fn inflight_proof_binds_real_started_lease_generation() {
    let temp = TempDir::new().unwrap();
    let store = Store::open(temp.path().join("state")).unwrap();
    let call = make_call(
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
        "join",
    );
    let binding = binding(&call);
    let lease = leader(store.acquire_gateway_call(&binding, "owner").unwrap());
    assert_eq!(
        store.start_gateway_execution(&lease, "owner").unwrap(),
        GatewayExecutionStart::Started
    );
    let proof = match store
        .observe_gateway_route_proof_v1(&binding, &call)
        .unwrap()
    {
        GatewayRouteProofObservationV1::Inflight(proof) => proof,
        other => panic!("expected inflight proof, got {other:?}"),
    };
    assert_eq!(proof.lifecycle_generation(), 1);
    let candidates = RoutingCandidatesV1::default().with_store_inflight_proof(proof);
    assert_eq!(route(&call, &candidates), GatewayDecision::JoinInflight);
    assert_eq!(route(&call, &candidates), GatewayDecision::Execute);
}

#[test]
fn genuine_proof_refuses_wrong_request_effect_and_freshness() {
    let temp = TempDir::new().unwrap();
    let mut store = Store::open(temp.path().join("state")).unwrap();
    let call = make_call(
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
        "bound",
    );
    let binding = binding(&call);
    let lease = leader(store.acquire_gateway_call(&binding, "owner").unwrap());
    complete(&mut store, &lease, &binding);

    for mismatched in [
        make_call(
            EffectClass::SnapshotRead,
            FreshnessRequirementV1::Snapshot,
            "other",
        ),
        make_call(
            EffectClass::FreshnessBoundRead,
            FreshnessRequirementV1::Snapshot,
            "bound",
        ),
        make_call(
            EffectClass::SnapshotRead,
            FreshnessRequirementV1::RequireRevalidation,
            "bound",
        ),
    ] {
        let proof = match store
            .observe_gateway_route_proof_v1(&binding, &call)
            .unwrap()
        {
            GatewayRouteProofObservationV1::Exact(proof) => proof,
            other => panic!("expected exact proof, got {other:?}"),
        };
        assert_eq!(
            route(
                &mismatched,
                &RoutingCandidatesV1::default().with_store_exact_proof(proof),
            ),
            GatewayDecision::Execute
        );
    }
}

#[test]
fn stale_freshness_never_issues_a_router_proof() {
    let temp = TempDir::new().unwrap();
    let store = Store::open(temp.path().join("state")).unwrap();
    let call = make_call(
        EffectClass::FreshnessBoundRead,
        FreshnessRequirementV1::MaxAgeMillis(0),
        "stale",
    );
    let binding = binding(&call);
    let lease = leader(store.acquire_gateway_call(&binding, "owner").unwrap());
    assert_eq!(
        store.start_gateway_execution(&lease, "owner").unwrap(),
        GatewayExecutionStart::Started
    );
    thread::sleep(Duration::from_millis(2));
    assert!(matches!(
        store
            .observe_gateway_route_proof_v1(&binding, &call)
            .unwrap(),
        GatewayRouteProofObservationV1::Unavailable(GatewayRouteProofUnavailableV1::Freshness)
    ));
}

#[test]
fn lifecycle_generation_advances_after_expiry_and_old_record_is_not_selected() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let call = make_call(
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
        "generation",
    );
    let binding = binding(&call);
    let store = Store::open(&root).unwrap();
    let first = leader(store.acquire_gateway_call(&binding, "owner").unwrap());
    drop(store);

    Connection::open(root.join("again.sqlite"))
        .unwrap()
        .execute(
            "UPDATE inflight_leases SET expires_ms = 0 WHERE lease_id = ?1",
            [&first],
        )
        .unwrap();
    let store = Store::open(&root).unwrap();
    let second = leader(store.acquire_gateway_call(&binding, "owner").unwrap());
    assert_ne!(first, second);
    assert_eq!(
        store.start_gateway_execution(&second, "owner").unwrap(),
        GatewayExecutionStart::Started
    );
    let proof = match store
        .observe_gateway_route_proof_v1(&binding, &call)
        .unwrap()
    {
        GatewayRouteProofObservationV1::Inflight(proof) => proof,
        other => panic!("expected current inflight proof, got {other:?}"),
    };
    assert_eq!(proof.lifecycle_generation(), 2);
}

#[test]
fn call_binding_mismatch_is_typed_non_authority() {
    let temp = TempDir::new().unwrap();
    let store = Store::open(temp.path().join("state")).unwrap();
    let call = make_call(
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
        "first",
    );
    let other = make_call(
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
        "second",
    );
    let binding = binding(&call);
    assert!(matches!(
        store
            .observe_gateway_route_proof_v1(&binding, &other)
            .unwrap(),
        GatewayRouteProofObservationV1::Unavailable(
            GatewayRouteProofUnavailableV1::BindingMismatch
        )
    ));
}
