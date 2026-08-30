//! Private adapter identities shared by the sealed profile registry.
//!
//! These adapters intentionally expose no executor, storage handle, or public
//! constructor. A profile contract names the reviewed adapter versions, while
//! the existing runtime retains every concrete authority capability.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AdapterSetV1 {
    pub(super) canonicalization: &'static str,
    pub(super) dependency_effect_plan: &'static str,
    pub(super) executable_runtime_binding: &'static str,
    pub(super) coordination: &'static str,
    pub(super) cas: &'static str,
    pub(super) quarantine: &'static str,
    pub(super) accounting: &'static str,
}

pub(super) const QUALIFIED_READ_ADAPTERS_V1: AdapterSetV1 = AdapterSetV1 {
    canonicalization: "gateway-canonical-request-v1",
    dependency_effect_plan: "descriptor-read-plan-v1",
    executable_runtime_binding: "workspace-runtime-binding-v1",
    coordination: "sqlite-lease-coordinator-v1",
    cas: "immutable-complete-stream-cas-v1",
    quarantine: "exact-divergence-quarantine-v1",
    accounting: "gateway-route-accounting-v1",
};

pub(super) const CONTRACT_ONLY_ADAPTERS_V1: AdapterSetV1 = AdapterSetV1 {
    canonicalization: "contract-only-canonicalization-v1",
    dependency_effect_plan: "unimplemented-dependency-effect-plan-v1",
    executable_runtime_binding: "unimplemented-runtime-binding-v1",
    coordination: "disabled-coordination-v1",
    cas: "disabled-cas-v1",
    quarantine: "disabled-quarantine-v1",
    accounting: "passthrough-accounting-v1",
};

pub(super) fn adapter_contract_digest_v1(adapters: AdapterSetV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.agent-gateway.profile-adapters.v1\0");
    for value in [
        adapters.canonicalization,
        adapters.dependency_effect_plan,
        adapters.executable_runtime_binding,
        adapters.coordination,
        adapters.cas,
        adapters.quarantine,
        adapters.accounting,
    ] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    *hasher.finalize().as_bytes()
}
