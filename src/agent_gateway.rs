//! Pure protocol, routing, and context-presentation primitives for agent tools.
//!
//! This module deliberately owns no executor and performs no I/O. Integrators
//! provide already-observed candidate metadata to [`router`] and remain
//! responsible for executing any decision that requires work.

#[path = "agent_gateway/context.rs"]
pub mod context;
#[path = "agent_gateway/protocol.rs"]
pub mod protocol;
#[path = "agent_gateway/router.rs"]
pub mod router;

pub use context::{
    AgentContextIdentityV1, DeliveryReceiptV1, GatewayResultIdentityV1, PresentationContextV1,
    PresentationDecisionV1, PresentationRefusalV1, decide_presentation_v1, select_presentation,
};
pub use protocol::{
    AgentCallIdentityV1, CanonicalArguments, CanonicalJsonError, DigestReferenceV1, EffectClass,
    FreshnessRequirementV1, GatewayAdapterToolCallV1, GatewayEffectClassV1, GatewayProtocolError,
    GatewayProtocolRefusalV1, GatewayToolCallInputV1, GatewayToolCallV1, ModelIdentityV1,
    PermissionClass, PresentationMode, ProviderIdentityV1, RepositoryEnvironmentStateV1,
    RequestDigestV1, StateDigestReferenceV1, TaskIdentityV1, ToolIdentityV1, WorkspaceIdentityV1,
};
pub use router::{
    CandidateEvidenceRefusalV1, CandidateFreshnessV1, GatewayCandidateKindV1,
    GatewayCandidateRequestV1, GatewayDecision, GatewayRouteDecisionV1, GatewayRouteRefusalV1,
    ReuseCandidateV1, RoutingCandidatesV1, route, route_gateway_candidate_v1,
};
