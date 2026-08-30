//! Sealed, versioned profiles for automatic universal action classification.
//!
//! The registry has no public registration or execution API. Initially only
//! the existing descriptor-bound repository and Git reads are qualified.
//! Developer-command profiles are visible contract placeholders and always
//! route through ordinary uncached execution.

#[path = "profile_registry/adapters.rs"]
mod adapters;
#[path = "profile_registry/lifecycle.rs"]
mod lifecycle;

use super::protocol::{
    EffectClass, FreshnessRequirementV1, GatewayToolCallV1, RepositoryEnvironmentStateV1,
    ToolCapabilityClassV1, ToolDependencyBindingV1, ToolDependencyKindV1, ToolDependencySetV1,
    ToolPolicyDispositionV1, UniversalActionContextV1, UniversalToolPolicyV1,
};
use adapters::{
    AdapterSetV1, CONTRACT_ONLY_ADAPTERS_V1, QUALIFIED_READ_ADAPTERS_V1, adapter_contract_digest_v1,
};

pub use lifecycle::{
    ProfileLifecycleRefusalV1, ProfileLifecycleStageV1, ProfileLifecycleTransitionV1,
    ProfileLifecycleV1,
};

const REGISTRY_SCHEMA_VERSION_V1: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileFamilyV1 {
    RepositoryRead,
    GitRead,
    Pytest,
    Rust,
    TypeScript,
    Python,
    Go,
    Build,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileQualificationV1 {
    QualifiedExactRead,
    ContractOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileIdentityV1 {
    id: &'static str,
    version: &'static str,
}

impl ProfileIdentityV1 {
    pub const fn id(&self) -> &'static str {
        self.id
    }

    pub const fn version(&self) -> &'static str {
        self.version
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileContractV1 {
    identity: ProfileIdentityV1,
    family: ProfileFamilyV1,
    qualification: ProfileQualificationV1,
    capability: ToolCapabilityClassV1,
    adapters: AdapterSetV1,
}

impl ProfileContractV1 {
    pub const fn identity(&self) -> ProfileIdentityV1 {
        self.identity
    }

    pub const fn family(&self) -> ProfileFamilyV1 {
        self.family
    }

    pub const fn qualification(&self) -> ProfileQualificationV1 {
        self.qualification
    }

    pub const fn capability(&self) -> ToolCapabilityClassV1 {
        self.capability
    }

    pub fn adapter_contract_digest(&self) -> [u8; 32] {
        adapter_contract_digest_v1(self.adapters)
    }
}

const PROFILE_CONTRACTS_V1: [ProfileContractV1; 8] = [
    qualified_contract(
        "again.profile.repository-read",
        "1",
        ProfileFamilyV1::RepositoryRead,
    ),
    qualified_contract("again.profile.git-read", "1", ProfileFamilyV1::GitRead),
    placeholder_contract(
        "again.profile.pytest",
        "contract-1",
        ProfileFamilyV1::Pytest,
    ),
    placeholder_contract("again.profile.rust", "contract-1", ProfileFamilyV1::Rust),
    placeholder_contract(
        "again.profile.typescript",
        "contract-1",
        ProfileFamilyV1::TypeScript,
    ),
    placeholder_contract(
        "again.profile.python",
        "contract-1",
        ProfileFamilyV1::Python,
    ),
    placeholder_contract("again.profile.go", "contract-1", ProfileFamilyV1::Go),
    placeholder_contract("again.profile.build", "contract-1", ProfileFamilyV1::Build),
];

const fn qualified_contract(
    id: &'static str,
    version: &'static str,
    family: ProfileFamilyV1,
) -> ProfileContractV1 {
    ProfileContractV1 {
        identity: ProfileIdentityV1 { id, version },
        family,
        qualification: ProfileQualificationV1::QualifiedExactRead,
        capability: ToolCapabilityClassV1::ExactStateBoundRead,
        adapters: QUALIFIED_READ_ADAPTERS_V1,
    }
}

const fn placeholder_contract(
    id: &'static str,
    version: &'static str,
    family: ProfileFamilyV1,
) -> ProfileContractV1 {
    ProfileContractV1 {
        identity: ProfileIdentityV1 { id, version },
        family,
        qualification: ProfileQualificationV1::ContractOnly,
        capability: ToolCapabilityClassV1::DeterministicCommand,
        adapters: CONTRACT_ONLY_ADAPTERS_V1,
    }
}

/// Why classification did not select a reusable qualified profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileSelectionStatusV1 {
    Qualified,
    ContractOnly,
    Unprofiled,
    DangerousInvalidConfiguration,
}

#[derive(Debug)]
pub struct ClassifiedUniversalActionV1 {
    policy: UniversalToolPolicyV1,
    profile: Option<&'static ProfileContractV1>,
    status: ProfileSelectionStatusV1,
}

impl ClassifiedUniversalActionV1 {
    pub const fn policy(&self) -> &UniversalToolPolicyV1 {
        &self.policy
    }

    pub const fn capability(&self) -> ToolCapabilityClassV1 {
        self.policy.capability()
    }

    pub const fn profile(&self) -> Option<&'static ProfileContractV1> {
        self.profile
    }

    pub const fn status(&self) -> ProfileSelectionStatusV1 {
        self.status
    }

    pub const fn is_reuse_qualified(&self) -> bool {
        matches!(self.status, ProfileSelectionStatusV1::Qualified)
    }
}

/// Built-in registry. It is a zero-sized sealed value with no mutation or
/// registration surface, so configuration cannot turn arbitrary commands into
/// qualified profiles.
#[derive(Clone, Copy, Debug, Default)]
pub struct SealedProfileRegistryV1 {
    _sealed: (),
}

impl SealedProfileRegistryV1 {
    pub const fn builtin() -> Self {
        Self { _sealed: () }
    }

    pub const fn schema_version(&self) -> u16 {
        REGISTRY_SCHEMA_VERSION_V1
    }

    pub fn contracts(&self) -> &'static [ProfileContractV1] {
        &PROFILE_CONTRACTS_V1
    }

    /// Deterministically classify one action. The returned policy remains
    /// descriptive; only existing store-issued proofs can authorize a hit or
    /// in-flight join.
    pub fn classify(
        &self,
        call: &GatewayToolCallV1,
        context: &UniversalActionContextV1,
    ) -> ClassifiedUniversalActionV1 {
        if context.requires_uncached_passthrough() {
            return unprofiled_policy(ToolCapabilityClassV1::Interactive);
        }

        if let Some(profile) = qualified_read_profile(call.tool()) {
            if call.effect_class() != EffectClass::SnapshotRead
                || call.freshness() != FreshnessRequirementV1::Snapshot
            {
                return invalid_configuration_policy();
            }
            let RepositoryEnvironmentStateV1::Known { reference } = call.state() else {
                return invalid_configuration_policy();
            };
            let dependencies = ToolDependencySetV1::bound(vec![
                ToolDependencyBindingV1::new(
                    ToolDependencyKindV1::RepositoryTree,
                    "sealed-repository-state",
                    reference.repository.clone(),
                )
                .expect("validated gateway state has a bounded repository digest"),
                ToolDependencyBindingV1::new(
                    ToolDependencyKindV1::Environment,
                    "sealed-environment-state",
                    reference.environment.clone(),
                )
                .expect("validated gateway state has a bounded environment digest"),
            ])
            .expect("qualified read dependencies are distinct and complete");
            return ClassifiedUniversalActionV1 {
                policy: policy(
                    profile.identity.id,
                    profile.identity.version,
                    ToolCapabilityClassV1::ExactStateBoundRead,
                    dependencies,
                    ToolPolicyDispositionV1::Allow,
                ),
                profile: Some(profile),
                status: ProfileSelectionStatusV1::Qualified,
            };
        }

        if let Some(capability) = restrictive_named_class(call.tool()) {
            return unprofiled_policy(capability);
        }

        if matches!(call.effect_class(), EffectClass::Mutation) {
            return unprofiled_policy(ToolCapabilityClassV1::Mutation);
        }
        if matches!(call.effect_class(), EffectClass::FreshnessBoundRead) {
            return unprofiled_policy(ToolCapabilityClassV1::FreshnessBoundRead);
        }

        if let Some(command) = context.command()
            && let Some(profile) = command_contract(command.argv())
        {
            return ClassifiedUniversalActionV1 {
                policy: policy(
                    profile.identity.id,
                    profile.identity.version,
                    ToolCapabilityClassV1::DeterministicCommand,
                    ToolDependencySetV1::ExplicitlyNone,
                    ToolPolicyDispositionV1::Allow,
                ),
                profile: Some(profile),
                status: ProfileSelectionStatusV1::ContractOnly,
            };
        }

        unprofiled_policy(match call.effect_class() {
            EffectClass::FreshnessBoundRead => ToolCapabilityClassV1::FreshnessBoundRead,
            EffectClass::Mutation => ToolCapabilityClassV1::Mutation,
            EffectClass::SnapshotRead | EffectClass::DeterministicCompute => {
                ToolCapabilityClassV1::Unknown
            }
            EffectClass::ExternalSideEffect | EffectClass::Unknown => {
                ToolCapabilityClassV1::Unknown
            }
        })
    }
}

fn policy(
    id: &'static str,
    version: &'static str,
    capability: ToolCapabilityClassV1,
    dependencies: ToolDependencySetV1,
    disposition: ToolPolicyDispositionV1,
) -> UniversalToolPolicyV1 {
    UniversalToolPolicyV1::new(
        REGISTRY_SCHEMA_VERSION_V1,
        id,
        version,
        capability,
        dependencies,
        None,
        disposition,
    )
    .expect("the sealed built-in registry contains only valid policies")
}

fn unprofiled_policy(capability: ToolCapabilityClassV1) -> ClassifiedUniversalActionV1 {
    ClassifiedUniversalActionV1 {
        policy: policy(
            "again.profile.unprofiled",
            "1",
            capability,
            ToolDependencySetV1::ExplicitlyNone,
            ToolPolicyDispositionV1::Allow,
        ),
        profile: None,
        status: ProfileSelectionStatusV1::Unprofiled,
    }
}

fn invalid_configuration_policy() -> ClassifiedUniversalActionV1 {
    ClassifiedUniversalActionV1 {
        policy: policy(
            "again.profile.invalid-configuration",
            "1",
            ToolCapabilityClassV1::Unknown,
            ToolDependencySetV1::ExplicitlyNone,
            ToolPolicyDispositionV1::Deny,
        ),
        profile: None,
        status: ProfileSelectionStatusV1::DangerousInvalidConfiguration,
    }
}

fn qualified_read_profile(tool: &str) -> Option<&'static ProfileContractV1> {
    const REPOSITORY_READS: [&str; 8] = [
        "repo.read",
        "repo.search",
        "repo.list",
        "repo.tree",
        "repo.stat",
        "repo.glob",
        "repo.references",
        "repo.manifest",
    ];
    const GIT_READS: [&str; 5] = ["git.status", "git.diff", "git.log", "git.show", "git.blame"];
    if REPOSITORY_READS.contains(&tool) {
        Some(&PROFILE_CONTRACTS_V1[0])
    } else if GIT_READS.contains(&tool) {
        Some(&PROFILE_CONTRACTS_V1[1])
    } else {
        None
    }
}

fn restrictive_named_class(tool: &str) -> Option<ToolCapabilityClassV1> {
    const NON_REUSABLE: [&str; 4] = [
        "browser.screenshot",
        "browser.open",
        "web.fetch",
        "process.inspect",
    ];
    const CREDENTIALS: [&str; 4] = [
        "auth.login",
        "credential.read",
        "secret.read",
        "token.create",
    ];
    const COMMUNICATION: [&str; 5] = [
        "chat.send",
        "email.send",
        "issue.comment",
        "issue.create",
        "pr.create",
    ];
    const DEPLOYMENT: [&str; 3] = ["deploy.start", "release.publish", "service.restart"];
    const PAYMENT: [&str; 3] = ["billing.charge", "payment.create", "payment.refund"];
    if NON_REUSABLE.contains(&tool) {
        Some(ToolCapabilityClassV1::NonReusableRead)
    } else if CREDENTIALS.contains(&tool) {
        Some(ToolCapabilityClassV1::CredentialOperation)
    } else if COMMUNICATION.contains(&tool) {
        Some(ToolCapabilityClassV1::Communication)
    } else if DEPLOYMENT.contains(&tool) {
        Some(ToolCapabilityClassV1::Deployment)
    } else if PAYMENT.contains(&tool) {
        Some(ToolCapabilityClassV1::Payment)
    } else {
        None
    }
}

fn command_contract(argv: &[String]) -> Option<&'static ProfileContractV1> {
    let strings = argv.iter().map(String::as_str).collect::<Vec<_>>();
    if is_pytest_contract(&strings) {
        Some(&PROFILE_CONTRACTS_V1[2])
    } else if is_rust_contract(&strings) {
        Some(&PROFILE_CONTRACTS_V1[3])
    } else if is_typescript_contract(&strings) {
        Some(&PROFILE_CONTRACTS_V1[4])
    } else if is_python_contract(&strings) {
        Some(&PROFILE_CONTRACTS_V1[5])
    } else if is_go_contract(&strings) {
        Some(&PROFILE_CONTRACTS_V1[6])
    } else if is_build_contract(&strings) {
        Some(&PROFILE_CONTRACTS_V1[7])
    } else {
        None
    }
}

fn is_pytest_contract(argv: &[&str]) -> bool {
    argv.len() >= 5
        && argv[0].ends_with("/.venv/bin/python")
        && argv[1..4] == ["-I", "-m", "pytest"]
        && argv[4..].iter().all(|value| !value.is_empty())
        && !argv[4..]
            .iter()
            .any(|value| matches!(*value, "-" | "--collect-only" | "--fixtures"))
}

fn is_rust_contract(argv: &[&str]) -> bool {
    matches!(argv, ["cargo", "check", ..])
        || matches!(argv, ["cargo", "test", selector, ..] if !selector.is_empty())
        || matches!(argv, ["cargo", "clippy", ..])
        || matches!(argv, ["cargo", "fmt", "--all", "--", "--check"])
        || matches!(argv, ["cargo", "fmt", "--all", "--check"])
}

fn is_typescript_contract(argv: &[&str]) -> bool {
    matches!(argv, ["tsc", "--noEmit", ..])
        || matches!(argv, ["npx", "tsc", "--noEmit", ..])
        || matches!(argv, ["jest" | "vitest", "run", selector, ..] if !selector.is_empty())
        || matches!(argv, ["eslint", "--no-fix", ..])
}

fn is_python_contract(argv: &[&str]) -> bool {
    matches!(argv, ["ruff", "check", ..]) || matches!(argv, ["mypy", path, ..] if !path.is_empty())
}

fn is_go_contract(argv: &[&str]) -> bool {
    matches!(argv, ["go", "test" | "vet", package, ..] if !package.is_empty())
}

fn is_build_contract(argv: &[&str]) -> bool {
    matches!(argv, ["cargo", "build", ..])
        || matches!(argv, ["go", "build", package, ..] if !package.is_empty())
        || matches!(argv, ["npm" | "pnpm" | "yarn", "run", "build", ..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_closed_versioned_and_only_reads_are_qualified() {
        let registry = SealedProfileRegistryV1::builtin();
        assert_eq!(registry.schema_version(), 1);
        assert_eq!(registry.contracts().len(), 8);
        assert!(registry.contracts().iter().all(|profile| {
            !profile.identity().id().is_empty()
                && !profile.identity().version().is_empty()
                && profile.adapter_contract_digest() != [0; 32]
        }));
        assert_eq!(
            registry
                .contracts()
                .iter()
                .filter(
                    |profile| profile.qualification() == ProfileQualificationV1::QualifiedExactRead
                )
                .count(),
            2
        );
    }

    #[test]
    fn lifecycle_cannot_skip_candidate_shadow_promotion_or_fresh_validation() {
        let lifecycle = ProfileLifecycleV1::execute_only();
        assert_eq!(
            lifecycle
                .transition(ProfileLifecycleTransitionV1::FreshlyValidate)
                .unwrap_err(),
            ProfileLifecycleRefusalV1::InvalidTransition
        );

        let hit = ProfileLifecycleV1::execute_only()
            .transition(ProfileLifecycleTransitionV1::CompleteCandidate)
            .unwrap()
            .transition(ProfileLifecycleTransitionV1::CompleteIndependentShadow)
            .unwrap()
            .transition(ProfileLifecycleTransitionV1::PromoteExactAgreement)
            .unwrap()
            .transition(ProfileLifecycleTransitionV1::FreshlyValidate)
            .unwrap();
        assert_eq!(hit.stage(), ProfileLifecycleStageV1::FreshlyValidatedHit);
    }
}
