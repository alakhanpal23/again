//! Closed canonical identities for the Linux pytest profile.
//!
//! Every exported digest in this module is derived under one fixed domain
//! from one strict canonical top-level object.  Decoders reject unknown,
//! reordered, truncated, over-sized, or non-canonical input.  The types are
//! deliberately separate from reuse authority: callers must still validate
//! the accepted profile, current workspace enrollment, sealed manifest, and
//! complete EffectIR record before using an identity operationally.

use super::*;

const TYPE_PROFILE_COMMITMENT: u16 = 0x0030;
const TYPE_WORKSPACE_IDENTITY_COMMITMENT: u16 = 0x0031;
const TYPE_LEXICAL_SHAPE: u16 = 0x0032;
const TYPE_EXECUTABLE_CHAIN: u16 = 0x0033;
const TYPE_EXECUTABLE_HOP: u16 = 0x0034;
const TYPE_EFFECT_SHAPE: u16 = 0x0035;
const TYPE_OBSERVATION_LAYOUT: u16 = 0x0036;
const TYPE_AMBIENT_LAYOUT: u16 = 0x0037;
const TYPE_ORDERED_EFFECT_LAYOUT: u16 = 0x0038;
const TYPE_QUARANTINE_CLASS: u16 = 0x0039;

pub const PROFILE_COMMITMENT_V1_SCHEMA: &str = "again.linux-pytest.profile-commitment.v1";
pub const WORKSPACE_IDENTITY_V1_SCHEMA: &str = "again.workspace-identity.v1";
pub const LEXICAL_SHAPE_V1_SCHEMA: &str = "again.linux-pytest.lexical-shape.v1";
pub const EXECUTABLE_CHAIN_V1_SCHEMA: &str = "again.linux-pytest.executable-chain.v1";
pub const EFFECT_SHAPE_V1_SCHEMA: &str = "again.linux-pytest.effect-shape.v1";
pub const QUARANTINE_CLASS_V1_SCHEMA: &str = "again.linux-pytest.quarantine-class.v1";

const MAX_EXECUTABLE_CHAIN_HOPS: usize = 40;
const FIELD_HEADER_BYTES: usize = 11;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileCommitmentV1 {
    policy_digests: PolicyDigestsV1,
}

impl ProfileCommitmentV1 {
    /// Crate-only until each component is produced by the compiled-policy
    /// constructors.  Untrusted records must be compared with an allowlisted
    /// commitment, never accepted merely because this object decodes.
    pub(crate) fn from_compiled_policy_digests(
        policy_digests: PolicyDigestsV1,
    ) -> Result<Self, LinuxPytestContractError> {
        let value = Self { policy_digests };
        value.validate()?;
        Ok(value)
    }

    pub fn policy_digests(&self) -> &PolicyDigestsV1 {
        &self.policy_digests
    }

    pub fn digest(&self) -> Result<ProfileDigest, LinuxPytestContractError> {
        let canonical = self.canonical_bytes()?;
        Ok(ProfileDigest::derive_tagged(
            PROFILE_DOMAIN,
            &[(1, &canonical)],
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        encode_profile_commitment(self, true)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let object = RawObject::parse_top(bytes)?;
        object.expect(
            TYPE_PROFILE_COMMITMENT,
            &[
                (1, WireType::Utf8),
                (2, WireType::Utf8),
                (3, WireType::Utf8),
                (4, WireType::Utf8),
                (5, WireType::U64),
                (6, WireType::Bytes),
                (7, WireType::U16),
                (8, WireType::U64),
                (9, WireType::U16),
                (10, WireType::Object),
            ],
        )?;
        expect_utf8(object.payload(1)?, PROFILE_COMMITMENT_V1_SCHEMA)?;
        expect_utf8(object.payload(2)?, LINUX_PYTEST_PROFILE_ID)?;
        expect_utf8(object.payload(3)?, EFFECT_IR_V2_SCHEMA)?;
        expect_utf8(object.payload(4)?, LINUX_PYTEST_SHAPE_V1_SCHEMA)?;
        expect_u64(object.payload(5)?, EFFECT_IR_V2_REQUIRED_MASK)?;
        if object.payload(6)? != EFFECT_IR_V2_WIRE_MAGIC {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        expect_u16(object.payload(7)?, EFFECT_IR_V2_WIRE_VERSION)?;
        expect_u64(object.payload(8)?, EFFECT_IR_V2_MAX_CANONICAL_BYTES)?;
        expect_u16(object.payload(9)?, LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES)?;
        let value = Self {
            policy_digests: decode_policy_digests(object.payload(10)?)?,
        };
        value.validate()?;
        require_exact_reencoding(bytes, value.canonical_bytes()?)?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if policy_digest_values(&self.policy_digests)
            .iter()
            .any(|digest| digest.is_zero())
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkspaceIdentityCommitmentV1 {
    stable_id: [u8; 32],
}

impl fmt::Debug for WorkspaceIdentityCommitmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceIdentityCommitmentV1")
            .field("stable_id", &"<private-state-id>")
            .field("identity", &self.identity().ok())
            .finish()
    }
}

impl WorkspaceIdentityCommitmentV1 {
    pub fn enroll(stable_id: [u8; 32]) -> Result<Self, LinuxPytestContractError> {
        if stable_id == [0; 32] {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(Self { stable_id })
    }

    pub(crate) fn stable_id(&self) -> &[u8; 32] {
        &self.stable_id
    }

    pub fn identity(&self) -> Result<WorkspaceIdentity, LinuxPytestContractError> {
        let canonical = self.canonical_bytes()?;
        Ok(WorkspaceIdentity::derive_tagged(
            WORKSPACE_IDENTITY_DOMAIN,
            &[(1, &canonical)],
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        if self.stable_id == [0; 32] {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        let mut object = ObjectBuilder::new(TYPE_WORKSPACE_IDENTITY_COMMITMENT);
        object.utf8(1, WORKSPACE_IDENTITY_V1_SCHEMA)?;
        object.bytes(2, &self.stable_id)?;
        object.finish_top()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let object = RawObject::parse_top(bytes)?;
        object.expect(
            TYPE_WORKSPACE_IDENTITY_COMMITMENT,
            &[(1, WireType::Utf8), (2, WireType::Bytes)],
        )?;
        expect_utf8(object.payload(1)?, WORKSPACE_IDENTITY_V1_SCHEMA)?;
        let value = Self::enroll(exact_array::<32>(object.payload(2)?)?)?;
        require_exact_reencoding(bytes, value.canonical_bytes()?)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalShapeV1 {
    profile_digest: ProfileDigest,
    workspace_identity: WorkspaceIdentity,
    invocation: PytestInvocationIdentityV1,
    environment: EnvironmentBindingV1,
}

impl LexicalShapeV1 {
    pub(crate) fn new(
        profile: &ProfileCommitmentV1,
        workspace: &WorkspaceIdentityCommitmentV1,
        invocation: PytestInvocationIdentityV1,
        environment: EnvironmentBindingV1,
    ) -> Result<Self, LinuxPytestContractError> {
        let value = Self {
            profile_digest: profile.digest()?,
            workspace_identity: workspace.identity()?,
            invocation,
            environment,
        };
        value.validate()?;
        if value.environment.policy_digest != profile.policy_digests.environment {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(value)
    }

    pub fn profile_digest(&self) -> ProfileDigest {
        self.profile_digest
    }

    pub fn workspace_identity(&self) -> WorkspaceIdentity {
        self.workspace_identity
    }

    pub fn invocation(&self) -> &PytestInvocationIdentityV1 {
        &self.invocation
    }

    pub fn environment(&self) -> &EnvironmentBindingV1 {
        &self.environment
    }

    pub fn key(&self) -> Result<LexicalShapeKey, LinuxPytestContractError> {
        let canonical = self.canonical_bytes()?;
        Ok(LexicalShapeKey::derive_tagged(
            LEXICAL_SHAPE_DOMAIN,
            &[(1, &canonical)],
        ))
    }

    pub fn validate_against(
        &self,
        profile: &ProfileCommitmentV1,
        workspace: &WorkspaceIdentityCommitmentV1,
        current_environment_key: EnvironmentKeyId,
    ) -> Result<(), LinuxPytestContractError> {
        self.validate()?;
        if self.profile_digest != profile.digest()?
            || self.workspace_identity != workspace.identity()?
            || self.environment.policy_digest != profile.policy_digests.environment
            || self.environment.key_id != current_environment_key
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        let mut object = ObjectBuilder::new(TYPE_LEXICAL_SHAPE);
        object.utf8(1, LEXICAL_SHAPE_V1_SCHEMA)?;
        object.utf8(2, LINUX_PYTEST_PROFILE_ID)?;
        object.bytes(3, self.profile_digest.as_bytes())?;
        object.bytes(4, self.workspace_identity.as_bytes())?;
        object.object(5, encode_invocation(&self.invocation)?)?;
        object.object(6, encode_environment(&self.environment)?)?;
        object.finish_top()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let object = RawObject::parse_top(bytes)?;
        object.expect(
            TYPE_LEXICAL_SHAPE,
            &[
                (1, WireType::Utf8),
                (2, WireType::Utf8),
                (3, WireType::Bytes),
                (4, WireType::Bytes),
                (5, WireType::Object),
                (6, WireType::Object),
            ],
        )?;
        expect_utf8(object.payload(1)?, LEXICAL_SHAPE_V1_SCHEMA)?;
        expect_utf8(object.payload(2)?, LINUX_PYTEST_PROFILE_ID)?;
        let value = Self {
            profile_digest: ProfileDigest(exact_array::<32>(object.payload(3)?)?),
            workspace_identity: WorkspaceIdentity(exact_array::<32>(object.payload(4)?)?),
            invocation: decode_invocation(object.payload(5)?)?,
            environment: decode_environment(object.payload(6)?)?,
        };
        value.validate()?;
        require_exact_reencoding(bytes, value.canonical_bytes()?)?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if self.profile_digest.is_zero()
            || self.workspace_identity.is_zero()
            || !valid_pytest_invocation(&self.invocation)
            || self.environment.key_id.is_zero()
            || self.environment.digest.is_zero()
            || self.environment.names_digest.is_zero()
            || self.environment.policy_digest.is_zero()
            || self.environment.entry_count == 0
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutableHopResolutionV1 {
    Symlink {
        raw_target: Vec<u8>,
        next_path: SandboxPath,
    },
    TerminalRegular,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableHopV1 {
    path: SandboxPath,
    node_digest: NodeDigest,
    resolution: ExecutableHopResolutionV1,
}

impl ExecutableHopV1 {
    pub fn symlink(
        path: SandboxPath,
        node_digest: NodeDigest,
        raw_target: Vec<u8>,
        next_path: SandboxPath,
    ) -> Result<Self, LinuxPytestContractError> {
        let value = Self {
            path,
            node_digest,
            resolution: ExecutableHopResolutionV1::Symlink {
                raw_target,
                next_path,
            },
        };
        value.validate()?;
        Ok(value)
    }

    pub fn terminal_regular(
        path: SandboxPath,
        node_digest: NodeDigest,
    ) -> Result<Self, LinuxPytestContractError> {
        let value = Self {
            path,
            node_digest,
            resolution: ExecutableHopResolutionV1::TerminalRegular,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn path(&self) -> &SandboxPath {
        &self.path
    }

    pub fn node_digest(&self) -> NodeDigest {
        self.node_digest
    }

    pub fn resolution(&self) -> &ExecutableHopResolutionV1 {
        &self.resolution
    }

    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if self.node_digest.is_zero() || !valid_sandbox_path_bytes(self.path.as_bytes()) {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        if let ExecutableHopResolutionV1::Symlink {
            raw_target,
            next_path,
        } = &self.resolution
        {
            if raw_target.is_empty()
                || raw_target.contains(&0)
                || !valid_sandbox_path_bytes(next_path.as_bytes())
                || resolved_symlink_target(self.path.as_bytes(), raw_target).as_deref()
                    != Some(next_path.as_bytes())
            {
                return Err(LinuxPytestContractError::MalformedLookupIdentity);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableChainV1 {
    requested_path: SandboxPath,
    hops: Vec<ExecutableHopV1>,
}

impl ExecutableChainV1 {
    pub fn new(
        requested_path: SandboxPath,
        hops: Vec<ExecutableHopV1>,
    ) -> Result<Self, LinuxPytestContractError> {
        let value = Self {
            requested_path,
            hops,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn requested_path(&self) -> &SandboxPath {
        &self.requested_path
    }

    pub fn hops(&self) -> &[ExecutableHopV1] {
        &self.hops
    }

    pub fn digest(&self) -> Result<ExecutableChainDigest, LinuxPytestContractError> {
        let canonical = self.canonical_bytes()?;
        Ok(ExecutableChainDigest::derive_tagged(
            EXECUTABLE_CHAIN_DOMAIN,
            &[(1, &canonical)],
        ))
    }

    pub fn validate_requested_by(
        &self,
        invocation: &PytestInvocationIdentityV1,
    ) -> Result<(), LinuxPytestContractError> {
        if !valid_pytest_invocation(invocation)
            || invocation.cwd != b"."
            || invocation.argv.first().map(Vec::as_slice) != Some(b".venv/bin/python")
            || self.requested_path.as_bytes() != b"/workspace/.venv/bin/python"
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(())
    }

    pub fn validate_against_manifest(
        &self,
        manifest: &SnapshotManifestV1,
    ) -> Result<(), LinuxPytestContractError> {
        self.validate()?;
        manifest.validate()?;
        for hop in &self.hops {
            let entry = manifest_entry_for_sandbox_path(manifest, hop.path.as_bytes())
                .ok_or(LinuxPytestContractError::MalformedLookupIdentity)?;
            if entry.node_digest != hop.node_digest {
                return Err(LinuxPytestContractError::MalformedLookupIdentity);
            }
            match (&hop.resolution, &entry.payload) {
                (
                    ExecutableHopResolutionV1::Symlink { raw_target, .. },
                    ManifestPayloadV1::Symlink { target },
                ) if raw_target == target => {}
                (ExecutableHopResolutionV1::TerminalRegular, ManifestPayloadV1::Regular { .. }) => {
                }
                _ => return Err(LinuxPytestContractError::MalformedLookupIdentity),
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        let mut object = ObjectBuilder::new(TYPE_EXECUTABLE_CHAIN);
        object.utf8(1, EXECUTABLE_CHAIN_V1_SCHEMA)?;
        object.bytes(2, self.requested_path.as_bytes())?;
        object.list(
            3,
            self.hops
                .iter()
                .map(encode_executable_hop)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        object.finish_top()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let object = RawObject::parse_top(bytes)?;
        object.expect(
            TYPE_EXECUTABLE_CHAIN,
            &[
                (1, WireType::Utf8),
                (2, WireType::Bytes),
                (3, WireType::List),
            ],
        )?;
        expect_utf8(object.payload(1)?, EXECUTABLE_CHAIN_V1_SCHEMA)?;
        let requested_path = SandboxPath::new(object.payload(2)?.to_vec().into_boxed_slice())?;
        let hops = decode_list(object.payload(3)?)?
            .into_iter()
            .map(decode_executable_hop)
            .collect::<Result<Vec<_>, _>>()?;
        let value = Self::new(requested_path, hops)?;
        require_exact_reencoding(bytes, value.canonical_bytes()?)?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if !valid_sandbox_path_bytes(self.requested_path.as_bytes())
            || self.hops.is_empty()
            || self.hops.len() > MAX_EXECUTABLE_CHAIN_HOPS
            || self.hops[0].path != self.requested_path
            || !matches!(
                self.hops.last().map(|hop| &hop.resolution),
                Some(ExecutableHopResolutionV1::TerminalRegular)
            )
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        let mut seen = BTreeSet::new();
        for (index, hop) in self.hops.iter().enumerate() {
            hop.validate()?;
            if !seen.insert(hop.path.as_bytes()) {
                return Err(LinuxPytestContractError::MalformedLookupIdentity);
            }
            match &hop.resolution {
                ExecutableHopResolutionV1::Symlink { next_path, .. } => {
                    if self.hops.get(index + 1).map(|next| &next.path) != Some(next_path) {
                        return Err(LinuxPytestContractError::MalformedLookupIdentity);
                    }
                }
                ExecutableHopResolutionV1::TerminalRegular if index + 1 == self.hops.len() => {}
                ExecutableHopResolutionV1::TerminalRegular => {
                    return Err(LinuxPytestContractError::MalformedLookupIdentity);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamStateClassV1 {
    Complete,
    Exceeded,
    Incomplete(ExecuteOnlyCode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitClassV1 {
    Success,
    Exited(u8),
    Signaled { signal: u8, core_dumped: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationLayoutV1 {
    sequence: u64,
    logical_task_id: LogicalTaskId,
    kind: ObservationKindV2,
    subject: SandboxPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbientLayoutV1 {
    sequence: u64,
    logical_task_id: LogicalTaskId,
    kind: AmbientKindV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedEffectLayoutV1 {
    sequence: u64,
    logical_task_id: LogicalTaskId,
    kind: EffectKindV2,
    subject: SandboxPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectShapeV1 {
    profile_digest: ProfileDigest,
    observations: Vec<ObservationLayoutV1>,
    ambient_events: Vec<AmbientLayoutV1>,
    ordered_effects: Vec<OrderedEffectLayoutV1>,
    stdout: StreamStateClassV1,
    stderr: StreamStateClassV1,
    wait: WaitClassV1,
    final_workspace_changed: bool,
}

impl EffectShapeV1 {
    pub fn from_record(record: &EffectRecordV2) -> Result<Self, LinuxPytestContractError> {
        record.validate()?;
        let value = Self {
            profile_digest: record.profile_digest,
            observations: record
                .observations
                .iter()
                .map(|event| ObservationLayoutV1 {
                    sequence: event.sequence,
                    logical_task_id: event.logical_task_id,
                    kind: event.kind,
                    subject: event.sandbox_subject.clone(),
                })
                .collect(),
            ambient_events: record
                .ambient_events
                .iter()
                .map(|event| AmbientLayoutV1 {
                    sequence: event.sequence,
                    logical_task_id: event.logical_task_id,
                    kind: event.kind,
                })
                .collect(),
            ordered_effects: record
                .ordered_effects
                .iter()
                .map(|event| OrderedEffectLayoutV1 {
                    sequence: event.sequence,
                    logical_task_id: event.logical_task_id,
                    kind: event.kind,
                    subject: event.sandbox_subject.clone(),
                })
                .collect(),
            stdout: stream_state_class(&record.result.stdout),
            stderr: stream_state_class(&record.result.stderr),
            wait: wait_class(record.result.raw_linux_wait_status)?,
            final_workspace_changed: record.final_workspace_root
                != record.sealed_snapshot.workspace_root,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn digest(&self) -> Result<EffectShapeDigest, LinuxPytestContractError> {
        let canonical = self.canonical_bytes()?;
        Ok(EffectShapeDigest::derive_tagged(
            EFFECT_SHAPE_DOMAIN,
            &[(1, &canonical)],
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        encode_effect_shape(self, true)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let object = RawObject::parse_top(bytes)?;
        object.expect(
            TYPE_EFFECT_SHAPE,
            &[
                (1, WireType::Utf8),
                (2, WireType::Bytes),
                (3, WireType::List),
                (4, WireType::List),
                (5, WireType::List),
                (6, WireType::Enum),
                (7, WireType::Enum),
                (8, WireType::Enum),
                (9, WireType::Bool),
            ],
        )?;
        expect_utf8(object.payload(1)?, EFFECT_SHAPE_V1_SCHEMA)?;
        let value = Self {
            profile_digest: ProfileDigest(exact_array::<32>(object.payload(2)?)?),
            observations: decode_list(object.payload(3)?)?
                .into_iter()
                .map(decode_observation_layout)
                .collect::<Result<Vec<_>, _>>()?,
            ambient_events: decode_list(object.payload(4)?)?
                .into_iter()
                .map(decode_ambient_layout)
                .collect::<Result<Vec<_>, _>>()?,
            ordered_effects: decode_list(object.payload(5)?)?
                .into_iter()
                .map(decode_ordered_effect_layout)
                .collect::<Result<Vec<_>, _>>()?,
            stdout: decode_stream_state(object.payload(6)?)?,
            stderr: decode_stream_state(object.payload(7)?)?,
            wait: decode_wait_class(object.payload(8)?)?,
            final_workspace_changed: decode_bool(object.payload(9)?)?,
        };
        value.validate()?;
        require_exact_reencoding(bytes, value.canonical_bytes()?)?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if self.profile_digest.is_zero()
            || self.observations.len() as u64 > EFFECT_IR_V2_MAX_COLLECTION_ITEMS
            || self.ambient_events.len() as u64 > EFFECT_IR_V2_MAX_COLLECTION_ITEMS
            || self.ordered_effects.len() as u64 > EFFECT_IR_V2_MAX_COLLECTION_ITEMS
        {
            return Err(LinuxPytestContractError::MalformedRecord);
        }
        let mut sequences = BTreeSet::new();
        let observations_valid = self.observations.iter().all(|event| {
            event.sequence != 0
                && event.logical_task_id.0 != 0
                && valid_sandbox_path_bytes(event.subject.as_bytes())
                && sequences.insert(event.sequence)
        });
        let ambient_valid = self.ambient_events.iter().all(|event| {
            event.sequence != 0 && event.logical_task_id.0 != 0 && sequences.insert(event.sequence)
        });
        let effects_valid = self.ordered_effects.iter().all(|event| {
            event.sequence != 0
                && event.logical_task_id.0 != 0
                && valid_sandbox_path_bytes(event.subject.as_bytes())
                && sequences.insert(event.sequence)
        });
        if !observations_valid
            || !ambient_valid
            || !effects_valid
            || !strictly_increasing(self.observations.iter().map(|event| event.sequence))
            || !strictly_increasing(self.ambient_events.iter().map(|event| event.sequence))
            || !strictly_increasing(self.ordered_effects.iter().map(|event| event.sequence))
        {
            return Err(LinuxPytestContractError::MalformedRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineClassV1 {
    profile_digest: ProfileDigest,
    workspace_identity: WorkspaceIdentity,
    shape_key: ShapeKey,
    request_key: RequestKey,
}

impl QuarantineClassV1 {
    pub fn from_record(record: &EffectRecordV2) -> Result<Self, LinuxPytestContractError> {
        record.validate()?;
        let derived_shape_key = record.shape.key()?;
        let derived_request_key = record.shape.request_key(&record.observation_closure)?;
        if derived_shape_key != record.shape_key || derived_request_key != record.request_key {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Self::from_checked_parts(
            record.profile_digest,
            record.workspace_identity,
            derived_shape_key,
            derived_request_key,
        )
    }

    fn from_checked_parts(
        profile_digest: ProfileDigest,
        workspace_identity: WorkspaceIdentity,
        shape_key: ShapeKey,
        request_key: RequestKey,
    ) -> Result<Self, LinuxPytestContractError> {
        if profile_digest.is_zero()
            || workspace_identity.is_zero()
            || shape_key.is_zero()
            || request_key.is_zero()
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(Self {
            profile_digest,
            workspace_identity,
            shape_key,
            request_key,
        })
    }

    pub fn key(&self) -> Result<ClassKey, LinuxPytestContractError> {
        let canonical = self.canonical_bytes()?;
        Ok(ClassKey::derive_tagged(
            QUARANTINE_CLASS_DOMAIN,
            &[(1, &canonical)],
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        Self::from_checked_parts(
            self.profile_digest,
            self.workspace_identity,
            self.shape_key,
            self.request_key,
        )?;
        let mut object = ObjectBuilder::new(TYPE_QUARANTINE_CLASS);
        object.utf8(1, QUARANTINE_CLASS_V1_SCHEMA)?;
        object.bytes(2, self.profile_digest.as_bytes())?;
        object.bytes(3, self.workspace_identity.as_bytes())?;
        object.bytes(4, self.shape_key.as_bytes())?;
        object.bytes(5, self.request_key.as_bytes())?;
        object.finish_top()
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let object = RawObject::parse_top(bytes)?;
        object.expect(
            TYPE_QUARANTINE_CLASS,
            &[
                (1, WireType::Utf8),
                (2, WireType::Bytes),
                (3, WireType::Bytes),
                (4, WireType::Bytes),
                (5, WireType::Bytes),
            ],
        )?;
        expect_utf8(object.payload(1)?, QUARANTINE_CLASS_V1_SCHEMA)?;
        let value = Self::from_checked_parts(
            ProfileDigest(exact_array::<32>(object.payload(2)?)?),
            WorkspaceIdentity(exact_array::<32>(object.payload(3)?)?),
            ShapeKey(exact_array::<32>(object.payload(4)?)?),
            RequestKey(exact_array::<32>(object.payload(5)?)?),
        )?;
        require_exact_reencoding(bytes, value.canonical_bytes()?)?;
        Ok(value)
    }
}

fn encode_profile_commitment(
    value: &ProfileCommitmentV1,
    top: bool,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_PROFILE_COMMITMENT);
    object.utf8(1, PROFILE_COMMITMENT_V1_SCHEMA)?;
    object.utf8(2, LINUX_PYTEST_PROFILE_ID)?;
    object.utf8(3, EFFECT_IR_V2_SCHEMA)?;
    object.utf8(4, LINUX_PYTEST_SHAPE_V1_SCHEMA)?;
    object.u64(5, EFFECT_IR_V2_REQUIRED_MASK)?;
    object.bytes(6, EFFECT_IR_V2_WIRE_MAGIC)?;
    object.u16(7, EFFECT_IR_V2_WIRE_VERSION)?;
    object.u64(8, EFFECT_IR_V2_MAX_CANONICAL_BYTES)?;
    object.u16(9, LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES)?;
    object.object(10, encode_policy_digests(&value.policy_digests)?)?;
    if top {
        object.finish_top()
    } else {
        object.finish_nested()
    }
}

fn encode_policy_digests(value: &PolicyDigestsV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(0x0008);
    for (tag, digest) in policy_digest_values(value).iter().enumerate() {
        object.bytes(
            u16::try_from(tag + 1).map_err(|_| LinuxPytestContractError::CanonicalEncoding)?,
            digest.as_bytes(),
        )?;
    }
    object.finish_nested()
}

fn decode_policy_digests(bytes: &[u8]) -> Result<PolicyDigestsV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        0x0008,
        &[
            (1, WireType::Bytes),
            (2, WireType::Bytes),
            (3, WireType::Bytes),
            (4, WireType::Bytes),
            (5, WireType::Bytes),
            (6, WireType::Bytes),
            (7, WireType::Bytes),
            (8, WireType::Bytes),
            (9, WireType::Bytes),
            (10, WireType::Bytes),
        ],
    )?;
    Ok(PolicyDigestsV1 {
        seccomp: PolicyDigest(exact_array::<32>(object.payload(1)?)?),
        landlock: PolicyDigest(exact_array::<32>(object.payload(2)?)?),
        namespace: PolicyDigest(exact_array::<32>(object.payload(3)?)?),
        tracer_runtime: PolicyDigest(exact_array::<32>(object.payload(4)?)?),
        ambient_broker: PolicyDigest(exact_array::<32>(object.payload(5)?)?),
        limits: PolicyDigest(exact_array::<32>(object.payload(6)?)?),
        environment: PolicyDigest(exact_array::<32>(object.payload(7)?)?),
        selector_grammar: PolicyDigest(exact_array::<32>(object.payload(8)?)?),
        runtime_closure: PolicyDigest(exact_array::<32>(object.payload(9)?)?),
        codec: PolicyDigest(exact_array::<32>(object.payload(10)?)?),
    })
}

fn policy_digest_values(value: &PolicyDigestsV1) -> [PolicyDigest; 10] {
    [
        value.seccomp,
        value.landlock,
        value.namespace,
        value.tracer_runtime,
        value.ambient_broker,
        value.limits,
        value.environment,
        value.selector_grammar,
        value.runtime_closure,
        value.codec,
    ]
}

fn encode_invocation(
    value: &PytestInvocationIdentityV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    if !valid_pytest_invocation(value) {
        return Err(LinuxPytestContractError::MalformedLookupIdentity);
    }
    let mut object = ObjectBuilder::new(0x0002);
    object.list(1, value.argv.clone())?;
    object.bytes(2, &value.cwd)?;
    object.list(
        3,
        value
            .selectors
            .iter()
            .map(encode_selector)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.enumeration(4, value.stdin_profile as u16, Vec::new())?;
    object.finish_nested()
}

fn decode_invocation(bytes: &[u8]) -> Result<PytestInvocationIdentityV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        0x0002,
        &[
            (1, WireType::List),
            (2, WireType::Bytes),
            (3, WireType::List),
            (4, WireType::Enum),
        ],
    )?;
    let stdin = RawEnum::parse(object.payload(4)?)?;
    stdin.expect_no_fields()?;
    let stdin_profile = match stdin.variant {
        1 => StdinProfileV1::ClosedEof,
        2 => StdinProfileV1::EmptyNonTtyEof,
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    let invocation = PytestInvocationIdentityV1 {
        argv: decode_list(object.payload(1)?)?
            .into_iter()
            .map(Vec::from)
            .collect(),
        cwd: object.payload(2)?.to_vec(),
        selectors: decode_list(object.payload(3)?)?
            .into_iter()
            .map(decode_selector)
            .collect::<Result<Vec<_>, _>>()?,
        stdin_profile,
    };
    if !valid_pytest_invocation(&invocation) || encode_invocation(&invocation)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(invocation)
}

fn encode_selector(value: &PytestSelectorV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    if PytestSelectorV1::parse(value.raw()).as_ref() != Ok(value) {
        return Err(LinuxPytestContractError::MalformedLookupIdentity);
    }
    let mut object = ObjectBuilder::new(0x0003);
    object.bytes(1, value.raw())?;
    object.bytes(2, value.path())?;
    object.list(3, value.nodes().iter().cloned())?;
    object.finish_nested()
}

fn decode_selector(bytes: &[u8]) -> Result<PytestSelectorV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        0x0003,
        &[
            (1, WireType::Bytes),
            (2, WireType::Bytes),
            (3, WireType::List),
        ],
    )?;
    let value = PytestSelectorV1::parse(object.payload(1)?)
        .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
    let nodes = decode_list(object.payload(3)?)?
        .into_iter()
        .map(Vec::from)
        .collect::<Vec<_>>();
    if value.path() != object.payload(2)?
        || value.nodes() != nodes
        || encode_selector(&value)? != bytes
    {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_environment(value: &EnvironmentBindingV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(0x0004);
    object.bytes(1, value.key_id.as_bytes())?;
    object.bytes(2, value.digest.as_bytes())?;
    object.bytes(3, value.names_digest.as_bytes())?;
    object.u32(4, value.entry_count)?;
    object.bytes(5, value.policy_digest.as_bytes())?;
    object.finish_nested()
}

fn decode_environment(bytes: &[u8]) -> Result<EnvironmentBindingV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        0x0004,
        &[
            (1, WireType::Bytes),
            (2, WireType::Bytes),
            (3, WireType::Bytes),
            (4, WireType::U32),
            (5, WireType::Bytes),
        ],
    )?;
    let value = EnvironmentBindingV1 {
        key_id: EnvironmentKeyId(exact_array::<32>(object.payload(1)?)?),
        digest: EnvironmentDigest(exact_array::<32>(object.payload(2)?)?),
        names_digest: EnvironmentNamesDigest(exact_array::<32>(object.payload(3)?)?),
        entry_count: decode_u32(object.payload(4)?)?,
        policy_digest: PolicyDigest(exact_array::<32>(object.payload(5)?)?),
    };
    if encode_environment(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_executable_hop(value: &ExecutableHopV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    value.validate()?;
    let mut object = ObjectBuilder::new(TYPE_EXECUTABLE_HOP);
    object.bytes(1, value.path.as_bytes())?;
    object.bytes(2, value.node_digest.as_bytes())?;
    match &value.resolution {
        ExecutableHopResolutionV1::Symlink {
            raw_target,
            next_path,
        } => object.enumeration(
            3,
            1,
            vec![
                enum_field(1, WireType::Bytes, raw_target.clone()),
                enum_field(2, WireType::Bytes, next_path.as_bytes().to_vec()),
            ],
        )?,
        ExecutableHopResolutionV1::TerminalRegular => object.enumeration(3, 2, Vec::new())?,
    }
    object.finish_nested()
}

fn decode_executable_hop(bytes: &[u8]) -> Result<ExecutableHopV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_EXECUTABLE_HOP,
        &[
            (1, WireType::Bytes),
            (2, WireType::Bytes),
            (3, WireType::Enum),
        ],
    )?;
    let path = SandboxPath::new(object.payload(1)?.to_vec().into_boxed_slice())?;
    let node_digest = NodeDigest(exact_array::<32>(object.payload(2)?)?);
    let resolution = RawEnum::parse(object.payload(3)?)?;
    let value = match resolution.variant {
        1 => {
            resolution.expect(&[(1, WireType::Bytes), (2, WireType::Bytes)])?;
            ExecutableHopV1::symlink(
                path,
                node_digest,
                resolution.payload(1)?.to_vec(),
                SandboxPath::new(resolution.payload(2)?.to_vec().into_boxed_slice())?,
            )?
        }
        2 => {
            resolution.expect_no_fields()?;
            ExecutableHopV1::terminal_regular(path, node_digest)?
        }
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    if encode_executable_hop(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_effect_shape(
    value: &EffectShapeV1,
    top: bool,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_EFFECT_SHAPE);
    object.utf8(1, EFFECT_SHAPE_V1_SCHEMA)?;
    object.bytes(2, value.profile_digest.as_bytes())?;
    object.list(
        3,
        value
            .observations
            .iter()
            .map(encode_observation_layout)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.list(
        4,
        value
            .ambient_events
            .iter()
            .map(encode_ambient_layout)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.list(
        5,
        value
            .ordered_effects
            .iter()
            .map(encode_ordered_effect_layout)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    encode_stream_state(&mut object, 6, value.stdout)?;
    encode_stream_state(&mut object, 7, value.stderr)?;
    encode_wait_class(&mut object, 8, value.wait)?;
    object.boolean(9, value.final_workspace_changed)?;
    if top {
        object.finish_top()
    } else {
        object.finish_nested()
    }
}

fn encode_observation_layout(
    value: &ObservationLayoutV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_OBSERVATION_LAYOUT);
    object.u64(1, value.sequence)?;
    object.u32(2, value.logical_task_id.0)?;
    object.enumeration(3, value.kind as u16, Vec::new())?;
    object.bytes(4, value.subject.as_bytes())?;
    object.finish_nested()
}

fn decode_observation_layout(
    bytes: &[u8],
) -> Result<ObservationLayoutV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_OBSERVATION_LAYOUT,
        &[
            (1, WireType::U64),
            (2, WireType::U32),
            (3, WireType::Enum),
            (4, WireType::Bytes),
        ],
    )?;
    let kind = RawEnum::parse(object.payload(3)?)?;
    kind.expect_no_fields()?;
    let value = ObservationLayoutV1 {
        sequence: decode_u64(object.payload(1)?)?,
        logical_task_id: LogicalTaskId(decode_u32(object.payload(2)?)?),
        kind: decode_observation_kind(kind.variant)?,
        subject: SandboxPath::new(object.payload(4)?.to_vec().into_boxed_slice())?,
    };
    if encode_observation_layout(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_ambient_layout(value: &AmbientLayoutV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_AMBIENT_LAYOUT);
    object.u64(1, value.sequence)?;
    object.u32(2, value.logical_task_id.0)?;
    object.enumeration(3, value.kind as u16, Vec::new())?;
    object.finish_nested()
}

fn decode_ambient_layout(bytes: &[u8]) -> Result<AmbientLayoutV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_AMBIENT_LAYOUT,
        &[(1, WireType::U64), (2, WireType::U32), (3, WireType::Enum)],
    )?;
    let kind = RawEnum::parse(object.payload(3)?)?;
    kind.expect_no_fields()?;
    let value = AmbientLayoutV1 {
        sequence: decode_u64(object.payload(1)?)?,
        logical_task_id: LogicalTaskId(decode_u32(object.payload(2)?)?),
        kind: decode_ambient_kind(kind.variant)?,
    };
    if encode_ambient_layout(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_ordered_effect_layout(
    value: &OrderedEffectLayoutV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_ORDERED_EFFECT_LAYOUT);
    object.u64(1, value.sequence)?;
    object.u32(2, value.logical_task_id.0)?;
    object.enumeration(3, value.kind as u16, Vec::new())?;
    object.bytes(4, value.subject.as_bytes())?;
    object.finish_nested()
}

fn decode_ordered_effect_layout(
    bytes: &[u8],
) -> Result<OrderedEffectLayoutV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_ORDERED_EFFECT_LAYOUT,
        &[
            (1, WireType::U64),
            (2, WireType::U32),
            (3, WireType::Enum),
            (4, WireType::Bytes),
        ],
    )?;
    let kind = RawEnum::parse(object.payload(3)?)?;
    kind.expect_no_fields()?;
    let value = OrderedEffectLayoutV1 {
        sequence: decode_u64(object.payload(1)?)?,
        logical_task_id: LogicalTaskId(decode_u32(object.payload(2)?)?),
        kind: decode_effect_kind(kind.variant)?,
        subject: SandboxPath::new(object.payload(4)?.to_vec().into_boxed_slice())?,
    };
    if encode_ordered_effect_layout(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn stream_state_class(value: &StreamCaptureV2) -> StreamStateClassV1 {
    match value {
        StreamCaptureV2::Complete { .. } => StreamStateClassV1::Complete,
        StreamCaptureV2::Exceeded { .. } => StreamStateClassV1::Exceeded,
        StreamCaptureV2::Incomplete { reason, .. } => StreamStateClassV1::Incomplete(*reason),
    }
}

fn encode_stream_state(
    object: &mut ObjectBuilder,
    tag: u16,
    value: StreamStateClassV1,
) -> Result<(), LinuxPytestContractError> {
    match value {
        StreamStateClassV1::Complete => object.enumeration(tag, 1, Vec::new()),
        StreamStateClassV1::Exceeded => object.enumeration(tag, 2, Vec::new()),
        StreamStateClassV1::Incomplete(reason) => object.enumeration(
            tag,
            3,
            vec![enum_field(
                1,
                WireType::U16,
                (reason as u16).to_be_bytes().to_vec(),
            )],
        ),
    }
}

fn decode_stream_state(bytes: &[u8]) -> Result<StreamStateClassV1, LinuxPytestContractError> {
    let value = RawEnum::parse(bytes)?;
    match value.variant {
        1 => {
            value.expect_no_fields()?;
            Ok(StreamStateClassV1::Complete)
        }
        2 => {
            value.expect_no_fields()?;
            Ok(StreamStateClassV1::Exceeded)
        }
        3 => {
            value.expect(&[(1, WireType::U16)])?;
            Ok(StreamStateClassV1::Incomplete(
                ExecuteOnlyCode::from_u16(decode_u16(value.payload(1)?)?)
                    .ok_or(LinuxPytestContractError::CanonicalDecoding)?,
            ))
        }
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn wait_class(value: RawLinuxWaitStatusV1) -> Result<WaitClassV1, LinuxPytestContractError> {
    match value
        .termination()
        .ok_or(LinuxPytestContractError::MalformedRecord)?
    {
        super::LinuxWaitTerminationV1::Exited { code: 0 } => Ok(WaitClassV1::Success),
        super::LinuxWaitTerminationV1::Exited { code } => Ok(WaitClassV1::Exited(code)),
        super::LinuxWaitTerminationV1::Signaled {
            signal,
            core_dumped,
        } => Ok(WaitClassV1::Signaled {
            signal,
            core_dumped,
        }),
    }
}

fn encode_wait_class(
    object: &mut ObjectBuilder,
    tag: u16,
    value: WaitClassV1,
) -> Result<(), LinuxPytestContractError> {
    match value {
        WaitClassV1::Success => object.enumeration(tag, 1, Vec::new()),
        WaitClassV1::Exited(code) => {
            object.enumeration(tag, 2, vec![enum_field(1, WireType::U8, vec![code])])
        }
        WaitClassV1::Signaled {
            signal,
            core_dumped,
        } => object.enumeration(
            tag,
            3,
            vec![
                enum_field(1, WireType::U8, vec![signal]),
                enum_field(2, WireType::Bool, vec![u8::from(core_dumped)]),
            ],
        ),
    }
}

fn decode_wait_class(bytes: &[u8]) -> Result<WaitClassV1, LinuxPytestContractError> {
    let value = RawEnum::parse(bytes)?;
    match value.variant {
        1 => {
            value.expect_no_fields()?;
            Ok(WaitClassV1::Success)
        }
        2 => {
            value.expect(&[(1, WireType::U8)])?;
            Ok(WaitClassV1::Exited(decode_u8(value.payload(1)?)?))
        }
        3 => {
            value.expect(&[(1, WireType::U8), (2, WireType::Bool)])?;
            let signal = decode_u8(value.payload(1)?)?;
            if !(1..=64).contains(&signal) {
                return Err(LinuxPytestContractError::CanonicalDecoding);
            }
            Ok(WaitClassV1::Signaled {
                signal,
                core_dumped: decode_bool(value.payload(2)?)?,
            })
        }
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_observation_kind(value: u16) -> Result<ObservationKindV2, LinuxPytestContractError> {
    match value {
        1 => Ok(ObservationKindV2::File),
        2 => Ok(ObservationKindV2::Directory),
        3 => Ok(ObservationKindV2::AbsentPath),
        4 => Ok(ObservationKindV2::Symlink),
        5 => Ok(ObservationKindV2::Executable),
        6 => Ok(ObservationKindV2::Mapping),
        7 => Ok(ObservationKindV2::Metadata),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_ambient_kind(value: u16) -> Result<AmbientKindV2, LinuxPytestContractError> {
    match value {
        1 => Ok(AmbientKindV2::LogicalTime),
        2 => Ok(AmbientKindV2::LogicalRandom),
        3 => Ok(AmbientKindV2::LogicalPid),
        4 => Ok(AmbientKindV2::Sleep),
        5 => Ok(AmbientKindV2::Signal),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_effect_kind(value: u16) -> Result<EffectKindV2, LinuxPytestContractError> {
    match value {
        1 => Ok(EffectKindV2::Write),
        2 => Ok(EffectKindV2::Truncate),
        3 => Ok(EffectKindV2::Metadata),
        4 => Ok(EffectKindV2::Link),
        5 => Ok(EffectKindV2::Rename),
        6 => Ok(EffectKindV2::Unlink),
        7 => Ok(EffectKindV2::Mkdir),
        8 => Ok(EffectKindV2::Rmdir),
        9 => Ok(EffectKindV2::WritableMapping),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn manifest_entry_for_sandbox_path<'a>(
    manifest: &'a SnapshotManifestV1,
    path: &[u8],
) -> Option<&'a ManifestEntryV1> {
    std::iter::once(&manifest.workspace_tree)
        .chain(manifest.runtime_trees.iter())
        .filter_map(|tree| {
            let mount = tree.mount_path.as_bytes();
            let relative = if path == mount {
                Some(&[][..])
            } else {
                path.strip_prefix(mount)
                    .and_then(|suffix| suffix.strip_prefix(b"/"))
            }?;
            let entry = tree
                .entries
                .binary_search_by(|candidate| candidate.relative_path.as_slice().cmp(relative))
                .ok()
                .map(|index| &tree.entries[index])?;
            Some((mount.len(), entry))
        })
        .max_by_key(|(mount_len, _)| *mount_len)
        .map(|(_, entry)| entry)
}

fn resolved_symlink_target(path: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    let combined = if target.starts_with(b"/") {
        target.to_vec()
    } else {
        let parent_end = path.iter().rposition(|byte| *byte == b'/')?;
        let mut value = path[..=parent_end].to_vec();
        value.extend_from_slice(target);
        value
    };
    if !combined.starts_with(b"/") || combined.contains(&0) {
        return None;
    }
    let mut components = Vec::<&[u8]>::new();
    for component in combined[1..].split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                components.pop()?;
            }
            value => components.push(value),
        }
    }
    let mut normalized = Vec::with_capacity(combined.len());
    normalized.push(b'/');
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(component);
    }
    Some(normalized)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum WireType {
    U8 = 0x01,
    U16 = 0x02,
    U32 = 0x03,
    U64 = 0x04,
    Bool = 0x07,
    Bytes = 0x08,
    Utf8 = 0x09,
    Object = 0x0a,
    List = 0x0b,
    Enum = 0x0d,
}

impl WireType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::U8),
            0x02 => Some(Self::U16),
            0x03 => Some(Self::U32),
            0x04 => Some(Self::U64),
            0x07 => Some(Self::Bool),
            0x08 => Some(Self::Bytes),
            0x09 => Some(Self::Utf8),
            0x0a => Some(Self::Object),
            0x0b => Some(Self::List),
            0x0d => Some(Self::Enum),
            _ => None,
        }
    }
}

struct Field {
    tag: u16,
    wire_type: WireType,
    payload: Vec<u8>,
}

fn enum_field(tag: u16, wire_type: WireType, payload: Vec<u8>) -> Field {
    Field {
        tag,
        wire_type,
        payload,
    }
}

struct ObjectBuilder {
    type_id: u16,
    fields: Vec<Field>,
}

impl ObjectBuilder {
    fn new(type_id: u16) -> Self {
        Self {
            type_id,
            fields: Vec::new(),
        }
    }

    fn field(
        &mut self,
        tag: u16,
        wire_type: WireType,
        payload: Vec<u8>,
    ) -> Result<(), LinuxPytestContractError> {
        if tag == 0
            || self
                .fields
                .last()
                .is_some_and(|previous| previous.tag >= tag)
        {
            return Err(LinuxPytestContractError::CanonicalEncoding);
        }
        self.fields.push(Field {
            tag,
            wire_type,
            payload,
        });
        Ok(())
    }

    fn u16(&mut self, tag: u16, value: u16) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::U16, value.to_be_bytes().to_vec())
    }

    fn u32(&mut self, tag: u16, value: u32) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::U32, value.to_be_bytes().to_vec())
    }

    fn u64(&mut self, tag: u16, value: u64) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::U64, value.to_be_bytes().to_vec())
    }

    fn boolean(&mut self, tag: u16, value: bool) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::Bool, vec![u8::from(value)])
    }

    fn bytes(&mut self, tag: u16, value: &[u8]) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::Bytes, value.to_vec())
    }

    fn utf8(&mut self, tag: u16, value: &str) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::Utf8, value.as_bytes().to_vec())
    }

    fn object(&mut self, tag: u16, value: Vec<u8>) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::Object, value)
    }

    fn list(
        &mut self,
        tag: u16,
        values: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::List, encode_list(values)?)
    }

    fn enumeration(
        &mut self,
        tag: u16,
        variant: u16,
        fields: Vec<Field>,
    ) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::Enum, encode_enum(variant, fields)?)
    }

    fn finish_nested(self) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.type_id.to_be_bytes());
        output.extend_from_slice(&EFFECT_IR_V2_WIRE_VERSION.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(self.fields.len())
                .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
                .to_be_bytes(),
        );
        put_fields(&mut output, self.fields)?;
        enforce_size(&output)?;
        Ok(output)
    }

    fn finish_top(self) -> Result<Vec<u8>, LinuxPytestContractError> {
        let nested = self.finish_nested()?;
        let mut output = Vec::with_capacity(EFFECT_IR_V2_WIRE_MAGIC.len() + nested.len());
        output.extend_from_slice(EFFECT_IR_V2_WIRE_MAGIC);
        output.extend_from_slice(&nested);
        enforce_size(&output)?;
        Ok(output)
    }
}

fn put_fields(output: &mut Vec<u8>, fields: Vec<Field>) -> Result<(), LinuxPytestContractError> {
    let mut previous = 0;
    for field in fields {
        if field.tag <= previous {
            return Err(LinuxPytestContractError::CanonicalEncoding);
        }
        previous = field.tag;
        output.extend_from_slice(&field.tag.to_be_bytes());
        output.push(field.wire_type as u8);
        output.extend_from_slice(
            &u64::try_from(field.payload.len())
                .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&field.payload);
    }
    Ok(())
}

fn encode_list(
    values: impl IntoIterator<Item = Vec<u8>>,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.len() as u64 > EFFECT_IR_V2_MAX_COLLECTION_ITEMS {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    let mut output = Vec::new();
    output.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        output.extend_from_slice(
            &u64::try_from(value.len())
                .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&value);
    }
    enforce_size(&output)?;
    Ok(output)
}

fn encode_enum(variant: u16, fields: Vec<Field>) -> Result<Vec<u8>, LinuxPytestContractError> {
    if variant == 0 {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    let mut output = Vec::new();
    output.extend_from_slice(&variant.to_be_bytes());
    output.extend_from_slice(
        &u16::try_from(fields.len())
            .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
            .to_be_bytes(),
    );
    put_fields(&mut output, fields)?;
    enforce_size(&output)?;
    Ok(output)
}

fn enforce_size(bytes: &[u8]) -> Result<(), LinuxPytestContractError> {
    if bytes.len() as u64 > EFFECT_IR_V2_MAX_CANONICAL_BYTES {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], LinuxPytestContractError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, LinuxPytestContractError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, LinuxPytestContractError> {
        decode_u16(self.take(2)?)
    }

    fn u64(&mut self) -> Result<u64, LinuxPytestContractError> {
        decode_u64(self.take(8)?)
    }

    fn finish(self) -> Result<(), LinuxPytestContractError> {
        if self.offset != self.bytes.len() {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

struct RawField<'a> {
    tag: u16,
    wire_type: WireType,
    payload: &'a [u8],
}

struct RawObject<'a> {
    type_id: u16,
    fields: Vec<RawField<'a>>,
}

impl<'a> RawObject<'a> {
    fn parse_top(bytes: &'a [u8]) -> Result<Self, LinuxPytestContractError> {
        enforce_size(bytes).map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
        let nested = bytes
            .strip_prefix(EFFECT_IR_V2_WIRE_MAGIC)
            .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
        Self::parse_nested(nested)
    }

    fn parse_nested(bytes: &'a [u8]) -> Result<Self, LinuxPytestContractError> {
        let mut cursor = Cursor::new(bytes);
        let type_id = cursor.u16()?;
        if cursor.u16()? != EFFECT_IR_V2_WIRE_VERSION {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        let count = usize::from(cursor.u16()?);
        if count
            .checked_mul(FIELD_HEADER_BYTES)
            .is_none_or(|minimum| minimum > cursor.remaining())
        {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(count)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
        let mut previous = 0;
        for _ in 0..count {
            let tag = cursor.u16()?;
            let wire_type = WireType::from_u8(cursor.u8()?)
                .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
            let length = usize::try_from(cursor.u64()?)
                .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
            if tag == 0 || tag <= previous {
                return Err(LinuxPytestContractError::CanonicalDecoding);
            }
            previous = tag;
            fields.push(RawField {
                tag,
                wire_type,
                payload: cursor.take(length)?,
            });
        }
        cursor.finish()?;
        Ok(Self { type_id, fields })
    }

    fn expect(
        &self,
        type_id: u16,
        fields: &[(u16, WireType)],
    ) -> Result<(), LinuxPytestContractError> {
        if self.type_id != type_id
            || self.fields.len() != fields.len()
            || self.fields.iter().zip(fields).any(|(actual, expected)| {
                actual.tag != expected.0 || actual.wire_type != expected.1
            })
        {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        Ok(())
    }

    fn payload(&self, tag: u16) -> Result<&'a [u8], LinuxPytestContractError> {
        self.fields
            .iter()
            .find(|field| field.tag == tag)
            .map(|field| field.payload)
            .ok_or(LinuxPytestContractError::CanonicalDecoding)
    }
}

struct RawEnum<'a> {
    variant: u16,
    fields: Vec<RawField<'a>>,
}

impl<'a> RawEnum<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, LinuxPytestContractError> {
        let mut cursor = Cursor::new(bytes);
        let variant = cursor.u16()?;
        if variant == 0 {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        let count = usize::from(cursor.u16()?);
        if count
            .checked_mul(FIELD_HEADER_BYTES)
            .is_none_or(|minimum| minimum > cursor.remaining())
        {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(count)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
        let mut previous = 0;
        for _ in 0..count {
            let tag = cursor.u16()?;
            let wire_type = WireType::from_u8(cursor.u8()?)
                .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
            let length = usize::try_from(cursor.u64()?)
                .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
            if tag == 0 || tag <= previous {
                return Err(LinuxPytestContractError::CanonicalDecoding);
            }
            previous = tag;
            fields.push(RawField {
                tag,
                wire_type,
                payload: cursor.take(length)?,
            });
        }
        cursor.finish()?;
        Ok(Self { variant, fields })
    }

    fn expect(&self, fields: &[(u16, WireType)]) -> Result<(), LinuxPytestContractError> {
        if self.fields.len() != fields.len()
            || self.fields.iter().zip(fields).any(|(actual, expected)| {
                actual.tag != expected.0 || actual.wire_type != expected.1
            })
        {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        Ok(())
    }

    fn expect_no_fields(&self) -> Result<(), LinuxPytestContractError> {
        self.expect(&[])
    }

    fn payload(&self, tag: u16) -> Result<&'a [u8], LinuxPytestContractError> {
        self.fields
            .iter()
            .find(|field| field.tag == tag)
            .map(|field| field.payload)
            .ok_or(LinuxPytestContractError::CanonicalDecoding)
    }
}

fn decode_list(bytes: &[u8]) -> Result<Vec<&[u8]>, LinuxPytestContractError> {
    let mut cursor = Cursor::new(bytes);
    let count = cursor.u64()?;
    if count > EFFECT_IR_V2_MAX_COLLECTION_ITEMS {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    let count = usize::try_from(count).map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
    if count
        .checked_mul(8)
        .is_none_or(|minimum| minimum > cursor.remaining())
    {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
    for _ in 0..count {
        let length = usize::try_from(cursor.u64()?)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
        values.push(cursor.take(length)?);
    }
    cursor.finish()?;
    Ok(values)
}

fn exact_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], LinuxPytestContractError> {
    bytes
        .try_into()
        .map_err(|_| LinuxPytestContractError::CanonicalDecoding)
}

fn decode_u8(bytes: &[u8]) -> Result<u8, LinuxPytestContractError> {
    Ok(exact_array::<1>(bytes)?[0])
}

fn decode_u16(bytes: &[u8]) -> Result<u16, LinuxPytestContractError> {
    Ok(u16::from_be_bytes(exact_array::<2>(bytes)?))
}

fn decode_u32(bytes: &[u8]) -> Result<u32, LinuxPytestContractError> {
    Ok(u32::from_be_bytes(exact_array::<4>(bytes)?))
}

fn decode_u64(bytes: &[u8]) -> Result<u64, LinuxPytestContractError> {
    Ok(u64::from_be_bytes(exact_array::<8>(bytes)?))
}

fn decode_bool(bytes: &[u8]) -> Result<bool, LinuxPytestContractError> {
    match decode_u8(bytes)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn expect_u16(bytes: &[u8], expected: u16) -> Result<(), LinuxPytestContractError> {
    if decode_u16(bytes)? != expected {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(())
}

fn expect_u64(bytes: &[u8], expected: u64) -> Result<(), LinuxPytestContractError> {
    if decode_u64(bytes)? != expected {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(())
}

fn expect_utf8(bytes: &[u8], expected: &str) -> Result<(), LinuxPytestContractError> {
    if std::str::from_utf8(bytes).ok() != Some(expected) {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(())
}

fn require_exact_reencoding(
    original: &[u8],
    encoded: Vec<u8>,
) -> Result<(), LinuxPytestContractError> {
    if original != encoded {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(label: &[u8]) -> PolicyDigest {
        PolicyDigest::derive("again linux pytest identity test policy v1", &[label])
    }

    fn policies() -> PolicyDigestsV1 {
        PolicyDigestsV1 {
            seccomp: policy(b"seccomp"),
            landlock: policy(b"landlock"),
            namespace: policy(b"namespace"),
            tracer_runtime: policy(b"tracer-runtime"),
            ambient_broker: policy(b"ambient-broker"),
            limits: policy(b"limits"),
            environment: policy(b"environment"),
            selector_grammar: policy(b"selector-grammar"),
            runtime_closure: policy(b"runtime-closure"),
            codec: policy(b"codec"),
        }
    }

    fn profile() -> ProfileCommitmentV1 {
        ProfileCommitmentV1::from_compiled_policy_digests(policies()).unwrap()
    }

    fn invocation() -> PytestInvocationIdentityV1 {
        PytestInvocationIdentityV1 {
            argv: vec![
                b".venv/bin/python".to_vec(),
                b"-I".to_vec(),
                b"-m".to_vec(),
                b"pytest".to_vec(),
                b"tests/test_unit.py::test_one".to_vec(),
            ],
            cwd: b".".to_vec(),
            selectors: vec![PytestSelectorV1::parse(b"tests/test_unit.py::test_one").unwrap()],
            stdin_profile: StdinProfileV1::ClosedEof,
        }
    }

    fn environment() -> EnvironmentBindingV1 {
        EnvironmentBindingV1 {
            key_id: EnvironmentKeyId::derive(
                "again linux pytest identity test environment key v1",
                &[b"key"],
            ),
            digest: EnvironmentDigest::derive(
                "again linux pytest identity test environment v1",
                &[b"values"],
            ),
            names_digest: EnvironmentNamesDigest::derive(
                "again linux pytest identity test environment names v1",
                &[b"names"],
            ),
            entry_count: 23,
            policy_digest: policies().environment,
        }
    }

    #[test]
    fn profile_and_workspace_vectors_are_stable() {
        let profile = profile();
        let workspace = WorkspaceIdentityCommitmentV1::enroll([0x5a; 32]).unwrap();
        assert_eq!(
            ProfileCommitmentV1::from_canonical_bytes(&profile.canonical_bytes().unwrap()).unwrap(),
            profile
        );
        assert_eq!(
            WorkspaceIdentityCommitmentV1::from_canonical_bytes(
                &workspace.canonical_bytes().unwrap()
            )
            .unwrap(),
            workspace
        );
        assert_eq!(
            profile.digest().unwrap().to_hex(),
            "afa460a6edd4966914ae6622b44161ee3637958948f9e927721ac86e43ab33f8"
        );
        assert_eq!(
            workspace.identity().unwrap().to_hex(),
            "e5cc3614b3486d30856ec654070803385b75b6a29819edf2b0eb4a678967c4e8"
        );
    }

    #[test]
    fn lexical_shape_roundtrips_and_partitions_environment_keys() {
        let profile = profile();
        let workspace = WorkspaceIdentityCommitmentV1::enroll([7; 32]).unwrap();
        let lexical =
            LexicalShapeV1::new(&profile, &workspace, invocation(), environment()).unwrap();
        let encoded = lexical.canonical_bytes().unwrap();
        assert_eq!(
            LexicalShapeV1::from_canonical_bytes(&encoded).unwrap(),
            lexical
        );
        lexical
            .validate_against(&profile, &workspace, environment().key_id)
            .unwrap();
        let mut changed = environment();
        changed.key_id = EnvironmentKeyId::derive(
            "again linux pytest identity test environment key v1",
            &[b"rotated"],
        );
        let changed = LexicalShapeV1::new(&profile, &workspace, invocation(), changed).unwrap();
        assert_ne!(lexical.key().unwrap(), changed.key().unwrap());
        assert_eq!(
            lexical.key().unwrap().to_hex(),
            "7229f4feeae49ae6f5ef1edd34263678c438c6996df4d98cd69263b132886d76"
        );
    }

    #[test]
    fn executable_chain_checks_resolution_and_roundtrips() {
        let requested =
            SandboxPath::new(b"/workspace/.venv/bin/python".to_vec().into_boxed_slice()).unwrap();
        let terminal =
            SandboxPath::new(b"/workspace/.venv/bin/python3".to_vec().into_boxed_slice()).unwrap();
        let chain = ExecutableChainV1::new(
            requested.clone(),
            vec![
                ExecutableHopV1::symlink(
                    requested,
                    NodeDigest::derive("again linux pytest identity test node v1", &[b"link"]),
                    b"python3".to_vec(),
                    terminal.clone(),
                )
                .unwrap(),
                ExecutableHopV1::terminal_regular(
                    terminal,
                    NodeDigest::derive("again linux pytest identity test node v1", &[b"file"]),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        chain.validate_requested_by(&invocation()).unwrap();
        let encoded = chain.canonical_bytes().unwrap();
        assert_eq!(
            ExecutableChainV1::from_canonical_bytes(&encoded).unwrap(),
            chain
        );
        assert_eq!(
            chain.digest().unwrap().to_hex(),
            "0a48d9ef59fa379795c4e358ff52b08b7534345383b2cfefd44a440bdcdb6ab6"
        );

        let bad_next = SandboxPath::new(
            b"/workspace/.venv/bin/not-python"
                .to_vec()
                .into_boxed_slice(),
        )
        .unwrap();
        assert!(
            ExecutableHopV1::symlink(
                SandboxPath::new(b"/workspace/.venv/bin/python".to_vec().into_boxed_slice())
                    .unwrap(),
                NodeDigest::derive("again linux pytest identity test node v1", &[b"bad"]),
                b"python3".to_vec(),
                bad_next,
            )
            .is_err()
        );
    }

    #[test]
    fn effect_shape_roundtrips_and_rejects_duplicate_global_sequence() {
        let shape = EffectShapeV1 {
            profile_digest: profile().digest().unwrap(),
            observations: vec![ObservationLayoutV1 {
                sequence: 1,
                logical_task_id: LogicalTaskId(1),
                kind: ObservationKindV2::File,
                subject: SandboxPath::new(
                    b"/workspace/tests/test_unit.py".to_vec().into_boxed_slice(),
                )
                .unwrap(),
            }],
            ambient_events: vec![AmbientLayoutV1 {
                sequence: 2,
                logical_task_id: LogicalTaskId(1),
                kind: AmbientKindV2::LogicalTime,
            }],
            ordered_effects: vec![OrderedEffectLayoutV1 {
                sequence: 3,
                logical_task_id: LogicalTaskId(1),
                kind: EffectKindV2::Write,
                subject: SandboxPath::new(
                    b"/workspace/.pytest_cache/state"
                        .to_vec()
                        .into_boxed_slice(),
                )
                .unwrap(),
            }],
            stdout: StreamStateClassV1::Complete,
            stderr: StreamStateClassV1::Incomplete(ExecuteOnlyCode::CaptureFailure),
            wait: WaitClassV1::Exited(7),
            final_workspace_changed: true,
        };
        let bytes = shape.canonical_bytes().unwrap();
        assert_eq!(EffectShapeV1::from_canonical_bytes(&bytes).unwrap(), shape);
        assert_eq!(
            shape.digest().unwrap().to_hex(),
            "ef2a1eaf40907642542c95ab2a619cfe99a7cc9ba78081d780c9a4a3b5c54ccc"
        );

        let mut duplicate = shape;
        duplicate.ambient_events[0].sequence = 1;
        assert_eq!(
            duplicate.canonical_bytes(),
            Err(LinuxPytestContractError::MalformedRecord)
        );
    }

    #[test]
    fn quarantine_class_is_exact_request_scoped_and_roundtrips() {
        let profile_digest = profile().digest().unwrap();
        let workspace_identity = WorkspaceIdentityCommitmentV1::enroll([0x33; 32])
            .unwrap()
            .identity()
            .unwrap();
        let shape_key = ShapeKey::derive("again linux pytest identity test shape v1", &[b"shape"]);
        let request_key =
            RequestKey::derive("again linux pytest identity test request v1", &[b"request"]);
        let class = QuarantineClassV1::from_checked_parts(
            profile_digest,
            workspace_identity,
            shape_key,
            request_key,
        )
        .unwrap();
        let bytes = class.canonical_bytes().unwrap();
        assert_eq!(
            QuarantineClassV1::from_canonical_bytes(&bytes).unwrap(),
            class
        );
        let different_request = QuarantineClassV1::from_checked_parts(
            profile_digest,
            workspace_identity,
            shape_key,
            RequestKey::derive(
                "again linux pytest identity test request v1",
                &[b"different"],
            ),
        )
        .unwrap();
        assert_ne!(class.key().unwrap(), different_request.key().unwrap());
        assert_eq!(
            class.key().unwrap().to_hex(),
            "eca31926b7f70b3124b6241d87bfcd9e6b748716bd1781336dfff2f2540512d0"
        );
    }

    #[test]
    fn strict_decoders_reject_truncation_trailing_and_unknown_fields() {
        let workspace = WorkspaceIdentityCommitmentV1::enroll([9; 32]).unwrap();
        let bytes = workspace.canonical_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(WorkspaceIdentityCommitmentV1::from_canonical_bytes(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(WorkspaceIdentityCommitmentV1::from_canonical_bytes(&trailing).is_err());

        let mut unknown = ObjectBuilder::new(TYPE_WORKSPACE_IDENTITY_COMMITMENT);
        unknown.utf8(1, WORKSPACE_IDENTITY_V1_SCHEMA).unwrap();
        unknown.bytes(2, &[9; 32]).unwrap();
        unknown.bytes(3, b"unknown").unwrap();
        assert!(
            WorkspaceIdentityCommitmentV1::from_canonical_bytes(&unknown.finish_top().unwrap())
                .is_err()
        );
    }

    #[test]
    fn workspace_zero_and_collection_bombs_are_rejected() {
        assert!(WorkspaceIdentityCommitmentV1::enroll([0; 32]).is_err());
        let mut bomb = Vec::new();
        bomb.extend_from_slice(&(EFFECT_IR_V2_MAX_COLLECTION_ITEMS + 1).to_be_bytes());
        assert!(decode_list(&bomb).is_err());
    }
}
