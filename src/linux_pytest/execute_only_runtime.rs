//! Gate 3 descriptor-selected Python executable qualification checkpoint.
//!
//! This is intentionally narrower than a runtime closure. It consumes the
//! connector-issued workspace binding, resolves the fixed executable beneath
//! that bound snapshot, cross-checks every observed node against the charged
//! canonical manifest, and validates the snapshotted terminal bytes as an
//! executable x86_64 ELF. It does not qualify `PT_INTERP`, `DT_NEEDED`, the
//! runtime forest, the virtual environment, pytest, isolation, execution, a
//! cache candidate, or reuse.
//!
//! The v1 host threat model excludes a malicious same-UID peer and host root.
//! Descriptor-relative pre/open/post checks detect ordinary drift, but are not
//! claimed to withstand a hostile peer that can mutate and restore the tree.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_manifest::{
    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1, FirstExecuteOnlyWorkspaceRuntimeEvidenceV1,
    FirstExecuteOnlyWorkspaceTreeBindingV1,
    consume_first_execute_only_workspace_runtime_evidence_v1,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_publish::VerifiedBoundNodeKindV1;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::{ExecutableChainDigest, FileContentDigest, NodeDigest};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::fmt;

const FIRST_EXECUTE_ONLY_EXECUTABLE_V1: &[u8] = b".venv/bin/python";
const FIRST_EXECUTE_ONLY_RUNTIME_CHECKPOINT_DOMAIN_V1: &str =
    "again first execute-only runtime checkpoint v1";
const RUNTIME_CHECKPOINT_MAGIC_V1: &[u8; 8] = b"AGRTCP01";
const RUNTIME_CLOSURE_NONCLAIMS_V1: &[u8] =
    b"PT_INTERP,DT_NEEDED,runtime-forest,venv,pytest:unqualified";
const ELF64_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_MAX_PROGRAM_HEADERS: usize = 1024;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_SYSV: u8 = 0;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;

/// Stable, payload-free refusals from the first runtime checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FirstExecuteOnlyRuntimeCheckpointRefusalV1 {
    InvalidFixedExecutable,
    PathComponentLimit,
    SymlinkLimit,
    SymlinkCycle,
    SymlinkTarget,
    MissingNode,
    MountCrossing,
    MagicLink,
    NodeType,
    IdentityDrift,
    SizeMismatch,
    ByteLimit,
    ShortRead,
    Io,
    ManifestNodeMissing,
    ManifestNodeAmbiguous,
    ManifestKindMismatch,
    ManifestMetadataMismatch,
    ManifestSymlinkMismatch,
    ManifestContentMismatch,
    ManifestDigestMismatch,
    ManifestRootMismatch,
    TerminalNotExecutable,
    ElfTooSmall,
    ElfMagic,
    ElfClass,
    ElfEndianness,
    ElfVersion,
    ElfOsAbi,
    ElfType,
    ElfMachine,
    ElfHeaderSize,
    ElfProgramHeader,
    ElfNoLoadSegment,
    ElfEntryPoint,
    CanonicalOverflow,
    MemoryBudget,
}

/// Opaque linear checkpoint for later Gate 3 composition. It retains the
/// original physical and charged manifest evidence and has no raw descriptor,
/// path, or byte accessor. It is checkpoint evidence, never execution or
/// reuse authority.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyRuntimeCheckpointV1<'resources> {
    _evidence: FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'resources>,
    _canonical_bytes: Box<[u8]>,
    chain_digest: ExecutableChainDigest,
    workspace_root_digest: NodeDigest,
    terminal_node_digest: NodeDigest,
    terminal_content_digest: FileContentDigest,
    node_count: u8,
    symlink_hop_count: u8,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl FirstExecuteOnlyRuntimeCheckpointV1<'_> {
    pub(super) const fn chain_digest(&self) -> ExecutableChainDigest {
        self.chain_digest
    }

    pub(super) const fn workspace_root_digest(&self) -> NodeDigest {
        self.workspace_root_digest
    }

    pub(super) const fn terminal_node_digest(&self) -> NodeDigest {
        self.terminal_node_digest
    }

    pub(super) const fn terminal_content_digest(&self) -> FileContentDigest {
        self.terminal_content_digest
    }

    pub(super) const fn node_count(&self) -> u8 {
        self.node_count
    }

    pub(super) const fn symlink_hop_count(&self) -> u8 {
        self.symlink_hop_count
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for FirstExecuteOnlyRuntimeCheckpointV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstExecuteOnlyRuntimeCheckpointV1")
            .field("evidence", &"<redacted>")
            .field("canonical_bytes", &"<redacted>")
            .field("digests", &"<redacted>")
            .field("node_count", &self.node_count)
            .field("symlink_hop_count", &self.symlink_hop_count)
            .field("runtime_closure", &"unqualified")
            .finish()
    }
}

/// Consume the only connector-issued workspace binding and mint the first
/// crate-private runtime checkpoint. No pure or caller-constructed identity
/// can reach this constructor.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn qualify_first_execute_only_runtime_checkpoint_v1<'resources>(
    binding: FirstExecuteOnlyWorkspaceTreeBindingV1<'resources>,
) -> Result<
    FirstExecuteOnlyRuntimeCheckpointV1<'resources>,
    FirstExecuteOnlyRuntimeCheckpointRefusalV1,
> {
    let evidence = consume_first_execute_only_workspace_runtime_evidence_v1(binding)
        .map_err(map_workspace_evidence_refusal_v1)?;
    if !terminal_is_logically_executable_v1(evidence.terminal_logical_mode()) {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::TerminalNotExecutable);
    }
    validate_x86_64_elf_v1(evidence.executable_bytes())?;

    let canonical_bytes = encode_runtime_checkpoint_v1(&evidence)?;
    let chain_digest = ExecutableChainDigest::derive(
        FIRST_EXECUTE_ONLY_RUNTIME_CHECKPOINT_DOMAIN_V1,
        &[&canonical_bytes],
    );
    let workspace_root_digest = evidence.workspace_root_digest();
    let terminal_node_digest = evidence.terminal_node_digest();
    let terminal_content_digest = evidence.terminal_content_digest();
    let node_count = u8::try_from(evidence.nodes().len())
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?;
    let symlink_hop_count = u8::try_from(
        evidence
            .nodes()
            .iter()
            .filter(|node| node.kind() == VerifiedBoundNodeKindV1::Symlink)
            .count(),
    )
    .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?;
    Ok(FirstExecuteOnlyRuntimeCheckpointV1 {
        _evidence: evidence,
        _canonical_bytes: canonical_bytes.into_boxed_slice(),
        chain_digest,
        workspace_root_digest,
        terminal_node_digest,
        terminal_content_digest,
        node_count,
        symlink_hop_count,
    })
}

const fn terminal_is_logically_executable_v1(mode: u32) -> bool {
    mode & 0o170_000 == 0o100_000 && mode & 0o111 != 0
}

pub(super) fn validate_x86_64_elf_v1(
    bytes: &[u8],
) -> Result<(), FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    if bytes.len() < ELF64_HEADER_BYTES {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfTooSmall);
    }
    if bytes[..4] != *b"\x7fELF" {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfMagic);
    }
    if bytes[4] != ELFCLASS64 {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfClass);
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfEndianness);
    }
    if bytes[6] != EV_CURRENT
        || u32::from_le_bytes(bytes[20..24].try_into().expect("bounded ELF header")) != 1
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfVersion);
    }
    if bytes[7] != ELFOSABI_SYSV || bytes[8] != 0 {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfOsAbi);
    }
    let elf_type = u16::from_le_bytes(bytes[16..18].try_into().expect("bounded ELF header"));
    if elf_type != ET_EXEC && elf_type != ET_DYN {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfType);
    }
    if u16::from_le_bytes(bytes[18..20].try_into().expect("bounded ELF header")) != EM_X86_64 {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfMachine);
    }
    if u16::from_le_bytes(bytes[52..54].try_into().expect("bounded ELF header"))
        != ELF64_HEADER_BYTES as u16
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfHeaderSize);
    }
    let program_offset = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("bounded ELF header"),
    ))
    .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
    let program_entry_size = usize::from(u16::from_le_bytes(
        bytes[54..56].try_into().expect("bounded ELF header"),
    ));
    let program_count = usize::from(u16::from_le_bytes(
        bytes[56..58].try_into().expect("bounded ELF header"),
    ));
    if program_offset < ELF64_HEADER_BYTES
        || program_entry_size != ELF64_PROGRAM_HEADER_BYTES
        || program_count == 0
        || program_count > ELF64_MAX_PROGRAM_HEADERS
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader);
    }
    let table_bytes = program_entry_size
        .checked_mul(program_count)
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
    let table_end = program_offset
        .checked_add(table_bytes)
        .filter(|end| *end <= bytes.len())
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
    let entry = u64::from_le_bytes(bytes[24..32].try_into().expect("bounded ELF header"));
    let mut has_load = false;
    let mut entry_is_executable = false;
    for header in bytes[program_offset..table_end].chunks_exact(program_entry_size) {
        if u32::from_le_bytes(header[0..4].try_into().expect("bounded program header")) != PT_LOAD {
            continue;
        }
        has_load = true;
        let flags = u32::from_le_bytes(header[4..8].try_into().expect("bounded program header"));
        let offset = u64::from_le_bytes(header[8..16].try_into().expect("bounded program header"));
        let virtual_address =
            u64::from_le_bytes(header[16..24].try_into().expect("bounded program header"));
        let file_size =
            u64::from_le_bytes(header[32..40].try_into().expect("bounded program header"));
        let memory_size =
            u64::from_le_bytes(header[40..48].try_into().expect("bounded program header"));
        let alignment =
            u64::from_le_bytes(header[48..56].try_into().expect("bounded program header"));
        let file_end = offset
            .checked_add(file_size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
        let memory_end = virtual_address
            .checked_add(memory_size)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
        if file_size > memory_size
            || !(alignment == 0 || alignment == 1 || alignment.is_power_of_two())
            || (alignment > 1 && virtual_address % alignment != offset % alignment)
            || file_end < offset
        {
            return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader);
        }
        if flags & PF_X != 0 && entry >= virtual_address && entry < memory_end {
            entry_is_executable = true;
        }
    }
    if !has_load {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNoLoadSegment);
    }
    if !entry_is_executable {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfEntryPoint);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn encode_runtime_checkpoint_v1(
    evidence: &FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'_>,
) -> Result<Vec<u8>, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let memory = evidence.runtime_memory();
    let mut output = runtime_vec_v1(memory, RUNTIME_CHECKPOINT_MAGIC_V1.len())?;
    memory
        .try_extend_bytes(&mut output, RUNTIME_CHECKPOINT_MAGIC_V1)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    push_canonical_field_v1(memory, &mut output, 1, FIRST_EXECUTE_ONLY_EXECUTABLE_V1)?;
    push_canonical_field_v1(
        memory,
        &mut output,
        2,
        evidence.workspace_root_digest().as_bytes(),
    )?;
    push_canonical_field_v1(
        memory,
        &mut output,
        3,
        evidence.workspace_root_statx_commitment(),
    )?;
    push_canonical_field_v1(
        memory,
        &mut output,
        4,
        evidence.terminal_identity_digest().as_bytes(),
    )?;
    push_canonical_field_v1(
        memory,
        &mut output,
        5,
        evidence.terminal_node_digest().as_bytes(),
    )?;
    push_canonical_field_v1(
        memory,
        &mut output,
        6,
        evidence.terminal_content_digest().as_bytes(),
    )?;
    push_canonical_field_v1(memory, &mut output, 7, RUNTIME_CLOSURE_NONCLAIMS_V1)?;
    let node_count = u16::try_from(evidence.nodes().len())
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?;
    push_canonical_field_v1(memory, &mut output, 8, &node_count.to_be_bytes())?;
    let mut encoded_nodes = runtime_vec_v1(memory, 0)?;
    for node in evidence.nodes() {
        let mut encoded = runtime_vec_v1(memory, 0)?;
        push_canonical_field_v1(memory, &mut encoded, 1, node.normalized_path())?;
        let kind = match node.kind() {
            VerifiedBoundNodeKindV1::Directory => 1,
            VerifiedBoundNodeKindV1::Symlink => 2,
            VerifiedBoundNodeKindV1::Regular => 3,
        };
        push_canonical_field_v1(memory, &mut encoded, 2, &[kind])?;
        push_canonical_field_v1(memory, &mut encoded, 3, node.statx_commitment())?;
        push_canonical_field_v1(memory, &mut encoded, 4, node.node_digest().as_bytes())?;
        push_canonical_field_v1(
            memory,
            &mut encoded,
            5,
            node.normalized_next_path().unwrap_or_default(),
        )?;
        push_canonical_field_v1(memory, &mut encoded, 6, &node.logical_mode().to_be_bytes())?;
        let encoded_length = u32::try_from(encoded.len())
            .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?;
        memory
            .try_extend_bytes(&mut encoded_nodes, &encoded_length.to_be_bytes())
            .and_then(|()| memory.try_extend_bytes(&mut encoded_nodes, &encoded))
            .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    }
    push_canonical_field_v1(memory, &mut output, 9, &encoded_nodes)?;
    Ok(output)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn runtime_vec_v1<T>(
    memory: &super::snapshot_publish::RuntimeMemoryEscrowV1,
    capacity: usize,
) -> Result<Vec<T>, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    memory
        .try_vec_with_capacity(capacity)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)
}

fn push_canonical_field_v1(
    memory: &super::snapshot_publish::RuntimeMemoryEscrowV1,
    output: &mut Vec<u8>,
    tag: u16,
    value: &[u8],
) -> Result<(), FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let length = u32::try_from(value.len())
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?;
    output
        .len()
        .checked_add(6)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?;
    memory
        .try_extend_bytes(output, &tag.to_be_bytes())
        .and_then(|()| memory.try_extend_bytes(output, &length.to_be_bytes()))
        .and_then(|()| memory.try_extend_bytes(output, value))
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn map_workspace_evidence_refusal_v1(
    refusal: FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1,
) -> FirstExecuteOnlyRuntimeCheckpointRefusalV1 {
    use FirstExecuteOnlyRuntimeCheckpointRefusalV1 as Output;
    use FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1 as Input;
    match refusal {
        Input::InvalidFixedExecutable => Output::InvalidFixedExecutable,
        Input::PathComponentLimit => Output::PathComponentLimit,
        Input::SymlinkLimit => Output::SymlinkLimit,
        Input::SymlinkCycle => Output::SymlinkCycle,
        Input::SymlinkTarget => Output::SymlinkTarget,
        Input::MissingNode => Output::MissingNode,
        Input::MountCrossing => Output::MountCrossing,
        Input::MagicLink => Output::MagicLink,
        Input::NodeType => Output::NodeType,
        Input::IdentityDrift => Output::IdentityDrift,
        Input::SizeMismatch => Output::SizeMismatch,
        Input::ByteLimit => Output::ByteLimit,
        Input::ShortRead => Output::ShortRead,
        Input::Io => Output::Io,
        Input::ManifestNodeMissing => Output::ManifestNodeMissing,
        Input::ManifestNodeAmbiguous => Output::ManifestNodeAmbiguous,
        Input::ManifestKindMismatch => Output::ManifestKindMismatch,
        Input::ManifestMetadataMismatch => Output::ManifestMetadataMismatch,
        Input::ManifestSymlinkMismatch => Output::ManifestSymlinkMismatch,
        Input::ManifestContentMismatch => Output::ManifestContentMismatch,
        Input::ManifestDigestMismatch => Output::ManifestDigestMismatch,
        Input::ManifestRootMismatch => Output::ManifestRootMismatch,
        Input::MemoryBudget => Output::MemoryBudget,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_fixture() -> Vec<u8> {
        let segment_offset = ELF64_HEADER_BYTES + ELF64_PROGRAM_HEADER_BYTES;
        let mut bytes = vec![0u8; segment_offset + 1];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[7] = ELFOSABI_SYSV;
        bytes[8] = 0;
        bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x40_0078u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF64_HEADER_BYTES as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        let program = &mut bytes[ELF64_HEADER_BYTES..segment_offset];
        program[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        program[4..8].copy_from_slice(&(PF_X | 4).to_le_bytes());
        program[8..16].copy_from_slice(&(segment_offset as u64).to_le_bytes());
        program[16..24].copy_from_slice(&0x40_0078u64.to_le_bytes());
        program[32..40].copy_from_slice(&1u64.to_le_bytes());
        program[40..48].copy_from_slice(&1u64.to_le_bytes());
        program[48..56].copy_from_slice(&1u64.to_le_bytes());
        bytes[segment_offset] = 0xc3;
        bytes
    }

    #[test]
    fn bounded_x86_64_elf_with_loadable_executable_segment_is_accepted() {
        assert_eq!(validate_x86_64_elf_v1(&elf_fixture()), Ok(()));
        let mut executable = elf_fixture();
        executable[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        assert_eq!(validate_x86_64_elf_v1(&executable), Ok(()));
    }

    #[test]
    fn header_only_and_malformed_program_tables_are_rejected() {
        assert_eq!(
            validate_x86_64_elf_v1(&elf_fixture()[..ELF64_HEADER_BYTES]),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );
        let mut wrong_size = elf_fixture();
        wrong_size[54..56].copy_from_slice(&55u16.to_le_bytes());
        assert_eq!(
            validate_x86_64_elf_v1(&wrong_size),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );
        let mut no_load = elf_fixture();
        no_load[ELF64_HEADER_BYTES..ELF64_HEADER_BYTES + 4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            validate_x86_64_elf_v1(&no_load),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNoLoadSegment)
        );
        let mut non_executable = elf_fixture();
        non_executable[ELF64_HEADER_BYTES + 4..ELF64_HEADER_BYTES + 8]
            .copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            validate_x86_64_elf_v1(&non_executable),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfEntryPoint)
        );
        let mut outside_file = elf_fixture();
        let outside_offset = outside_file.len() as u64;
        outside_file[ELF64_HEADER_BYTES + 8..ELF64_HEADER_BYTES + 16]
            .copy_from_slice(&outside_offset.to_le_bytes());
        assert_eq!(
            validate_x86_64_elf_v1(&outside_file),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );
    }

    #[test]
    fn every_elf_identity_dimension_refuses_stably() {
        let cases: &[(usize, u8, FirstExecuteOnlyRuntimeCheckpointRefusalV1)] = &[
            (0, 0, FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfMagic),
            (4, 1, FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfClass),
            (
                5,
                2,
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfEndianness,
            ),
            (6, 0, FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfVersion),
            (7, 3, FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfOsAbi),
            (16, 0, FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfType),
            (
                18,
                0,
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfMachine,
            ),
            (
                52,
                0,
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfHeaderSize,
            ),
        ];
        for (offset, value, expected) in cases {
            let mut bytes = elf_fixture();
            bytes[*offset] = *value;
            assert_eq!(validate_x86_64_elf_v1(&bytes), Err(*expected));
        }
        let mut bad_version = elf_fixture();
        bad_version[20] = 2;
        assert_eq!(
            validate_x86_64_elf_v1(&bad_version),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfVersion)
        );
        let mut bad_abi_version = elf_fixture();
        bad_abi_version[8] = 1;
        assert_eq!(
            validate_x86_64_elf_v1(&bad_abi_version),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfOsAbi)
        );
    }

    #[test]
    fn every_short_elf_prefix_refuses_without_parsing_past_the_bound() {
        let bytes = elf_fixture();
        for length in 0..ELF64_HEADER_BYTES {
            assert_eq!(
                validate_x86_64_elf_v1(&bytes[..length]),
                Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfTooSmall)
            );
        }
    }

    #[test]
    fn canonical_field_encoding_is_deterministic_and_mutation_sensitive() {
        let first_memory =
            super::super::snapshot_publish::RuntimeMemoryEscrowV1::first_checkpoint();
        let mut first = Vec::new();
        push_canonical_field_v1(&first_memory, &mut first, 7, b"value").unwrap();
        let second_memory =
            super::super::snapshot_publish::RuntimeMemoryEscrowV1::first_checkpoint();
        let mut second = Vec::new();
        push_canonical_field_v1(&second_memory, &mut second, 7, b"value").unwrap();
        assert_eq!(first, second);
        push_canonical_field_v1(&second_memory, &mut second, 8, b"mutation").unwrap();
        assert_ne!(first, second);
        assert_eq!(&first[..2], &7u16.to_be_bytes());
        assert_eq!(&first[2..6], &5u32.to_be_bytes());
    }

    #[test]
    fn checkpoint_nonclaims_are_explicit_and_fixed() {
        assert_eq!(FIRST_EXECUTE_ONLY_EXECUTABLE_V1, b".venv/bin/python");
        assert!(RUNTIME_CLOSURE_NONCLAIMS_V1.starts_with(b"PT_INTERP,DT_NEEDED"));
        assert!(RUNTIME_CLOSURE_NONCLAIMS_V1.ends_with(b"pytest:unqualified"));
    }

    #[test]
    fn terminal_permission_requires_regular_type_and_any_logical_execute_bit() {
        for mode in [0o100_100, 0o100_010, 0o100_001, 0o100_755] {
            assert!(terminal_is_logically_executable_v1(mode));
        }
        for mode in [0o100_644, 0o040_755, 0o120_777, 0] {
            assert!(!terminal_is_logically_executable_v1(mode));
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn checkpoint_is_linear_non_clone_non_copy() {
        trait AmbiguousIfClone<A> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}
        trait AmbiguousIfCopy<A> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
        impl<T: Copy> AmbiguousIfCopy<u8> for T {}
        <FirstExecuteOnlyRuntimeCheckpointV1<'static> as AmbiguousIfClone<_>>::probe();
        <FirstExecuteOnlyRuntimeCheckpointV1<'static> as AmbiguousIfCopy<_>>::probe();
        assert!(std::mem::needs_drop::<
            FirstExecuteOnlyRuntimeCheckpointV1<'static>,
        >());
    }
}
