//! Gate 3 descriptor-selected Python executable and runtime-forest checkpoints.
//!
//! This is intentionally narrower than a runtime closure. It consumes the
//! connector-issued workspace binding, resolves the fixed executable beneath
//! that bound snapshot, cross-checks every observed node against the charged
//! canonical manifest, and validates the snapshotted terminal bytes as an
//! executable x86_64 ELF. A second, still non-authoritative checkpoint can
//! resolve the canonical `PT_INTERP` and ordered `DT_NEEDED` closure beneath
//! separately supplied published workspace/runtime root descriptors. It never
//! consults an ambient pathname. Neither checkpoint qualifies the virtual
//! environment, pytest, isolation, execution, a cache candidate, or reuse.
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
use super::snapshot_publish::RuntimeMemoryEscrowV1;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_publish::VerifiedBoundNodeKindV1;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_tree::{SOURCE_TREE_REQUESTED_STATX_MASK_V1, SourceStatxV1};
use super::{Blake3Digest, FileContentDigest};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::{ExecutableChainDigest, NodeDigest};
use std::fmt;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::fd::BorrowedFd;

const FIRST_EXECUTE_ONLY_EXECUTABLE_V1: &[u8] = b".venv/bin/python";
const FIRST_EXECUTE_ONLY_RUNTIME_CHECKPOINT_DOMAIN_V1: &str =
    "again first execute-only runtime checkpoint v1";
const RUNTIME_CHECKPOINT_MAGIC_V1: &[u8; 8] = b"AGRTCP01";
const RUNTIME_CLOSURE_NONCLAIMS_V1: &[u8] =
    b"PT_INTERP,DT_NEEDED,runtime-forest,venv,pytest:unqualified";
const RUNTIME_FOREST_DOMAIN_V1: &str = "again execute-only runtime forest evidence v1";
const RUNTIME_FOREST_MAGIC_V1: &[u8; 8] = b"AGRTFR01";
const RUNTIME_FOREST_NONCLAIMS_V1: &[u8] =
    b"venv,pytest,isolation,execution,profile,candidate,replay,reuse:unauthorized";
const RUNTIME_FOREST_MAX_NODES_V1: usize = 128;
const RUNTIME_FOREST_MAX_DEPTH_V1: u16 = 32;
const RUNTIME_FOREST_MAX_EDGES_V1: usize = RUNTIME_FOREST_MAX_NODES_V1 * ELF64_MAX_NEEDED_NAMES;
const RUNTIME_FOREST_NODE_MAX_BYTES_V1: u32 = 16 * 1024 * 1024;
const RUNTIME_FOREST_TOTAL_MAX_BYTES_V1: u64 = 64 * 1024 * 1024;
const RUNTIME_FOREST_MAX_COMPONENTS_V1: usize = 64;
const RUNTIME_FOREST_OPERATION_LIMIT_V1: u32 = 262_144;
const RUNTIME_FOREST_SEARCH_DIRECTORIES_V1: [&[u8]; 6] = [
    b"lib64",
    b"usr/lib64",
    b"lib/x86_64-linux-gnu",
    b"usr/lib/x86_64-linux-gnu",
    b"lib",
    b"usr/lib",
];
const ELF64_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_MAX_PROGRAM_HEADERS: usize = 1024;
const ELF64_LOAD_PAGE_BYTES: u64 = 4096;
const ELF64_USER_VIRTUAL_LIMIT: u64 = 1 << 47;
const ELF64_MAX_MAPPING_SPAN: u64 = 4 * 1024 * 1024 * 1024;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_SYSV: u8 = 0;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const ELF64_DYNAMIC_ENTRY_BYTES: usize = 16;
const ELF64_MAX_DYNAMIC_BYTES: usize = 64 * 1024;
const ELF64_MAX_DYNAMIC_ENTRIES: usize = ELF64_MAX_DYNAMIC_BYTES / ELF64_DYNAMIC_ENTRY_BYTES;
const ELF64_MAX_INTERPRETER_BYTES: usize = 4096;
const ELF64_MAX_STRING_TABLE_BYTES: usize = 1024 * 1024;
const ELF64_MAX_NEEDED_NAMES: usize = 64;
const ELF64_MAX_NEEDED_NAME_BYTES: usize = 255;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
#[cfg(test)]
const DF_BIND_NOW: u64 = 0x8;
#[cfg(test)]
const DF_1_NODEFLIB: u64 = 0x800;

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
    ElfInterpreter,
    ElfDynamic,
    ElfDynamicTag,
    ElfStringTable,
    ElfNeeded,
    ElfRuntimeClosureLimit,
    RuntimeForestInvalidPath,
    RuntimeForestMissingObject,
    RuntimeForestAmbiguousObject,
    RuntimeForestSymlink,
    RuntimeForestNodeLimit,
    RuntimeForestDepthLimit,
    RuntimeForestByteLimit,
    RuntimeForestCycle,
    RuntimeForestRootMismatch,
    RuntimeForestOperationBudget,
    RuntimeForestUnsupportedPlatform,
    CanonicalOverflow,
    MemoryBudget,
}

const fn runtime_forest_platform_support_v1()
-> Result<(), FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok(())
    } else {
        Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestUnsupportedPlatform)
    }
}

/// A linear, unresolved description of the runtime objects named by the
/// descriptor-bound executable. Raw names are data only: a later checkpoint
/// must consume this request and bind every object to published descriptors.
/// This value cannot qualify loader search, a runtime forest, or execution.
pub(super) struct RuntimeClosureRequestV1 {
    interpreter: Vec<u8>,
    needed: Vec<Vec<u8>>,
}

impl fmt::Debug for RuntimeClosureRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeClosureRequestV1")
            .field("interpreter", &"<redacted-unresolved-path>")
            .field("needed_count", &self.needed.len())
            .field("resolution_authority", &false)
            .finish()
    }
}

impl Drop for RuntimeClosureRequestV1 {
    fn drop(&mut self) {
        self.interpreter.fill(0);
        for name in &mut self.needed {
            name.fill(0);
        }
    }
}

/// Opaque linear checkpoint for later Gate 3 composition. It retains the
/// original physical and charged manifest evidence and has no raw descriptor,
/// path, or byte accessor. It is checkpoint evidence, never execution or
/// reuse authority.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyRuntimeCheckpointV1<'resources> {
    _evidence: FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'resources>,
    _runtime_closure_request: RuntimeClosureRequestV1,
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
    let runtime_closure_request =
        parse_runtime_closure_request_v1(evidence.executable_bytes(), evidence.runtime_memory())?;

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
        _runtime_closure_request: runtime_closure_request,
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
    let mut previous_load_virtual_address = None;
    let mut first_load_page = None;
    let mut maximum_load_page_end = 0u64;
    for (index, header) in bytes[program_offset..table_end]
        .chunks_exact(program_entry_size)
        .enumerate()
    {
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
        let load_page = virtual_address & !(ELF64_LOAD_PAGE_BYTES - 1);
        let load_page_end = memory_end
            .checked_add(ELF64_LOAD_PAGE_BYTES - 1)
            .map(|end| end & !(ELF64_LOAD_PAGE_BYTES - 1))
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
        if file_size > memory_size
            || !(alignment == 0 || alignment == 1 || alignment.is_power_of_two())
            || (alignment > 1 && virtual_address % alignment != offset % alignment)
            || virtual_address % ELF64_LOAD_PAGE_BYTES != offset % ELF64_LOAD_PAGE_BYTES
            || virtual_address >= ELF64_USER_VIRTUAL_LIMIT
            || memory_end >= ELF64_USER_VIRTUAL_LIMIT
            || previous_load_virtual_address.is_some_and(|previous| virtual_address < previous)
        {
            return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader);
        }
        for previous in bytes[program_offset..program_offset + index * program_entry_size]
            .chunks_exact(program_entry_size)
        {
            if u32::from_le_bytes(previous[0..4].try_into().expect("bounded program header"))
                != PT_LOAD
            {
                continue;
            }
            let previous_offset =
                u64::from_le_bytes(previous[8..16].try_into().expect("bounded program header"));
            let previous_virtual_address =
                u64::from_le_bytes(previous[16..24].try_into().expect("bounded program header"));
            let previous_file_size =
                u64::from_le_bytes(previous[32..40].try_into().expect("bounded program header"));
            let previous_memory_size =
                u64::from_le_bytes(previous[40..48].try_into().expect("bounded program header"));
            let previous_file_end = previous_offset
                .checked_add(previous_file_size)
                .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
            let previous_memory_end = previous_virtual_address
                .checked_add(previous_memory_size)
                .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
            let previous_load_page = previous_virtual_address & !(ELF64_LOAD_PAGE_BYTES - 1);
            let previous_load_page_end = previous_memory_end
                .checked_add(ELF64_LOAD_PAGE_BYTES - 1)
                .map(|end| end & !(ELF64_LOAD_PAGE_BYTES - 1))
                .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
            let file_overlap = file_size != 0
                && previous_file_size != 0
                && offset < previous_file_end
                && previous_offset < file_end;
            // Linux maps PT_LOAD at page granularity. Byte-disjoint segments
            // that share a page can still replace that page's bias or final
            // permissions, so byte-range overlap alone is not sufficient.
            let virtual_page_overlap = memory_size != 0
                && previous_memory_size != 0
                && load_page < previous_load_page_end
                && previous_load_page < load_page_end;
            if file_overlap || virtual_page_overlap {
                return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader);
            }
        }
        previous_load_virtual_address = Some(virtual_address);
        let first_page = *first_load_page.get_or_insert(load_page);
        maximum_load_page_end = maximum_load_page_end.max(load_page_end);
        if maximum_load_page_end
            .checked_sub(first_page)
            .is_none_or(|span| span > ELF64_MAX_MAPPING_SPAN)
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

#[derive(Clone, Copy)]
struct Elf64ProgramHeaderV1 {
    kind: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn parse_program_header_v1(header: &[u8]) -> Elf64ProgramHeaderV1 {
    Elf64ProgramHeaderV1 {
        kind: u32::from_le_bytes(header[0..4].try_into().expect("bounded program header")),
        offset: u64::from_le_bytes(header[8..16].try_into().expect("bounded program header")),
        virtual_address: u64::from_le_bytes(
            header[16..24].try_into().expect("bounded program header"),
        ),
        file_size: u64::from_le_bytes(header[32..40].try_into().expect("bounded program header")),
        memory_size: u64::from_le_bytes(header[40..48].try_into().expect("bounded program header")),
        alignment: u64::from_le_bytes(header[48..56].try_into().expect("bounded program header")),
    }
}

fn program_headers_v1(bytes: &[u8]) -> Result<&[u8], FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let offset = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("validated ELF header"),
    ))
    .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
    let count = usize::from(u16::from_le_bytes(
        bytes[56..58].try_into().expect("validated ELF header"),
    ));
    let size = ELF64_PROGRAM_HEADER_BYTES
        .checked_mul(count)
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
    let end = offset
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)?;
    Ok(&bytes[offset..end])
}

fn bounded_segment_file_range_v1(
    segment: Elf64ProgramHeaderV1,
    bytes: &[u8],
    maximum: usize,
    refusal: FirstExecuteOnlyRuntimeCheckpointRefusalV1,
) -> Result<std::ops::Range<usize>, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let size = usize::try_from(segment.file_size).map_err(|_| refusal)?;
    if size == 0
        || size > maximum
        || segment.file_size > segment.memory_size
        || !(segment.alignment == 0
            || segment.alignment == 1
            || segment.alignment.is_power_of_two())
        || (segment.alignment > 1
            && segment.virtual_address % segment.alignment != segment.offset % segment.alignment)
    {
        return Err(refusal);
    }
    segment
        .virtual_address
        .checked_add(segment.memory_size)
        .filter(|end| *end < ELF64_USER_VIRTUAL_LIMIT)
        .ok_or(refusal)?;
    let start = usize::try_from(segment.offset).map_err(|_| refusal)?;
    let end = start
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or(refusal)?;
    Ok(start..end)
}

fn unique_load_file_range_v1(
    bytes: &[u8],
    headers: &[u8],
    virtual_address: u64,
    size: u64,
) -> Result<std::ops::Range<usize>, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let virtual_end = virtual_address
        .checked_add(size)
        .filter(|end| *end < ELF64_USER_VIRTUAL_LIMIT)
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)?;
    let mut matched = None;
    for raw in headers.chunks_exact(ELF64_PROGRAM_HEADER_BYTES) {
        let load = parse_program_header_v1(raw);
        if load.kind != PT_LOAD {
            continue;
        }
        let file_backed_end = load
            .virtual_address
            .checked_add(load.file_size)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)?;
        if virtual_address < load.virtual_address || virtual_end > file_backed_end {
            continue;
        }
        let delta = virtual_address - load.virtual_address;
        let file_start = load
            .offset
            .checked_add(delta)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)?;
        let file_end = file_start
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)?;
        let candidate = usize::try_from(file_start)
            .ok()
            .zip(usize::try_from(file_end).ok())
            .map(|(start, end)| start..end)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)?;
        if matched.replace(candidate).is_some() {
            return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable);
        }
    }
    matched.ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)
}

fn canonical_interpreter_path_v1(
    segment_bytes: &[u8],
) -> Result<&[u8], FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    if segment_bytes.len() < 2
        || segment_bytes.last() != Some(&0)
        || segment_bytes[..segment_bytes.len() - 1].contains(&0)
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter);
    }
    let path = &segment_bytes[..segment_bytes.len() - 1];
    if path.first() != Some(&b'/') || path.last() == Some(&b'/') {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter);
    }
    for component in path[1..].split(|byte| *byte == b'/') {
        if component.is_empty()
            || component.len() > ELF64_MAX_NEEDED_NAME_BYTES
            || component == b"."
            || component == b".."
        {
            return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter);
        }
    }
    Ok(path)
}

fn known_dynamic_tag_v1(tag: u64) -> bool {
    matches!(
        tag,
        0..=30
            | 32..=37
            | 0x6fff_fef5
            | 0x6fff_fff0
            | 0x6fff_fff9..=0x6fff_ffff
    )
}

fn dynamic_entries_v1(
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Result<&[u8], FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let dynamic = &bytes[range];
    if dynamic.is_empty()
        || dynamic.len() > ELF64_MAX_DYNAMIC_BYTES
        || dynamic.len() % ELF64_DYNAMIC_ENTRY_BYTES != 0
        || dynamic.len() / ELF64_DYNAMIC_ENTRY_BYTES > ELF64_MAX_DYNAMIC_ENTRIES
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic);
    }
    Ok(dynamic)
}

fn dynamic_tag_and_value_v1(entry: &[u8]) -> (u64, u64) {
    (
        u64::from_le_bytes(entry[0..8].try_into().expect("bounded dynamic entry")),
        u64::from_le_bytes(entry[8..16].try_into().expect("bounded dynamic entry")),
    )
}

fn needed_name_at_v1(
    string_table: &[u8],
    offset: usize,
) -> Result<&[u8], FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let tail = string_table
        .get(offset..)
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded)?;
    let name = &tail[..end];
    if name.is_empty()
        || name.len() > ELF64_MAX_NEEDED_NAME_BYTES
        || name.contains(&b'/')
        || name.contains(&b'$')
        || name == b"."
        || name == b".."
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded);
    }
    Ok(name)
}

fn parse_runtime_closure_request_v1(
    bytes: &[u8],
    memory: &RuntimeMemoryEscrowV1,
) -> Result<RuntimeClosureRequestV1, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    parse_runtime_object_request_v1(bytes, memory, true)
}

fn parse_runtime_object_request_v1(
    bytes: &[u8],
    memory: &RuntimeMemoryEscrowV1,
    is_executable: bool,
) -> Result<RuntimeClosureRequestV1, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    validate_x86_64_elf_v1(bytes)?;
    let headers = program_headers_v1(bytes)?;
    let mut interpreter = None;
    let mut dynamic = None;
    for raw in headers.chunks_exact(ELF64_PROGRAM_HEADER_BYTES) {
        let segment = parse_program_header_v1(raw);
        match segment.kind {
            PT_INTERP => {
                if interpreter.replace(segment).is_some() {
                    return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter);
                }
            }
            PT_DYNAMIC => {
                if dynamic.replace(segment).is_some() {
                    return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic);
                }
            }
            _ => {}
        }
    }
    let interpreter_path = match (is_executable, interpreter) {
        (true, Some(interpreter)) => {
            let interpreter_range = bounded_segment_file_range_v1(
                interpreter,
                bytes,
                ELF64_MAX_INTERPRETER_BYTES,
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter,
            )?;
            canonical_interpreter_path_v1(&bytes[interpreter_range])?
        }
        (false, None) => &[],
        _ => return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter),
    };

    let dynamic = dynamic.ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic)?;
    let dynamic_range = bounded_segment_file_range_v1(
        dynamic,
        bytes,
        ELF64_MAX_DYNAMIC_BYTES,
        FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic,
    )?;
    let translated_dynamic =
        unique_load_file_range_v1(bytes, headers, dynamic.virtual_address, dynamic.file_size)
            .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic)?;
    if translated_dynamic != dynamic_range {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic);
    }
    let dynamic_entries = dynamic_entries_v1(bytes, dynamic_range)?;

    let mut string_table_address = None;
    let mut string_table_size = None;
    let mut needed_count = 0usize;
    let mut terminated = false;
    let mut seen_singletons = [u64::MAX; 64];
    let mut singleton_count = 0usize;
    for entry in dynamic_entries.chunks_exact(ELF64_DYNAMIC_ENTRY_BYTES) {
        let (tag, value) = dynamic_tag_and_value_v1(entry);
        if tag == DT_NULL {
            terminated = true;
            continue;
        }
        let unmodeled_flags = matches!(tag, DT_FLAGS | DT_FLAGS_1) && value != 0;
        if terminated
            || tag == DT_RPATH
            || tag == DT_RUNPATH
            || unmodeled_flags
            || !known_dynamic_tag_v1(tag)
        {
            return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamicTag);
        }
        if tag != DT_NEEDED {
            if seen_singletons[..singleton_count].contains(&tag)
                || singleton_count == seen_singletons.len()
            {
                return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamicTag);
            }
            seen_singletons[singleton_count] = tag;
            singleton_count += 1;
        }
        match tag {
            DT_NEEDED => {
                needed_count = needed_count
                    .checked_add(1)
                    .filter(|count| *count <= ELF64_MAX_NEEDED_NAMES)
                    .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfRuntimeClosureLimit)?;
            }
            DT_STRTAB => string_table_address = Some(value),
            DT_STRSZ => string_table_size = Some(value),
            _ => {}
        }
    }
    if !terminated || (is_executable && needed_count == 0) {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic);
    }
    let string_table_address =
        string_table_address.ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)?;
    let string_table_size =
        string_table_size.ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable)?;
    let string_table_size_usize = usize::try_from(string_table_size)
        .ok()
        .filter(|size| *size != 0 && *size <= ELF64_MAX_STRING_TABLE_BYTES)
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfRuntimeClosureLimit)?;
    let string_table_range =
        unique_load_file_range_v1(bytes, headers, string_table_address, string_table_size)?;
    if string_table_range.len() != string_table_size_usize {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable);
    }
    let string_table = &bytes[string_table_range];

    let mut needed_offsets = [0usize; ELF64_MAX_NEEDED_NAMES];
    let mut needed_index = 0usize;
    for entry in dynamic_entries.chunks_exact(ELF64_DYNAMIC_ENTRY_BYTES) {
        let (tag, value) = dynamic_tag_and_value_v1(entry);
        if tag != DT_NEEDED {
            continue;
        }
        let offset = usize::try_from(value)
            .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded)?;
        let name = needed_name_at_v1(string_table, offset)?;
        for previous_offset in &needed_offsets[..needed_index] {
            if needed_name_at_v1(string_table, *previous_offset)? == name {
                return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded);
            }
        }
        needed_offsets[needed_index] = offset;
        needed_index += 1;
    }

    let needed = memory
        .try_vec_with_capacity(needed_count)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    let interpreter = memory
        .try_bytes_from_slice(interpreter_path)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    let mut request = RuntimeClosureRequestV1 {
        interpreter,
        needed,
    };
    for offset in &needed_offsets[..needed_index] {
        let name = needed_name_at_v1(string_table, *offset)?;
        request.needed.push(
            memory
                .try_bytes_from_slice(name)
                .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?,
        );
    }
    Ok(request)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeForestRootV1 {
    Workspace,
    Runtime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeForestReadRefusalV1 {
    Missing,
    Symlink,
    NodeType,
    IdentityDrift,
    ByteLimit,
    OperationBudget,
    Io,
    MemoryBudget,
}

struct RuntimeForestObservedObjectV1 {
    identity: [u8; 102],
    bytes: Vec<u8>,
}

impl Drop for RuntimeForestObservedObjectV1 {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

struct RuntimeForestOperationBudgetV1 {
    remaining: u32,
}

impl RuntimeForestOperationBudgetV1 {
    const fn new() -> Self {
        Self {
            remaining: RUNTIME_FOREST_OPERATION_LIMIT_V1,
        }
    }

    fn charge(&mut self) -> Result<(), RuntimeForestReadRefusalV1> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(RuntimeForestReadRefusalV1::OperationBudget)?;
        Ok(())
    }

    const fn consumed(&self) -> u32 {
        RUNTIME_FOREST_OPERATION_LIMIT_V1 - self.remaining
    }
}

trait RuntimeForestReaderV1 {
    fn read_object(
        &mut self,
        root: RuntimeForestRootV1,
        path: &[u8],
        byte_ceiling: u32,
        memory: &RuntimeMemoryEscrowV1,
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<RuntimeForestObservedObjectV1, RuntimeForestReadRefusalV1>;
}

struct RuntimeForestNodeV1 {
    root: RuntimeForestRootV1,
    path: Box<[u8]>,
    identity: [u8; 102],
    content_digest: Blake3Digest,
    depth: u16,
    request: RuntimeClosureRequestV1,
}

impl Drop for RuntimeForestNodeV1 {
    fn drop(&mut self) {
        self.path.fill(0);
    }
}

#[derive(Clone, Copy)]
struct RuntimeForestEdgeV1 {
    from: u16,
    to: u16,
    ordinal: u16,
}

struct RuntimeForestPlanV1 {
    nodes: Vec<RuntimeForestNodeV1>,
    edges: Vec<RuntimeForestEdgeV1>,
    canonical_bytes: Box<[u8]>,
    digest: Blake3Digest,
    total_bytes: u64,
    operation_count: u32,
}

impl fmt::Debug for RuntimeForestPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeForestPlanV1")
            .field("node_count", &self.nodes.len())
            .field("edge_count", &self.edges.len())
            .field("total_bytes", &self.total_bytes)
            .field("operation_count", &self.operation_count)
            .field("paths", &"<redacted>")
            .field("authority", &false)
            .finish()
    }
}

fn map_runtime_forest_read_refusal_v1(
    refusal: RuntimeForestReadRefusalV1,
) -> FirstExecuteOnlyRuntimeCheckpointRefusalV1 {
    match refusal {
        RuntimeForestReadRefusalV1::Missing => {
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestMissingObject
        }
        RuntimeForestReadRefusalV1::Symlink => {
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestSymlink
        }
        RuntimeForestReadRefusalV1::NodeType => {
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::NodeType
        }
        RuntimeForestReadRefusalV1::IdentityDrift => {
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::IdentityDrift
        }
        RuntimeForestReadRefusalV1::ByteLimit => {
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestByteLimit
        }
        RuntimeForestReadRefusalV1::OperationBudget => {
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestOperationBudget
        }
        RuntimeForestReadRefusalV1::Io => FirstExecuteOnlyRuntimeCheckpointRefusalV1::Io,
        RuntimeForestReadRefusalV1::MemoryBudget => {
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget
        }
    }
}

fn validate_runtime_forest_relative_path_v1(
    path: &[u8],
) -> Result<(), FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    if path.is_empty() || path[0] == b'/' || path.contains(&0) {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestInvalidPath);
    }
    let mut component_count = 0usize;
    for component in path.split(|byte| *byte == b'/') {
        component_count = component_count
            .checked_add(1)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestInvalidPath)?;
        if component.is_empty()
            || component == b"."
            || component == b".."
            || component.len() > ELF64_MAX_NEEDED_NAME_BYTES
            || component_count > RUNTIME_FOREST_MAX_COMPONENTS_V1
        {
            return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestInvalidPath);
        }
    }
    Ok(())
}

fn charged_runtime_forest_path_v1(
    memory: &RuntimeMemoryEscrowV1,
    directory: &[u8],
    name: &[u8],
) -> Result<Vec<u8>, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    if name.is_empty()
        || name.len() > ELF64_MAX_NEEDED_NAME_BYTES
        || name.contains(&0)
        || name.contains(&b'/')
        || name == b"."
        || name == b".."
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestInvalidPath);
    }
    let capacity = directory
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(name.len()))
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?;
    let mut path = memory
        .try_vec_with_capacity(capacity)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    path.extend_from_slice(directory);
    path.push(b'/');
    path.extend_from_slice(name);
    validate_runtime_forest_relative_path_v1(&path)?;
    Ok(path)
}

fn read_runtime_forest_object_v1<R: RuntimeForestReaderV1>(
    reader: &mut R,
    root: RuntimeForestRootV1,
    path: &[u8],
    memory: &RuntimeMemoryEscrowV1,
    operations: &mut RuntimeForestOperationBudgetV1,
) -> Result<RuntimeForestObservedObjectV1, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    validate_runtime_forest_relative_path_v1(path)?;
    operations
        .charge()
        .map_err(map_runtime_forest_read_refusal_v1)?;
    reader
        .read_object(
            root,
            path,
            RUNTIME_FOREST_NODE_MAX_BYTES_V1,
            memory,
            operations,
        )
        .map_err(map_runtime_forest_read_refusal_v1)
}

fn find_runtime_forest_node_v1(
    nodes: &[RuntimeForestNodeV1],
    root: RuntimeForestRootV1,
    path: &[u8],
) -> Option<usize> {
    nodes
        .iter()
        .position(|node| node.root == root && node.path.as_ref() == path)
}

fn resolve_needed_object_v1<R: RuntimeForestReaderV1>(
    reader: &mut R,
    name: &[u8],
    memory: &RuntimeMemoryEscrowV1,
    operations: &mut RuntimeForestOperationBudgetV1,
) -> Result<(Vec<u8>, RuntimeForestObservedObjectV1), FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let mut match_found = None;
    for directory in RUNTIME_FOREST_SEARCH_DIRECTORIES_V1 {
        let path = charged_runtime_forest_path_v1(memory, directory, name)?;
        match read_runtime_forest_object_v1(
            reader,
            RuntimeForestRootV1::Runtime,
            &path,
            memory,
            operations,
        ) {
            Ok(observed) => {
                if match_found.is_some() {
                    return Err(
                        FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestAmbiguousObject,
                    );
                }
                match_found = Some((path, observed));
            }
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestMissingObject) => {}
            Err(refusal) => return Err(refusal),
        }
    }
    match_found.ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestMissingObject)
}

fn checked_runtime_forest_total_bytes_v1(
    total: &mut u64,
    bytes: usize,
) -> Result<(), FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    *total = total
        .checked_add(
            u64::try_from(bytes)
                .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestByteLimit)?,
        )
        .filter(|total| *total <= RUNTIME_FOREST_TOTAL_MAX_BYTES_V1)
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestByteLimit)?;
    Ok(())
}

struct RuntimeForestNodeInputV1 {
    root: RuntimeForestRootV1,
    path: Vec<u8>,
    observed: RuntimeForestObservedObjectV1,
    depth: u16,
    is_executable: bool,
}

fn push_runtime_forest_node_v1(
    nodes: &mut Vec<RuntimeForestNodeV1>,
    input: RuntimeForestNodeInputV1,
    memory: &RuntimeMemoryEscrowV1,
    total_bytes: &mut u64,
) -> Result<usize, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    if nodes.len() >= RUNTIME_FOREST_MAX_NODES_V1 {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestNodeLimit);
    }
    if input.depth > RUNTIME_FOREST_MAX_DEPTH_V1 {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestDepthLimit);
    }
    checked_runtime_forest_total_bytes_v1(total_bytes, input.observed.bytes.len())?;
    let request =
        parse_runtime_object_request_v1(&input.observed.bytes, memory, input.is_executable)?;
    let content_digest = Blake3Digest::derive(
        "again runtime forest object content v1",
        &[&input.observed.bytes],
    );
    let index = nodes.len();
    nodes.push(RuntimeForestNodeV1 {
        root: input.root,
        path: input.path.into_boxed_slice(),
        identity: input.observed.identity,
        content_digest,
        depth: input.depth,
        request,
    });
    Ok(index)
}

fn verify_runtime_forest_acyclic_v1(
    nodes: &[RuntimeForestNodeV1],
    edges: &[RuntimeForestEdgeV1],
    memory: &RuntimeMemoryEscrowV1,
) -> Result<(), FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let mut indegree = memory
        .try_vec_with_capacity(nodes.len())
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    indegree.resize(nodes.len(), 0u16);
    for edge in edges {
        let target = usize::from(edge.to);
        indegree[target] = indegree[target]
            .checked_add(1)
            .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestNodeLimit)?;
    }
    let mut removed = memory
        .try_vec_with_capacity(nodes.len())
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    removed.resize(nodes.len(), false);
    let mut count = 0usize;
    loop {
        let next = indegree
            .iter()
            .enumerate()
            .find(|(index, degree)| !removed[*index] && **degree == 0)
            .map(|(index, _)| index);
        let Some(next) = next else {
            break;
        };
        removed[next] = true;
        count += 1;
        for edge in edges.iter().filter(|edge| usize::from(edge.from) == next) {
            let target = usize::from(edge.to);
            indegree[target] = indegree[target]
                .checked_sub(1)
                .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestCycle)?;
        }
    }
    if count != nodes.len() {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestCycle);
    }
    Ok(())
}

fn encode_runtime_forest_v1(
    nodes: &[RuntimeForestNodeV1],
    edges: &[RuntimeForestEdgeV1],
    total_bytes: u64,
    memory: &RuntimeMemoryEscrowV1,
) -> Result<Vec<u8>, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let mut output = runtime_vec_v1(memory, RUNTIME_FOREST_MAGIC_V1.len())?;
    memory
        .try_extend_bytes(&mut output, RUNTIME_FOREST_MAGIC_V1)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    push_canonical_field_v1(memory, &mut output, 1, RUNTIME_FOREST_NONCLAIMS_V1)?;
    push_canonical_field_v1(
        memory,
        &mut output,
        2,
        &u16::try_from(nodes.len())
            .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?
            .to_be_bytes(),
    )?;
    push_canonical_field_v1(
        memory,
        &mut output,
        3,
        &u16::try_from(edges.len())
            .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?
            .to_be_bytes(),
    )?;
    push_canonical_field_v1(memory, &mut output, 4, &total_bytes.to_be_bytes())?;
    for (index, node) in nodes.iter().enumerate() {
        let mut encoded = runtime_vec_v1(memory, 0)?;
        push_canonical_field_v1(
            memory,
            &mut encoded,
            1,
            &u16::try_from(index)
                .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?
                .to_be_bytes(),
        )?;
        let root = match node.root {
            RuntimeForestRootV1::Workspace => 1,
            RuntimeForestRootV1::Runtime => 2,
        };
        push_canonical_field_v1(memory, &mut encoded, 2, &[root])?;
        push_canonical_field_v1(memory, &mut encoded, 3, &node.path)?;
        push_canonical_field_v1(memory, &mut encoded, 4, &node.identity)?;
        push_canonical_field_v1(memory, &mut encoded, 5, node.content_digest.as_bytes())?;
        push_canonical_field_v1(memory, &mut encoded, 6, &node.depth.to_be_bytes())?;
        push_canonical_field_v1(
            memory,
            &mut encoded,
            7,
            &u16::try_from(node.request.needed.len())
                .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?
                .to_be_bytes(),
        )?;
        push_canonical_field_v1(memory, &mut output, 10, &encoded)?;
    }
    for edge in edges {
        let mut encoded = [0u8; 6];
        encoded[0..2].copy_from_slice(&edge.from.to_be_bytes());
        encoded[2..4].copy_from_slice(&edge.to.to_be_bytes());
        encoded[4..6].copy_from_slice(&edge.ordinal.to_be_bytes());
        push_canonical_field_v1(memory, &mut output, 11, &encoded)?;
    }
    Ok(output)
}

fn build_runtime_forest_plan_v1<R: RuntimeForestReaderV1>(
    reader: &mut R,
    expected_root_content: Option<FileContentDigest>,
    expected_root_request: Option<(&[u8], &[Vec<u8>])>,
    memory: &RuntimeMemoryEscrowV1,
) -> Result<RuntimeForestPlanV1, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
    let mut operations = RuntimeForestOperationBudgetV1::new();
    let mut total_bytes = 0u64;
    let mut nodes = runtime_vec_v1(memory, RUNTIME_FOREST_MAX_NODES_V1)?;
    let mut edges = runtime_vec_v1(memory, RUNTIME_FOREST_MAX_EDGES_V1)?;
    let executable_path = memory
        .try_bytes_from_slice(FIRST_EXECUTE_ONLY_EXECUTABLE_V1)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    let executable = read_runtime_forest_object_v1(
        reader,
        RuntimeForestRootV1::Workspace,
        &executable_path,
        memory,
        &mut operations,
    )?;
    if let Some(expected) = expected_root_content
        && FileContentDigest::derive(super::FILE_CONTENT_DOMAIN, &[&executable.bytes]) != expected
    {
        return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestRootMismatch);
    }
    let root_index = push_runtime_forest_node_v1(
        &mut nodes,
        RuntimeForestNodeInputV1 {
            root: RuntimeForestRootV1::Workspace,
            path: executable_path,
            observed: executable,
            depth: 0,
            is_executable: true,
        },
        memory,
        &mut total_bytes,
    )?;
    debug_assert_eq!(root_index, 0);
    if let Some((interpreter, needed)) = expected_root_request {
        let observed = &nodes[0].request;
        if observed.interpreter != interpreter || observed.needed.as_slice() != needed {
            return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestRootMismatch);
        }
    }

    let interpreter = nodes[0]
        .request
        .interpreter
        .strip_prefix(b"/")
        .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestInvalidPath)?;
    validate_runtime_forest_relative_path_v1(interpreter)?;
    let interpreter_path = memory
        .try_bytes_from_slice(interpreter)
        .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
    let interpreter_observed = read_runtime_forest_object_v1(
        reader,
        RuntimeForestRootV1::Runtime,
        &interpreter_path,
        memory,
        &mut operations,
    )?;
    let interpreter_index = push_runtime_forest_node_v1(
        &mut nodes,
        RuntimeForestNodeInputV1 {
            root: RuntimeForestRootV1::Runtime,
            path: interpreter_path,
            observed: interpreter_observed,
            depth: 1,
            is_executable: false,
        },
        memory,
        &mut total_bytes,
    )?;
    edges.push(RuntimeForestEdgeV1 {
        from: 0,
        to: u16::try_from(interpreter_index)
            .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?,
        ordinal: 0,
    });

    let mut cursor = 0usize;
    while cursor < nodes.len() {
        let depth = nodes[cursor].depth;
        let needed_count = nodes[cursor].request.needed.len();
        for ordinal in 0..needed_count {
            let needed = memory
                .try_bytes_from_slice(&nodes[cursor].request.needed[ordinal])
                .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget)?;
            let (path, observed) =
                resolve_needed_object_v1(reader, &needed, memory, &mut operations)?;
            let content_digest =
                Blake3Digest::derive("again runtime forest object content v1", &[&observed.bytes]);
            let target = if let Some(existing) =
                find_runtime_forest_node_v1(&nodes, RuntimeForestRootV1::Runtime, &path)
            {
                if nodes[existing].identity != observed.identity
                    || nodes[existing].content_digest != content_digest
                {
                    return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::IdentityDrift);
                }
                existing
            } else {
                let child_depth = depth
                    .checked_add(1)
                    .ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestDepthLimit)?;
                push_runtime_forest_node_v1(
                    &mut nodes,
                    RuntimeForestNodeInputV1 {
                        root: RuntimeForestRootV1::Runtime,
                        path,
                        observed,
                        depth: child_depth,
                        is_executable: false,
                    },
                    memory,
                    &mut total_bytes,
                )?
            };
            if edges.len() == RUNTIME_FOREST_MAX_EDGES_V1 {
                return Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestNodeLimit);
            }
            edges.push(RuntimeForestEdgeV1 {
                from: u16::try_from(cursor)
                    .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?,
                to: u16::try_from(target)
                    .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?,
                ordinal: u16::try_from(ordinal + 1)
                    .map_err(|_| FirstExecuteOnlyRuntimeCheckpointRefusalV1::CanonicalOverflow)?,
            });
        }
        cursor += 1;
    }
    verify_runtime_forest_acyclic_v1(&nodes, &edges, memory)?;
    let operation_count = operations.consumed();
    // Retry and missing-candidate operation counts are retained as bounded
    // evidence, but excluded from the semantic digest so transient `EAGAIN`
    // retries cannot perturb an otherwise identical forest.
    let canonical = encode_runtime_forest_v1(&nodes, &edges, total_bytes, memory)?;
    let digest = Blake3Digest::derive(RUNTIME_FOREST_DOMAIN_V1, &[&canonical]);
    Ok(RuntimeForestPlanV1 {
        nodes,
        edges,
        canonical_bytes: canonical.into_boxed_slice(),
        digest,
        total_bytes,
        operation_count,
    })
}

/// Descriptor borrows held by the future connector while it consumes the
/// first runtime checkpoint. Construction proves no immutability on its own;
/// the forest leaf revalidates every object and remains non-authoritative.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct PublishedRuntimeForestRootsV1<'roots> {
    workspace: BorrowedFd<'roots>,
    runtime: BorrowedFd<'roots>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<'roots> PublishedRuntimeForestRootsV1<'roots> {
    pub(super) const fn from_connector_owned_roots(
        workspace: BorrowedFd<'roots>,
        runtime: BorrowedFd<'roots>,
    ) -> Self {
        Self { workspace, runtime }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for PublishedRuntimeForestRootsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublishedRuntimeForestRootsV1(<redacted-descriptors>)")
    }
}

/// Opaque immutable evidence that the exact root executable's bounded loader
/// forest was observed beneath connector-selected descriptors. It deliberately
/// carries no descriptor/path/byte accessor and grants no authority.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyRuntimeForestEvidenceV1<'resources> {
    _checkpoint: FirstExecuteOnlyRuntimeCheckpointV1<'resources>,
    plan: RuntimeForestPlanV1,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl FirstExecuteOnlyRuntimeForestEvidenceV1<'_> {
    pub(super) const fn digest(&self) -> Blake3Digest {
        self.plan.digest
    }

    pub(super) fn node_count(&self) -> u16 {
        u16::try_from(self.plan.nodes.len()).expect("runtime forest node bound fits u16")
    }

    pub(super) fn edge_count(&self) -> u16 {
        u16::try_from(self.plan.edges.len()).expect("runtime forest edge bound fits u16")
    }

    pub(super) const fn total_bytes(&self) -> u64 {
        self.plan.total_bytes
    }

    pub(super) const fn operation_count(&self) -> u32 {
        self.plan.operation_count
    }

    pub(super) const fn execution_authority(&self) -> bool {
        false
    }

    pub(super) const fn profile_authority(&self) -> bool {
        false
    }

    pub(super) const fn isolation_authority(&self) -> bool {
        false
    }

    pub(super) const fn command_authority(&self) -> bool {
        false
    }

    pub(super) const fn candidate_authority(&self) -> bool {
        false
    }

    pub(super) const fn replay_authority(&self) -> bool {
        false
    }

    pub(super) const fn reuse_authority(&self) -> bool {
        false
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for FirstExecuteOnlyRuntimeForestEvidenceV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstExecuteOnlyRuntimeForestEvidenceV1")
            .field("plan", &self.plan)
            .field("canonical", &"<redacted>")
            .field("authority", &false)
            .finish()
    }
}

/// Later connector seam: consume the descriptor-bound executable checkpoint
/// and two still-live published-root borrows into non-authoritative forest
/// evidence. The descriptors never enter the result.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn qualify_first_execute_only_runtime_forest_v1<'resources>(
    checkpoint: FirstExecuteOnlyRuntimeCheckpointV1<'resources>,
    roots: PublishedRuntimeForestRootsV1<'_>,
) -> Result<
    FirstExecuteOnlyRuntimeForestEvidenceV1<'resources>,
    FirstExecuteOnlyRuntimeCheckpointRefusalV1,
> {
    runtime_forest_platform_support_v1()?;
    let mut reader = linux_runtime_forest::LinuxRuntimeForestReaderV1::new(roots);
    let plan = {
        let expected_content = checkpoint.terminal_content_digest;
        let expected_request = (
            checkpoint._runtime_closure_request.interpreter.as_slice(),
            checkpoint._runtime_closure_request.needed.as_slice(),
        );
        build_runtime_forest_plan_v1(
            &mut reader,
            Some(expected_content),
            Some(expected_request),
            checkpoint._evidence.runtime_memory(),
        )?
    };
    Ok(FirstExecuteOnlyRuntimeForestEvidenceV1 {
        _checkpoint: checkpoint,
        plan,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_runtime_forest {
    use super::*;
    use std::ffi::CStr;
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    const RUNTIME_RESOLVE_V1: u64 = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const OPENAT2_ATTEMPTS_V1: u8 = 4;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenHowV1 {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    pub(super) struct LinuxRuntimeForestReaderV1<'roots> {
        roots: PublishedRuntimeForestRootsV1<'roots>,
        workspace_identity: Option<[u8; 102]>,
        runtime_identity: Option<[u8; 102]>,
    }

    impl<'roots> LinuxRuntimeForestReaderV1<'roots> {
        pub(super) const fn new(roots: PublishedRuntimeForestRootsV1<'roots>) -> Self {
            Self {
                roots,
                workspace_identity: None,
                runtime_identity: None,
            }
        }

        fn root(&self, root: RuntimeForestRootV1) -> BorrowedFd<'roots> {
            match root {
                RuntimeForestRootV1::Workspace => self.roots.workspace,
                RuntimeForestRootV1::Runtime => self.roots.runtime,
            }
        }
    }

    impl RuntimeForestReaderV1 for LinuxRuntimeForestReaderV1<'_> {
        fn read_object(
            &mut self,
            root: RuntimeForestRootV1,
            path: &[u8],
            byte_ceiling: u32,
            memory: &RuntimeMemoryEscrowV1,
            operations: &mut RuntimeForestOperationBudgetV1,
        ) -> Result<RuntimeForestObservedObjectV1, RuntimeForestReadRefusalV1> {
            let root_fd = self.root(root);
            let before = statx_fd_v1(root_fd, operations)?.commitment_bytes_v1();
            let expected = match root {
                RuntimeForestRootV1::Workspace => &mut self.workspace_identity,
                RuntimeForestRootV1::Runtime => &mut self.runtime_identity,
            };
            if expected.is_some_and(|expected| expected != before) {
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
            expected.get_or_insert(before);
            let result =
                read_descriptor_relative_object_v1(root_fd, path, byte_ceiling, memory, operations);
            let after = statx_fd_v1(root_fd, operations)?.commitment_bytes_v1();
            if after != before {
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
            result
        }
    }

    fn component_cstr_v1<'storage>(
        component: &[u8],
        storage: &'storage mut [u8; 256],
    ) -> &'storage CStr {
        debug_assert!(!component.is_empty() && component.len() < storage.len());
        storage.fill(0);
        storage[..component.len()].copy_from_slice(component);
        CStr::from_bytes_until_nul(storage).expect("validated component has stack terminator")
    }

    fn statx_fd_v1(
        fd: BorrowedFd<'_>,
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<SourceStatxV1, RuntimeForestReadRefusalV1> {
        statx_v1(fd, c"", AT_EMPTY_PATH, operations)
    }

    fn statx_name_v1(
        parent: BorrowedFd<'_>,
        name: &CStr,
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<SourceStatxV1, RuntimeForestReadRefusalV1> {
        statx_v1(parent, name, libc::AT_SYMLINK_NOFOLLOW, operations)
    }

    fn statx_v1(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<SourceStatxV1, RuntimeForestReadRefusalV1> {
        operations.charge()?;
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                parent.as_raw_fd(),
                name.as_ptr(),
                flags,
                SOURCE_TREE_REQUESTED_STATX_MASK_V1,
                raw.as_mut_ptr(),
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::ENOENT) => RuntimeForestReadRefusalV1::Missing,
                Some(libc::ELOOP) => RuntimeForestReadRefusalV1::Symlink,
                _ => RuntimeForestReadRefusalV1::Io,
            });
        }
        let raw = unsafe { raw.assume_init() };
        SourceStatxV1::from_linux_statx_v1(&raw).map_err(|_| RuntimeForestReadRefusalV1::Io)
    }

    fn openat2_component_v1(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<OwnedFd, RuntimeForestReadRefusalV1> {
        let how = OpenHowV1 {
            flags: flags as u64,
            mode: 0,
            resolve: RUNTIME_RESOLVE_V1,
        };
        for attempt in 0..OPENAT2_ATTEMPTS_V1 {
            operations.charge()?;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    &how,
                    mem::size_of::<OpenHowV1>(),
                )
            };
            if result >= 0 {
                return Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) });
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EAGAIN) if attempt + 1 < OPENAT2_ATTEMPTS_V1 => continue,
                Some(libc::ENOENT) => return Err(RuntimeForestReadRefusalV1::Missing),
                Some(libc::ELOOP) => return Err(RuntimeForestReadRefusalV1::Symlink),
                _ => return Err(RuntimeForestReadRefusalV1::Io),
            }
        }
        Err(RuntimeForestReadRefusalV1::Io)
    }

    fn revalidate_ancestors_v1(
        root: BorrowedFd<'_>,
        root_identity: &[u8; 102],
        ancestors: &[(OwnedFd, [u8; 102])],
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<(), RuntimeForestReadRefusalV1> {
        if statx_fd_v1(root, operations)?.commitment_bytes_v1() != *root_identity {
            return Err(RuntimeForestReadRefusalV1::IdentityDrift);
        }
        for (fd, identity) in ancestors {
            if statx_fd_v1(fd.as_fd(), operations)?.commitment_bytes_v1() != *identity {
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
        }
        Ok(())
    }

    fn pread_exact_v1(
        fd: BorrowedFd<'_>,
        size: usize,
        memory: &RuntimeMemoryEscrowV1,
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<Vec<u8>, RuntimeForestReadRefusalV1> {
        let mut bytes = memory
            .try_vec_with_capacity(size)
            .map_err(|_| RuntimeForestReadRefusalV1::MemoryBudget)?;
        bytes.resize(size, 0);
        let mut offset = 0usize;
        while offset < size {
            operations.charge()?;
            let count = unsafe {
                libc::pread(
                    fd.as_raw_fd(),
                    bytes[offset..].as_mut_ptr().cast(),
                    size - offset,
                    offset as libc::off_t,
                )
            };
            if count < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                bytes.fill(0);
                return Err(RuntimeForestReadRefusalV1::Io);
            }
            if count == 0 {
                bytes.fill(0);
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
            offset = offset
                .checked_add(usize::try_from(count).map_err(|_| RuntimeForestReadRefusalV1::Io)?)
                .ok_or(RuntimeForestReadRefusalV1::Io)?;
        }
        operations.charge()?;
        let mut extra = 0u8;
        let count = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                (&mut extra as *mut u8).cast(),
                1,
                size as libc::off_t,
            )
        };
        if count < 0 {
            bytes.fill(0);
            return Err(RuntimeForestReadRefusalV1::Io);
        }
        if count != 0 {
            bytes.fill(0);
            return Err(RuntimeForestReadRefusalV1::IdentityDrift);
        }
        Ok(bytes)
    }

    fn read_descriptor_relative_object_v1(
        root: BorrowedFd<'_>,
        path: &[u8],
        byte_ceiling: u32,
        memory: &RuntimeMemoryEscrowV1,
        operations: &mut RuntimeForestOperationBudgetV1,
    ) -> Result<RuntimeForestObservedObjectV1, RuntimeForestReadRefusalV1> {
        validate_runtime_forest_relative_path_v1(path)
            .map_err(|_| RuntimeForestReadRefusalV1::Io)?;
        let root_before = statx_fd_v1(root, operations)?;
        if root_before.mode() & libc::S_IFMT != libc::S_IFDIR {
            return Err(RuntimeForestReadRefusalV1::NodeType);
        }
        let root_identity = root_before.commitment_bytes_v1();
        let component_count = path.split(|byte| *byte == b'/').count();
        let mut ancestors = memory
            .try_vec_with_capacity(component_count.saturating_sub(1))
            .map_err(|_| RuntimeForestReadRefusalV1::MemoryBudget)?;
        let mut parent = root;
        for (index, component) in path.split(|byte| *byte == b'/').enumerate() {
            let terminal = index + 1 == component_count;
            revalidate_ancestors_v1(root, &root_identity, &ancestors, operations)?;
            let mut name_storage = [0u8; 256];
            let name = component_cstr_v1(component, &mut name_storage);
            let before = statx_name_v1(parent, name, operations)?;
            let kind = before.mode() & libc::S_IFMT;
            if kind == libc::S_IFLNK {
                return Err(RuntimeForestReadRefusalV1::Symlink);
            }
            let path_fd = openat2_component_v1(
                parent,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                operations,
            )?;
            let opened = statx_fd_v1(path_fd.as_fd(), operations)?;
            if before.commitment_bytes_v1() != opened.commitment_bytes_v1() {
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
            if !terminal {
                if kind != libc::S_IFDIR {
                    return Err(RuntimeForestReadRefusalV1::NodeType);
                }
                ancestors.push((path_fd, before.commitment_bytes_v1()));
                parent = ancestors.last().expect("just pushed ancestor").0.as_fd();
                continue;
            }
            if kind != libc::S_IFREG || before.nlink() != 1 {
                return Err(RuntimeForestReadRefusalV1::NodeType);
            }
            let size = usize::try_from(before.size())
                .map_err(|_| RuntimeForestReadRefusalV1::ByteLimit)?;
            if size > byte_ceiling as usize {
                return Err(RuntimeForestReadRefusalV1::ByteLimit);
            }
            let read_fd = openat2_component_v1(
                parent,
                name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_CLOEXEC,
                operations,
            )?;
            let read_opened = statx_fd_v1(read_fd.as_fd(), operations)?;
            if before.commitment_bytes_v1() != read_opened.commitment_bytes_v1() {
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
            let bytes = pread_exact_v1(read_fd.as_fd(), size, memory, operations)?;
            if statx_fd_v1(read_fd.as_fd(), operations)?.commitment_bytes_v1()
                != before.commitment_bytes_v1()
                || statx_name_v1(parent, name, operations)?.commitment_bytes_v1()
                    != before.commitment_bytes_v1()
            {
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
            revalidate_ancestors_v1(root, &root_identity, &ancestors, operations)?;
            return Ok(RuntimeForestObservedObjectV1 {
                identity: before.commitment_bytes_v1(),
                bytes,
            });
        }
        Err(RuntimeForestReadRefusalV1::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNTIME_FIXTURE_BASE: u64 = 0x40_0000;
    const RUNTIME_FIXTURE_INTERP_OFFSET: usize = 0x100;
    const RUNTIME_FIXTURE_DYNAMIC_OFFSET: usize = 0x140;
    const RUNTIME_FIXTURE_STRTAB_OFFSET: usize = 0x1a0;

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

    fn append_second_load(
        bytes: &mut Vec<u8>,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
    ) {
        let second_start = ELF64_HEADER_BYTES + ELF64_PROGRAM_HEADER_BYTES;
        bytes.resize(ELF64_HEADER_BYTES + 2 * ELF64_PROGRAM_HEADER_BYTES, 0);
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        let program = &mut bytes[second_start..second_start + ELF64_PROGRAM_HEADER_BYTES];
        program[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        program[4..8].copy_from_slice(&4u32.to_le_bytes());
        program[8..16].copy_from_slice(&offset.to_le_bytes());
        program[16..24].copy_from_slice(&virtual_address.to_le_bytes());
        program[32..40].copy_from_slice(&file_size.to_le_bytes());
        program[40..48].copy_from_slice(&memory_size.to_le_bytes());
        program[48..56].copy_from_slice(&1u64.to_le_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    fn write_program_header(
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

    fn write_dynamic_entry(bytes: &mut [u8], index: usize, tag: u64, value: u64) {
        let start = RUNTIME_FIXTURE_DYNAMIC_OFFSET + index * ELF64_DYNAMIC_ENTRY_BYTES;
        bytes[start..start + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn runtime_closure_elf_fixture() -> Vec<u8> {
        const INTERPRETER: &[u8] = b"/lib64/ld-linux-x86-64.so.2\0";
        const STRING_TABLE: &[u8] = b"\0libc.so.6\0libm.so.6\0";
        const FILE_BYTES: usize = 512;
        const DYNAMIC_BYTES: usize = 5 * ELF64_DYNAMIC_ENTRY_BYTES;

        let mut bytes = vec![0u8; FILE_BYTES];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[7] = ELFOSABI_SYSV;
        bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&RUNTIME_FIXTURE_BASE.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF64_HEADER_BYTES as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
        write_program_header(
            &mut bytes,
            0,
            PT_LOAD,
            PF_X | 4,
            0,
            RUNTIME_FIXTURE_BASE,
            FILE_BYTES as u64,
            FILE_BYTES as u64,
            ELF64_LOAD_PAGE_BYTES,
        );
        write_program_header(
            &mut bytes,
            1,
            PT_INTERP,
            4,
            RUNTIME_FIXTURE_INTERP_OFFSET as u64,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_INTERP_OFFSET as u64,
            INTERPRETER.len() as u64,
            INTERPRETER.len() as u64,
            1,
        );
        write_program_header(
            &mut bytes,
            2,
            PT_DYNAMIC,
            4,
            RUNTIME_FIXTURE_DYNAMIC_OFFSET as u64,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_DYNAMIC_OFFSET as u64,
            DYNAMIC_BYTES as u64,
            DYNAMIC_BYTES as u64,
            8,
        );
        bytes[RUNTIME_FIXTURE_INTERP_OFFSET..RUNTIME_FIXTURE_INTERP_OFFSET + INTERPRETER.len()]
            .copy_from_slice(INTERPRETER);
        bytes[RUNTIME_FIXTURE_STRTAB_OFFSET..RUNTIME_FIXTURE_STRTAB_OFFSET + STRING_TABLE.len()]
            .copy_from_slice(STRING_TABLE);
        write_dynamic_entry(&mut bytes, 0, DT_NEEDED, 1);
        write_dynamic_entry(&mut bytes, 1, DT_NEEDED, 11);
        write_dynamic_entry(
            &mut bytes,
            2,
            DT_STRTAB,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_STRTAB_OFFSET as u64,
        );
        write_dynamic_entry(&mut bytes, 3, DT_STRSZ, STRING_TABLE.len() as u64);
        write_dynamic_entry(&mut bytes, 4, DT_NULL, 0);
        bytes
    }

    fn parse_runtime_fixture(
        bytes: &[u8],
    ) -> Result<RuntimeClosureRequestV1, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
        parse_runtime_closure_request_v1(
            bytes,
            &super::super::snapshot_publish::RuntimeMemoryEscrowV1::first_checkpoint(),
        )
    }

    fn write_dynamic_entry_at(
        bytes: &mut [u8],
        dynamic_offset: usize,
        index: usize,
        tag: u64,
        value: u64,
    ) {
        let start = dynamic_offset + index * ELF64_DYNAMIC_ENTRY_BYTES;
        bytes[start..start + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn forest_elf_fixture(interpreter: Option<&[u8]>, needed: &[&[u8]]) -> Vec<u8> {
        const INTERPRETER_OFFSET: usize = 0x200;
        const DYNAMIC_OFFSET: usize = 0x400;
        const STRING_TABLE_OFFSET: usize = 0x1000;

        let mut string_table = vec![0u8];
        let mut offsets = Vec::new();
        for name in needed {
            offsets.push(string_table.len());
            string_table.extend_from_slice(name);
            string_table.push(0);
        }
        let dynamic_count = needed.len() + 3;
        let dynamic_bytes = dynamic_count * ELF64_DYNAMIC_ENTRY_BYTES;
        let interpreter_bytes = interpreter.map_or(0, |path| path.len() + 1);
        let file_bytes = 8192usize
            .max(DYNAMIC_OFFSET + dynamic_bytes)
            .max(STRING_TABLE_OFFSET + string_table.len())
            .max(INTERPRETER_OFFSET + interpreter_bytes);
        let program_count = if interpreter.is_some() { 3 } else { 2 };
        let mut bytes = vec![0u8; file_bytes];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[7] = ELFOSABI_SYSV;
        bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(RUNTIME_FIXTURE_BASE + 0x100).to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF64_HEADER_BYTES as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(program_count as u16).to_le_bytes());
        write_program_header(
            &mut bytes,
            0,
            PT_LOAD,
            PF_X | 4,
            0,
            RUNTIME_FIXTURE_BASE,
            file_bytes as u64,
            file_bytes as u64,
            ELF64_LOAD_PAGE_BYTES,
        );
        let dynamic_index = if let Some(interpreter) = interpreter {
            let mut interpreter_with_nul = interpreter.to_vec();
            interpreter_with_nul.push(0);
            bytes[INTERPRETER_OFFSET..INTERPRETER_OFFSET + interpreter_with_nul.len()]
                .copy_from_slice(&interpreter_with_nul);
            write_program_header(
                &mut bytes,
                1,
                PT_INTERP,
                4,
                INTERPRETER_OFFSET as u64,
                RUNTIME_FIXTURE_BASE + INTERPRETER_OFFSET as u64,
                interpreter_with_nul.len() as u64,
                interpreter_with_nul.len() as u64,
                1,
            );
            2
        } else {
            1
        };
        write_program_header(
            &mut bytes,
            dynamic_index,
            PT_DYNAMIC,
            4,
            DYNAMIC_OFFSET as u64,
            RUNTIME_FIXTURE_BASE + DYNAMIC_OFFSET as u64,
            dynamic_bytes as u64,
            dynamic_bytes as u64,
            8,
        );
        bytes[STRING_TABLE_OFFSET..STRING_TABLE_OFFSET + string_table.len()]
            .copy_from_slice(&string_table);
        for (index, offset) in offsets.into_iter().enumerate() {
            write_dynamic_entry_at(&mut bytes, DYNAMIC_OFFSET, index, DT_NEEDED, offset as u64);
        }
        write_dynamic_entry_at(
            &mut bytes,
            DYNAMIC_OFFSET,
            needed.len(),
            DT_STRTAB,
            RUNTIME_FIXTURE_BASE + STRING_TABLE_OFFSET as u64,
        );
        write_dynamic_entry_at(
            &mut bytes,
            DYNAMIC_OFFSET,
            needed.len() + 1,
            DT_STRSZ,
            string_table.len() as u64,
        );
        write_dynamic_entry_at(&mut bytes, DYNAMIC_OFFSET, needed.len() + 2, DT_NULL, 0);
        bytes
    }

    #[derive(Clone)]
    struct FakeForestEntryV1 {
        root: RuntimeForestRootV1,
        path: Vec<u8>,
        identity: [u8; 102],
        bytes: Vec<u8>,
    }

    struct FakeForestReaderV1 {
        entries: Vec<FakeForestEntryV1>,
        calls: usize,
        drift_on_call: Option<usize>,
    }

    impl RuntimeForestReaderV1 for FakeForestReaderV1 {
        fn read_object(
            &mut self,
            root: RuntimeForestRootV1,
            path: &[u8],
            byte_ceiling: u32,
            memory: &RuntimeMemoryEscrowV1,
            _operations: &mut RuntimeForestOperationBudgetV1,
        ) -> Result<RuntimeForestObservedObjectV1, RuntimeForestReadRefusalV1> {
            self.calls += 1;
            if self.drift_on_call == Some(self.calls) {
                return Err(RuntimeForestReadRefusalV1::IdentityDrift);
            }
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.root == root && entry.path == path)
                .ok_or(RuntimeForestReadRefusalV1::Missing)?;
            if entry.bytes.len() > byte_ceiling as usize {
                return Err(RuntimeForestReadRefusalV1::ByteLimit);
            }
            Ok(RuntimeForestObservedObjectV1 {
                identity: entry.identity,
                bytes: memory
                    .try_bytes_from_slice(&entry.bytes)
                    .map_err(|_| RuntimeForestReadRefusalV1::MemoryBudget)?,
            })
        }
    }

    fn fake_forest_entry(
        index: u8,
        root: RuntimeForestRootV1,
        path: &[u8],
        bytes: Vec<u8>,
    ) -> FakeForestEntryV1 {
        let mut identity = [index; 102];
        identity[0] = 1;
        FakeForestEntryV1 {
            root,
            path: path.to_vec(),
            identity,
            bytes,
        }
    }

    fn representative_forest_entries() -> Vec<FakeForestEntryV1> {
        vec![
            fake_forest_entry(
                1,
                RuntimeForestRootV1::Workspace,
                FIRST_EXECUTE_ONLY_EXECUTABLE_V1,
                forest_elf_fixture(
                    Some(b"/lib64/ld-linux-x86-64.so.2"),
                    &[b"libc.so.6", b"libm.so.6"],
                ),
            ),
            fake_forest_entry(
                2,
                RuntimeForestRootV1::Runtime,
                b"lib64/ld-linux-x86-64.so.2",
                forest_elf_fixture(None, &[]),
            ),
            fake_forest_entry(
                3,
                RuntimeForestRootV1::Runtime,
                b"lib64/libc.so.6",
                forest_elf_fixture(None, &[b"libdl.so.2"]),
            ),
            fake_forest_entry(
                4,
                RuntimeForestRootV1::Runtime,
                b"lib64/libm.so.6",
                forest_elf_fixture(None, &[b"libc.so.6"]),
            ),
            fake_forest_entry(
                5,
                RuntimeForestRootV1::Runtime,
                b"lib64/libdl.so.2",
                forest_elf_fixture(None, &[]),
            ),
        ]
    }

    fn build_representative_forest(
        entries: Vec<FakeForestEntryV1>,
    ) -> Result<RuntimeForestPlanV1, FirstExecuteOnlyRuntimeCheckpointRefusalV1> {
        let mut reader = FakeForestReaderV1 {
            entries,
            calls: 0,
            drift_on_call: None,
        };
        build_runtime_forest_plan_v1(
            &mut reader,
            None,
            None,
            &RuntimeMemoryEscrowV1::first_checkpoint(),
        )
    }

    #[test]
    fn runtime_forest_resolves_interpreter_and_ordered_transitive_dependencies() {
        let plan = build_representative_forest(representative_forest_entries()).unwrap();
        let paths = plan
            .nodes
            .iter()
            .map(|node| node.path.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                b".venv/bin/python".as_slice(),
                b"lib64/ld-linux-x86-64.so.2".as_slice(),
                b"lib64/libc.so.6".as_slice(),
                b"lib64/libm.so.6".as_slice(),
                b"lib64/libdl.so.2".as_slice(),
            ]
        );
        assert_eq!(plan.edges.len(), 5);
        assert_eq!(plan.edges[0].ordinal, 0);
        assert!(plan.total_bytes > 0);
        assert!(plan.operation_count > 0);
        assert!(!plan.canonical_bytes.is_empty());
    }

    #[test]
    fn runtime_forest_digest_and_canonical_order_are_deterministic_and_sensitive() {
        let first = build_representative_forest(representative_forest_entries()).unwrap();
        let second = build_representative_forest(representative_forest_entries()).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.canonical_bytes, second.canonical_bytes);

        let mut changed = representative_forest_entries();
        let libdl = changed
            .iter_mut()
            .find(|entry| entry.path == b"lib64/libdl.so.2")
            .unwrap();
        libdl.identity[101] ^= 1;
        let changed = build_representative_forest(changed).unwrap();
        assert_ne!(first.digest, changed.digest);
    }

    #[test]
    fn runtime_forest_digest_excludes_transient_operation_retry_count() {
        struct ExtraChargeReaderV1(FakeForestReaderV1);
        impl RuntimeForestReaderV1 for ExtraChargeReaderV1 {
            fn read_object(
                &mut self,
                root: RuntimeForestRootV1,
                path: &[u8],
                byte_ceiling: u32,
                memory: &RuntimeMemoryEscrowV1,
                operations: &mut RuntimeForestOperationBudgetV1,
            ) -> Result<RuntimeForestObservedObjectV1, RuntimeForestReadRefusalV1> {
                operations.charge()?;
                self.0
                    .read_object(root, path, byte_ceiling, memory, operations)
            }
        }

        let ordinary = build_representative_forest(representative_forest_entries()).unwrap();
        let mut charged = ExtraChargeReaderV1(FakeForestReaderV1 {
            entries: representative_forest_entries(),
            calls: 0,
            drift_on_call: None,
        });
        let charged = build_runtime_forest_plan_v1(
            &mut charged,
            None,
            None,
            &RuntimeMemoryEscrowV1::first_checkpoint(),
        )
        .unwrap();
        assert!(charged.operation_count > ordinary.operation_count);
        assert_eq!(charged.digest, ordinary.digest);
        assert_eq!(charged.canonical_bytes, ordinary.canonical_bytes);
    }

    #[test]
    fn runtime_forest_rejects_duplicate_soname_resolution_even_for_equal_bytes() {
        let mut entries = representative_forest_entries();
        let libc = entries
            .iter()
            .find(|entry| entry.path == b"lib64/libc.so.6")
            .unwrap()
            .clone();
        entries.push(fake_forest_entry(
            9,
            RuntimeForestRootV1::Runtime,
            b"usr/lib64/libc.so.6",
            libc.bytes,
        ));
        assert_eq!(
            build_representative_forest(entries).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestAmbiguousObject
        );
    }

    #[test]
    fn runtime_forest_rejects_dependency_cycles() {
        let entries = vec![
            fake_forest_entry(
                1,
                RuntimeForestRootV1::Workspace,
                FIRST_EXECUTE_ONLY_EXECUTABLE_V1,
                forest_elf_fixture(Some(b"/lib64/ld-linux-x86-64.so.2"), &[b"liba.so"]),
            ),
            fake_forest_entry(
                2,
                RuntimeForestRootV1::Runtime,
                b"lib64/ld-linux-x86-64.so.2",
                forest_elf_fixture(None, &[]),
            ),
            fake_forest_entry(
                3,
                RuntimeForestRootV1::Runtime,
                b"lib64/liba.so",
                forest_elf_fixture(None, &[b"libb.so"]),
            ),
            fake_forest_entry(
                4,
                RuntimeForestRootV1::Runtime,
                b"lib64/libb.so",
                forest_elf_fixture(None, &[b"liba.so"]),
            ),
        ];
        assert_eq!(
            build_representative_forest(entries).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestCycle
        );
    }

    #[test]
    fn runtime_forest_rejects_swap_before_and_after_observation() {
        for drift_on_call in [1, 8] {
            let mut reader = FakeForestReaderV1 {
                entries: representative_forest_entries(),
                calls: 0,
                drift_on_call: Some(drift_on_call),
            };
            assert_eq!(
                build_runtime_forest_plan_v1(
                    &mut reader,
                    None,
                    None,
                    &RuntimeMemoryEscrowV1::first_checkpoint(),
                )
                .unwrap_err(),
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::IdentityDrift
            );
        }
    }

    #[test]
    fn runtime_forest_depth_byte_path_and_operation_bounds_are_fail_closed() {
        for invalid in [
            b"/absolute".as_slice(),
            b"escape/../object".as_slice(),
            b"double//component".as_slice(),
            b"nul\0object".as_slice(),
        ] {
            assert_eq!(
                validate_runtime_forest_relative_path_v1(invalid),
                Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestInvalidPath)
            );
        }
        let mut total = RUNTIME_FOREST_TOTAL_MAX_BYTES_V1;
        assert_eq!(
            checked_runtime_forest_total_bytes_v1(&mut total, 1),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestByteLimit)
        );
        let mut operations = RuntimeForestOperationBudgetV1 { remaining: 0 };
        assert_eq!(
            operations.charge(),
            Err(RuntimeForestReadRefusalV1::OperationBudget)
        );

        let mut entries = vec![
            fake_forest_entry(
                1,
                RuntimeForestRootV1::Workspace,
                FIRST_EXECUTE_ONLY_EXECUTABLE_V1,
                forest_elf_fixture(Some(b"/lib64/ld-linux-x86-64.so.2"), &[b"lib00.so"]),
            ),
            fake_forest_entry(
                2,
                RuntimeForestRootV1::Runtime,
                b"lib64/ld-linux-x86-64.so.2",
                forest_elf_fixture(None, &[]),
            ),
        ];
        for index in 0..=RUNTIME_FOREST_MAX_DEPTH_V1 {
            let name = format!("lib{index:02}.so");
            let next = format!("lib{:02}.so", index + 1);
            let needed = if index == RUNTIME_FOREST_MAX_DEPTH_V1 {
                Vec::new()
            } else {
                vec![next.as_bytes()]
            };
            entries.push(fake_forest_entry(
                u8::try_from(index + 3).unwrap(),
                RuntimeForestRootV1::Runtime,
                format!("lib64/{name}").as_bytes(),
                forest_elf_fixture(None, &needed),
            ));
        }
        assert_eq!(
            build_representative_forest(entries).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestDepthLimit
        );
    }

    #[test]
    fn runtime_forest_node_bound_refuses_before_a_129th_object_is_retained() {
        let root_names = (0..ELF64_MAX_NEEDED_NAMES)
            .map(|index| format!("libr{index:02}.so"))
            .collect::<Vec<_>>();
        let root_needed = root_names
            .iter()
            .map(|name| name.as_bytes())
            .collect::<Vec<_>>();
        let child_names = (0..ELF64_MAX_NEEDED_NAMES)
            .map(|index| format!("libs{index:02}.so"))
            .collect::<Vec<_>>();
        let child_needed = child_names
            .iter()
            .map(|name| name.as_bytes())
            .collect::<Vec<_>>();
        let mut entries = vec![
            fake_forest_entry(
                1,
                RuntimeForestRootV1::Workspace,
                FIRST_EXECUTE_ONLY_EXECUTABLE_V1,
                forest_elf_fixture(Some(b"/lib64/ld-linux-x86-64.so.2"), &root_needed),
            ),
            fake_forest_entry(
                2,
                RuntimeForestRootV1::Runtime,
                b"lib64/ld-linux-x86-64.so.2",
                forest_elf_fixture(None, &[]),
            ),
        ];
        for (index, name) in root_names.iter().enumerate() {
            let needed = if index == 0 {
                child_needed.as_slice()
            } else {
                &[]
            };
            entries.push(fake_forest_entry(
                u8::try_from(index + 3).unwrap(),
                RuntimeForestRootV1::Runtime,
                format!("lib64/{name}").as_bytes(),
                forest_elf_fixture(None, needed),
            ));
        }
        for (index, name) in child_names.iter().enumerate() {
            entries.push(fake_forest_entry(
                u8::try_from(index + 80).unwrap(),
                RuntimeForestRootV1::Runtime,
                format!("lib64/{name}").as_bytes(),
                forest_elf_fixture(None, &[]),
            ));
        }
        assert_eq!(
            build_representative_forest(entries).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestNodeLimit
        );
    }

    #[test]
    fn runtime_forest_rejects_missing_objects_and_unsupported_loader_search() {
        let mut missing = representative_forest_entries();
        missing.retain(|entry| entry.path != b"lib64/libm.so.6");
        assert_eq!(
            build_representative_forest(missing).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestMissingObject
        );

        let mut unsupported = representative_forest_entries();
        let root = unsupported
            .iter_mut()
            .find(|entry| entry.root == RuntimeForestRootV1::Workspace)
            .unwrap();
        let dynamic_offset = 0x400;
        write_dynamic_entry_at(&mut root.bytes, dynamic_offset, 0, DT_RUNPATH, 1);
        assert_eq!(
            build_representative_forest(unsupported).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamicTag
        );
    }

    #[test]
    fn runtime_forest_root_content_and_closure_are_bound_exactly() {
        let entries = representative_forest_entries();
        let root_bytes = &entries
            .iter()
            .find(|entry| entry.root == RuntimeForestRootV1::Workspace)
            .unwrap()
            .bytes;
        let expected_content =
            FileContentDigest::derive(super::super::FILE_CONTENT_DOMAIN, &[root_bytes]);
        let memory = RuntimeMemoryEscrowV1::first_checkpoint();
        let expected_request = parse_runtime_closure_request_v1(root_bytes, &memory).unwrap();
        let mut reader = FakeForestReaderV1 {
            entries: entries.clone(),
            calls: 0,
            drift_on_call: None,
        };
        assert!(
            build_runtime_forest_plan_v1(
                &mut reader,
                Some(expected_content),
                Some((&expected_request.interpreter, &expected_request.needed,)),
                &memory,
            )
            .is_ok()
        );

        let mut reader = FakeForestReaderV1 {
            entries,
            calls: 0,
            drift_on_call: None,
        };
        assert_eq!(
            build_runtime_forest_plan_v1(
                &mut reader,
                Some(FileContentDigest::derive(
                    super::super::FILE_CONTENT_DOMAIN,
                    &[b"wrong"],
                )),
                None,
                &RuntimeMemoryEscrowV1::first_checkpoint(),
            )
            .unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestRootMismatch
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn live_runtime_forest_uses_only_root_descriptors_and_rejects_symlinks() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("workspace");
        let runtime = temporary.path().join("runtime");
        std::fs::create_dir_all(workspace.join(".venv/bin")).unwrap();
        std::fs::create_dir_all(runtime.join("lib64")).unwrap();
        std::fs::write(
            workspace.join(".venv/bin/python"),
            forest_elf_fixture(
                Some(b"/lib64/ld-linux-x86-64.so.2"),
                &[b"libc.so.6", b"libm.so.6"],
            ),
        )
        .unwrap();
        std::fs::write(
            runtime.join("lib64/ld-linux-x86-64.so.2"),
            forest_elf_fixture(None, &[]),
        )
        .unwrap();
        std::fs::write(
            runtime.join("lib64/libc.so.6"),
            forest_elf_fixture(None, &[b"libdl.so.2"]),
        )
        .unwrap();
        std::fs::write(
            runtime.join("lib64/libm.so.6"),
            forest_elf_fixture(None, &[b"libc.so.6"]),
        )
        .unwrap();
        std::fs::write(
            runtime.join("lib64/libdl.so.2"),
            forest_elf_fixture(None, &[]),
        )
        .unwrap();
        let workspace_fd = std::fs::File::open(&workspace).unwrap();
        let runtime_fd = std::fs::File::open(&runtime).unwrap();
        let roots = PublishedRuntimeForestRootsV1::from_connector_owned_roots(
            workspace_fd.as_fd(),
            runtime_fd.as_fd(),
        );
        let mut reader = linux_runtime_forest::LinuxRuntimeForestReaderV1::new(roots);
        let plan = build_runtime_forest_plan_v1(
            &mut reader,
            None,
            None,
            &RuntimeMemoryEscrowV1::first_checkpoint(),
        )
        .unwrap();
        assert_eq!(plan.nodes.len(), 5);
        assert!(plan.operation_count > 20);

        std::fs::remove_file(runtime.join("lib64/libm.so.6")).unwrap();
        symlink("libc.so.6", runtime.join("lib64/libm.so.6")).unwrap();
        let roots = PublishedRuntimeForestRootsV1::from_connector_owned_roots(
            workspace_fd.as_fd(),
            runtime_fd.as_fd(),
        );
        let mut reader = linux_runtime_forest::LinuxRuntimeForestReaderV1::new(roots);
        assert_eq!(
            build_runtime_forest_plan_v1(
                &mut reader,
                None,
                None,
                &RuntimeMemoryEscrowV1::first_checkpoint(),
            )
            .unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::RuntimeForestSymlink
        );
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
    fn load_layout_rejects_page_address_order_and_span_violations() {
        let mut page_incongruent = elf_fixture();
        page_incongruent[24..32].copy_from_slice(&0x40_0079u64.to_le_bytes());
        page_incongruent[ELF64_HEADER_BYTES + 16..ELF64_HEADER_BYTES + 24]
            .copy_from_slice(&0x40_0079u64.to_le_bytes());
        assert_eq!(
            validate_x86_64_elf_v1(&page_incongruent),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );

        for invalid_address in [ELF64_USER_VIRTUAL_LIMIT, 1u64 << 63] {
            let mut high = elf_fixture();
            high[24..32].copy_from_slice(&invalid_address.to_le_bytes());
            let program = &mut high[ELF64_HEADER_BYTES..];
            program[8..16].copy_from_slice(&0u64.to_le_bytes());
            program[16..24].copy_from_slice(&invalid_address.to_le_bytes());
            assert_eq!(
                validate_x86_64_elf_v1(&high),
                Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
            );
        }

        let mut descending = elf_fixture();
        descending[24..32].copy_from_slice(&0x50_0078u64.to_le_bytes());
        descending[ELF64_HEADER_BYTES + 16..ELF64_HEADER_BYTES + 24]
            .copy_from_slice(&0x50_0078u64.to_le_bytes());
        append_second_load(&mut descending, 0, 0x40_0000, 0, 1);
        assert_eq!(
            validate_x86_64_elf_v1(&descending),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );

        let mut excessive_span = elf_fixture();
        append_second_load(
            &mut excessive_span,
            0,
            0x40_0000 + ELF64_MAX_MAPPING_SPAN,
            0,
            1,
        );
        assert_eq!(
            validate_x86_64_elf_v1(&excessive_span),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );

        let mut virtual_overlap = elf_fixture();
        append_second_load(&mut virtual_overlap, 120, 0x40_0078, 0, 1);
        assert_eq!(
            validate_x86_64_elf_v1(&virtual_overlap),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );

        let mut file_overlap = elf_fixture();
        append_second_load(&mut file_overlap, 120, 0x50_0078, 1, 1);
        assert_eq!(
            validate_x86_64_elf_v1(&file_overlap),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );

        let mut later_permission_removal = elf_fixture();
        append_second_load(&mut later_permission_removal, 121, 0x40_0079, 1, 1);
        assert_eq!(
            validate_x86_64_elf_v1(&later_permission_removal),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );

        let mut differing_page_bias = elf_fixture();
        append_second_load(&mut differing_page_bias, 0x1079, 0x40_0079, 1, 1);
        differing_page_bias.resize(0x107a, 0);
        assert_eq!(
            validate_x86_64_elf_v1(&differing_page_bias),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );
    }

    #[test]
    fn load_layout_accepts_exact_address_and_mapping_span_boundaries() {
        let mut address_boundary = elf_fixture();
        let highest_page = ELF64_USER_VIRTUAL_LIMIT - ELF64_LOAD_PAGE_BYTES;
        address_boundary[24..32].copy_from_slice(&highest_page.to_le_bytes());
        let program = &mut address_boundary[ELF64_HEADER_BYTES..];
        program[8..16].copy_from_slice(&0u64.to_le_bytes());
        program[16..24].copy_from_slice(&highest_page.to_le_bytes());
        program[40..48].copy_from_slice(&(ELF64_LOAD_PAGE_BYTES - 1).to_le_bytes());
        assert_eq!(validate_x86_64_elf_v1(&address_boundary), Ok(()));

        let mut span_boundary = elf_fixture();
        append_second_load(
            &mut span_boundary,
            0,
            0x40_0000 + ELF64_MAX_MAPPING_SPAN - ELF64_LOAD_PAGE_BYTES,
            0,
            ELF64_LOAD_PAGE_BYTES - 1,
        );
        assert_eq!(validate_x86_64_elf_v1(&span_boundary), Ok(()));

        let mut page_disjoint_adjacency = elf_fixture();
        append_second_load(&mut page_disjoint_adjacency, 0, 0x40_1000, 0, 1);
        assert_eq!(validate_x86_64_elf_v1(&page_disjoint_adjacency), Ok(()));

        let mut adjacent_file = elf_fixture();
        append_second_load(&mut adjacent_file, 121, 0x50_0079, 1, 1);
        assert_eq!(validate_x86_64_elf_v1(&adjacent_file), Ok(()));
    }

    #[test]
    fn runtime_closure_request_retains_only_unresolved_redacted_names() {
        let request = parse_runtime_fixture(&runtime_closure_elf_fixture()).unwrap();
        assert_eq!(&*request.interpreter, b"/lib64/ld-linux-x86-64.so.2");
        assert_eq!(
            request.needed.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            [b"libc.so.6".as_slice(), b"libm.so.6".as_slice()]
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("ld-linux"));
        assert!(!debug.contains("libc"));
        assert!(debug.contains("resolution_authority: false"));

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
        <RuntimeClosureRequestV1 as AmbiguousIfClone<_>>::probe();
        <RuntimeClosureRequestV1 as AmbiguousIfCopy<_>>::probe();
        assert!(std::mem::needs_drop::<RuntimeClosureRequestV1>());
    }

    #[test]
    fn interpreter_segment_is_unique_absolute_canonical_and_exact() {
        let mut missing = runtime_closure_elf_fixture();
        write_program_header(
            &mut missing,
            1,
            4,
            4,
            RUNTIME_FIXTURE_INTERP_OFFSET as u64,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_INTERP_OFFSET as u64,
            1,
            1,
            1,
        );
        assert_eq!(
            parse_runtime_fixture(&missing).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter
        );

        let mut duplicate = runtime_closure_elf_fixture();
        let dynamic = parse_program_header_v1(
            &duplicate[ELF64_HEADER_BYTES + 2 * ELF64_PROGRAM_HEADER_BYTES
                ..ELF64_HEADER_BYTES + 3 * ELF64_PROGRAM_HEADER_BYTES],
        );
        write_program_header(
            &mut duplicate,
            2,
            PT_INTERP,
            4,
            dynamic.offset,
            dynamic.virtual_address,
            dynamic.file_size,
            dynamic.memory_size,
            dynamic.alignment,
        );
        assert_eq!(
            parse_runtime_fixture(&duplicate).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter
        );

        for replacement in [
            b"relative/ld.so\0".as_slice(),
            b"/lib/../ld.so\0".as_slice(),
            b"/lib//ld.so\0".as_slice(),
            b"/lib/ld.so\0x".as_slice(),
        ] {
            let mut malformed = runtime_closure_elf_fixture();
            malformed
                [RUNTIME_FIXTURE_INTERP_OFFSET..RUNTIME_FIXTURE_INTERP_OFFSET + replacement.len()]
                .copy_from_slice(replacement);
            let start = ELF64_HEADER_BYTES + ELF64_PROGRAM_HEADER_BYTES;
            malformed[start + 32..start + 40]
                .copy_from_slice(&(replacement.len() as u64).to_le_bytes());
            malformed[start + 40..start + 48]
                .copy_from_slice(&(replacement.len() as u64).to_le_bytes());
            assert_eq!(
                parse_runtime_fixture(&malformed).unwrap_err(),
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter
            );
        }

        let mut oversized = runtime_closure_elf_fixture();
        let interpreter_header = ELF64_HEADER_BYTES + ELF64_PROGRAM_HEADER_BYTES;
        let oversized_length = ELF64_MAX_INTERPRETER_BYTES as u64 + 1;
        oversized[interpreter_header + 32..interpreter_header + 40]
            .copy_from_slice(&oversized_length.to_le_bytes());
        oversized[interpreter_header + 40..interpreter_header + 48]
            .copy_from_slice(&oversized_length.to_le_bytes());
        assert_eq!(
            parse_runtime_fixture(&oversized).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter
        );
    }

    #[test]
    fn dynamic_table_rejects_duplicate_unknown_lookup_and_termination_ambiguity() {
        let original = runtime_closure_elf_fixture();
        let dynamic_start = ELF64_HEADER_BYTES + 2 * ELF64_PROGRAM_HEADER_BYTES;
        let dynamic = parse_program_header_v1(
            &original[dynamic_start..dynamic_start + ELF64_PROGRAM_HEADER_BYTES],
        );
        let interpreter_start = ELF64_HEADER_BYTES + ELF64_PROGRAM_HEADER_BYTES;
        let interpreter = parse_program_header_v1(
            &original[interpreter_start..interpreter_start + ELF64_PROGRAM_HEADER_BYTES],
        );

        let mut missing = original.clone();
        write_program_header(
            &mut missing,
            2,
            4,
            4,
            dynamic.offset,
            dynamic.virtual_address,
            dynamic.file_size,
            dynamic.memory_size,
            dynamic.alignment,
        );
        assert_eq!(
            parse_runtime_fixture(&missing).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic
        );

        let mut duplicate = original.clone();
        write_program_header(
            &mut duplicate,
            1,
            PT_DYNAMIC,
            4,
            interpreter.offset,
            interpreter.virtual_address,
            interpreter.file_size,
            interpreter.memory_size,
            interpreter.alignment,
        );
        assert_eq!(
            parse_runtime_fixture(&duplicate).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic
        );

        let mut outside_file = original.clone();
        write_program_header(
            &mut outside_file,
            2,
            PT_DYNAMIC,
            4,
            1000,
            RUNTIME_FIXTURE_BASE + 1000,
            dynamic.file_size,
            dynamic.memory_size,
            8,
        );
        assert_eq!(
            parse_runtime_fixture(&outside_file).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic
        );

        let mut ambiguous_load_mapping = original.clone();
        let interpreter_size = usize::try_from(interpreter.file_size).unwrap();
        let interpreter_bytes = ambiguous_load_mapping
            [RUNTIME_FIXTURE_INTERP_OFFSET..RUNTIME_FIXTURE_INTERP_OFFSET + interpreter_size]
            .to_vec();
        const MOVED_INTERPRETER_OFFSET: usize = 448;
        ambiguous_load_mapping
            [MOVED_INTERPRETER_OFFSET..MOVED_INTERPRETER_OFFSET + interpreter_bytes.len()]
            .copy_from_slice(&interpreter_bytes);
        ambiguous_load_mapping[56..58].copy_from_slice(&4u16.to_le_bytes());
        write_program_header(
            &mut ambiguous_load_mapping,
            1,
            PT_INTERP,
            4,
            MOVED_INTERPRETER_OFFSET as u64,
            RUNTIME_FIXTURE_BASE + MOVED_INTERPRETER_OFFSET as u64,
            interpreter_bytes.len() as u64,
            interpreter_bytes.len() as u64,
            1,
        );
        let ambiguous_file_size = ambiguous_load_mapping.len() as u64;
        write_program_header(
            &mut ambiguous_load_mapping,
            3,
            PT_LOAD,
            4,
            0,
            RUNTIME_FIXTURE_BASE,
            ambiguous_file_size,
            ambiguous_file_size,
            ELF64_LOAD_PAGE_BYTES,
        );
        assert_eq!(
            parse_runtime_fixture(&ambiguous_load_mapping).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader
        );

        for tag in [DT_RPATH, DT_RUNPATH, 0x1234_5678] {
            let mut malformed = runtime_closure_elf_fixture();
            write_dynamic_entry(&mut malformed, 0, tag, 1);
            assert_eq!(
                parse_runtime_fixture(&malformed).unwrap_err(),
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamicTag
            );
        }

        for (tag, value) in [
            (DT_FLAGS, DF_BIND_NOW),
            (DT_FLAGS_1, DF_1_NODEFLIB),
            (DT_FLAGS, 1 << 63),
            (DT_FLAGS_1, 1 << 63),
        ] {
            let mut unmodeled_flags = runtime_closure_elf_fixture();
            write_dynamic_entry(&mut unmodeled_flags, 1, tag, value);
            assert_eq!(
                parse_runtime_fixture(&unmodeled_flags).unwrap_err(),
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamicTag
            );
        }

        for tag in [DT_FLAGS, DT_FLAGS_1] {
            let mut zero_flags = runtime_closure_elf_fixture();
            write_dynamic_entry(&mut zero_flags, 1, tag, 0);
            assert!(parse_runtime_fixture(&zero_flags).is_ok());
        }

        let mut duplicate_strtab = runtime_closure_elf_fixture();
        write_dynamic_entry(
            &mut duplicate_strtab,
            1,
            DT_STRTAB,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_STRTAB_OFFSET as u64,
        );
        assert_eq!(
            parse_runtime_fixture(&duplicate_strtab).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamicTag
        );

        for (index, replacement_tag) in [(2, 12), (3, 13)] {
            let mut missing_required = runtime_closure_elf_fixture();
            write_dynamic_entry(&mut missing_required, index, replacement_tag, 0);
            assert_eq!(
                parse_runtime_fixture(&missing_required).unwrap_err(),
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable
            );
        }

        let mut non_null_after_terminator = runtime_closure_elf_fixture();
        write_dynamic_entry(&mut non_null_after_terminator, 3, DT_NULL, 0);
        write_dynamic_entry(&mut non_null_after_terminator, 4, DT_STRSZ, 21);
        assert_eq!(
            parse_runtime_fixture(&non_null_after_terminator).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamicTag
        );

        let mut no_terminator = runtime_closure_elf_fixture();
        write_dynamic_entry(&mut no_terminator, 4, 12, 0);
        assert_eq!(
            parse_runtime_fixture(&no_terminator).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfDynamic
        );

        let mut too_many_needed = runtime_closure_elf_fixture();
        let entry_count = ELF64_MAX_NEEDED_NAMES + 4;
        let dynamic_bytes = entry_count * ELF64_DYNAMIC_ENTRY_BYTES;
        too_many_needed.resize(RUNTIME_FIXTURE_DYNAMIC_OFFSET + dynamic_bytes, 0);
        let file_size = too_many_needed.len() as u64;
        write_program_header(
            &mut too_many_needed,
            0,
            PT_LOAD,
            PF_X | 4,
            0,
            RUNTIME_FIXTURE_BASE,
            file_size,
            file_size,
            ELF64_LOAD_PAGE_BYTES,
        );
        write_program_header(
            &mut too_many_needed,
            2,
            PT_DYNAMIC,
            4,
            RUNTIME_FIXTURE_DYNAMIC_OFFSET as u64,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_DYNAMIC_OFFSET as u64,
            dynamic_bytes as u64,
            dynamic_bytes as u64,
            8,
        );
        for index in 0..=ELF64_MAX_NEEDED_NAMES {
            write_dynamic_entry(&mut too_many_needed, index, DT_NEEDED, 1);
        }
        write_dynamic_entry(
            &mut too_many_needed,
            ELF64_MAX_NEEDED_NAMES + 1,
            DT_STRTAB,
            RUNTIME_FIXTURE_BASE + RUNTIME_FIXTURE_STRTAB_OFFSET as u64,
        );
        write_dynamic_entry(
            &mut too_many_needed,
            ELF64_MAX_NEEDED_NAMES + 2,
            DT_STRSZ,
            21,
        );
        write_dynamic_entry(&mut too_many_needed, ELF64_MAX_NEEDED_NAMES + 3, DT_NULL, 0);
        assert_eq!(
            parse_runtime_fixture(&too_many_needed).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfRuntimeClosureLimit
        );
    }

    #[test]
    fn string_table_translation_and_needed_names_are_bounded_unambiguous_and_ordered() {
        let mut outside_load = runtime_closure_elf_fixture();
        write_dynamic_entry(&mut outside_load, 2, DT_STRTAB, RUNTIME_FIXTURE_BASE + 4096);
        assert_eq!(
            parse_runtime_fixture(&outside_load).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfStringTable
        );

        let mut oversized = runtime_closure_elf_fixture();
        write_dynamic_entry(
            &mut oversized,
            3,
            DT_STRSZ,
            ELF64_MAX_STRING_TABLE_BYTES as u64 + 1,
        );
        assert_eq!(
            parse_runtime_fixture(&oversized).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfRuntimeClosureLimit
        );

        let mut duplicate_name = runtime_closure_elf_fixture();
        write_dynamic_entry(&mut duplicate_name, 1, DT_NEEDED, 1);
        assert_eq!(
            parse_runtime_fixture(&duplicate_name).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded
        );

        for (offset, replacement) in [
            (99u64, None),
            (1, Some(b"lib/escape\0".as_slice())),
            (1, Some(b"$ORIGIN\0".as_slice())),
            (1, Some(b".\0".as_slice())),
        ] {
            let mut malformed = runtime_closure_elf_fixture();
            write_dynamic_entry(&mut malformed, 0, DT_NEEDED, offset);
            if let Some(replacement) = replacement {
                malformed[RUNTIME_FIXTURE_STRTAB_OFFSET + 1
                    ..RUNTIME_FIXTURE_STRTAB_OFFSET + 1 + replacement.len()]
                    .copy_from_slice(replacement);
            }
            assert_eq!(
                parse_runtime_fixture(&malformed).unwrap_err(),
                FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded
            );
        }

        let mut unterminated = runtime_closure_elf_fixture();
        write_dynamic_entry(&mut unterminated, 3, DT_STRSZ, 10);
        assert_eq!(
            parse_runtime_fixture(&unterminated).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded
        );

        let mut overlong_name = runtime_closure_elf_fixture();
        let string_table_size = ELF64_MAX_NEEDED_NAME_BYTES + 3;
        let needed_end = RUNTIME_FIXTURE_STRTAB_OFFSET + string_table_size;
        overlong_name.resize(needed_end, 0);
        overlong_name[RUNTIME_FIXTURE_STRTAB_OFFSET + 1
            ..RUNTIME_FIXTURE_STRTAB_OFFSET + 2 + ELF64_MAX_NEEDED_NAME_BYTES]
            .fill(b'a');
        let file_size = overlong_name.len() as u64;
        write_program_header(
            &mut overlong_name,
            0,
            PT_LOAD,
            PF_X | 4,
            0,
            RUNTIME_FIXTURE_BASE,
            file_size,
            file_size,
            ELF64_LOAD_PAGE_BYTES,
        );
        write_dynamic_entry(&mut overlong_name, 1, DT_NEEDED, 1);
        write_dynamic_entry(&mut overlong_name, 3, DT_STRSZ, string_table_size as u64);
        assert_eq!(
            parse_runtime_fixture(&overlong_name).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfNeeded
        );

        let memory = super::super::snapshot_publish::RuntimeMemoryEscrowV1::with_limit_for_test(1);
        assert_eq!(
            parse_runtime_closure_request_v1(&runtime_closure_elf_fixture(), &memory).unwrap_err(),
            FirstExecuteOnlyRuntimeCheckpointRefusalV1::MemoryBudget
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn real_system_python_parse_is_diagnostic_only_and_never_pinned_evidence() {
        let Some(path) = ["/usr/bin/python3", "/usr/local/bin/python3"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
        else {
            return;
        };
        let bytes = std::fs::read(path).unwrap();
        // The ambient host path is not descriptor-bound published evidence.
        // This diagnostic may accept or conservatively refuse that host's
        // current ELF shape, but neither outcome participates in qualification.
        let diagnostic = format!("{:?}", parse_runtime_fixture(&bytes));
        assert!(!diagnostic.contains("qualified"));
        assert!(!diagnostic.contains("pinned"));
        if diagnostic.starts_with("Ok(") {
            assert!(diagnostic.contains("resolution_authority: false"));
        }
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
        assert!(RUNTIME_FOREST_NONCLAIMS_V1.starts_with(b"venv,pytest,isolation"));
        assert!(RUNTIME_FOREST_NONCLAIMS_V1.ends_with(b"reuse:unauthorized"));
        assert_eq!(
            runtime_forest_platform_support_v1().is_ok(),
            cfg!(all(target_os = "linux", target_arch = "x86_64"))
        );
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
        <FirstExecuteOnlyRuntimeForestEvidenceV1<'static> as AmbiguousIfClone<_>>::probe();
        <FirstExecuteOnlyRuntimeForestEvidenceV1<'static> as AmbiguousIfCopy<_>>::probe();
        assert!(std::mem::needs_drop::<
            FirstExecuteOnlyRuntimeForestEvidenceV1<'static>,
        >());
    }
}
