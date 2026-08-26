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
    CanonicalOverflow,
    MemoryBudget,
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
    memory: &super::snapshot_publish::RuntimeMemoryEscrowV1,
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
    let interpreter =
        interpreter.ok_or(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter)?;
    let interpreter_range = bounded_segment_file_range_v1(
        interpreter,
        bytes,
        ELF64_MAX_INTERPRETER_BYTES,
        FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfInterpreter,
    )?;
    let interpreter_path = canonical_interpreter_path_v1(&bytes[interpreter_range])?;

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
    if !terminated || needed_count == 0 {
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
        append_second_load(&mut later_permission_removal, 121, 0x40_0079, 0, 1);
        assert_eq!(
            validate_x86_64_elf_v1(&later_permission_removal),
            Err(FirstExecuteOnlyRuntimeCheckpointRefusalV1::ElfProgramHeader)
        );

        let mut differing_page_bias = elf_fixture();
        append_second_load(&mut differing_page_bias, 0x1079, 0x40_0079, 0, 1);
        differing_page_bias.resize(0x1079, 0);
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
