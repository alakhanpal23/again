//! Dependency-free canonical encoding for the disabled Linux pytest profile.
//!
//! Serde remains a diagnostic representation only. Bytes produced here are
//! the sole input to V2 record, comparison, and storage identities.

use super::*;

const TYPE_EFFECT_RECORD: u16 = 0x0001;
const TYPE_INVOCATION: u16 = 0x0002;
const TYPE_SELECTOR: u16 = 0x0003;
const TYPE_ENVIRONMENT: u16 = 0x0004;
const TYPE_SNAPSHOT: u16 = 0x0005;
const TYPE_PLATFORM: u16 = 0x0006;
const TYPE_NAMESPACE_IDS: u16 = 0x0007;
const TYPE_POLICY_DIGESTS: u16 = 0x0008;
const TYPE_TRACE: u16 = 0x0009;
const TYPE_TRACE_COUNTERS: u16 = 0x000a;
const TYPE_FIRST_FAILURE: u16 = 0x000b;
const TYPE_OBSERVATION: u16 = 0x000c;
const TYPE_AMBIENT_EVENT: u16 = 0x000d;
const TYPE_ORDERED_EFFECT: u16 = 0x000e;
const TYPE_BLOB_REF: u16 = 0x000f;
const TYPE_RESULT: u16 = 0x0010;
const TYPE_COMPARISON_VIEW: u16 = 0x0011;
const TYPE_SHAPE: u16 = 0x0012;
const TYPE_OBSERVATION_CLOSURE: u16 = 0x0013;
const TYPE_OBSERVATION_DEPENDENCY: u16 = 0x0014;
const TYPE_COMPARISON_SNAPSHOT: u16 = 0x0015;
const TYPE_COMPARISON_PLATFORM: u16 = 0x0016;
const TYPE_COMPARISON_RULES: u16 = 0x0017;
const TYPE_OBSERVATION_DETAIL: u16 = 0x0018;
const TYPE_SNAPSHOT_MANIFEST: u16 = 0x0020;
const TYPE_TREE_MANIFEST: u16 = 0x0021;
const TYPE_MANIFEST_ENTRY: u16 = 0x0022;
const TYPE_METADATA: u16 = 0x0023;
const TYPE_TIMESPEC: u16 = 0x0024;
const TYPE_XATTR: u16 = 0x0025;
const TYPE_EXTENT: u16 = 0x0026;
const TYPE_CHILD_COMMITMENT: u16 = 0x0027;
const TYPE_RUNTIME_MOUNT: u16 = 0x0028;

const COMPARISON_RULE_VERSION: &[u8] = b"comparison-view-v1";
const FIELD_HEADER_BYTES: usize = 2 + 1 + 8;
const LIST_ITEM_HEADER_BYTES: usize = 8;
const COMPARISON_EXCLUSIONS: [&[u8]; 10] = [
    b"record_id",
    b"snapshot_id",
    b"namespace_ids",
    b"disposition",
    b"disposition_reason",
    b"primary_record_id",
    b"comparison_digest",
    b"created_monotonic_ns",
    b"outer_host_pid",
    b"duration",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum WireType {
    U8 = 0x01,
    U16 = 0x02,
    U32 = 0x03,
    U64 = 0x04,
    I32 = 0x05,
    I64 = 0x06,
    Bool = 0x07,
    Bytes = 0x08,
    Utf8 = 0x09,
    Object = 0x0a,
    List = 0x0b,
    Optional = 0x0c,
    Enum = 0x0d,
}

impl WireType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::U8),
            0x02 => Some(Self::U16),
            0x03 => Some(Self::U32),
            0x04 => Some(Self::U64),
            0x05 => Some(Self::I32),
            0x06 => Some(Self::I64),
            0x07 => Some(Self::Bool),
            0x08 => Some(Self::Bytes),
            0x09 => Some(Self::Utf8),
            0x0a => Some(Self::Object),
            0x0b => Some(Self::List),
            0x0c => Some(Self::Optional),
            0x0d => Some(Self::Enum),
            _ => None,
        }
    }
}

/// Minimal allocation-free output boundary for canonical manifest bytes.
///
/// The snapshot resource layer can implement this trait for its private
/// charged byte container without lending allocator or ledger authority to
/// this module. Implementations must either append the complete slice or
/// return an error; partial-success semantics are forbidden.
pub(super) trait ManifestCanonicalByteSinkV1 {
    type Error;

    fn try_extend_canonical(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ManifestCanonicalWriteErrorV1<E> {
    Canonical(LinuxPytestContractError),
    Sink(E),
}

impl<E> From<LinuxPytestContractError> for ManifestCanonicalWriteErrorV1<E> {
    fn from(error: LinuxPytestContractError) -> Self {
        Self::Canonical(error)
    }
}

/// Borrowed metadata projection for allocation-free manifest hashing and
/// canonical writing. Construction grants no validation or snapshot
/// authority; callers must retain the owners behind every borrowed slice.
#[derive(Clone, Copy)]
pub(super) struct ManifestMetadataProjectionV1<'value> {
    mode: u32,
    logical_uid: u32,
    logical_gid: u32,
    size: u64,
    nlink: u64,
    atime: &'value TimespecV1,
    mtime: &'value TimespecV1,
    ctime: &'value TimespecV1,
    btime: Option<&'value TimespecV1>,
    xattrs: &'value [XattrV1],
}

impl<'value> ManifestMetadataProjectionV1<'value> {
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new(
        mode: u32,
        logical_uid: u32,
        logical_gid: u32,
        size: u64,
        nlink: u64,
        atime: &'value TimespecV1,
        mtime: &'value TimespecV1,
        ctime: &'value TimespecV1,
        btime: Option<&'value TimespecV1>,
        xattrs: &'value [XattrV1],
    ) -> Self {
        Self {
            mode,
            logical_uid,
            logical_gid,
            size,
            nlink,
            atime,
            mtime,
            ctime,
            btime,
            xattrs,
        }
    }
}

impl<'value> From<&'value MetadataV1> for ManifestMetadataProjectionV1<'value> {
    fn from(value: &'value MetadataV1) -> Self {
        Self::new(
            value.mode,
            value.logical_uid,
            value.logical_gid,
            value.size,
            value.nlink,
            &value.atime,
            &value.mtime,
            &value.ctime,
            value.btime.as_ref(),
            &value.xattrs,
        )
    }
}

/// Borrowed payload projection matching the frozen manifest variants without
/// requiring their owning `Vec` containers.
#[derive(Clone, Copy)]
pub(super) enum ManifestPayloadProjectionV1<'value> {
    Directory {
        children: &'value [ChildCommitmentV1],
    },
    Regular {
        content_digest: FileContentDigest,
        data_extents: &'value [ExtentV1],
    },
    Symlink {
        target: &'value [u8],
    },
    ExternalTree {
        tree_role: TreeRoleV1,
        target_root: NodeDigest,
        readonly: bool,
    },
}

impl ManifestPayloadProjectionV1<'_> {
    const fn kind(self) -> ManifestEntryKindV1 {
        match self {
            Self::Directory { .. } => ManifestEntryKindV1::Directory,
            Self::Regular { .. } => ManifestEntryKindV1::Regular,
            Self::Symlink { .. } => ManifestEntryKindV1::Symlink,
            Self::ExternalTree { .. } => ManifestEntryKindV1::ExternalTree,
        }
    }
}

impl<'value> From<&'value ManifestPayloadV1> for ManifestPayloadProjectionV1<'value> {
    fn from(value: &'value ManifestPayloadV1) -> Self {
        match value {
            ManifestPayloadV1::Directory { children } => Self::Directory { children },
            ManifestPayloadV1::Regular {
                content_digest,
                data_extents,
            } => Self::Regular {
                content_digest: *content_digest,
                data_extents,
            },
            ManifestPayloadV1::Symlink { target } => Self::Symlink { target },
            ManifestPayloadV1::ExternalTree {
                tree_role,
                target_root,
                readonly,
            } => Self::ExternalTree {
                tree_role: *tree_role,
                target_root: *target_root,
                readonly: *readonly,
            },
        }
    }
}

/// One borrowed entry view supplied by either the frozen manifest type or a
/// charged compiler-owned projection.
#[derive(Clone, Copy)]
pub(super) struct ManifestEntryProjectionViewV1<'value> {
    relative_path: &'value [u8],
    metadata: ManifestMetadataProjectionV1<'value>,
    payload: ManifestPayloadProjectionV1<'value>,
    hardlink_group: Option<HardlinkGroupDigest>,
    node_digest: NodeDigest,
}

impl<'value> ManifestEntryProjectionViewV1<'value> {
    pub(super) const fn new(
        relative_path: &'value [u8],
        metadata: ManifestMetadataProjectionV1<'value>,
        payload: ManifestPayloadProjectionV1<'value>,
        hardlink_group: Option<HardlinkGroupDigest>,
        node_digest: NodeDigest,
    ) -> Self {
        Self {
            relative_path,
            metadata,
            payload,
            hardlink_group,
            node_digest,
        }
    }
}

/// Private, audited adapter used only by the frozen owning manifest type.
/// Public projection entry points accept immutable view slices directly and
/// never depend on a caller-provided replayable trait implementation.
trait ManifestEntryProjectionV1 {
    fn manifest_entry_projection_v1(&self) -> ManifestEntryProjectionViewV1<'_>;
}

impl ManifestEntryProjectionV1 for ManifestEntryV1 {
    fn manifest_entry_projection_v1(&self) -> ManifestEntryProjectionViewV1<'_> {
        ManifestEntryProjectionViewV1::new(
            &self.relative_path,
            (&self.metadata).into(),
            (&self.payload).into(),
            self.hardlink_group,
            self.node_digest,
        )
    }
}

impl ManifestEntryProjectionV1 for ManifestEntryProjectionViewV1<'_> {
    fn manifest_entry_projection_v1(&self) -> ManifestEntryProjectionViewV1<'_> {
        *self
    }
}

struct ManifestCanonicalWriterV1<'sink, S> {
    sink: &'sink mut S,
    written: usize,
}

impl<'sink, S> ManifestCanonicalWriterV1<'sink, S>
where
    S: ManifestCanonicalByteSinkV1,
{
    fn new(sink: &'sink mut S) -> Self {
        Self { sink, written: 0 }
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>> {
        let next = self
            .written
            .checked_add(bytes.len())
            .ok_or(LinuxPytestContractError::CanonicalEncoding)?;
        self.sink
            .try_extend_canonical(bytes)
            .map_err(ManifestCanonicalWriteErrorV1::Sink)?;
        self.written = next;
        Ok(())
    }

    const fn written(&self) -> usize {
        self.written
    }

    fn object_header(
        &mut self,
        type_id: u16,
        field_count: u16,
    ) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>> {
        self.bytes(&type_id.to_be_bytes())?;
        self.bytes(&EFFECT_IR_V2_WIRE_VERSION.to_be_bytes())?;
        self.bytes(&field_count.to_be_bytes())
    }

    fn enum_header(
        &mut self,
        variant: u16,
        field_count: u16,
    ) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>> {
        if variant == 0 {
            return Err(LinuxPytestContractError::CanonicalEncoding.into());
        }
        self.bytes(&variant.to_be_bytes())?;
        self.bytes(&field_count.to_be_bytes())
    }

    fn field_header(
        &mut self,
        tag: u16,
        wire_type: WireType,
        payload_length: usize,
    ) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>> {
        if tag == 0 {
            return Err(LinuxPytestContractError::CanonicalEncoding.into());
        }
        let payload_length = u64::try_from(payload_length)
            .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
        self.bytes(&tag.to_be_bytes())?;
        self.bytes(&[wire_type as u8])?;
        self.bytes(&payload_length.to_be_bytes())
    }

    fn list_header(
        &mut self,
        item_count: usize,
    ) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>> {
        let item_count = canonical_collection_count(item_count)?;
        self.bytes(&item_count.to_be_bytes())
    }

    fn list_item_header(
        &mut self,
        item_length: usize,
    ) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>> {
        let item_length =
            u64::try_from(item_length).map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
        self.bytes(&item_length.to_be_bytes())
    }
}

struct ManifestCanonicalVecSinkV1 {
    bytes: Vec<u8>,
    exact_length: usize,
}

impl ManifestCanonicalVecSinkV1 {
    fn new(exact_length: usize) -> Result<Self, LinuxPytestContractError> {
        checked_canonical_payload_length(exact_length)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(exact_length)
            .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
        Ok(Self {
            bytes,
            exact_length,
        })
    }

    fn finish(self) -> Result<Vec<u8>, LinuxPytestContractError> {
        if self.bytes.len() != self.exact_length {
            return Err(LinuxPytestContractError::CanonicalEncoding);
        }
        Ok(self.bytes)
    }
}

impl ManifestCanonicalByteSinkV1 for ManifestCanonicalVecSinkV1 {
    type Error = LinuxPytestContractError;

    fn try_extend_canonical(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let next_length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(LinuxPytestContractError::CanonicalEncoding)?;
        if next_length > self.exact_length {
            return Err(LinuxPytestContractError::CanonicalEncoding);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

fn encode_manifest_canonical_vec(
    exact_length: usize,
    write: impl FnOnce(
        &mut ManifestCanonicalWriterV1<'_, ManifestCanonicalVecSinkV1>,
    ) -> Result<(), ManifestCanonicalWriteErrorV1<LinuxPytestContractError>>,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut sink = ManifestCanonicalVecSinkV1::new(exact_length)?;
    let result = {
        let mut writer = ManifestCanonicalWriterV1::new(&mut sink);
        write(&mut writer)
    };
    match result {
        Ok(()) => sink.finish(),
        Err(
            ManifestCanonicalWriteErrorV1::Canonical(error)
            | ManifestCanonicalWriteErrorV1::Sink(error),
        ) => Err(error),
    }
}

struct Field {
    tag: u16,
    wire_type: WireType,
    payload: Vec<u8>,
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
            || u64::try_from(payload.len()).is_err()
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

    fn i64(&mut self, tag: u16, value: i64) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::I64, value.to_be_bytes().to_vec())
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
        items: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::List, encode_list(items)?)
    }

    fn enumeration(
        &mut self,
        tag: u16,
        variant: u16,
        fields: Vec<Field>,
    ) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::Enum, encode_enum(variant, fields)?)
    }

    fn optional(
        &mut self,
        tag: u16,
        value: Option<Vec<u8>>,
    ) -> Result<(), LinuxPytestContractError> {
        self.field(tag, WireType::Optional, encode_optional(value)?)
    }

    fn finish_nested(self) -> Result<Vec<u8>, LinuxPytestContractError> {
        let field_count = u16::try_from(self.fields.len())
            .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
        let mut output = Vec::new();
        output.extend_from_slice(&self.type_id.to_be_bytes());
        output.extend_from_slice(&EFFECT_IR_V2_WIRE_VERSION.to_be_bytes());
        output.extend_from_slice(&field_count.to_be_bytes());
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
    let mut previous = 0u16;
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
    items: impl IntoIterator<Item = Vec<u8>>,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let items = items.into_iter().collect::<Vec<_>>();
    let item_count =
        u64::try_from(items.len()).map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
    if item_count > EFFECT_IR_V2_MAX_COLLECTION_ITEMS {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    let mut output = Vec::new();
    output.extend_from_slice(&item_count.to_be_bytes());
    for item in items {
        output.extend_from_slice(
            &u64::try_from(item.len())
                .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&item);
    }
    enforce_size(&output)?;
    Ok(output)
}

fn encode_optional(value: Option<Vec<u8>>) -> Result<Vec<u8>, LinuxPytestContractError> {
    let Some(value) = value else {
        return Ok(vec![0]);
    };
    let mut output = Vec::with_capacity(9 + value.len());
    output.push(1);
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&value);
    enforce_size(&output)?;
    Ok(output)
}

fn encode_enum(variant: u16, fields: Vec<Field>) -> Result<Vec<u8>, LinuxPytestContractError> {
    if variant == 0 {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    let field_count =
        u16::try_from(fields.len()).map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
    let mut output = Vec::new();
    output.extend_from_slice(&variant.to_be_bytes());
    output.extend_from_slice(&field_count.to_be_bytes());
    put_fields(&mut output, fields)?;
    enforce_size(&output)?;
    Ok(output)
}

fn enum_field(tag: u16, wire_type: WireType, payload: Vec<u8>) -> Field {
    Field {
        tag,
        wire_type,
        payload,
    }
}

fn enforce_size(bytes: &[u8]) -> Result<(), LinuxPytestContractError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > EFFECT_IR_V2_MAX_CANONICAL_BYTES) {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    Ok(())
}

const OBJECT_HEADER_BYTES: usize = 2 + 2 + 2;
const ENUM_HEADER_BYTES: usize = 2 + 2;
const LIST_HEADER_BYTES: usize = 8;
const OPTIONAL_ABSENT_BYTES: usize = 1;
const OPTIONAL_PRESENT_HEADER_BYTES: usize = 1 + 8;

fn canonical_collection_count(count: usize) -> Result<u64, LinuxPytestContractError> {
    let count = u64::try_from(count).map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
    if count > EFFECT_IR_V2_MAX_COLLECTION_ITEMS {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    Ok(count)
}

fn checked_canonical_add(left: usize, right: usize) -> Result<usize, LinuxPytestContractError> {
    left.checked_add(right)
        .ok_or(LinuxPytestContractError::CanonicalEncoding)
}

fn checked_canonical_payload_length(length: usize) -> Result<usize, LinuxPytestContractError> {
    let length_u64 =
        u64::try_from(length).map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
    if length_u64 > EFFECT_IR_V2_MAX_CANONICAL_BYTES {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    Ok(length)
}

fn checked_canonical_field_length(
    payload_length: usize,
) -> Result<usize, LinuxPytestContractError> {
    checked_canonical_payload_length(checked_canonical_add(FIELD_HEADER_BYTES, payload_length)?)
}

fn checked_canonical_object_length(
    payload_lengths: &[usize],
) -> Result<usize, LinuxPytestContractError> {
    u16::try_from(payload_lengths.len())
        .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
    let mut length = OBJECT_HEADER_BYTES;
    for payload_length in payload_lengths {
        length = checked_canonical_add(length, checked_canonical_field_length(*payload_length)?)?;
    }
    checked_canonical_payload_length(length)
}

fn checked_canonical_enum_length(
    variant: u16,
    payload_lengths: &[usize],
) -> Result<usize, LinuxPytestContractError> {
    if variant == 0 {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    u16::try_from(payload_lengths.len())
        .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
    let mut length = ENUM_HEADER_BYTES;
    for payload_length in payload_lengths {
        length = checked_canonical_add(length, checked_canonical_field_length(*payload_length)?)?;
    }
    checked_canonical_payload_length(length)
}

fn checked_canonical_list_length(
    item_count: usize,
    item_lengths: impl IntoIterator<Item = Result<usize, LinuxPytestContractError>>,
) -> Result<usize, LinuxPytestContractError> {
    canonical_collection_count(item_count)?;
    let mut observed_count = 0usize;
    let mut length = LIST_HEADER_BYTES;
    for item_length in item_lengths {
        observed_count = observed_count
            .checked_add(1)
            .ok_or(LinuxPytestContractError::CanonicalEncoding)?;
        let item_length = item_length?;
        length = checked_canonical_add(length, LIST_ITEM_HEADER_BYTES)?;
        length = checked_canonical_add(length, item_length)?;
    }
    if observed_count != item_count {
        return Err(LinuxPytestContractError::CanonicalEncoding);
    }
    checked_canonical_payload_length(length)
}

fn checked_canonical_optional_length(
    payload_length: Option<usize>,
) -> Result<usize, LinuxPytestContractError> {
    match payload_length {
        None => Ok(OPTIONAL_ABSENT_BYTES),
        Some(payload_length) => checked_canonical_payload_length(checked_canonical_add(
            OPTIONAL_PRESENT_HEADER_BYTES,
            payload_length,
        )?),
    }
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
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| LinuxPytestContractError::CanonicalDecoding,
        )?))
    }

    fn u64(&mut self) -> Result<u64, LinuxPytestContractError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| LinuxPytestContractError::CanonicalDecoding,
        )?))
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

fn reserve_decoded<T>(values: &mut Vec<T>, count: usize) -> Result<(), LinuxPytestContractError> {
    values
        .try_reserve_exact(count)
        .map_err(|_| LinuxPytestContractError::CanonicalDecoding)
}

fn require_minimum_framing(
    count: usize,
    bytes_per_item: usize,
    remaining: usize,
) -> Result<(), LinuxPytestContractError> {
    let minimum = count
        .checked_mul(bytes_per_item)
        .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
    if minimum > remaining {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(())
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
    fn parse_nested(bytes: &'a [u8]) -> Result<Self, LinuxPytestContractError> {
        let mut cursor = Cursor::new(bytes);
        let type_id = cursor.u16()?;
        if cursor.u16()? != EFFECT_IR_V2_WIRE_VERSION {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        let count = usize::from(cursor.u16()?);
        require_minimum_framing(count, FIELD_HEADER_BYTES, cursor.remaining())?;
        let mut fields = Vec::new();
        reserve_decoded(&mut fields, count)?;
        let mut previous = 0u16;
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
            let payload = cursor.take(length)?;
            fields.push(RawField {
                tag,
                wire_type,
                payload,
            });
        }
        cursor.finish()?;
        Ok(Self { type_id, fields })
    }

    fn parse_top(bytes: &'a [u8]) -> Result<Self, LinuxPytestContractError> {
        enforce_size(bytes)?;
        let nested = bytes
            .strip_prefix(EFFECT_IR_V2_WIRE_MAGIC)
            .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
        Self::parse_nested(nested)
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
        require_minimum_framing(count, FIELD_HEADER_BYTES, cursor.remaining())?;
        let mut fields = Vec::new();
        reserve_decoded(&mut fields, count)?;
        let mut previous = 0u16;
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

    fn expect(
        &self,
        variant: u16,
        fields: &[(u16, WireType)],
    ) -> Result<(), LinuxPytestContractError> {
        if self.variant != variant
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

fn decode_list(bytes: &[u8]) -> Result<Vec<&[u8]>, LinuxPytestContractError> {
    let mut cursor = Cursor::new(bytes);
    let count = cursor.u64()?;
    if count > EFFECT_IR_V2_MAX_COLLECTION_ITEMS {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    let count = usize::try_from(count).map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
    require_minimum_framing(count, LIST_ITEM_HEADER_BYTES, cursor.remaining())?;
    let mut values = Vec::new();
    reserve_decoded(&mut values, count)?;
    for _ in 0..count {
        let length = usize::try_from(cursor.u64()?)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
        values.push(cursor.take(length)?);
    }
    cursor.finish()?;
    Ok(values)
}

fn decode_optional(bytes: &[u8]) -> Result<Option<&[u8]>, LinuxPytestContractError> {
    let mut cursor = Cursor::new(bytes);
    match cursor.u8()? {
        0 => {
            cursor.finish()?;
            Ok(None)
        }
        1 => {
            let length = usize::try_from(cursor.u64()?)
                .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?;
            let value = cursor.take(length)?;
            cursor.finish()?;
            Ok(Some(value))
        }
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], LinuxPytestContractError> {
    bytes
        .try_into()
        .map_err(|_| LinuxPytestContractError::CanonicalDecoding)
}

fn decode_u16(bytes: &[u8]) -> Result<u16, LinuxPytestContractError> {
    Ok(u16::from_be_bytes(exact(bytes)?))
}

fn decode_u32(bytes: &[u8]) -> Result<u32, LinuxPytestContractError> {
    Ok(u32::from_be_bytes(exact(bytes)?))
}

fn decode_u64(bytes: &[u8]) -> Result<u64, LinuxPytestContractError> {
    Ok(u64::from_be_bytes(exact(bytes)?))
}

fn decode_i64(bytes: &[u8]) -> Result<i64, LinuxPytestContractError> {
    Ok(i64::from_be_bytes(exact(bytes)?))
}

fn decode_bool(bytes: &[u8]) -> Result<bool, LinuxPytestContractError> {
    match exact::<1>(bytes)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_simple_enum(bytes: &[u8]) -> Result<u16, LinuxPytestContractError> {
    let value = RawEnum::parse(bytes)?;
    if !value.fields.is_empty() {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value.variant)
}

fn encode_blob(value: &BlobRefV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_BLOB_REF);
    object.bytes(1, value.digest.as_bytes())?;
    object.u64(2, value.byte_count)?;
    object.finish_nested()
}

fn encode_selector(value: &PytestSelectorV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_SELECTOR);
    object.bytes(1, &value.raw)?;
    object.bytes(2, &value.path)?;
    object.list(3, value.nodes.iter().cloned())?;
    object.finish_nested()
}

fn encode_invocation(
    value: &PytestInvocationIdentityV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_INVOCATION);
    object.list(1, value.argv.iter().cloned())?;
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

fn encode_environment(value: &EnvironmentBindingV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_ENVIRONMENT);
    object.bytes(1, value.key_id.as_bytes())?;
    object.bytes(2, value.digest.as_bytes())?;
    object.bytes(3, value.names_digest.as_bytes())?;
    object.u32(4, value.entry_count)?;
    object.bytes(5, value.policy_digest.as_bytes())?;
    object.finish_nested()
}

fn encode_snapshot(value: &SealedSnapshotIdentityV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_SNAPSHOT);
    object.bytes(1, value.snapshot_id.as_bytes())?;
    object.bytes(2, value.workspace_root.as_bytes())?;
    object.bytes(3, value.runtime_root.as_bytes())?;
    object.object(4, encode_blob(&value.manifest_blob)?)?;
    object.bytes(5, value.profile_digest.as_bytes())?;
    object.finish_nested()
}

fn encode_namespace_ids(value: &NamespaceIdsV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_NAMESPACE_IDS);
    object.u64(1, value.user)?;
    object.u64(2, value.mount)?;
    object.u64(3, value.pid)?;
    object.u64(4, value.network)?;
    object.u64(5, value.uts)?;
    object.u64(6, value.ipc)?;
    object.finish_nested()
}

fn encode_policy_digests(value: &PolicyDigestsV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_POLICY_DIGESTS);
    object.bytes(1, value.seccomp.as_bytes())?;
    object.bytes(2, value.landlock.as_bytes())?;
    object.bytes(3, value.namespace.as_bytes())?;
    object.bytes(4, value.tracer_runtime.as_bytes())?;
    object.bytes(5, value.ambient_broker.as_bytes())?;
    object.bytes(6, value.limits.as_bytes())?;
    object.bytes(7, value.environment.as_bytes())?;
    object.bytes(8, value.selector_grammar.as_bytes())?;
    object.bytes(9, value.runtime_closure.as_bytes())?;
    object.bytes(10, value.codec.as_bytes())?;
    object.finish_nested()
}

fn encode_platform(value: &PlatformIdentityV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_PLATFORM);
    object.enumeration(1, value.architecture as u16, Vec::new())?;
    object.bytes(2, &value.kernel_release)?;
    object.bytes(3, value.capability_digest.as_bytes())?;
    object.object(4, encode_namespace_ids(&value.namespace_ids)?)?;
    object.bytes(5, value.namespace_policy_digest.as_bytes())?;
    object.object(6, encode_policy_digests(&value.policy_digests)?)?;
    object.finish_nested()
}

fn encode_trace_counters(value: &TraceCountersV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_TRACE_COUNTERS);
    object.u64(1, value.final_sequence)?;
    object.u64(2, value.event_count)?;
    object.u64(3, value.syscall_event_count)?;
    object.u64(4, value.seccomp_trace_count)?;
    object.u64(5, value.ptrace_event_count)?;
    object.u64(6, value.trace_encoded_bytes)?;
    object.u64(7, value.task_birth_count)?;
    object.u64(8, value.task_exec_count)?;
    object.u64(9, value.task_exit_count)?;
    object.u64(10, value.task_reap_count)?;
    object.u64(11, value.observation_count)?;
    object.u64(12, value.ambient_event_count)?;
    object.u64(13, value.ordered_effect_count)?;
    object.u64(14, value.denied_operation_count)?;
    object.u64(15, value.unsupported_operation_count)?;
    object.u64(16, value.decoder_error_count)?;
    object.u64(17, value.lost_event_count)?;
    object.u64(18, value.final_ack_count)?;
    object.finish_nested()
}

fn encode_first_failure(value: &FirstFailureV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_FIRST_FAILURE);
    object.field(1, WireType::U8, vec![value.dimension as u8])?;
    object.u16(2, value.reason as u16)?;
    object.enumeration(3, value.phase as u16, Vec::new())?;
    object.optional(
        4,
        value.event_sequence.map(|item| item.to_be_bytes().to_vec()),
    )?;
    object.optional(
        5,
        value
            .logical_task_id
            .map(|item| item.0.to_be_bytes().to_vec()),
    )?;
    object.finish_nested()
}

fn encode_trace(value: &TraceCompletenessV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_TRACE);
    object.u64(1, value.required.bits())?;
    object.u64(2, value.complete.bits())?;
    object.u64(3, value.unsupported.bits())?;
    object.u64(4, value.violation.bits())?;
    object.object(5, encode_trace_counters(&value.counters)?)?;
    object.optional(
        6,
        value
            .first_failure
            .as_ref()
            .map(encode_first_failure)
            .transpose()?,
    )?;
    object.finish_nested()
}

fn encode_observation(value: &ObservationV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_OBSERVATION);
    object.u64(1, value.sequence)?;
    object.u32(2, value.logical_task_id.0)?;
    object.enumeration(3, value.kind as u16, Vec::new())?;
    object.bytes(4, value.sandbox_subject.as_bytes())?;
    object.object(
        5,
        encode_observation_detail(value.canonical_detail.clone(), false)?,
    )?;
    object.finish_nested()
}

fn encode_observation_detail(
    value: ObservationDetailV1,
    top: bool,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    value.validate()?;
    let (variant, fields) = match value {
        ObservationDetailV1::File {
            content_digest,
            byte_count,
        } => (
            1,
            vec![
                enum_field(1, WireType::Bytes, content_digest.as_bytes().to_vec()),
                enum_field(2, WireType::U64, byte_count.to_be_bytes().to_vec()),
            ],
        ),
        ObservationDetailV1::Directory {
            membership_digest,
            entry_count,
        } => (
            2,
            vec![
                enum_field(1, WireType::Bytes, membership_digest.as_bytes().to_vec()),
                enum_field(2, WireType::U64, entry_count.to_be_bytes().to_vec()),
            ],
        ),
        ObservationDetailV1::AbsentPath {
            parent_membership_digest,
            missing_component,
        } => (
            3,
            vec![
                enum_field(
                    1,
                    WireType::Bytes,
                    parent_membership_digest.as_bytes().to_vec(),
                ),
                enum_field(2, WireType::Bytes, missing_component),
            ],
        ),
        ObservationDetailV1::Symlink { target } => {
            (4, vec![enum_field(1, WireType::Bytes, target)])
        }
        ObservationDetailV1::Executable {
            node_digest,
            chain_digest,
        } => (
            5,
            vec![
                enum_field(1, WireType::Bytes, node_digest.as_bytes().to_vec()),
                enum_field(2, WireType::Bytes, chain_digest.as_bytes().to_vec()),
            ],
        ),
        ObservationDetailV1::Mapping {
            content_digest,
            offset,
            length,
            protection,
            flags,
        } => (
            6,
            vec![
                enum_field(1, WireType::Bytes, content_digest.as_bytes().to_vec()),
                enum_field(2, WireType::U64, offset.to_be_bytes().to_vec()),
                enum_field(3, WireType::U64, length.to_be_bytes().to_vec()),
                enum_field(4, WireType::U32, protection.to_be_bytes().to_vec()),
                enum_field(5, WireType::U32, flags.to_be_bytes().to_vec()),
            ],
        ),
        ObservationDetailV1::Metadata {
            field_mask,
            value_digest,
        } => (
            7,
            vec![
                enum_field(1, WireType::U64, field_mask.to_be_bytes().to_vec()),
                enum_field(2, WireType::Bytes, value_digest.as_bytes().to_vec()),
            ],
        ),
    };
    let mut object = ObjectBuilder::new(TYPE_OBSERVATION_DETAIL);
    object.enumeration(1, variant, fields)?;
    if top {
        object.finish_top()
    } else {
        object.finish_nested()
    }
}

pub(super) fn encode_observation_detail_top(
    value: &ObservationDetailV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_observation_detail(value.clone(), true)
}

fn encode_ambient(value: &AmbientEventV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_AMBIENT_EVENT);
    object.u64(1, value.sequence)?;
    object.u32(2, value.logical_task_id.0)?;
    object.enumeration(3, value.kind as u16, Vec::new())?;
    object.object(4, encode_blob(&value.canonical_detail)?)?;
    object.finish_nested()
}

fn encode_effect(value: &OrderedEffectV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_ORDERED_EFFECT);
    object.u64(1, value.sequence)?;
    object.u32(2, value.logical_task_id.0)?;
    object.enumeration(3, value.kind as u16, Vec::new())?;
    object.bytes(4, value.sandbox_subject.as_bytes())?;
    object.object(5, encode_blob(&value.canonical_detail)?)?;
    object.finish_nested()
}

fn encode_stream(value: &StreamCaptureV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    match value {
        StreamCaptureV2::Complete { blob } => Ok(encode_enum(
            1,
            vec![enum_field(1, WireType::Object, encode_blob(blob)?)],
        )?),
        StreamCaptureV2::Exceeded { observed_bytes } => Ok(encode_enum(
            2,
            vec![enum_field(
                1,
                WireType::U64,
                observed_bytes.to_be_bytes().to_vec(),
            )],
        )?),
        StreamCaptureV2::Incomplete {
            observed_bytes,
            reason,
        } => Ok(encode_enum(
            3,
            vec![
                enum_field(1, WireType::U64, observed_bytes.to_be_bytes().to_vec()),
                enum_field(2, WireType::U16, (*reason as u16).to_be_bytes().to_vec()),
            ],
        )?),
    }
}

fn encode_result(value: &EffectResultV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_RESULT);
    object.field(1, WireType::Enum, encode_stream(&value.stdout)?)?;
    object.field(2, WireType::Enum, encode_stream(&value.stderr)?)?;
    object.u32(3, value.raw_linux_wait_status.0)?;
    object.finish_nested()
}

fn decode_blob(bytes: &[u8]) -> Result<BlobRefV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(TYPE_BLOB_REF, &[(1, WireType::Bytes), (2, WireType::U64)])?;
    Ok(BlobRefV2 {
        digest: BlobDigest(exact(object.payload(1)?)?),
        byte_count: decode_u64(object.payload(2)?)?,
    })
}

fn decode_selector(bytes: &[u8]) -> Result<PytestSelectorV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_SELECTOR,
        &[
            (1, WireType::Bytes),
            (2, WireType::Bytes),
            (3, WireType::List),
        ],
    )?;
    Ok(PytestSelectorV1 {
        raw: object.payload(1)?.to_vec(),
        path: object.payload(2)?.to_vec(),
        nodes: decode_list(object.payload(3)?)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect(),
    })
}

fn decode_invocation(bytes: &[u8]) -> Result<PytestInvocationIdentityV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_INVOCATION,
        &[
            (1, WireType::List),
            (2, WireType::Bytes),
            (3, WireType::List),
            (4, WireType::Enum),
        ],
    )?;
    let stdin_profile = match decode_simple_enum(object.payload(4)?)? {
        1 => StdinProfileV1::ClosedEof,
        2 => StdinProfileV1::EmptyNonTtyEof,
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    Ok(PytestInvocationIdentityV1 {
        argv: decode_list(object.payload(1)?)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect(),
        cwd: object.payload(2)?.to_vec(),
        selectors: decode_list(object.payload(3)?)?
            .into_iter()
            .map(decode_selector)
            .collect::<Result<Vec<_>, _>>()?,
        stdin_profile,
    })
}

fn decode_environment(bytes: &[u8]) -> Result<EnvironmentBindingV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_ENVIRONMENT,
        &[
            (1, WireType::Bytes),
            (2, WireType::Bytes),
            (3, WireType::Bytes),
            (4, WireType::U32),
            (5, WireType::Bytes),
        ],
    )?;
    Ok(EnvironmentBindingV1 {
        key_id: EnvironmentKeyId(exact(object.payload(1)?)?),
        digest: EnvironmentDigest(exact(object.payload(2)?)?),
        names_digest: EnvironmentNamesDigest(exact(object.payload(3)?)?),
        entry_count: decode_u32(object.payload(4)?)?,
        policy_digest: PolicyDigest(exact(object.payload(5)?)?),
    })
}

fn decode_snapshot(bytes: &[u8]) -> Result<SealedSnapshotIdentityV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_SNAPSHOT,
        &[
            (1, WireType::Bytes),
            (2, WireType::Bytes),
            (3, WireType::Bytes),
            (4, WireType::Object),
            (5, WireType::Bytes),
        ],
    )?;
    Ok(SealedSnapshotIdentityV2 {
        snapshot_id: SnapshotId(exact(object.payload(1)?)?),
        workspace_root: MerkleRoot(exact(object.payload(2)?)?),
        runtime_root: MerkleRoot(exact(object.payload(3)?)?),
        manifest_blob: decode_blob(object.payload(4)?)?,
        profile_digest: ProfileDigest(exact(object.payload(5)?)?),
    })
}

fn decode_namespace_ids(bytes: &[u8]) -> Result<NamespaceIdsV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_NAMESPACE_IDS,
        &[
            (1, WireType::U64),
            (2, WireType::U64),
            (3, WireType::U64),
            (4, WireType::U64),
            (5, WireType::U64),
            (6, WireType::U64),
        ],
    )?;
    Ok(NamespaceIdsV1 {
        user: decode_u64(object.payload(1)?)?,
        mount: decode_u64(object.payload(2)?)?,
        pid: decode_u64(object.payload(3)?)?,
        network: decode_u64(object.payload(4)?)?,
        uts: decode_u64(object.payload(5)?)?,
        ipc: decode_u64(object.payload(6)?)?,
    })
}

fn decode_policy_digests(bytes: &[u8]) -> Result<PolicyDigestsV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_POLICY_DIGESTS,
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
        seccomp: PolicyDigest(exact(object.payload(1)?)?),
        landlock: PolicyDigest(exact(object.payload(2)?)?),
        namespace: PolicyDigest(exact(object.payload(3)?)?),
        tracer_runtime: PolicyDigest(exact(object.payload(4)?)?),
        ambient_broker: PolicyDigest(exact(object.payload(5)?)?),
        limits: PolicyDigest(exact(object.payload(6)?)?),
        environment: PolicyDigest(exact(object.payload(7)?)?),
        selector_grammar: PolicyDigest(exact(object.payload(8)?)?),
        runtime_closure: PolicyDigest(exact(object.payload(9)?)?),
        codec: PolicyDigest(exact(object.payload(10)?)?),
    })
}

fn decode_architecture(bytes: &[u8]) -> Result<ArchitectureV1, LinuxPytestContractError> {
    match decode_simple_enum(bytes)? {
        1 => Ok(ArchitectureV1::X86_64),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_platform(bytes: &[u8]) -> Result<PlatformIdentityV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_PLATFORM,
        &[
            (1, WireType::Enum),
            (2, WireType::Bytes),
            (3, WireType::Bytes),
            (4, WireType::Object),
            (5, WireType::Bytes),
            (6, WireType::Object),
        ],
    )?;
    Ok(PlatformIdentityV2 {
        architecture: decode_architecture(object.payload(1)?)?,
        kernel_release: object.payload(2)?.to_vec(),
        capability_digest: CapabilityDigest(exact(object.payload(3)?)?),
        namespace_ids: decode_namespace_ids(object.payload(4)?)?,
        namespace_policy_digest: PolicyDigest(exact(object.payload(5)?)?),
        policy_digests: decode_policy_digests(object.payload(6)?)?,
    })
}

fn decode_trace_counters(bytes: &[u8]) -> Result<TraceCountersV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    let expected = (1..=18).map(|tag| (tag, WireType::U64)).collect::<Vec<_>>();
    object.expect(TYPE_TRACE_COUNTERS, &expected)?;
    Ok(TraceCountersV1 {
        final_sequence: decode_u64(object.payload(1)?)?,
        event_count: decode_u64(object.payload(2)?)?,
        syscall_event_count: decode_u64(object.payload(3)?)?,
        seccomp_trace_count: decode_u64(object.payload(4)?)?,
        ptrace_event_count: decode_u64(object.payload(5)?)?,
        trace_encoded_bytes: decode_u64(object.payload(6)?)?,
        task_birth_count: decode_u64(object.payload(7)?)?,
        task_exec_count: decode_u64(object.payload(8)?)?,
        task_exit_count: decode_u64(object.payload(9)?)?,
        task_reap_count: decode_u64(object.payload(10)?)?,
        observation_count: decode_u64(object.payload(11)?)?,
        ambient_event_count: decode_u64(object.payload(12)?)?,
        ordered_effect_count: decode_u64(object.payload(13)?)?,
        denied_operation_count: decode_u64(object.payload(14)?)?,
        unsupported_operation_count: decode_u64(object.payload(15)?)?,
        decoder_error_count: decode_u64(object.payload(16)?)?,
        lost_event_count: decode_u64(object.payload(17)?)?,
        final_ack_count: decode_u64(object.payload(18)?)?,
    })
}

fn decode_first_failure(bytes: &[u8]) -> Result<FirstFailureV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_FIRST_FAILURE,
        &[
            (1, WireType::U8),
            (2, WireType::U16),
            (3, WireType::Enum),
            (4, WireType::Optional),
            (5, WireType::Optional),
        ],
    )?;
    let dimension = CompletenessDimensionV2::from_u8(exact::<1>(object.payload(1)?)?[0])
        .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
    let reason = ExecuteOnlyCode::from_u16(decode_u16(object.payload(2)?)?)
        .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
    let phase = match decode_simple_enum(object.payload(3)?)? {
        1 => TracePhaseV1::Snapshot,
        2 => TracePhaseV1::Isolation,
        3 => TracePhaseV1::Trace,
        4 => TracePhaseV1::Finalize,
        5 => TracePhaseV1::Capture,
        6 => TracePhaseV1::Cleanup,
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    Ok(FirstFailureV1 {
        dimension,
        reason,
        phase,
        event_sequence: decode_optional(object.payload(4)?)?
            .map(decode_u64)
            .transpose()?,
        logical_task_id: decode_optional(object.payload(5)?)?
            .map(decode_u32)
            .transpose()?
            .map(LogicalTaskId),
    })
}

fn decode_trace(bytes: &[u8]) -> Result<TraceCompletenessV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_TRACE,
        &[
            (1, WireType::U64),
            (2, WireType::U64),
            (3, WireType::U64),
            (4, WireType::U64),
            (5, WireType::Object),
            (6, WireType::Optional),
        ],
    )?;
    let value = TraceCompletenessV2 {
        required: EffectBitmap::from_bits(decode_u64(object.payload(1)?)?),
        complete: EffectBitmap::from_bits(decode_u64(object.payload(2)?)?),
        unsupported: EffectBitmap::from_bits(decode_u64(object.payload(3)?)?),
        violation: EffectBitmap::from_bits(decode_u64(object.payload(4)?)?),
        counters: decode_trace_counters(object.payload(5)?)?,
        first_failure: decode_optional(object.payload(6)?)?
            .map(decode_first_failure)
            .transpose()?,
    };
    value.validate()?;
    Ok(value)
}

fn decode_observation_detail(
    bytes: &[u8],
) -> Result<ObservationDetailV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(TYPE_OBSERVATION_DETAIL, &[(1, WireType::Enum)])?;
    let value = RawEnum::parse(object.payload(1)?)?;
    let detail = match value.variant {
        1 => {
            value.expect(1, &[(1, WireType::Bytes), (2, WireType::U64)])?;
            ObservationDetailV1::File {
                content_digest: FileContentDigest(exact(value.payload(1)?)?),
                byte_count: decode_u64(value.payload(2)?)?,
            }
        }
        2 => {
            value.expect(2, &[(1, WireType::Bytes), (2, WireType::U64)])?;
            ObservationDetailV1::Directory {
                membership_digest: BlobDigest(exact(value.payload(1)?)?),
                entry_count: decode_u64(value.payload(2)?)?,
            }
        }
        3 => {
            value.expect(3, &[(1, WireType::Bytes), (2, WireType::Bytes)])?;
            ObservationDetailV1::AbsentPath {
                parent_membership_digest: BlobDigest(exact(value.payload(1)?)?),
                missing_component: value.payload(2)?.to_vec(),
            }
        }
        4 => {
            value.expect(4, &[(1, WireType::Bytes)])?;
            ObservationDetailV1::Symlink {
                target: value.payload(1)?.to_vec(),
            }
        }
        5 => {
            value.expect(5, &[(1, WireType::Bytes), (2, WireType::Bytes)])?;
            ObservationDetailV1::Executable {
                node_digest: NodeDigest(exact(value.payload(1)?)?),
                chain_digest: ExecutableChainDigest(exact(value.payload(2)?)?),
            }
        }
        6 => {
            value.expect(
                6,
                &[
                    (1, WireType::Bytes),
                    (2, WireType::U64),
                    (3, WireType::U64),
                    (4, WireType::U32),
                    (5, WireType::U32),
                ],
            )?;
            ObservationDetailV1::Mapping {
                content_digest: FileContentDigest(exact(value.payload(1)?)?),
                offset: decode_u64(value.payload(2)?)?,
                length: decode_u64(value.payload(3)?)?,
                protection: decode_u32(value.payload(4)?)?,
                flags: decode_u32(value.payload(5)?)?,
            }
        }
        7 => {
            value.expect(7, &[(1, WireType::U64), (2, WireType::Bytes)])?;
            ObservationDetailV1::Metadata {
                field_mask: decode_u64(value.payload(1)?)?,
                value_digest: BlobDigest(exact(value.payload(2)?)?),
            }
        }
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    detail.validate()?;
    if encode_observation_detail(detail.clone(), false)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(detail)
}

pub(super) fn decode_observation_detail_top(
    bytes: &[u8],
) -> Result<ObservationDetailV1, LinuxPytestContractError> {
    enforce_size(bytes)?;
    let nested = bytes
        .strip_prefix(EFFECT_IR_V2_WIRE_MAGIC)
        .ok_or(LinuxPytestContractError::CanonicalDecoding)?;
    let detail = decode_observation_detail(nested)?;
    if encode_observation_detail_top(&detail)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(detail)
}

fn decode_observation(bytes: &[u8]) -> Result<ObservationV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_OBSERVATION,
        &[
            (1, WireType::U64),
            (2, WireType::U32),
            (3, WireType::Enum),
            (4, WireType::Bytes),
            (5, WireType::Object),
        ],
    )?;
    let kind = match decode_simple_enum(object.payload(3)?)? {
        1 => ObservationKindV2::File,
        2 => ObservationKindV2::Directory,
        3 => ObservationKindV2::AbsentPath,
        4 => ObservationKindV2::Symlink,
        5 => ObservationKindV2::Executable,
        6 => ObservationKindV2::Mapping,
        7 => ObservationKindV2::Metadata,
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    Ok(ObservationV2 {
        sequence: decode_u64(object.payload(1)?)?,
        logical_task_id: LogicalTaskId(decode_u32(object.payload(2)?)?),
        kind,
        sandbox_subject: SandboxPath::new(object.payload(4)?.to_vec().into_boxed_slice())?,
        canonical_detail: decode_observation_detail(object.payload(5)?)?,
    })
}

fn decode_ambient(bytes: &[u8]) -> Result<AmbientEventV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_AMBIENT_EVENT,
        &[
            (1, WireType::U64),
            (2, WireType::U32),
            (3, WireType::Enum),
            (4, WireType::Object),
        ],
    )?;
    let kind = match decode_simple_enum(object.payload(3)?)? {
        1 => AmbientKindV2::LogicalTime,
        2 => AmbientKindV2::LogicalRandom,
        3 => AmbientKindV2::LogicalPid,
        4 => AmbientKindV2::Sleep,
        5 => AmbientKindV2::Signal,
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    Ok(AmbientEventV2 {
        sequence: decode_u64(object.payload(1)?)?,
        logical_task_id: LogicalTaskId(decode_u32(object.payload(2)?)?),
        kind,
        canonical_detail: decode_blob(object.payload(4)?)?,
    })
}

fn decode_effect(bytes: &[u8]) -> Result<OrderedEffectV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_ORDERED_EFFECT,
        &[
            (1, WireType::U64),
            (2, WireType::U32),
            (3, WireType::Enum),
            (4, WireType::Bytes),
            (5, WireType::Object),
        ],
    )?;
    let kind = match decode_simple_enum(object.payload(3)?)? {
        1 => EffectKindV2::Write,
        2 => EffectKindV2::Truncate,
        3 => EffectKindV2::Metadata,
        4 => EffectKindV2::Link,
        5 => EffectKindV2::Rename,
        6 => EffectKindV2::Unlink,
        7 => EffectKindV2::Mkdir,
        8 => EffectKindV2::Rmdir,
        9 => EffectKindV2::WritableMapping,
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    Ok(OrderedEffectV2 {
        sequence: decode_u64(object.payload(1)?)?,
        logical_task_id: LogicalTaskId(decode_u32(object.payload(2)?)?),
        kind,
        sandbox_subject: SandboxPath::new(object.payload(4)?.to_vec().into_boxed_slice())?,
        canonical_detail: decode_blob(object.payload(5)?)?,
    })
}

fn decode_stream(bytes: &[u8]) -> Result<StreamCaptureV2, LinuxPytestContractError> {
    let value = RawEnum::parse(bytes)?;
    match value.variant {
        1 => {
            value.expect(1, &[(1, WireType::Object)])?;
            Ok(StreamCaptureV2::Complete {
                blob: decode_blob(value.payload(1)?)?,
            })
        }
        2 => {
            value.expect(2, &[(1, WireType::U64)])?;
            Ok(StreamCaptureV2::Exceeded {
                observed_bytes: decode_u64(value.payload(1)?)?,
            })
        }
        3 => {
            value.expect(3, &[(1, WireType::U64), (2, WireType::U16)])?;
            Ok(StreamCaptureV2::Incomplete {
                observed_bytes: decode_u64(value.payload(1)?)?,
                reason: ExecuteOnlyCode::from_u16(decode_u16(value.payload(2)?)?)
                    .ok_or(LinuxPytestContractError::CanonicalDecoding)?,
            })
        }
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_result(bytes: &[u8]) -> Result<EffectResultV2, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_RESULT,
        &[(1, WireType::Enum), (2, WireType::Enum), (3, WireType::U32)],
    )?;
    Ok(EffectResultV2 {
        stdout: decode_stream(object.payload(1)?)?,
        stderr: decode_stream(object.payload(2)?)?,
        raw_linux_wait_status: RawLinuxWaitStatusV1(decode_u32(object.payload(3)?)?),
    })
}

fn encode_shape(value: &ShapeV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_SHAPE);
    object.utf8(1, &value.schema)?;
    object.utf8(2, &value.profile_id)?;
    object.bytes(3, value.profile_digest.as_bytes())?;
    object.bytes(4, value.workspace_identity.as_bytes())?;
    object.object(5, encode_invocation(&value.invocation)?)?;
    object.object(6, encode_environment(&value.environment)?)?;
    object.list(
        7,
        value
            .resolved_selector_targets
            .iter()
            .map(|target| target.as_bytes().to_vec()),
    )?;
    object.bytes(8, value.executable_chain_digest.as_bytes())?;
    object.bytes(9, value.runtime_root.as_bytes())?;
    object.enumeration(10, value.architecture as u16, Vec::new())?;
    object.bytes(11, value.capability_digest.as_bytes())?;
    object.bytes(12, value.namespace_policy_digest.as_bytes())?;
    object.object(13, encode_policy_digests(&value.policy_digests)?)?;
    object.bytes(14, &value.executable_chain_witness)?;
    object.finish_top()
}

fn decode_shape(bytes: &[u8]) -> Result<ShapeV1, LinuxPytestContractError> {
    let object = RawObject::parse_top(bytes)?;
    object.expect(
        TYPE_SHAPE,
        &[
            (1, WireType::Utf8),
            (2, WireType::Utf8),
            (3, WireType::Bytes),
            (4, WireType::Bytes),
            (5, WireType::Object),
            (6, WireType::Object),
            (7, WireType::List),
            (8, WireType::Bytes),
            (9, WireType::Bytes),
            (10, WireType::Enum),
            (11, WireType::Bytes),
            (12, WireType::Bytes),
            (13, WireType::Object),
            (14, WireType::Bytes),
        ],
    )?;
    let value = ShapeV1 {
        schema: std::str::from_utf8(object.payload(1)?)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?
            .to_owned(),
        profile_id: std::str::from_utf8(object.payload(2)?)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?
            .to_owned(),
        profile_digest: ProfileDigest(exact(object.payload(3)?)?),
        workspace_identity: WorkspaceIdentity(exact(object.payload(4)?)?),
        invocation: decode_invocation(object.payload(5)?)?,
        environment: decode_environment(object.payload(6)?)?,
        resolved_selector_targets: decode_list(object.payload(7)?)?
            .into_iter()
            .map(|target| {
                SandboxPath::new(target.to_vec().into_boxed_slice())
                    .map_err(|_| LinuxPytestContractError::CanonicalDecoding)
            })
            .collect::<Result<Vec<_>, _>>()?,
        executable_chain_digest: ExecutableChainDigest(exact(object.payload(8)?)?),
        runtime_root: MerkleRoot(exact(object.payload(9)?)?),
        architecture: decode_architecture(object.payload(10)?)?,
        capability_digest: CapabilityDigest(exact(object.payload(11)?)?),
        namespace_policy_digest: PolicyDigest(exact(object.payload(12)?)?),
        policy_digests: decode_policy_digests(object.payload(13)?)?,
        executable_chain_witness: object.payload(14)?.to_vec(),
    };
    value.validate()?;
    if encode_shape(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_observation_dependency(
    value: &ObservationDependencyV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_OBSERVATION_DEPENDENCY);
    object.bytes(1, &value.key)?;
    object.enumeration(2, value.kind as u16, Vec::new())?;
    object.bytes(3, value.subject.as_bytes())?;
    object.object(4, encode_blob(&value.current_value)?)?;
    object.finish_nested()
}

fn decode_observation_kind(bytes: &[u8]) -> Result<ObservationKindV2, LinuxPytestContractError> {
    match decode_simple_enum(bytes)? {
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

fn decode_observation_dependency(
    bytes: &[u8],
) -> Result<ObservationDependencyV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_OBSERVATION_DEPENDENCY,
        &[
            (1, WireType::Bytes),
            (2, WireType::Enum),
            (3, WireType::Bytes),
            (4, WireType::Object),
        ],
    )?;
    Ok(ObservationDependencyV1 {
        key: object.payload(1)?.to_vec(),
        kind: decode_observation_kind(object.payload(2)?)?,
        subject: SandboxPath::new(object.payload(3)?.to_vec().into_boxed_slice())
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?,
        current_value: decode_blob(object.payload(4)?)?,
    })
}

fn encode_observation_closure(
    value: &ObservationClosureV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_OBSERVATION_CLOSURE);
    object.list(
        1,
        value
            .dependencies()
            .iter()
            .map(encode_observation_dependency)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.finish_top()
}

fn decode_observation_closure(
    bytes: &[u8],
) -> Result<ObservationClosureV1, LinuxPytestContractError> {
    let object = RawObject::parse_top(bytes)?;
    object.expect(TYPE_OBSERVATION_CLOSURE, &[(1, WireType::List)])?;
    let value = ObservationClosureV1::new(
        decode_list(object.payload(1)?)?
            .into_iter()
            .map(decode_observation_dependency)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    if encode_observation_closure(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_record(value: &EffectRecordV2) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_EFFECT_RECORD);
    object.utf8(1, &value.schema)?;
    object.bytes(2, value.record_id.as_bytes())?;
    object.utf8(3, &value.profile_id)?;
    object.bytes(4, value.profile_digest.as_bytes())?;
    object.bytes(5, value.shape_key.as_bytes())?;
    object.bytes(6, value.request_key.as_bytes())?;
    object.object(7, encode_invocation(&value.invocation)?)?;
    object.bytes(8, value.workspace_identity.as_bytes())?;
    object.object(9, encode_environment(&value.environment)?)?;
    object.object(10, encode_snapshot(&value.sealed_snapshot)?)?;
    object.object(11, encode_platform(&value.platform)?)?;
    object.object(12, encode_trace(&value.trace)?)?;
    object.list(
        13,
        value
            .observations
            .iter()
            .map(encode_observation)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.list(
        14,
        value
            .ambient_events
            .iter()
            .map(encode_ambient)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.list(
        15,
        value
            .ordered_effects
            .iter()
            .map(encode_effect)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.bytes(16, value.final_workspace_root.as_bytes())?;
    object.object(17, encode_result(&value.result)?)?;
    object.enumeration(18, value.disposition as u16, Vec::new())?;
    object.optional(
        19,
        value
            .disposition_reason
            .map(|reason| (reason as u16).to_be_bytes().to_vec()),
    )?;
    object.optional(
        20,
        value
            .primary_record_id
            .map(|record_id| record_id.as_bytes().to_vec()),
    )?;
    object.optional(21, None)?;
    object.u64(22, value.created_monotonic_ns.0)?;
    object.bytes(23, &value.shape.canonical_bytes()?)?;
    object.bytes(24, &value.observation_closure.canonical_bytes()?)?;
    object.finish_top()
}

fn decode_record(bytes: &[u8]) -> Result<EffectRecordV2, LinuxPytestContractError> {
    let object = RawObject::parse_top(bytes)?;
    object.expect(
        TYPE_EFFECT_RECORD,
        &[
            (1, WireType::Utf8),
            (2, WireType::Bytes),
            (3, WireType::Utf8),
            (4, WireType::Bytes),
            (5, WireType::Bytes),
            (6, WireType::Bytes),
            (7, WireType::Object),
            (8, WireType::Bytes),
            (9, WireType::Object),
            (10, WireType::Object),
            (11, WireType::Object),
            (12, WireType::Object),
            (13, WireType::List),
            (14, WireType::List),
            (15, WireType::List),
            (16, WireType::Bytes),
            (17, WireType::Object),
            (18, WireType::Enum),
            (19, WireType::Optional),
            (20, WireType::Optional),
            (21, WireType::Optional),
            (22, WireType::U64),
            (23, WireType::Bytes),
            (24, WireType::Bytes),
        ],
    )?;
    let disposition = match decode_simple_enum(object.payload(18)?)? {
        1 => EffectRecordDispositionV2::ExecutedOnly,
        2 => EffectRecordDispositionV2::PrimaryCandidate,
        3 => EffectRecordDispositionV2::ShadowCandidate,
        _ => return Err(LinuxPytestContractError::CanonicalDecoding),
    };
    let disposition_reason = decode_optional(object.payload(19)?)?
        .map(decode_u16)
        .transpose()?
        .map(|code| {
            ExecuteOnlyCode::from_u16(code).ok_or(LinuxPytestContractError::CanonicalDecoding)
        })
        .transpose()?;
    let primary_record_id = decode_optional(object.payload(20)?)?
        .map(|value| exact(value).map(RecordId))
        .transpose()?;
    if decode_optional(object.payload(21)?)?.is_some() {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    let value = EffectRecordV2 {
        schema: std::str::from_utf8(object.payload(1)?)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?
            .to_owned(),
        record_id: RecordId(exact(object.payload(2)?)?),
        profile_id: std::str::from_utf8(object.payload(3)?)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?
            .to_owned(),
        profile_digest: ProfileDigest(exact(object.payload(4)?)?),
        shape_key: ShapeKey(exact(object.payload(5)?)?),
        request_key: RequestKey(exact(object.payload(6)?)?),
        invocation: decode_invocation(object.payload(7)?)?,
        workspace_identity: WorkspaceIdentity(exact(object.payload(8)?)?),
        environment: decode_environment(object.payload(9)?)?,
        sealed_snapshot: decode_snapshot(object.payload(10)?)?,
        platform: decode_platform(object.payload(11)?)?,
        trace: decode_trace(object.payload(12)?)?,
        observations: decode_list(object.payload(13)?)?
            .into_iter()
            .map(decode_observation)
            .collect::<Result<Vec<_>, _>>()?,
        ambient_events: decode_list(object.payload(14)?)?
            .into_iter()
            .map(decode_ambient)
            .collect::<Result<Vec<_>, _>>()?,
        ordered_effects: decode_list(object.payload(15)?)?
            .into_iter()
            .map(decode_effect)
            .collect::<Result<Vec<_>, _>>()?,
        final_workspace_root: MerkleRoot(exact(object.payload(16)?)?),
        result: decode_result(object.payload(17)?)?,
        disposition,
        disposition_reason,
        primary_record_id,
        created_monotonic_ns: MonotonicNs(decode_u64(object.payload(22)?)?),
        shape: ShapeV1::from_canonical_bytes(object.payload(23)?)?,
        observation_closure: ObservationClosureV1::from_canonical_bytes(object.payload(24)?)?,
    };
    value.validate()?;
    if encode_record(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

fn encode_comparison_snapshot(
    value: &ComparisonSnapshotV1<'_>,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_COMPARISON_SNAPSHOT);
    object.bytes(1, value.workspace_root.as_bytes())?;
    object.bytes(2, value.runtime_root.as_bytes())?;
    object.object(3, encode_blob(value.manifest_blob)?)?;
    object.bytes(4, value.profile_digest.as_bytes())?;
    object.finish_nested()
}

fn encode_comparison_platform(
    value: &ComparisonPlatformV1<'_>,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_COMPARISON_PLATFORM);
    object.enumeration(1, value.architecture as u16, Vec::new())?;
    object.bytes(2, value.kernel_release)?;
    object.bytes(3, value.capability_digest.as_bytes())?;
    object.bytes(4, value.namespace_policy_digest.as_bytes())?;
    object.object(5, encode_policy_digests(value.policy_digests)?)?;
    object.finish_nested()
}

fn encode_comparison_view(
    value: &ComparisonViewV1<'_>,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_COMPARISON_VIEW);
    object.utf8(1, value.schema)?;
    object.utf8(2, value.profile_id)?;
    object.bytes(3, value.profile_digest.as_bytes())?;
    object.bytes(4, value.shape_key.as_bytes())?;
    object.bytes(5, value.request_key.as_bytes())?;
    object.object(6, encode_invocation(value.invocation)?)?;
    object.bytes(7, value.workspace_identity.as_bytes())?;
    object.object(8, encode_environment(value.environment)?)?;
    object.object(9, encode_comparison_snapshot(&value.sealed_snapshot)?)?;
    object.object(10, encode_comparison_platform(&value.platform)?)?;
    object.object(11, encode_trace(value.trace)?)?;
    object.list(
        12,
        value
            .observations
            .iter()
            .map(encode_observation)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.list(
        13,
        value
            .ambient_events
            .iter()
            .map(encode_ambient)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.list(
        14,
        value
            .ordered_effects
            .iter()
            .map(encode_effect)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.bytes(15, value.final_workspace_root.as_bytes())?;
    object.object(16, encode_result(value.result)?)?;
    object.bytes(17, &value.shape.canonical_bytes()?)?;
    object.bytes(18, &value.observation_closure.canonical_bytes()?)?;
    object.finish_top()
}

fn comparison_rules_bytes() -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_COMPARISON_RULES);
    object.bytes(1, COMPARISON_RULE_VERSION)?;
    object.list(2, COMPARISON_EXCLUSIONS.iter().map(|item| item.to_vec()))?;
    object.finish_top()
}

fn manifest_timespec_canonical_length() -> Result<usize, LinuxPytestContractError> {
    checked_canonical_object_length(&[std::mem::size_of::<i64>(), std::mem::size_of::<u32>()])
}

fn manifest_xattr_canonical_length(value: &XattrV1) -> Result<usize, LinuxPytestContractError> {
    checked_canonical_object_length(&[value.name.len(), value.value.len()])
}

fn manifest_xattr_list_canonical_length(
    values: &[XattrV1],
) -> Result<usize, LinuxPytestContractError> {
    checked_canonical_list_length(
        values.len(),
        values.iter().map(manifest_xattr_canonical_length),
    )
}

fn manifest_metadata_projection_canonical_length(
    value: ManifestMetadataProjectionV1<'_>,
) -> Result<usize, LinuxPytestContractError> {
    let timespec = manifest_timespec_canonical_length()?;
    let btime = checked_canonical_optional_length(value.btime.map(|_| timespec))?;
    let xattrs = manifest_xattr_list_canonical_length(value.xattrs)?;
    checked_canonical_object_length(&[
        std::mem::size_of::<u32>(),
        std::mem::size_of::<u32>(),
        std::mem::size_of::<u32>(),
        std::mem::size_of::<u64>(),
        std::mem::size_of::<u64>(),
        timespec,
        timespec,
        timespec,
        btime,
        xattrs,
    ])
}

fn manifest_metadata_canonical_length(
    value: &MetadataV1,
) -> Result<usize, LinuxPytestContractError> {
    manifest_metadata_projection_canonical_length(value.into())
}

fn manifest_extent_canonical_length() -> Result<usize, LinuxPytestContractError> {
    checked_canonical_object_length(&[std::mem::size_of::<u64>(), std::mem::size_of::<u64>()])
}

fn manifest_extent_list_canonical_length(
    values: &[ExtentV1],
) -> Result<usize, LinuxPytestContractError> {
    let extent = manifest_extent_canonical_length()?;
    checked_canonical_list_length(values.len(), values.iter().map(|_| Ok(extent)))
}

fn manifest_child_canonical_length(
    value: &ChildCommitmentV1,
) -> Result<usize, LinuxPytestContractError> {
    let kind = checked_canonical_enum_length(value.kind as u16, &[])?;
    checked_canonical_object_length(&[value.name.len(), kind, value.node_digest.as_bytes().len()])
}

fn manifest_child_list_canonical_length(
    values: &[ChildCommitmentV1],
) -> Result<usize, LinuxPytestContractError> {
    checked_canonical_list_length(
        values.len(),
        values.iter().map(manifest_child_canonical_length),
    )
}

fn manifest_payload_projection_canonical_length(
    value: ManifestPayloadProjectionV1<'_>,
) -> Result<usize, LinuxPytestContractError> {
    match value {
        ManifestPayloadProjectionV1::Directory { children } => checked_canonical_enum_length(
            ManifestEntryKindV1::Directory as u16,
            &[manifest_child_list_canonical_length(children)?],
        ),
        ManifestPayloadProjectionV1::Regular {
            content_digest,
            data_extents,
        } => checked_canonical_enum_length(
            ManifestEntryKindV1::Regular as u16,
            &[
                content_digest.as_bytes().len(),
                manifest_extent_list_canonical_length(data_extents)?,
            ],
        ),
        ManifestPayloadProjectionV1::Symlink { target } => {
            checked_canonical_enum_length(ManifestEntryKindV1::Symlink as u16, &[target.len()])
        }
        ManifestPayloadProjectionV1::ExternalTree {
            tree_role,
            target_root,
            ..
        } => checked_canonical_enum_length(
            ManifestEntryKindV1::ExternalTree as u16,
            &[
                checked_canonical_enum_length(tree_role as u16, &[])?,
                target_root.as_bytes().len(),
                std::mem::size_of::<u8>(),
            ],
        ),
    }
}

#[cfg(test)]
fn manifest_payload_canonical_length(
    value: &ManifestPayloadV1,
) -> Result<usize, LinuxPytestContractError> {
    manifest_payload_projection_canonical_length(value.into())
}

fn manifest_entry_projection_canonical_length(
    value: ManifestEntryProjectionViewV1<'_>,
) -> Result<usize, LinuxPytestContractError> {
    let kind = checked_canonical_enum_length(value.payload.kind() as u16, &[])?;
    let metadata = manifest_metadata_projection_canonical_length(value.metadata)?;
    let payload = manifest_payload_projection_canonical_length(value.payload)?;
    let hardlink = checked_canonical_optional_length(
        value
            .hardlink_group
            .as_ref()
            .map(|digest| digest.as_bytes().len()),
    )?;
    checked_canonical_object_length(&[
        value.relative_path.len(),
        kind,
        metadata,
        payload,
        hardlink,
        value.node_digest.as_bytes().len(),
    ])
}

#[cfg(test)]
fn manifest_entry_canonical_length(
    value: &ManifestEntryV1,
) -> Result<usize, LinuxPytestContractError> {
    manifest_entry_projection_canonical_length(value.manifest_entry_projection_v1())
}

fn manifest_entry_projection_list_canonical_length<E>(
    values: &[E],
) -> Result<usize, LinuxPytestContractError>
where
    E: ManifestEntryProjectionV1,
{
    checked_canonical_list_length(
        values.len(),
        values.iter().map(|value| {
            manifest_entry_projection_canonical_length(value.manifest_entry_projection_v1())
        }),
    )
}

/// Exact canonical length for a borrowed tree projection. This validates only
/// canonical framing and collection bounds; semantic admission remains the
/// charged compiler's responsibility.
pub(super) fn checked_tree_manifest_projection_canonical_length_v1(
    mount_path: &[u8],
    tree_role: TreeRoleV1,
    entries: &[ManifestEntryProjectionViewV1<'_>],
    root_digest: NodeDigest,
) -> Result<usize, LinuxPytestContractError> {
    let role = checked_canonical_enum_length(tree_role as u16, &[])?;
    let entries = manifest_entry_projection_list_canonical_length(entries)?;
    checked_canonical_object_length(&[
        mount_path.len(),
        role,
        entries,
        root_digest.as_bytes().len(),
    ])
}

/// Exact byte length of the frozen nested `TreeManifestV1` canonical object.
///
/// This performs checked arithmetic and collection-limit validation only; it
/// does not allocate or replace `TreeManifestV1::validate`.
pub(super) fn checked_tree_manifest_canonical_length_v1(
    value: &TreeManifestV1,
) -> Result<usize, LinuxPytestContractError> {
    let role = checked_canonical_enum_length(value.tree_role as u16, &[])?;
    let entries = manifest_entry_projection_list_canonical_length(&value.entries)?;
    checked_canonical_object_length(&[
        value.mount_path.as_bytes().len(),
        role,
        entries,
        value.root_digest.as_bytes().len(),
    ])
}

fn write_manifest_timespec<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &TimespecV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    writer.object_header(TYPE_TIMESPEC, 2)?;
    writer.field_header(1, WireType::I64, std::mem::size_of::<i64>())?;
    writer.bytes(&value.seconds.to_be_bytes())?;
    writer.field_header(2, WireType::U32, std::mem::size_of::<u32>())?;
    writer.bytes(&value.nanoseconds.to_be_bytes())
}

fn write_manifest_xattr<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &XattrV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    writer.object_header(TYPE_XATTR, 2)?;
    writer.field_header(1, WireType::Bytes, value.name.len())?;
    writer.bytes(&value.name)?;
    writer.field_header(2, WireType::Bytes, value.value.len())?;
    writer.bytes(&value.value)
}

fn write_manifest_xattr_list<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    values: &[XattrV1],
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    writer.list_header(values.len())?;
    for value in values {
        let length = manifest_xattr_canonical_length(value)?;
        writer.list_item_header(length)?;
        write_manifest_xattr(writer, value)?;
    }
    Ok(())
}

fn write_manifest_metadata_projection<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: ManifestMetadataProjectionV1<'_>,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    let timespec = manifest_timespec_canonical_length()?;
    let btime = checked_canonical_optional_length(value.btime.map(|_| timespec))?;
    let xattrs = manifest_xattr_list_canonical_length(value.xattrs)?;

    writer.object_header(TYPE_METADATA, 10)?;
    writer.field_header(1, WireType::U32, std::mem::size_of::<u32>())?;
    writer.bytes(&value.mode.to_be_bytes())?;
    writer.field_header(2, WireType::U32, std::mem::size_of::<u32>())?;
    writer.bytes(&value.logical_uid.to_be_bytes())?;
    writer.field_header(3, WireType::U32, std::mem::size_of::<u32>())?;
    writer.bytes(&value.logical_gid.to_be_bytes())?;
    writer.field_header(4, WireType::U64, std::mem::size_of::<u64>())?;
    writer.bytes(&value.size.to_be_bytes())?;
    writer.field_header(5, WireType::U64, std::mem::size_of::<u64>())?;
    writer.bytes(&value.nlink.to_be_bytes())?;
    writer.field_header(6, WireType::Object, timespec)?;
    write_manifest_timespec(writer, value.atime)?;
    writer.field_header(7, WireType::Object, timespec)?;
    write_manifest_timespec(writer, value.mtime)?;
    writer.field_header(8, WireType::Object, timespec)?;
    write_manifest_timespec(writer, value.ctime)?;
    writer.field_header(9, WireType::Optional, btime)?;
    match value.btime {
        None => writer.bytes(&[0])?,
        Some(value) => {
            writer.bytes(&[1])?;
            writer.bytes(
                &u64::try_from(timespec)
                    .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
                    .to_be_bytes(),
            )?;
            write_manifest_timespec(writer, value)?;
        }
    }
    writer.field_header(10, WireType::List, xattrs)?;
    write_manifest_xattr_list(writer, value.xattrs)
}

fn write_manifest_metadata<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &MetadataV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    write_manifest_metadata_projection(writer, value.into())
}

fn write_manifest_extent<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &ExtentV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    writer.object_header(TYPE_EXTENT, 2)?;
    writer.field_header(1, WireType::U64, std::mem::size_of::<u64>())?;
    writer.bytes(&value.offset.to_be_bytes())?;
    writer.field_header(2, WireType::U64, std::mem::size_of::<u64>())?;
    writer.bytes(&value.length.to_be_bytes())
}

fn write_manifest_extent_list<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    values: &[ExtentV1],
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    let item_length = manifest_extent_canonical_length()?;
    writer.list_header(values.len())?;
    for value in values {
        writer.list_item_header(item_length)?;
        write_manifest_extent(writer, value)?;
    }
    Ok(())
}

fn write_manifest_child<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &ChildCommitmentV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    let kind = checked_canonical_enum_length(value.kind as u16, &[])?;
    writer.object_header(TYPE_CHILD_COMMITMENT, 3)?;
    writer.field_header(1, WireType::Bytes, value.name.len())?;
    writer.bytes(&value.name)?;
    writer.field_header(2, WireType::Enum, kind)?;
    writer.enum_header(value.kind as u16, 0)?;
    writer.field_header(3, WireType::Bytes, value.node_digest.as_bytes().len())?;
    writer.bytes(value.node_digest.as_bytes())
}

fn write_manifest_child_list<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    values: &[ChildCommitmentV1],
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    writer.list_header(values.len())?;
    for value in values {
        let length = manifest_child_canonical_length(value)?;
        writer.list_item_header(length)?;
        write_manifest_child(writer, value)?;
    }
    Ok(())
}

fn write_manifest_payload_projection<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: ManifestPayloadProjectionV1<'_>,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    match value {
        ManifestPayloadProjectionV1::Directory { children } => {
            let children_length = manifest_child_list_canonical_length(children)?;
            writer.enum_header(ManifestEntryKindV1::Directory as u16, 1)?;
            writer.field_header(1, WireType::List, children_length)?;
            write_manifest_child_list(writer, children)
        }
        ManifestPayloadProjectionV1::Regular {
            content_digest,
            data_extents,
        } => {
            let extents_length = manifest_extent_list_canonical_length(data_extents)?;
            writer.enum_header(ManifestEntryKindV1::Regular as u16, 2)?;
            writer.field_header(1, WireType::Bytes, content_digest.as_bytes().len())?;
            writer.bytes(content_digest.as_bytes())?;
            writer.field_header(2, WireType::List, extents_length)?;
            write_manifest_extent_list(writer, data_extents)
        }
        ManifestPayloadProjectionV1::Symlink { target } => {
            writer.enum_header(ManifestEntryKindV1::Symlink as u16, 1)?;
            writer.field_header(1, WireType::Bytes, target.len())?;
            writer.bytes(target)
        }
        ManifestPayloadProjectionV1::ExternalTree {
            tree_role,
            target_root,
            readonly,
        } => {
            let role = checked_canonical_enum_length(tree_role as u16, &[])?;
            writer.enum_header(ManifestEntryKindV1::ExternalTree as u16, 3)?;
            writer.field_header(1, WireType::Enum, role)?;
            writer.enum_header(tree_role as u16, 0)?;
            writer.field_header(2, WireType::Bytes, target_root.as_bytes().len())?;
            writer.bytes(target_root.as_bytes())?;
            writer.field_header(3, WireType::Bool, std::mem::size_of::<u8>())?;
            writer.bytes(&[u8::from(readonly)])
        }
    }
}

#[cfg(test)]
fn write_manifest_payload<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &ManifestPayloadV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    write_manifest_payload_projection(writer, value.into())
}

fn write_manifest_entry_projection<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: ManifestEntryProjectionViewV1<'_>,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    let kind = checked_canonical_enum_length(value.payload.kind() as u16, &[])?;
    let metadata = manifest_metadata_projection_canonical_length(value.metadata)?;
    let payload = manifest_payload_projection_canonical_length(value.payload)?;
    let hardlink = checked_canonical_optional_length(
        value
            .hardlink_group
            .as_ref()
            .map(|digest| digest.as_bytes().len()),
    )?;

    writer.object_header(TYPE_MANIFEST_ENTRY, 6)?;
    writer.field_header(1, WireType::Bytes, value.relative_path.len())?;
    writer.bytes(value.relative_path)?;
    writer.field_header(2, WireType::Enum, kind)?;
    writer.enum_header(value.payload.kind() as u16, 0)?;
    writer.field_header(3, WireType::Object, metadata)?;
    write_manifest_metadata_projection(writer, value.metadata)?;
    writer.field_header(4, WireType::Enum, payload)?;
    write_manifest_payload_projection(writer, value.payload)?;
    writer.field_header(5, WireType::Optional, hardlink)?;
    match value.hardlink_group {
        None => writer.bytes(&[0])?,
        Some(digest) => {
            writer.bytes(&[1])?;
            writer.bytes(
                &u64::try_from(digest.as_bytes().len())
                    .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?
                    .to_be_bytes(),
            )?;
            writer.bytes(digest.as_bytes())?;
        }
    }
    writer.field_header(6, WireType::Bytes, value.node_digest.as_bytes().len())?;
    writer.bytes(value.node_digest.as_bytes())
}

#[cfg(test)]
fn write_manifest_entry<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &ManifestEntryV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    write_manifest_entry_projection(writer, value.manifest_entry_projection_v1())
}

fn write_manifest_entry_projection_list<S, E>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    values: &[E],
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
    E: ManifestEntryProjectionV1,
{
    writer.list_header(values.len())?;
    for value in values {
        let value = value.manifest_entry_projection_v1();
        let length = manifest_entry_projection_canonical_length(value)?;
        writer.list_item_header(length)?;
        write_manifest_entry_projection(writer, value)?;
    }
    Ok(())
}

fn write_tree_manifest_projection_canonical_inner<S, E>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    mount_path: &[u8],
    tree_role: TreeRoleV1,
    entries: &[E],
    root_digest: NodeDigest,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
    E: ManifestEntryProjectionV1,
{
    let role = checked_canonical_enum_length(tree_role as u16, &[])?;
    let entries_length = manifest_entry_projection_list_canonical_length(entries)?;
    writer.object_header(TYPE_TREE_MANIFEST, 4)?;
    writer.field_header(1, WireType::Bytes, mount_path.len())?;
    writer.bytes(mount_path)?;
    writer.field_header(2, WireType::Enum, role)?;
    writer.enum_header(tree_role as u16, 0)?;
    writer.field_header(3, WireType::List, entries_length)?;
    write_manifest_entry_projection_list(writer, entries)?;
    writer.field_header(4, WireType::Bytes, root_digest.as_bytes().len())?;
    writer.bytes(root_digest.as_bytes())
}

fn write_tree_manifest_canonical_inner<S>(
    writer: &mut ManifestCanonicalWriterV1<'_, S>,
    value: &TreeManifestV1,
) -> Result<(), ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    write_tree_manifest_projection_canonical_inner(
        writer,
        value.mount_path.as_bytes(),
        value.tree_role,
        &value.entries,
        value.root_digest,
    )
}

/// Write a borrowed tree projection directly into a bounded caller-owned
/// sink without materializing the frozen owning structs.
pub(super) fn write_tree_manifest_projection_canonical_v1<S>(
    mount_path: &[u8],
    tree_role: TreeRoleV1,
    entries: &[ManifestEntryProjectionViewV1<'_>],
    root_digest: NodeDigest,
    sink: &mut S,
) -> Result<usize, ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    let length = checked_tree_manifest_projection_canonical_length_v1(
        mount_path,
        tree_role,
        entries,
        root_digest,
    )?;
    let mut writer = ManifestCanonicalWriterV1::new(sink);
    write_tree_manifest_projection_canonical_inner(
        &mut writer,
        mount_path,
        tree_role,
        entries,
        root_digest,
    )?;
    if writer.written() != length {
        return Err(LinuxPytestContractError::CanonicalEncoding.into());
    }
    Ok(writer.written())
}

/// Write the frozen nested tree-manifest object directly into a caller-owned
/// bounded sink. No intermediate canonical `Vec` or nested payload allocation
/// is created. The exact total length is checked before the first sink write.
#[cfg(test)]
pub(super) fn write_tree_manifest_canonical_v1<S>(
    value: &TreeManifestV1,
    sink: &mut S,
) -> Result<usize, ManifestCanonicalWriteErrorV1<S::Error>>
where
    S: ManifestCanonicalByteSinkV1,
{
    let length = checked_tree_manifest_canonical_length_v1(value)?;
    let mut writer = ManifestCanonicalWriterV1::new(sink);
    write_tree_manifest_canonical_inner(&mut writer, value)?;
    if writer.written() != length {
        return Err(LinuxPytestContractError::CanonicalEncoding.into());
    }
    Ok(writer.written())
}

struct ManifestCanonicalHasherSinkV1<'hasher> {
    hasher: &'hasher mut blake3::Hasher,
}

impl ManifestCanonicalByteSinkV1 for ManifestCanonicalHasherSinkV1<'_> {
    type Error = std::convert::Infallible;

    fn try_extend_canonical(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.hasher.update(bytes);
        Ok(())
    }
}

fn map_infallible_manifest_write(
    result: Result<(), ManifestCanonicalWriteErrorV1<std::convert::Infallible>>,
) -> Result<(), LinuxPytestContractError> {
    match result {
        Ok(()) => Ok(()),
        Err(ManifestCanonicalWriteErrorV1::Canonical(error)) => Err(error),
        Err(ManifestCanonicalWriteErrorV1::Sink(error)) => match error {},
    }
}

struct ManifestTaggedDigestV1 {
    hasher: blake3::Hasher,
    declared_field_count: u32,
    written_field_count: u32,
    previous_tag: u16,
}

impl ManifestTaggedDigestV1 {
    fn new(domain: &'static str, declared_field_count: u32) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        hasher.update(HASH_FRAME_MAGIC);
        hasher.update(&declared_field_count.to_be_bytes());
        Self {
            hasher,
            declared_field_count,
            written_field_count: 0,
            previous_tag: 0,
        }
    }

    fn field_header(&mut self, tag: u16, length: usize) -> Result<(), LinuxPytestContractError> {
        if tag == 0
            || tag <= self.previous_tag
            || self.written_field_count >= self.declared_field_count
        {
            return Err(LinuxPytestContractError::CanonicalEncoding);
        }
        let length =
            u64::try_from(length).map_err(|_| LinuxPytestContractError::CanonicalEncoding)?;
        self.hasher.update(&tag.to_be_bytes());
        self.hasher.update(&length.to_be_bytes());
        self.previous_tag = tag;
        self.written_field_count += 1;
        Ok(())
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    fn finish(self) -> Result<[u8; 32], LinuxPytestContractError> {
        if self.written_field_count != self.declared_field_count {
            return Err(LinuxPytestContractError::CanonicalEncoding);
        }
        Ok(*self.hasher.finalize().as_bytes())
    }
}

fn write_optional_hardlink_digest(
    digest: &mut ManifestTaggedDigestV1,
    hardlink_group: Option<&HardlinkGroupDigest>,
) {
    match hardlink_group {
        None => digest.bytes(&[0]),
        Some(hardlink_group) => {
            digest.bytes(&[1]);
            digest.bytes(&32u64.to_be_bytes());
            digest.bytes(hardlink_group.as_bytes());
        }
    }
}

fn write_manifest_metadata_projection_to_hasher(
    hasher: &mut blake3::Hasher,
    value: ManifestMetadataProjectionV1<'_>,
) -> Result<(), LinuxPytestContractError> {
    let mut sink = ManifestCanonicalHasherSinkV1 { hasher };
    let mut writer = ManifestCanonicalWriterV1::new(&mut sink);
    map_infallible_manifest_write(write_manifest_metadata_projection(&mut writer, value))
}

fn write_manifest_children_to_hasher(
    hasher: &mut blake3::Hasher,
    values: &[ChildCommitmentV1],
) -> Result<(), LinuxPytestContractError> {
    let mut sink = ManifestCanonicalHasherSinkV1 { hasher };
    let mut writer = ManifestCanonicalWriterV1::new(&mut sink);
    map_infallible_manifest_write(write_manifest_child_list(&mut writer, values))
}

fn write_manifest_extents_to_hasher(
    hasher: &mut blake3::Hasher,
    values: &[ExtentV1],
) -> Result<(), LinuxPytestContractError> {
    let mut sink = ManifestCanonicalHasherSinkV1 { hasher };
    let mut writer = ManifestCanonicalWriterV1::new(&mut sink);
    map_infallible_manifest_write(write_manifest_extent_list(&mut writer, values))
}

/// Allocation-free manifest node digest over borrowed projection views.
pub(super) fn derive_manifest_node_digest_projection_streaming_v1(
    metadata: ManifestMetadataProjectionV1<'_>,
    payload: ManifestPayloadProjectionV1<'_>,
    hardlink_group: Option<&HardlinkGroupDigest>,
) -> Result<NodeDigest, LinuxPytestContractError> {
    let metadata_length = manifest_metadata_projection_canonical_length(metadata)?;
    let field_count = match payload {
        ManifestPayloadProjectionV1::Directory { .. } => 2,
        ManifestPayloadProjectionV1::Regular { .. } => 4,
        ManifestPayloadProjectionV1::Symlink { .. } => 3,
        ManifestPayloadProjectionV1::ExternalTree { .. } => 4,
    };
    let domain = match payload {
        ManifestPayloadProjectionV1::Directory { .. } => DIRECTORY_NODE_DOMAIN,
        ManifestPayloadProjectionV1::Regular { .. } => REGULAR_NODE_DOMAIN,
        ManifestPayloadProjectionV1::Symlink { .. } => SYMLINK_NODE_DOMAIN,
        ManifestPayloadProjectionV1::ExternalTree { .. } => EXTERNAL_TREE_NODE_DOMAIN,
    };
    let mut digest = ManifestTaggedDigestV1::new(domain, field_count);
    digest.field_header(1, metadata_length)?;
    write_manifest_metadata_projection_to_hasher(&mut digest.hasher, metadata)?;

    match payload {
        ManifestPayloadProjectionV1::Directory { children } => {
            if hardlink_group.is_some() {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
            let children_length = manifest_child_list_canonical_length(children)?;
            digest.field_header(2, children_length)?;
            write_manifest_children_to_hasher(&mut digest.hasher, children)?;
        }
        ManifestPayloadProjectionV1::Regular {
            content_digest,
            data_extents,
        } => {
            let extents_length = manifest_extent_list_canonical_length(data_extents)?;
            digest.field_header(2, content_digest.as_bytes().len())?;
            digest.bytes(content_digest.as_bytes());
            digest.field_header(3, extents_length)?;
            write_manifest_extents_to_hasher(&mut digest.hasher, data_extents)?;
            let hardlink_length = if hardlink_group.is_some() { 41 } else { 1 };
            digest.field_header(4, hardlink_length)?;
            write_optional_hardlink_digest(&mut digest, hardlink_group);
        }
        ManifestPayloadProjectionV1::Symlink { target } => {
            digest.field_header(2, target.len())?;
            digest.bytes(target);
            let hardlink_length = if hardlink_group.is_some() { 41 } else { 1 };
            digest.field_header(3, hardlink_length)?;
            write_optional_hardlink_digest(&mut digest, hardlink_group);
        }
        ManifestPayloadProjectionV1::ExternalTree {
            tree_role,
            target_root,
            readonly,
        } => {
            if !readonly || tree_role != TreeRoleV1::Runtime || hardlink_group.is_some() {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
            digest.field_header(2, std::mem::size_of::<u16>())?;
            digest.bytes(&(tree_role as u16).to_be_bytes());
            digest.field_header(3, target_root.as_bytes().len())?;
            digest.bytes(target_root.as_bytes());
            digest.field_header(4, 1)?;
            digest.bytes(&[1]);
        }
    }
    Ok(NodeDigest(digest.finish()?))
}

/// Allocation-free equivalent of the frozen owning manifest node digest.
#[cfg(test)]
pub(super) fn derive_manifest_node_digest_streaming_v1(
    metadata: &MetadataV1,
    payload: &ManifestPayloadV1,
    hardlink_group: Option<&HardlinkGroupDigest>,
) -> Result<NodeDigest, LinuxPytestContractError> {
    derive_manifest_node_digest_projection_streaming_v1(
        metadata.into(),
        payload.into(),
        hardlink_group,
    )
}

fn manifest_raw_path_list_canonical_length(
    values: &[&[u8]],
) -> Result<usize, LinuxPytestContractError> {
    checked_canonical_list_length(values.len(), values.iter().map(|value| Ok(value.len())))
}

fn write_manifest_raw_path_list_to_hasher(
    hasher: &mut blake3::Hasher,
    values: &[&[u8]],
) -> Result<(), LinuxPytestContractError> {
    let mut sink = ManifestCanonicalHasherSinkV1 { hasher };
    let mut writer = ManifestCanonicalWriterV1::new(&mut sink);
    let result = (|| {
        writer.list_header(values.len())?;
        for value in values {
            writer.list_item_header(value.len())?;
            writer.bytes(value)?;
        }
        Ok(())
    })();
    map_infallible_manifest_write(result)
}

/// Hash a stable slice of canonical hard-link member paths without allocating.
pub(super) fn derive_hardlink_group_digest_streaming_v1(
    values: &[&[u8]],
) -> Result<HardlinkGroupDigest, LinuxPytestContractError> {
    canonical_collection_count(values.len())?;
    if values.len() < 2 {
        return Err(LinuxPytestContractError::MalformedManifest);
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(LinuxPytestContractError::MalformedManifest);
    }
    let paths_length = manifest_raw_path_list_canonical_length(values)?;
    let mut digest = ManifestTaggedDigestV1::new(HARDLINK_GROUP_DOMAIN, 1);
    digest.field_header(1, paths_length)?;
    write_manifest_raw_path_list_to_hasher(&mut digest.hasher, values)?;
    Ok(HardlinkGroupDigest(digest.finish()?))
}

fn encode_metadata(value: &MetadataV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_manifest_canonical_vec(manifest_metadata_canonical_length(value)?, |writer| {
        write_manifest_metadata(writer, value)
    })
}

fn encode_tree(value: &TreeManifestV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_manifest_canonical_vec(
        checked_tree_manifest_canonical_length_v1(value)?,
        |writer| write_tree_manifest_canonical_inner(writer, value),
    )
}

fn encode_runtime_mount(value: &TreeManifestV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_RUNTIME_MOUNT);
    object.bytes(1, value.mount_path.as_bytes())?;
    object.bytes(2, value.root_digest.as_bytes())?;
    object.finish_nested()
}

fn encode_snapshot_manifest(
    value: &SnapshotManifestV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_SNAPSHOT_MANIFEST);
    object.utf8(1, &value.schema)?;
    object.bytes(2, value.profile_digest.as_bytes())?;
    object.bytes(3, value.workspace_identity.as_bytes())?;
    object.object(4, encode_tree(&value.workspace_tree)?)?;
    object.list(
        5,
        value
            .runtime_trees
            .iter()
            .map(encode_tree)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.bytes(6, value.workspace_root.as_bytes())?;
    object.bytes(7, value.runtime_root.as_bytes())?;
    object.finish_top()
}

fn decode_tree_role(bytes: &[u8]) -> Result<TreeRoleV1, LinuxPytestContractError> {
    match decode_simple_enum(bytes)? {
        1 => Ok(TreeRoleV1::Workspace),
        2 => Ok(TreeRoleV1::Runtime),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_manifest_entry_kind(
    bytes: &[u8],
) -> Result<ManifestEntryKindV1, LinuxPytestContractError> {
    match decode_simple_enum(bytes)? {
        1 => Ok(ManifestEntryKindV1::Directory),
        2 => Ok(ManifestEntryKindV1::Regular),
        3 => Ok(ManifestEntryKindV1::Symlink),
        4 => Ok(ManifestEntryKindV1::ExternalTree),
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_timespec(bytes: &[u8]) -> Result<TimespecV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(TYPE_TIMESPEC, &[(1, WireType::I64), (2, WireType::U32)])?;
    Ok(TimespecV1 {
        seconds: decode_i64(object.payload(1)?)?,
        nanoseconds: decode_u32(object.payload(2)?)?,
    })
}

fn decode_xattr(bytes: &[u8]) -> Result<XattrV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(TYPE_XATTR, &[(1, WireType::Bytes), (2, WireType::Bytes)])?;
    Ok(XattrV1 {
        name: object.payload(1)?.to_vec(),
        value: object.payload(2)?.to_vec(),
    })
}

fn decode_metadata(bytes: &[u8]) -> Result<MetadataV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_METADATA,
        &[
            (1, WireType::U32),
            (2, WireType::U32),
            (3, WireType::U32),
            (4, WireType::U64),
            (5, WireType::U64),
            (6, WireType::Object),
            (7, WireType::Object),
            (8, WireType::Object),
            (9, WireType::Optional),
            (10, WireType::List),
        ],
    )?;
    Ok(MetadataV1 {
        mode: decode_u32(object.payload(1)?)?,
        logical_uid: decode_u32(object.payload(2)?)?,
        logical_gid: decode_u32(object.payload(3)?)?,
        size: decode_u64(object.payload(4)?)?,
        nlink: decode_u64(object.payload(5)?)?,
        atime: decode_timespec(object.payload(6)?)?,
        mtime: decode_timespec(object.payload(7)?)?,
        ctime: decode_timespec(object.payload(8)?)?,
        btime: decode_optional(object.payload(9)?)?
            .map(decode_timespec)
            .transpose()?,
        xattrs: decode_list(object.payload(10)?)?
            .into_iter()
            .map(decode_xattr)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn decode_extent(bytes: &[u8]) -> Result<ExtentV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(TYPE_EXTENT, &[(1, WireType::U64), (2, WireType::U64)])?;
    Ok(ExtentV1 {
        offset: decode_u64(object.payload(1)?)?,
        length: decode_u64(object.payload(2)?)?,
    })
}

fn decode_child(bytes: &[u8]) -> Result<ChildCommitmentV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_CHILD_COMMITMENT,
        &[
            (1, WireType::Bytes),
            (2, WireType::Enum),
            (3, WireType::Bytes),
        ],
    )?;
    Ok(ChildCommitmentV1 {
        name: object.payload(1)?.to_vec(),
        kind: decode_manifest_entry_kind(object.payload(2)?)?,
        node_digest: NodeDigest(exact(object.payload(3)?)?),
    })
}

fn decode_manifest_payload(bytes: &[u8]) -> Result<ManifestPayloadV1, LinuxPytestContractError> {
    let value = RawEnum::parse(bytes)?;
    match value.variant {
        1 => {
            value.expect(1, &[(1, WireType::List)])?;
            Ok(ManifestPayloadV1::Directory {
                children: decode_list(value.payload(1)?)?
                    .into_iter()
                    .map(decode_child)
                    .collect::<Result<Vec<_>, _>>()?,
            })
        }
        2 => {
            value.expect(2, &[(1, WireType::Bytes), (2, WireType::List)])?;
            Ok(ManifestPayloadV1::Regular {
                content_digest: FileContentDigest(exact(value.payload(1)?)?),
                data_extents: decode_list(value.payload(2)?)?
                    .into_iter()
                    .map(decode_extent)
                    .collect::<Result<Vec<_>, _>>()?,
            })
        }
        3 => {
            value.expect(3, &[(1, WireType::Bytes)])?;
            Ok(ManifestPayloadV1::Symlink {
                target: value.payload(1)?.to_vec(),
            })
        }
        4 => {
            value.expect(
                4,
                &[
                    (1, WireType::Enum),
                    (2, WireType::Bytes),
                    (3, WireType::Bool),
                ],
            )?;
            Ok(ManifestPayloadV1::ExternalTree {
                tree_role: decode_tree_role(value.payload(1)?)?,
                target_root: NodeDigest(exact(value.payload(2)?)?),
                readonly: decode_bool(value.payload(3)?)?,
            })
        }
        _ => Err(LinuxPytestContractError::CanonicalDecoding),
    }
}

fn decode_manifest_entry(bytes: &[u8]) -> Result<ManifestEntryV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_MANIFEST_ENTRY,
        &[
            (1, WireType::Bytes),
            (2, WireType::Enum),
            (3, WireType::Object),
            (4, WireType::Enum),
            (5, WireType::Optional),
            (6, WireType::Bytes),
        ],
    )?;
    let declared_kind = decode_manifest_entry_kind(object.payload(2)?)?;
    let payload = decode_manifest_payload(object.payload(4)?)?;
    if declared_kind != payload.kind() {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(ManifestEntryV1 {
        relative_path: object.payload(1)?.to_vec(),
        metadata: decode_metadata(object.payload(3)?)?,
        payload,
        hardlink_group: decode_optional(object.payload(5)?)?
            .map(|digest| exact(digest).map(HardlinkGroupDigest))
            .transpose()?,
        node_digest: NodeDigest(exact(object.payload(6)?)?),
    })
}

fn decode_tree(bytes: &[u8]) -> Result<TreeManifestV1, LinuxPytestContractError> {
    let object = RawObject::parse_nested(bytes)?;
    object.expect(
        TYPE_TREE_MANIFEST,
        &[
            (1, WireType::Bytes),
            (2, WireType::Enum),
            (3, WireType::List),
            (4, WireType::Bytes),
        ],
    )?;
    Ok(TreeManifestV1 {
        mount_path: SandboxPath::new(object.payload(1)?.to_vec().into_boxed_slice())
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?,
        tree_role: decode_tree_role(object.payload(2)?)?,
        entries: decode_list(object.payload(3)?)?
            .into_iter()
            .map(decode_manifest_entry)
            .collect::<Result<Vec<_>, _>>()?,
        root_digest: NodeDigest(exact(object.payload(4)?)?),
    })
}

fn decode_snapshot_manifest(bytes: &[u8]) -> Result<SnapshotManifestV1, LinuxPytestContractError> {
    let object = RawObject::parse_top(bytes)?;
    object.expect(
        TYPE_SNAPSHOT_MANIFEST,
        &[
            (1, WireType::Utf8),
            (2, WireType::Bytes),
            (3, WireType::Bytes),
            (4, WireType::Object),
            (5, WireType::List),
            (6, WireType::Bytes),
            (7, WireType::Bytes),
        ],
    )?;
    let value = SnapshotManifestV1 {
        schema: std::str::from_utf8(object.payload(1)?)
            .map_err(|_| LinuxPytestContractError::CanonicalDecoding)?
            .to_owned(),
        profile_digest: ProfileDigest(exact(object.payload(2)?)?),
        workspace_identity: WorkspaceIdentity(exact(object.payload(3)?)?),
        workspace_tree: decode_tree(object.payload(4)?)?,
        runtime_trees: decode_list(object.payload(5)?)?
            .into_iter()
            .map(decode_tree)
            .collect::<Result<Vec<_>, _>>()?,
        workspace_root: MerkleRoot(exact(object.payload(6)?)?),
        runtime_root: MerkleRoot(exact(object.payload(7)?)?),
    };
    value.validate()?;
    if encode_snapshot_manifest(&value)? != bytes {
        return Err(LinuxPytestContractError::CanonicalDecoding);
    }
    Ok(value)
}

pub(super) fn encode_metadata_for_hash(
    value: &MetadataV1,
) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_metadata(value)
}

pub(super) fn encode_extents_for_hash(
    values: &[ExtentV1],
) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_manifest_canonical_vec(manifest_extent_list_canonical_length(values)?, |writer| {
        write_manifest_extent_list(writer, values)
    })
}

pub(super) fn encode_children_for_hash(
    values: &[ChildCommitmentV1],
) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_manifest_canonical_vec(manifest_child_list_canonical_length(values)?, |writer| {
        write_manifest_child_list(writer, values)
    })
}

pub(super) fn encode_runtime_forest_for_hash(
    values: &[TreeManifestV1],
) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_list(
        values
            .iter()
            .map(encode_runtime_mount)
            .collect::<Result<Vec<_>, _>>()?,
    )
}

pub(super) fn encode_paths_for_hash(values: &[&[u8]]) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_manifest_canonical_vec(manifest_raw_path_list_canonical_length(values)?, |writer| {
        writer.list_header(values.len())?;
        for value in values {
            writer.list_item_header(value.len())?;
            writer.bytes(value)?;
        }
        Ok(())
    })
}

impl ShapeV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        encode_shape(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        decode_shape(bytes)
    }
}

impl ObservationClosureV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        encode_observation_closure(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        decode_observation_closure(bytes)
    }
}

impl EffectRecordV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        encode_record(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        decode_record(bytes)
    }

    pub fn comparison_view_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        encode_comparison_view(&self.comparison_view())
    }

    pub fn comparison_view_digest(&self) -> Result<ComparisonViewDigest, LinuxPytestContractError> {
        let encoded = self.comparison_view_bytes()?;
        Ok(ComparisonViewDigest::derive(
            EFFECT_IR_V2_COMPARISON_VIEW_DOMAIN,
            &[&encoded],
        ))
    }
}

impl SnapshotManifestV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LinuxPytestContractError> {
        self.validate()?;
        encode_snapshot_manifest(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        decode_snapshot_manifest(bytes)
    }
}

pub(super) fn pair_comparison_digest(
    primary: &VerifiedCandidateRecordV2,
    shadow: &VerifiedCandidateRecordV2,
) -> Result<PairComparisonDigest, LinuxPytestContractError> {
    let primary_record = primary.record();
    let shadow_record = shadow.record();
    if primary_record.disposition != EffectRecordDispositionV2::PrimaryCandidate
        || shadow_record.disposition != EffectRecordDispositionV2::ShadowCandidate
        || !primary_record.is_complete_candidate()
        || !shadow_record.is_complete_candidate()
        || primary_record.record_id == shadow_record.record_id
        || shadow_record.primary_record_id != Some(primary_record.record_id)
        || primary.canonical().record_blob().digest == shadow.canonical().record_blob().digest
    {
        return Err(LinuxPytestContractError::ComparisonMismatch);
    }
    let primary_view = primary_record.comparison_view_bytes()?;
    let shadow_view = shadow_record.comparison_view_bytes()?;
    if primary_view != shadow_view {
        return Err(LinuxPytestContractError::ComparisonMismatch);
    }
    let rules = comparison_rules_bytes()?;
    let rules_digest = Blake3Digest::derive(EFFECT_IR_V2_COMPARISON_RULES_DOMAIN, &[&rules]);
    let view_digest =
        ComparisonViewDigest::derive(EFFECT_IR_V2_COMPARISON_VIEW_DOMAIN, &[&primary_view]);
    Ok(PairComparisonDigest::derive_tagged(
        EFFECT_IR_V2_COMPARISON_DOMAIN,
        &[
            (1, rules_digest.as_bytes()),
            (2, primary.canonical().record_blob().digest.as_bytes()),
            (3, shadow.canonical().record_blob().digest.as_bytes()),
            (4, view_digest.as_bytes()),
            (5, view_digest.as_bytes()),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    enum FixedSliceSinkError {
        Capacity,
    }

    struct FixedSliceSinkV1<'buffer> {
        buffer: &'buffer mut [u8],
        written: usize,
    }

    impl ManifestCanonicalByteSinkV1 for FixedSliceSinkV1<'_> {
        type Error = FixedSliceSinkError;

        fn try_extend_canonical(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            let Some(end) = self.written.checked_add(bytes.len()) else {
                return Err(FixedSliceSinkError::Capacity);
            };
            let Some(destination) = self.buffer.get_mut(self.written..end) else {
                return Err(FixedSliceSinkError::Capacity);
            };
            destination.copy_from_slice(bytes);
            self.written = end;
            Ok(())
        }
    }

    fn reference_encode_timespec(value: &TimespecV1) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut object = ObjectBuilder::new(TYPE_TIMESPEC);
        object.i64(1, value.seconds)?;
        object.u32(2, value.nanoseconds)?;
        object.finish_nested()
    }

    fn reference_encode_xattr(value: &XattrV1) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut object = ObjectBuilder::new(TYPE_XATTR);
        object.bytes(1, &value.name)?;
        object.bytes(2, &value.value)?;
        object.finish_nested()
    }

    fn reference_encode_metadata(value: &MetadataV1) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut object = ObjectBuilder::new(TYPE_METADATA);
        object.u32(1, value.mode)?;
        object.u32(2, value.logical_uid)?;
        object.u32(3, value.logical_gid)?;
        object.u64(4, value.size)?;
        object.u64(5, value.nlink)?;
        object.object(6, reference_encode_timespec(&value.atime)?)?;
        object.object(7, reference_encode_timespec(&value.mtime)?)?;
        object.object(8, reference_encode_timespec(&value.ctime)?)?;
        object.optional(
            9,
            value
                .btime
                .as_ref()
                .map(reference_encode_timespec)
                .transpose()?,
        )?;
        object.list(
            10,
            value
                .xattrs
                .iter()
                .map(reference_encode_xattr)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        object.finish_nested()
    }

    fn reference_encode_extent(value: &ExtentV1) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut object = ObjectBuilder::new(TYPE_EXTENT);
        object.u64(1, value.offset)?;
        object.u64(2, value.length)?;
        object.finish_nested()
    }

    fn reference_encode_child(
        value: &ChildCommitmentV1,
    ) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut object = ObjectBuilder::new(TYPE_CHILD_COMMITMENT);
        object.bytes(1, &value.name)?;
        object.enumeration(2, value.kind as u16, Vec::new())?;
        object.bytes(3, value.node_digest.as_bytes())?;
        object.finish_nested()
    }

    fn reference_encode_payload(
        value: &ManifestPayloadV1,
    ) -> Result<Vec<u8>, LinuxPytestContractError> {
        match value {
            ManifestPayloadV1::Directory { children } => encode_enum(
                ManifestEntryKindV1::Directory as u16,
                vec![enum_field(
                    1,
                    WireType::List,
                    encode_list(
                        children
                            .iter()
                            .map(reference_encode_child)
                            .collect::<Result<Vec<_>, _>>()?,
                    )?,
                )],
            ),
            ManifestPayloadV1::Regular {
                content_digest,
                data_extents,
            } => encode_enum(
                ManifestEntryKindV1::Regular as u16,
                vec![
                    enum_field(1, WireType::Bytes, content_digest.as_bytes().to_vec()),
                    enum_field(
                        2,
                        WireType::List,
                        encode_list(
                            data_extents
                                .iter()
                                .map(reference_encode_extent)
                                .collect::<Result<Vec<_>, _>>()?,
                        )?,
                    ),
                ],
            ),
            ManifestPayloadV1::Symlink { target } => encode_enum(
                ManifestEntryKindV1::Symlink as u16,
                vec![enum_field(1, WireType::Bytes, target.clone())],
            ),
            ManifestPayloadV1::ExternalTree {
                tree_role,
                target_root,
                readonly,
            } => encode_enum(
                ManifestEntryKindV1::ExternalTree as u16,
                vec![
                    enum_field(
                        1,
                        WireType::Enum,
                        encode_enum(*tree_role as u16, Vec::new())?,
                    ),
                    enum_field(2, WireType::Bytes, target_root.as_bytes().to_vec()),
                    enum_field(3, WireType::Bool, vec![u8::from(*readonly)]),
                ],
            ),
        }
    }

    fn reference_encode_entry(
        value: &ManifestEntryV1,
    ) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut object = ObjectBuilder::new(TYPE_MANIFEST_ENTRY);
        object.bytes(1, &value.relative_path)?;
        object.enumeration(2, value.payload.kind() as u16, Vec::new())?;
        object.object(3, reference_encode_metadata(&value.metadata)?)?;
        object.field(4, WireType::Enum, reference_encode_payload(&value.payload)?)?;
        object.optional(
            5,
            value
                .hardlink_group
                .map(|digest| digest.as_bytes().to_vec()),
        )?;
        object.bytes(6, value.node_digest.as_bytes())?;
        object.finish_nested()
    }

    fn reference_encode_tree(value: &TreeManifestV1) -> Result<Vec<u8>, LinuxPytestContractError> {
        let mut object = ObjectBuilder::new(TYPE_TREE_MANIFEST);
        object.bytes(1, value.mount_path.as_bytes())?;
        object.enumeration(2, value.tree_role as u16, Vec::new())?;
        object.list(
            3,
            value
                .entries
                .iter()
                .map(reference_encode_entry)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        object.bytes(4, value.root_digest.as_bytes())?;
        object.finish_nested()
    }

    fn sample_metadata(mode: u32, size: u64, nlink: u64, detailed: bool) -> MetadataV1 {
        MetadataV1 {
            mode,
            logical_uid: 12,
            logical_gid: 34,
            size,
            nlink,
            atime: TimespecV1 {
                seconds: -7,
                nanoseconds: 8,
            },
            mtime: TimespecV1 {
                seconds: 9,
                nanoseconds: 10,
            },
            ctime: TimespecV1 {
                seconds: 11,
                nanoseconds: 12,
            },
            btime: detailed.then_some(TimespecV1 {
                seconds: 13,
                nanoseconds: 14,
            }),
            xattrs: if detailed {
                vec![
                    XattrV1 {
                        name: b"security.selinux".to_vec(),
                        value: vec![0, 1, 0xff],
                    },
                    XattrV1 {
                        name: b"user.\xff".to_vec(),
                        value: b"raw\0value".to_vec(),
                    },
                ]
            } else {
                Vec::new()
            },
        }
    }

    fn sample_tree() -> TreeManifestV1 {
        let regular_metadata = sample_metadata(0o100_555, 3, 1, true);
        let regular_payload = ManifestPayloadV1::Regular {
            content_digest: FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[b"a\0b"]),
            data_extents: vec![
                ExtentV1 {
                    offset: 0,
                    length: 1,
                },
                ExtentV1 {
                    offset: 2,
                    length: 1,
                },
            ],
        };
        let regular = ManifestEntryV1::with_computed_node_digest(
            b"raw-\xff".to_vec(),
            regular_metadata,
            regular_payload,
            None,
        )
        .expect("regular fixture must be encodable");
        let root_payload = ManifestPayloadV1::Directory {
            children: vec![ChildCommitmentV1 {
                name: b"raw-\xff".to_vec(),
                kind: ManifestEntryKindV1::Regular,
                node_digest: regular.node_digest,
            }],
        };
        let root = ManifestEntryV1::with_computed_node_digest(
            Vec::new(),
            sample_metadata(0o040_555, 0, 1, false),
            root_payload,
            None,
        )
        .expect("directory fixture must be encodable");
        let root_digest = root.node_digest;
        let tree = TreeManifestV1 {
            mount_path: SandboxPath::new(Box::<[u8]>::from(b"/workspace".as_slice()))
                .expect("fixture path must be valid"),
            tree_role: TreeRoleV1::Workspace,
            entries: vec![root, regular],
            root_digest,
        };
        tree.validate().expect("fixture tree must validate");
        tree
    }

    fn test_metadata_projection(value: &MetadataV1) -> ManifestMetadataProjectionV1<'_> {
        ManifestMetadataProjectionV1::new(
            value.mode,
            value.logical_uid,
            value.logical_gid,
            value.size,
            value.nlink,
            &value.atime,
            &value.mtime,
            &value.ctime,
            value.btime.as_ref(),
            &value.xattrs,
        )
    }

    fn test_payload_projection(value: &ManifestPayloadV1) -> ManifestPayloadProjectionV1<'_> {
        match value {
            ManifestPayloadV1::Directory { children } => {
                ManifestPayloadProjectionV1::Directory { children }
            }
            ManifestPayloadV1::Regular {
                content_digest,
                data_extents,
            } => ManifestPayloadProjectionV1::Regular {
                content_digest: *content_digest,
                data_extents,
            },
            ManifestPayloadV1::Symlink { target } => {
                ManifestPayloadProjectionV1::Symlink { target }
            }
            ManifestPayloadV1::ExternalTree {
                tree_role,
                target_root,
                readonly,
            } => ManifestPayloadProjectionV1::ExternalTree {
                tree_role: *tree_role,
                target_root: *target_root,
                readonly: *readonly,
            },
        }
    }

    fn test_entry_projection(value: &ManifestEntryV1) -> ManifestEntryProjectionViewV1<'_> {
        ManifestEntryProjectionViewV1::new(
            &value.relative_path,
            test_metadata_projection(&value.metadata),
            test_payload_projection(&value.payload),
            value.hardlink_group,
            value.node_digest,
        )
    }

    fn every_payload_tree() -> TreeManifestV1 {
        let child = ChildCommitmentV1 {
            name: b"child-\xff".to_vec(),
            kind: ManifestEntryKindV1::Regular,
            node_digest: NodeDigest::derive(REGULAR_NODE_DOMAIN, &[b"child"]),
        };
        let hardlink = HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[b"test-group"]);
        let payloads = [
            ManifestPayloadV1::Directory {
                children: vec![child],
            },
            ManifestPayloadV1::Regular {
                content_digest: FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[b"contents"]),
                data_extents: vec![ExtentV1 {
                    offset: 3,
                    length: 5,
                }],
            },
            ManifestPayloadV1::Symlink {
                target: b"../raw-\xff".to_vec(),
            },
            ManifestPayloadV1::ExternalTree {
                tree_role: TreeRoleV1::Runtime,
                target_root: NodeDigest::derive(RUNTIME_MERKLE_DOMAIN, &[b"runtime"]),
                readonly: true,
            },
        ];
        let entries = payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| ManifestEntryV1 {
                relative_path: format!("entry-{index}").into_bytes(),
                metadata: sample_metadata(
                    match payload.kind() {
                        ManifestEntryKindV1::Directory | ManifestEntryKindV1::ExternalTree => {
                            0o040_555
                        }
                        ManifestEntryKindV1::Regular => 0o100_555,
                        ManifestEntryKindV1::Symlink => 0o120_555,
                    },
                    u64::try_from(index).expect("small fixture index"),
                    if index == 2 { 2 } else { 1 },
                    index % 2 == 0,
                ),
                hardlink_group: (index == 2).then_some(hardlink),
                node_digest: NodeDigest::derive(REGULAR_NODE_DOMAIN, &[&[index as u8]]),
                payload,
            })
            .collect::<Vec<_>>();
        TreeManifestV1 {
            mount_path: SandboxPath::new(Box::<[u8]>::from(b"/projection".as_slice()))
                .expect("fixture path"),
            tree_role: TreeRoleV1::Workspace,
            root_digest: entries[0].node_digest,
            entries,
        }
    }

    fn encode_payload_with_streaming_writer(
        value: &ManifestPayloadV1,
    ) -> Result<Vec<u8>, LinuxPytestContractError> {
        encode_manifest_canonical_vec(manifest_payload_canonical_length(value)?, |writer| {
            write_manifest_payload(writer, value)
        })
    }

    fn encode_entry_with_streaming_writer(
        value: &ManifestEntryV1,
    ) -> Result<Vec<u8>, LinuxPytestContractError> {
        encode_manifest_canonical_vec(manifest_entry_canonical_length(value)?, |writer| {
            write_manifest_entry(writer, value)
        })
    }

    #[test]
    fn streaming_manifest_encoding_matches_frozen_builder_for_every_shape() {
        let metadata_without_optional = sample_metadata(0o040_555, 0, 1, false);
        let metadata_with_optional = sample_metadata(0o100_555, 8, 2, true);
        for metadata in [&metadata_without_optional, &metadata_with_optional] {
            let expected = reference_encode_metadata(metadata).expect("reference metadata");
            assert_eq!(
                manifest_metadata_canonical_length(metadata),
                Ok(expected.len())
            );
            assert_eq!(encode_metadata(metadata), Ok(expected));
        }

        let extents = vec![
            ExtentV1 {
                offset: 0,
                length: 2,
            },
            ExtentV1 {
                offset: 7,
                length: 1,
            },
        ];
        for values in [&[][..], extents.as_slice()] {
            let expected = encode_list(
                values
                    .iter()
                    .map(reference_encode_extent)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("reference extents"),
            )
            .expect("reference extent list");
            assert_eq!(
                manifest_extent_list_canonical_length(values),
                Ok(expected.len())
            );
            assert_eq!(encode_extents_for_hash(values), Ok(expected));
        }

        let node_a = NodeDigest::derive(REGULAR_NODE_DOMAIN, &[b"node-a"]);
        let node_b = NodeDigest::derive(SYMLINK_NODE_DOMAIN, &[b"node-b"]);
        let children = vec![
            ChildCommitmentV1 {
                name: b"a".to_vec(),
                kind: ManifestEntryKindV1::Regular,
                node_digest: node_a,
            },
            ChildCommitmentV1 {
                name: b"raw-\xff".to_vec(),
                kind: ManifestEntryKindV1::Symlink,
                node_digest: node_b,
            },
        ];
        for values in [&[][..], children.as_slice()] {
            let expected = encode_list(
                values
                    .iter()
                    .map(reference_encode_child)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("reference children"),
            )
            .expect("reference child list");
            assert_eq!(
                manifest_child_list_canonical_length(values),
                Ok(expected.len())
            );
            assert_eq!(encode_children_for_hash(values), Ok(expected));
        }

        let payloads = vec![
            ManifestPayloadV1::Directory {
                children: children.clone(),
            },
            ManifestPayloadV1::Regular {
                content_digest: FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[b"payload"]),
                data_extents: extents,
            },
            ManifestPayloadV1::Symlink {
                target: b"../raw-\xff".to_vec(),
            },
            ManifestPayloadV1::ExternalTree {
                tree_role: TreeRoleV1::Runtime,
                target_root: NodeDigest::derive(RUNTIME_MERKLE_DOMAIN, &[b"runtime"]),
                readonly: true,
            },
        ];
        for payload in &payloads {
            let expected = reference_encode_payload(payload).expect("reference payload");
            assert_eq!(
                manifest_payload_canonical_length(payload),
                Ok(expected.len())
            );
            assert_eq!(encode_payload_with_streaming_writer(payload), Ok(expected));
        }

        let hardlink_group = HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[b"group"]);
        let entries = [
            ManifestEntryV1 {
                relative_path: b"plain".to_vec(),
                metadata: metadata_without_optional,
                payload: payloads[0].clone(),
                hardlink_group: None,
                node_digest: node_a,
            },
            ManifestEntryV1 {
                relative_path: b"linked-\xff".to_vec(),
                metadata: metadata_with_optional,
                payload: payloads[2].clone(),
                hardlink_group: Some(hardlink_group),
                node_digest: node_b,
            },
        ];
        for entry in &entries {
            let expected = reference_encode_entry(entry).expect("reference entry");
            assert_eq!(manifest_entry_canonical_length(entry), Ok(expected.len()));
            assert_eq!(encode_entry_with_streaming_writer(entry), Ok(expected));
        }

        let tree = sample_tree();
        let expected = reference_encode_tree(&tree).expect("reference tree");
        assert_eq!(
            checked_tree_manifest_canonical_length_v1(&tree),
            Ok(expected.len())
        );
        assert_eq!(encode_tree(&tree), Ok(expected));
    }

    #[test]
    fn direct_tree_writer_honors_exact_and_exact_minus_one_capacity() {
        let tree = sample_tree();
        let expected = reference_encode_tree(&tree).expect("reference tree");
        let mut exact = vec![0; expected.len()];
        {
            let mut sink = FixedSliceSinkV1 {
                buffer: &mut exact,
                written: 0,
            };
            let written = write_tree_manifest_canonical_v1(&tree, &mut sink)
                .expect("exact sink must accept the manifest");
            assert_eq!(written, expected.len());
            assert_eq!(sink.written, expected.len());
        }
        assert_eq!(exact, expected);

        let mut short = vec![0; expected.len() - 1];
        let mut sink = FixedSliceSinkV1 {
            buffer: &mut short,
            written: 0,
        };
        assert_eq!(
            write_tree_manifest_canonical_v1(&tree, &mut sink),
            Err(ManifestCanonicalWriteErrorV1::Sink(
                FixedSliceSinkError::Capacity
            ))
        );
        assert!(sink.written < expected.len());
    }

    #[test]
    fn borrowed_tree_projection_matches_every_frozen_payload_and_capacity_boundary() {
        let tree = every_payload_tree();
        let entry_views = tree
            .entries
            .iter()
            .map(test_entry_projection)
            .collect::<Vec<_>>();
        let expected = reference_encode_tree(&tree).expect("reference tree");
        assert_eq!(
            checked_tree_manifest_projection_canonical_length_v1(
                tree.mount_path.as_bytes(),
                tree.tree_role,
                &entry_views,
                tree.root_digest,
            ),
            Ok(expected.len())
        );

        let mut exact = vec![0; expected.len()];
        {
            let mut sink = FixedSliceSinkV1 {
                buffer: &mut exact,
                written: 0,
            };
            assert_eq!(
                write_tree_manifest_projection_canonical_v1(
                    tree.mount_path.as_bytes(),
                    tree.tree_role,
                    &entry_views,
                    tree.root_digest,
                    &mut sink,
                ),
                Ok(expected.len())
            );
            assert_eq!(sink.written, expected.len());
        }
        assert_eq!(exact, expected);

        let mut short = vec![0; expected.len() - 1];
        let mut sink = FixedSliceSinkV1 {
            buffer: &mut short,
            written: 0,
        };
        assert_eq!(
            write_tree_manifest_projection_canonical_v1(
                tree.mount_path.as_bytes(),
                tree.tree_role,
                &entry_views,
                tree.root_digest,
                &mut sink,
            ),
            Err(ManifestCanonicalWriteErrorV1::Sink(
                FixedSliceSinkError::Capacity
            ))
        );
    }

    #[test]
    fn checked_manifest_lengths_enforce_nested_and_total_bounds() {
        let maximum = usize::try_from(EFFECT_IR_V2_MAX_CANONICAL_BYTES)
            .expect("canonical bound must fit the supported target");
        assert_eq!(checked_canonical_payload_length(maximum), Ok(maximum));
        assert_eq!(
            checked_canonical_payload_length(maximum + 1),
            Err(LinuxPytestContractError::CanonicalEncoding)
        );
        assert_eq!(
            checked_canonical_field_length(maximum),
            Err(LinuxPytestContractError::CanonicalEncoding)
        );
        assert_eq!(
            checked_canonical_add(usize::MAX, 1),
            Err(LinuxPytestContractError::CanonicalEncoding)
        );
        assert_eq!(
            checked_canonical_list_length(2, [Ok(0)]),
            Err(LinuxPytestContractError::CanonicalEncoding)
        );
        assert_eq!(
            canonical_collection_count(
                usize::try_from(EFFECT_IR_V2_MAX_COLLECTION_ITEMS + 1)
                    .expect("collection bound must fit the supported target")
            ),
            Err(LinuxPytestContractError::CanonicalEncoding)
        );

        let mut digest = ManifestTaggedDigestV1::new(REGULAR_NODE_DOMAIN, 2);
        assert_eq!(digest.field_header(2, 0), Ok(()));
        assert_eq!(
            digest.field_header(1, 0),
            Err(LinuxPytestContractError::CanonicalEncoding)
        );
        assert_eq!(
            digest.finish(),
            Err(LinuxPytestContractError::CanonicalEncoding)
        );
    }

    #[test]
    fn streaming_manifest_digests_match_frozen_digest_framing() {
        let directory = ManifestPayloadV1::Directory {
            children: vec![ChildCommitmentV1 {
                name: b"child".to_vec(),
                kind: ManifestEntryKindV1::Regular,
                node_digest: NodeDigest::derive(REGULAR_NODE_DOMAIN, &[b"child"]),
            }],
        };
        let regular = ManifestPayloadV1::Regular {
            content_digest: FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[b"contents"]),
            data_extents: vec![ExtentV1 {
                offset: 2,
                length: 3,
            }],
        };
        let symlink = ManifestPayloadV1::Symlink {
            target: b"raw-\xff".to_vec(),
        };
        let external = ManifestPayloadV1::ExternalTree {
            tree_role: TreeRoleV1::Runtime,
            target_root: NodeDigest::derive(RUNTIME_MERKLE_DOMAIN, &[b"external"]),
            readonly: true,
        };
        let hardlink_group = HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[b"hardlink"]);
        let cases = [
            (sample_metadata(0o040_555, 0, 1, false), directory, None),
            (
                sample_metadata(0o100_555, 5, 1, true),
                regular.clone(),
                None,
            ),
            (
                sample_metadata(0o100_555, 5, 2, true),
                regular,
                Some(hardlink_group),
            ),
            (
                sample_metadata(0o120_555, 5, 1, false),
                symlink.clone(),
                None,
            ),
            (
                sample_metadata(0o120_555, 5, 2, false),
                symlink,
                Some(hardlink_group),
            ),
            (sample_metadata(0o040_555, 0, 1, true), external, None),
        ];
        for (metadata, payload, hardlink) in cases {
            let expected =
                super::super::compute_manifest_node_digest(&metadata, &payload, hardlink.as_ref())
                    .expect("reference digest");
            assert_eq!(
                derive_manifest_node_digest_streaming_v1(&metadata, &payload, hardlink.as_ref()),
                Ok(expected)
            );
            assert_eq!(
                derive_manifest_node_digest_projection_streaming_v1(
                    test_metadata_projection(&metadata),
                    test_payload_projection(&payload),
                    hardlink.as_ref(),
                ),
                Ok(expected)
            );
        }

        let invalid_directory_hardlink =
            HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[b"x"]);
        assert_eq!(
            derive_manifest_node_digest_streaming_v1(
                &sample_metadata(0o040_555, 0, 2, false),
                &ManifestPayloadV1::Directory {
                    children: Vec::new()
                },
                Some(&invalid_directory_hardlink)
            ),
            Err(LinuxPytestContractError::MalformedManifest)
        );
        assert_eq!(
            derive_manifest_node_digest_streaming_v1(
                &sample_metadata(0o040_555, 0, 1, false),
                &ManifestPayloadV1::ExternalTree {
                    tree_role: TreeRoleV1::Runtime,
                    target_root: NodeDigest::derive(RUNTIME_MERKLE_DOMAIN, &[b"x"]),
                    readonly: false,
                },
                None
            ),
            Err(LinuxPytestContractError::MalformedManifest)
        );

        let paths = [&b"a"[..], &b"raw-\xff"[..]];
        let reference_paths =
            encode_list(paths.iter().map(|path| path.to_vec())).expect("reference path list");
        let expected =
            HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[reference_paths.as_slice()]);
        assert_eq!(
            derive_hardlink_group_digest_streaming_v1(&paths),
            Ok(expected)
        );
        for invalid in [
            &[][..],
            &[&b"only"[..]][..],
            &[&b"same"[..], &b"same"[..]][..],
            &[&b"z"[..], &b"a"[..]][..],
        ] {
            assert_eq!(
                derive_hardlink_group_digest_streaming_v1(invalid),
                Err(LinuxPytestContractError::MalformedManifest)
            );
        }
    }

    #[test]
    fn declared_counts_require_minimum_framing_before_allocation() {
        let mut object = Vec::new();
        object.extend_from_slice(&TYPE_EFFECT_RECORD.to_be_bytes());
        object.extend_from_slice(&EFFECT_IR_V2_WIRE_VERSION.to_be_bytes());
        object.extend_from_slice(&1u16.to_be_bytes());
        assert!(RawObject::parse_nested(&object).is_err());

        let mut enumeration = Vec::new();
        enumeration.extend_from_slice(&1u16.to_be_bytes());
        enumeration.extend_from_slice(&1u16.to_be_bytes());
        assert!(RawEnum::parse(&enumeration).is_err());

        let mut list = Vec::new();
        list.extend_from_slice(&2u64.to_be_bytes());
        list.extend_from_slice(&0u64.to_be_bytes());
        assert!(decode_list(&list).is_err());
    }

    #[test]
    fn declared_lengths_cannot_run_past_the_input() {
        let mut object = Vec::new();
        object.extend_from_slice(&TYPE_EFFECT_RECORD.to_be_bytes());
        object.extend_from_slice(&EFFECT_IR_V2_WIRE_VERSION.to_be_bytes());
        object.extend_from_slice(&1u16.to_be_bytes());
        object.extend_from_slice(&1u16.to_be_bytes());
        object.push(WireType::Bytes as u8);
        object.extend_from_slice(&1u64.to_be_bytes());
        assert!(RawObject::parse_nested(&object).is_err());

        let mut enumeration = Vec::new();
        enumeration.extend_from_slice(&1u16.to_be_bytes());
        enumeration.extend_from_slice(&1u16.to_be_bytes());
        enumeration.extend_from_slice(&1u16.to_be_bytes());
        enumeration.push(WireType::Bytes as u8);
        enumeration.extend_from_slice(&1u64.to_be_bytes());
        assert!(RawEnum::parse(&enumeration).is_err());

        let mut truncated_length = Vec::new();
        truncated_length.extend_from_slice(&1u64.to_be_bytes());
        truncated_length.extend_from_slice(&1u64.to_be_bytes()[..7]);
        assert!(decode_list(&truncated_length).is_err());

        let mut truncated_payload = Vec::new();
        truncated_payload.extend_from_slice(&1u64.to_be_bytes());
        truncated_payload.extend_from_slice(&1u64.to_be_bytes());
        assert!(decode_list(&truncated_payload).is_err());
    }
}
