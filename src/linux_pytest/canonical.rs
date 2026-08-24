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

fn encode_timespec(value: &TimespecV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_TIMESPEC);
    object.i64(1, value.seconds)?;
    object.u32(2, value.nanoseconds)?;
    object.finish_nested()
}

fn encode_xattr(value: &XattrV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_XATTR);
    object.bytes(1, &value.name)?;
    object.bytes(2, &value.value)?;
    object.finish_nested()
}

fn encode_metadata(value: &MetadataV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_METADATA);
    object.u32(1, value.mode)?;
    object.u32(2, value.logical_uid)?;
    object.u32(3, value.logical_gid)?;
    object.u64(4, value.size)?;
    object.u64(5, value.nlink)?;
    object.object(6, encode_timespec(&value.atime)?)?;
    object.object(7, encode_timespec(&value.mtime)?)?;
    object.object(8, encode_timespec(&value.ctime)?)?;
    object.optional(9, value.btime.as_ref().map(encode_timespec).transpose()?)?;
    object.list(
        10,
        value
            .xattrs
            .iter()
            .map(encode_xattr)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.finish_nested()
}

fn encode_extent(value: &ExtentV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_EXTENT);
    object.u64(1, value.offset)?;
    object.u64(2, value.length)?;
    object.finish_nested()
}

fn encode_child(value: &ChildCommitmentV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_CHILD_COMMITMENT);
    object.bytes(1, &value.name)?;
    object.enumeration(2, value.kind as u16, Vec::new())?;
    object.bytes(3, value.node_digest.as_bytes())?;
    object.finish_nested()
}

fn encode_manifest_payload(value: &ManifestPayloadV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    match value {
        ManifestPayloadV1::Directory { children } => Ok(encode_enum(
            ManifestEntryKindV1::Directory as u16,
            vec![enum_field(
                1,
                WireType::List,
                encode_list(
                    children
                        .iter()
                        .map(encode_child)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            )],
        )?),
        ManifestPayloadV1::Regular {
            content_digest,
            data_extents,
        } => Ok(encode_enum(
            ManifestEntryKindV1::Regular as u16,
            vec![
                enum_field(1, WireType::Bytes, content_digest.as_bytes().to_vec()),
                enum_field(
                    2,
                    WireType::List,
                    encode_list(
                        data_extents
                            .iter()
                            .map(encode_extent)
                            .collect::<Result<Vec<_>, _>>()?,
                    )?,
                ),
            ],
        )?),
        ManifestPayloadV1::Symlink { target } => Ok(encode_enum(
            ManifestEntryKindV1::Symlink as u16,
            vec![enum_field(1, WireType::Bytes, target.clone())],
        )?),
        ManifestPayloadV1::ExternalTree {
            tree_role,
            target_root,
            readonly,
        } => Ok(encode_enum(
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
        )?),
    }
}

fn encode_manifest_entry(value: &ManifestEntryV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_MANIFEST_ENTRY);
    object.bytes(1, &value.relative_path)?;
    object.enumeration(2, value.payload.kind() as u16, Vec::new())?;
    object.object(3, encode_metadata(&value.metadata)?)?;
    object.field(4, WireType::Enum, encode_manifest_payload(&value.payload)?)?;
    object.optional(
        5,
        value
            .hardlink_group
            .map(|digest| digest.as_bytes().to_vec()),
    )?;
    object.bytes(6, value.node_digest.as_bytes())?;
    object.finish_nested()
}

fn encode_tree(value: &TreeManifestV1) -> Result<Vec<u8>, LinuxPytestContractError> {
    let mut object = ObjectBuilder::new(TYPE_TREE_MANIFEST);
    object.bytes(1, value.mount_path.as_bytes())?;
    object.enumeration(2, value.tree_role as u16, Vec::new())?;
    object.list(
        3,
        value
            .entries
            .iter()
            .map(encode_manifest_entry)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    object.bytes(4, value.root_digest.as_bytes())?;
    object.finish_nested()
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
    encode_list(
        values
            .iter()
            .map(encode_extent)
            .collect::<Result<Vec<_>, _>>()?,
    )
}

pub(super) fn encode_children_for_hash(
    values: &[ChildCommitmentV1],
) -> Result<Vec<u8>, LinuxPytestContractError> {
    encode_list(
        values
            .iter()
            .map(encode_child)
            .collect::<Result<Vec<_>, _>>()?,
    )
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
    encode_list(values.iter().map(|value| value.to_vec()))
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
