#![allow(dead_code)]

use std::fmt;
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::mem::zeroed;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use whoathere_artifact::Sha256Digest;
use zeroize::Zeroize;

const EGRESS_EVENT_MAGIC_V1: &[u8; 4] = b"WTEG";
const EGRESS_EVENT_VERSION_V1: u16 = 1;
const EGRESS_EVENT_KIND_PACKET_V1: u16 = 1;
const EGRESS_EVENT_FLAG_PREFIX_TRUNCATED_V1: u32 = 1 << 0;
const EGRESS_EVENT_FLAG_ALLOW_V1: u32 = 1 << 1;
const EGRESS_EVENT_FLAG_BLOCK_V1: u32 = 1 << 2;
const EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1: u32 = 1 << 3;
const EGRESS_EVENT_ALLOWED_FLAGS_V1: u32 = EGRESS_EVENT_FLAG_PREFIX_TRUNCATED_V1
    | EGRESS_EVENT_FLAG_ALLOW_V1
    | EGRESS_EVENT_FLAG_BLOCK_V1
    | EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1;
const EGRESS_EVENT_PREFIX_OFFSET_V1: usize = 72;
const EGRESS_EVENT_PREFIX_BYTES_V1: usize = 160;
const RAW_ETHERTYPE_IPV4_LITTLE_ENDIAN_V1: u32 = 0x0000_0008;
const RAW_ETHERTYPE_IPV6_LITTLE_ENDIAN_V1: u32 = 0x0000_dd86;

pub(crate) const LINUX_VZ_PACKAGE_EGRESS_EVENT_BYTES_V1: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageEgressDecisionV1 {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageEgressNetworkProtocolV1 {
    Ipv4,
    Ipv6,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageEgressStreamErrorV1 {
    InvalidMagic,
    InvalidVersion,
    InvalidKind,
    InvalidLength,
    InvalidFlags,
    InvalidBinding,
    InvalidTimestamp,
    InvalidPacket,
    InvalidMetadata,
    InvalidSequence,
    InvalidDescriptor,
    InvalidMap,
    LimitExceeded,
    MappingFailed,
}

impl LinuxVzPackageEgressStreamErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidMagic => "linux_vz_package_egress_event_magic_invalid",
            Self::InvalidVersion => "linux_vz_package_egress_event_version_invalid",
            Self::InvalidKind => "linux_vz_package_egress_event_kind_invalid",
            Self::InvalidLength => "linux_vz_package_egress_event_length_invalid",
            Self::InvalidFlags => "linux_vz_package_egress_event_flags_invalid",
            Self::InvalidBinding => "linux_vz_package_egress_event_binding_invalid",
            Self::InvalidTimestamp => "linux_vz_package_egress_event_timestamp_invalid",
            Self::InvalidPacket => "linux_vz_package_egress_event_packet_invalid",
            Self::InvalidMetadata => "linux_vz_package_egress_event_metadata_invalid",
            Self::InvalidSequence => "linux_vz_package_egress_event_sequence_invalid",
            Self::InvalidDescriptor => "linux_vz_package_egress_event_descriptor_invalid",
            Self::InvalidMap => "linux_vz_package_egress_event_map_invalid",
            Self::LimitExceeded => "linux_vz_package_egress_event_limit_exceeded",
            Self::MappingFailed => "linux_vz_package_egress_event_mapping_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageEgressStreamErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageEgressStreamErrorV1 {}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageEgressEventV1 {
    decision: LinuxVzPackageEgressDecisionV1,
    protocol: LinuxVzPackageEgressNetworkProtocolV1,
    cgroup_id: u64,
    timestamp_nanoseconds: u64,
    packet_length: u32,
    wire_length: u32,
    raw_skb_protocol: u32,
    ingress_interface_index: u32,
    egress_interface_index: u32,
    gso_segment_count: u32,
    gso_segment_size: u32,
    packet_prefix: Vec<u8>,
    prefix_truncated: bool,
    source_sequence: u64,
    cpu: u32,
}

impl fmt::Debug for LinuxVzPackageEgressEventV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageEgressEventV1")
            .field("decision", &self.decision)
            .field("protocol", &self.protocol)
            .field("cgroup_id", &self.cgroup_id)
            .field("timestamp_nanoseconds", &self.timestamp_nanoseconds)
            .field("packet_length", &self.packet_length)
            .field("wire_length", &self.wire_length)
            .field("raw_skb_protocol", &self.raw_skb_protocol)
            .field("ingress_interface_index", &self.ingress_interface_index)
            .field("egress_interface_index", &self.egress_interface_index)
            .field("gso_segment_count", &self.gso_segment_count)
            .field("gso_segment_size", &self.gso_segment_size)
            .field("wire_gso_metadata_available", &false)
            .field("packet_prefix_length", &self.packet_prefix.len())
            .field("packet_prefix", &"<redacted>")
            .field("prefix_truncated", &self.prefix_truncated)
            .field("source_sequence", &self.source_sequence)
            .field("cpu", &self.cpu)
            .finish()
    }
}

impl Drop for LinuxVzPackageEgressEventV1 {
    fn drop(&mut self) {
        self.packet_prefix.zeroize();
    }
}

impl LinuxVzPackageEgressEventV1 {
    pub(crate) const fn decision_v1(&self) -> LinuxVzPackageEgressDecisionV1 {
        self.decision
    }

    pub(crate) const fn protocol_v1(&self) -> LinuxVzPackageEgressNetworkProtocolV1 {
        self.protocol
    }

    pub(crate) const fn cgroup_id_v1(&self) -> u64 {
        self.cgroup_id
    }

    pub(crate) const fn timestamp_nanoseconds_v1(&self) -> u64 {
        self.timestamp_nanoseconds
    }

    pub(crate) const fn packet_length_v1(&self) -> u32 {
        self.packet_length
    }

    pub(crate) const fn wire_length_v1(&self) -> u32 {
        self.wire_length
    }

    pub(crate) const fn raw_skb_protocol_v1(&self) -> u32 {
        self.raw_skb_protocol
    }

    pub(crate) const fn ingress_interface_index_v1(&self) -> u32 {
        self.ingress_interface_index
    }

    pub(crate) const fn egress_interface_index_v1(&self) -> u32 {
        self.egress_interface_index
    }

    pub(crate) const fn gso_segment_count_v1(&self) -> u32 {
        self.gso_segment_count
    }

    pub(crate) const fn gso_segment_size_v1(&self) -> u32 {
        self.gso_segment_size
    }

    pub(crate) const fn wire_gso_metadata_available_v1(&self) -> bool {
        false
    }

    pub(crate) fn packet_prefix_v1(&self) -> &[u8] {
        &self.packet_prefix
    }

    pub(crate) fn packet_prefix_sha256_v1(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&self.packet_prefix)
    }

    pub(crate) fn packet_correlation_sha256_v1(
        &self,
    ) -> Result<Sha256Digest, LinuxVzPackageEgressStreamErrorV1> {
        if self.decision != LinuxVzPackageEgressDecisionV1::Allow || self.prefix_truncated {
            return Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket);
        }
        let mut normalized = self.packet_prefix.clone();
        let protocol_marker = match self.protocol {
            LinuxVzPackageEgressNetworkProtocolV1::Ipv4 => {
                let header_length = usize::from(normalized[0] & 0x0f) * 4;
                if header_length < 20 || header_length > normalized.len() {
                    return Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket);
                }
                let transport_protocol = normalized[9];
                normalized[10..12].zeroize();
                zero_transport_checksum_v1(&mut normalized, header_length, transport_protocol)?;
                4_u8
            }
            LinuxVzPackageEgressNetworkProtocolV1::Ipv6 => {
                let transport_protocol = normalized[6];
                zero_transport_checksum_v1(&mut normalized, 40, transport_protocol)?;
                6_u8
            }
            LinuxVzPackageEgressNetworkProtocolV1::Unsupported => {
                return Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket);
            }
        };
        let mut input = b"whoathere.linux_vz_package_egress_packet_correlation.v1\0".to_vec();
        input.push(protocol_marker);
        input.extend_from_slice(&self.packet_length.to_be_bytes());
        input.extend_from_slice(&normalized);
        let digest = Sha256Digest::from_bytes(&input);
        input.zeroize();
        normalized.zeroize();
        Ok(digest)
    }

    pub(crate) const fn prefix_truncated_v1(&self) -> bool {
        self.prefix_truncated
    }

    pub(crate) const fn source_sequence_v1(&self) -> u64 {
        self.source_sequence
    }

    pub(crate) const fn cpu_v1(&self) -> u32 {
        self.cpu
    }
}

fn zero_transport_checksum_v1(
    packet: &mut [u8],
    transport_offset: usize,
    transport_protocol: u8,
) -> Result<(), LinuxVzPackageEgressStreamErrorV1> {
    let checksum_offset = match transport_protocol {
        6 => 16,
        17 => 6,
        _ => return Ok(()),
    };
    let start = transport_offset
        .checked_add(checksum_offset)
        .ok_or(LinuxVzPackageEgressStreamErrorV1::InvalidPacket)?;
    packet
        .get_mut(start..start + 2)
        .ok_or(LinuxVzPackageEgressStreamErrorV1::InvalidPacket)?
        .zeroize();
    Ok(())
}

pub(crate) fn decode_linux_vz_package_egress_event_v1(
    bytes: &[u8],
    expected_cgroup_id: u64,
    source_sequence: u64,
) -> Result<LinuxVzPackageEgressEventV1, LinuxVzPackageEgressStreamErrorV1> {
    if bytes.len() != LINUX_VZ_PACKAGE_EGRESS_EVENT_BYTES_V1 {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidLength);
    }
    if bytes.get(0..4) != Some(EGRESS_EVENT_MAGIC_V1) {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidMagic);
    }
    if read_u16_v1(bytes, 4)? != EGRESS_EVENT_VERSION_V1 {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidVersion);
    }
    if read_u16_v1(bytes, 6)? != EGRESS_EVENT_KIND_PACKET_V1 {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidKind);
    }
    let flags = read_u32_v1(bytes, 8)?;
    if flags & !EGRESS_EVENT_ALLOWED_FLAGS_V1 != 0
        || (flags & EGRESS_EVENT_FLAG_ALLOW_V1 != 0) == (flags & EGRESS_EVENT_FLAG_BLOCK_V1 != 0)
    {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidFlags);
    }
    if read_u32_v1(bytes, 12)? as usize != LINUX_VZ_PACKAGE_EGRESS_EVENT_BYTES_V1 {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidLength);
    }
    let cgroup_id = read_u64_v1(bytes, 16)?;
    if expected_cgroup_id == 0 || cgroup_id != expected_cgroup_id {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidBinding);
    }
    let timestamp_nanoseconds = read_u64_v1(bytes, 24)?;
    if timestamp_nanoseconds == 0 {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidTimestamp);
    }
    if source_sequence == 0 {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidSequence);
    }
    let packet_length = read_u32_v1(bytes, 32)?;
    let wire_length = read_u32_v1(bytes, 36)?;
    let raw_skb_protocol = read_u32_v1(bytes, 40)?;
    let ingress_interface_index = read_u32_v1(bytes, 44)?;
    let egress_interface_index = read_u32_v1(bytes, 48)?;
    let gso_segment_count = read_u32_v1(bytes, 52)?;
    let gso_segment_size = read_u32_v1(bytes, 56)?;
    let prefix_length = read_u32_v1(bytes, 60)? as usize;
    let cpu = read_u32_v1(bytes, 64)?;
    if bytes[68..EGRESS_EVENT_PREFIX_OFFSET_V1]
        .iter()
        .chain(bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + EGRESS_EVENT_PREFIX_BYTES_V1..].iter())
        .any(|byte| *byte != 0)
    {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidMetadata);
    }
    let expected_prefix_length = usize::try_from(packet_length)
        .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidPacket)?
        .min(EGRESS_EVENT_PREFIX_BYTES_V1);
    let prefix_truncated = flags & EGRESS_EVENT_FLAG_PREFIX_TRUNCATED_V1 != 0;
    let wire_gso_metadata_unavailable =
        flags & EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1 != 0;
    if packet_length == 0
        || prefix_length != expected_prefix_length
        || prefix_truncated != (expected_prefix_length < packet_length as usize)
        || bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + prefix_length
            ..EGRESS_EVENT_PREFIX_OFFSET_V1 + EGRESS_EVENT_PREFIX_BYTES_V1]
            .iter()
            .any(|byte| *byte != 0)
        || !wire_gso_metadata_unavailable
        || wire_length != 0
        || gso_segment_count != 0
        || gso_segment_size != 0
    {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket);
    }
    let prefix =
        &bytes[EGRESS_EVENT_PREFIX_OFFSET_V1..EGRESS_EVENT_PREFIX_OFFSET_V1 + prefix_length];
    let protocol = packet_protocol_v1(raw_skb_protocol, prefix);
    let decision = if flags & EGRESS_EVENT_FLAG_ALLOW_V1 != 0 {
        LinuxVzPackageEgressDecisionV1::Allow
    } else {
        LinuxVzPackageEgressDecisionV1::Block
    };
    if (decision == LinuxVzPackageEgressDecisionV1::Allow
        && protocol == LinuxVzPackageEgressNetworkProtocolV1::Unsupported)
        || (decision == LinuxVzPackageEgressDecisionV1::Block
            && protocol != LinuxVzPackageEgressNetworkProtocolV1::Unsupported)
    {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket);
    }
    Ok(LinuxVzPackageEgressEventV1 {
        decision,
        protocol,
        cgroup_id,
        timestamp_nanoseconds,
        packet_length,
        wire_length,
        raw_skb_protocol,
        ingress_interface_index,
        egress_interface_index,
        gso_segment_count,
        gso_segment_size,
        packet_prefix: prefix.to_vec(),
        prefix_truncated,
        source_sequence,
        cpu,
    })
}

fn packet_protocol_v1(
    raw_skb_protocol: u32,
    prefix: &[u8],
) -> LinuxVzPackageEgressNetworkProtocolV1 {
    match (raw_skb_protocol, prefix.first().map(|byte| byte >> 4)) {
        (RAW_ETHERTYPE_IPV4_LITTLE_ENDIAN_V1, Some(4)) if prefix.len() >= 20 => {
            LinuxVzPackageEgressNetworkProtocolV1::Ipv4
        }
        (RAW_ETHERTYPE_IPV6_LITTLE_ENDIAN_V1, Some(6)) if prefix.len() >= 40 => {
            LinuxVzPackageEgressNetworkProtocolV1::Ipv6
        }
        _ => LinuxVzPackageEgressNetworkProtocolV1::Unsupported,
    }
}

fn read_u16_v1(bytes: &[u8], offset: usize) -> Result<u16, LinuxVzPackageEgressStreamErrorV1> {
    let value = bytes
        .get(offset..offset + size_of::<u16>())
        .ok_or(LinuxVzPackageEgressStreamErrorV1::InvalidLength)?
        .try_into()
        .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidLength)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32_v1(bytes: &[u8], offset: usize) -> Result<u32, LinuxVzPackageEgressStreamErrorV1> {
    let value = bytes
        .get(offset..offset + size_of::<u32>())
        .ok_or(LinuxVzPackageEgressStreamErrorV1::InvalidLength)?
        .try_into()
        .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidLength)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64_v1(bytes: &[u8], offset: usize) -> Result<u64, LinuxVzPackageEgressStreamErrorV1> {
    let value = bytes
        .get(offset..offset + size_of::<u64>())
        .ok_or(LinuxVzPackageEgressStreamErrorV1::InvalidLength)?
        .try_into()
        .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidLength)?;
    Ok(u64::from_le_bytes(value))
}

#[cfg(target_os = "linux")]
const MIN_RING_BUFFER_BYTES_V1: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const MAX_RING_BUFFER_BYTES_V1: usize = 16 * 1024 * 1024;
#[cfg(target_os = "linux")]
const BPF_OBJ_GET_INFO_BY_FD_V1: libc::c_long = 15;
#[cfg(target_os = "linux")]
const BPF_MAP_TYPE_RINGBUF_V1: u32 = 27;
#[cfg(target_os = "linux")]
const BPF_RINGBUF_BUSY_BIT_V1: u32 = 1 << 31;
#[cfg(target_os = "linux")]
const BPF_RINGBUF_DISCARD_BIT_V1: u32 = 1 << 30;
#[cfg(target_os = "linux")]
const BPF_RINGBUF_LENGTH_MASK_V1: u32 = !(BPF_RINGBUF_BUSY_BIT_V1 | BPF_RINGBUF_DISCARD_BIT_V1);
#[cfg(target_os = "linux")]
const BPF_RINGBUF_RECORD_HEADER_BYTES_V1: usize = 8;

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfObjectInfoAttributeV1 {
    descriptor: u32,
    info_length: u32,
    info: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfMapInfoPrefixV1 {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxVzPackageEgressBpfRingBufferV1 {
    map: OwnedFd,
    consumer_mapping: *mut libc::c_void,
    consumer_mapping_length: usize,
    producer_mapping: *mut libc::c_void,
    producer_mapping_length: usize,
    data: *const u8,
    capacity: usize,
    last_source_sequence: u64,
    discarded_record_count: u64,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for LinuxVzPackageEgressBpfRingBufferV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageEgressBpfRingBufferV1")
            .field("map", &"<root-only-bpf-egress-ring-buffer>")
            .field("capacity", &self.capacity)
            .field("last_source_sequence", &self.last_source_sequence)
            .field("discarded_record_count", &self.discarded_record_count)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageEgressBpfRingBufferV1 {
    fn drop(&mut self) {
        if self.consumer_mapping != libc::MAP_FAILED {
            let _ = unsafe { libc::munmap(self.consumer_mapping, self.consumer_mapping_length) };
        }
        if self.producer_mapping != libc::MAP_FAILED {
            let _ = unsafe { libc::munmap(self.producer_mapping, self.producer_mapping_length) };
        }
    }
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageEgressBpfRingBufferV1 {
    pub(crate) fn from_map_v1(
        map: OwnedFd,
        expected_capacity: usize,
    ) -> Result<Self, LinuxVzPackageEgressStreamErrorV1> {
        if unsafe { libc::geteuid() } != 0
            || unsafe { libc::getegid() } != 0
            || !(MIN_RING_BUFFER_BYTES_V1..=MAX_RING_BUFFER_BYTES_V1).contains(&expected_capacity)
            || !expected_capacity.is_power_of_two()
        {
            return Err(LinuxVzPackageEgressStreamErrorV1::LimitExceeded);
        }
        let descriptor_flags = unsafe { libc::fcntl(map.as_raw_fd(), libc::F_GETFD) };
        if descriptor_flags < 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
            return Err(LinuxVzPackageEgressStreamErrorV1::InvalidDescriptor);
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = usize::try_from(page_size)
            .map_err(|_| LinuxVzPackageEgressStreamErrorV1::MappingFailed)?;
        if page_size == 0
            || !page_size.is_power_of_two()
            || !expected_capacity.is_multiple_of(page_size)
        {
            return Err(LinuxVzPackageEgressStreamErrorV1::MappingFailed);
        }
        validate_ring_buffer_map_v1(map.as_raw_fd(), expected_capacity)?;
        let producer_mapping_length = page_size
            .checked_add(
                expected_capacity
                    .checked_mul(2)
                    .ok_or(LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?,
            )
            .ok_or(LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?;
        let consumer_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                map.as_raw_fd(),
                0,
            )
        };
        if consumer_mapping == libc::MAP_FAILED {
            return Err(LinuxVzPackageEgressStreamErrorV1::MappingFailed);
        }
        let producer_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                producer_mapping_length,
                libc::PROT_READ,
                libc::MAP_SHARED,
                map.as_raw_fd(),
                page_size as libc::off_t,
            )
        };
        if producer_mapping == libc::MAP_FAILED {
            let _ = unsafe { libc::munmap(consumer_mapping, page_size) };
            return Err(LinuxVzPackageEgressStreamErrorV1::MappingFailed);
        }
        let data = unsafe { producer_mapping.cast::<u8>().add(page_size) };
        Ok(Self {
            map,
            consumer_mapping,
            consumer_mapping_length: page_size,
            producer_mapping,
            producer_mapping_length,
            data,
            capacity: expected_capacity,
            last_source_sequence: 0,
            discarded_record_count: 0,
        })
    }

    pub(crate) fn drain_available_v1(
        &mut self,
        expected_cgroup_id: u64,
        maximum_records: usize,
    ) -> Result<Vec<LinuxVzPackageEgressEventV1>, LinuxVzPackageEgressStreamErrorV1> {
        if expected_cgroup_id == 0 || maximum_records == 0 {
            return Err(LinuxVzPackageEgressStreamErrorV1::LimitExceeded);
        }
        let consumer_position = self.consumer_mapping.cast::<AtomicU64>();
        let producer_position = self.producer_mapping.cast::<AtomicU64>();
        let mut consumer = unsafe { (*consumer_position).load(Ordering::Acquire) };
        let producer = unsafe { (*producer_position).load(Ordering::Acquire) };
        if producer < consumer
            || usize::try_from(producer - consumer)
                .map_err(|_| LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?
                > self.capacity
        {
            return Err(LinuxVzPackageEgressStreamErrorV1::InvalidMap);
        }
        let mut events = Vec::new();
        while consumer < producer && events.len() < maximum_records {
            let offset = usize::try_from(consumer & (self.capacity as u64 - 1))
                .map_err(|_| LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?;
            let length =
                unsafe { (*self.data.add(offset).cast::<AtomicU32>()).load(Ordering::Acquire) };
            if length & BPF_RINGBUF_BUSY_BIT_V1 != 0 {
                break;
            }
            let payload_length = usize::try_from(length & BPF_RINGBUF_LENGTH_MASK_V1)
                .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidLength)?;
            let record_length = align_ring_buffer_record_v1(
                BPF_RINGBUF_RECORD_HEADER_BYTES_V1
                    .checked_add(payload_length)
                    .ok_or(LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?,
            )?;
            if payload_length != LINUX_VZ_PACKAGE_EGRESS_EVENT_BYTES_V1
                || record_length > self.capacity
                || u64::try_from(record_length)
                    .map_err(|_| LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?
                    > producer - consumer
            {
                return Err(LinuxVzPackageEgressStreamErrorV1::InvalidLength);
            }
            if length & BPF_RINGBUF_DISCARD_BIT_V1 != 0 {
                self.discarded_record_count = self
                    .discarded_record_count
                    .checked_add(1)
                    .ok_or(LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?;
            } else {
                let payload = unsafe {
                    std::slice::from_raw_parts(
                        self.data.add(offset + BPF_RINGBUF_RECORD_HEADER_BYTES_V1),
                        payload_length,
                    )
                };
                let expected_sequence = self
                    .last_source_sequence
                    .checked_add(1)
                    .ok_or(LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?;
                let event = decode_linux_vz_package_egress_event_v1(
                    payload,
                    expected_cgroup_id,
                    expected_sequence,
                )?;
                self.last_source_sequence = event.source_sequence_v1();
                events.push(event);
            }
            consumer = consumer
                .checked_add(
                    u64::try_from(record_length)
                        .map_err(|_| LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?,
                )
                .ok_or(LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?;
            unsafe { (*consumer_position).store(consumer, Ordering::Release) };
        }
        Ok(events)
    }

    pub(crate) const fn last_source_sequence_v1(&self) -> u64 {
        self.last_source_sequence
    }

    pub(crate) const fn discarded_record_count_v1(&self) -> u64 {
        self.discarded_record_count
    }
}

#[cfg(target_os = "linux")]
fn validate_ring_buffer_map_v1(
    descriptor: libc::c_int,
    expected_capacity: usize,
) -> Result<(), LinuxVzPackageEgressStreamErrorV1> {
    let mut info = unsafe { zeroed::<BpfMapInfoPrefixV1>() };
    let mut attributes = BpfObjectInfoAttributeV1 {
        descriptor: u32::try_from(descriptor)
            .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidDescriptor)?,
        info_length: u32::try_from(size_of::<BpfMapInfoPrefixV1>())
            .map_err(|_| LinuxVzPackageEgressStreamErrorV1::LimitExceeded)?,
        info: (&mut info as *mut BpfMapInfoPrefixV1) as u64,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD_V1,
            &mut attributes,
            size_of::<BpfObjectInfoAttributeV1>(),
        )
    };
    if result != 0
        || usize::try_from(attributes.info_length)
            .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidMap)?
            < size_of::<BpfMapInfoPrefixV1>()
        || info.map_type != BPF_MAP_TYPE_RINGBUF_V1
        || info.key_size != 0
        || info.value_size != 0
        || usize::try_from(info.max_entries)
            .map_err(|_| LinuxVzPackageEgressStreamErrorV1::InvalidMap)?
            != expected_capacity
    {
        return Err(LinuxVzPackageEgressStreamErrorV1::InvalidMap);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn align_ring_buffer_record_v1(length: usize) -> Result<usize, LinuxVzPackageEgressStreamErrorV1> {
    length
        .checked_add(7)
        .map(|value| value & !7)
        .ok_or(LinuxVzPackageEgressStreamErrorV1::LimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_bytes_v1(protocol: LinuxVzPackageEgressNetworkProtocolV1) -> Vec<u8> {
        let mut bytes = vec![0_u8; LINUX_VZ_PACKAGE_EGRESS_EVENT_BYTES_V1];
        bytes[0..4].copy_from_slice(EGRESS_EVENT_MAGIC_V1);
        bytes[4..6].copy_from_slice(&EGRESS_EVENT_VERSION_V1.to_le_bytes());
        bytes[6..8].copy_from_slice(&EGRESS_EVENT_KIND_PACKET_V1.to_le_bytes());
        bytes[8..12].copy_from_slice(
            &(EGRESS_EVENT_FLAG_ALLOW_V1 | EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1)
                .to_le_bytes(),
        );
        bytes[12..16].copy_from_slice(
            &u32::try_from(LINUX_VZ_PACKAGE_EGRESS_EVENT_BYTES_V1)
                .unwrap()
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&41_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&99_u64.to_le_bytes());
        let (packet_length, raw_protocol, version) = match protocol {
            LinuxVzPackageEgressNetworkProtocolV1::Ipv4 => {
                (48_u32, RAW_ETHERTYPE_IPV4_LITTLE_ENDIAN_V1, 0x45)
            }
            LinuxVzPackageEgressNetworkProtocolV1::Ipv6 => {
                (64_u32, RAW_ETHERTYPE_IPV6_LITTLE_ENDIAN_V1, 0x60)
            }
            LinuxVzPackageEgressNetworkProtocolV1::Unsupported => (48_u32, 0_u32, 0xf0),
        };
        bytes[32..36].copy_from_slice(&packet_length.to_le_bytes());
        bytes[40..44].copy_from_slice(&raw_protocol.to_le_bytes());
        bytes[48..52].copy_from_slice(&2_u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&packet_length.to_le_bytes());
        bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1] = version;
        bytes
    }

    #[test]
    fn decodes_bound_ipv4_and_ipv6_packets_without_exposing_prefix() {
        for protocol in [
            LinuxVzPackageEgressNetworkProtocolV1::Ipv4,
            LinuxVzPackageEgressNetworkProtocolV1::Ipv6,
        ] {
            let event =
                decode_linux_vz_package_egress_event_v1(&event_bytes_v1(protocol), 41, 7).unwrap();
            assert_eq!(event.decision_v1(), LinuxVzPackageEgressDecisionV1::Allow);
            assert_eq!(event.protocol_v1(), protocol);
            assert_eq!(event.cgroup_id_v1(), 41);
            assert_eq!(event.timestamp_nanoseconds_v1(), 99);
            assert_eq!(event.source_sequence_v1(), 7);
            assert_eq!(event.cpu_v1(), 3);
            assert!(!event.wire_gso_metadata_available_v1());
            assert!(!event.prefix_truncated_v1());
            let debug = format!("{event:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("[69"));
            assert_ne!(
                event.packet_prefix_sha256_v1(),
                Sha256Digest::from_bytes(&[])
            );
        }
    }

    #[test]
    fn decodes_truncated_prefix_and_unsupported_block() {
        let mut bytes = event_bytes_v1(LinuxVzPackageEgressNetworkProtocolV1::Ipv4);
        bytes[8..12].copy_from_slice(
            &(EGRESS_EVENT_FLAG_ALLOW_V1
                | EGRESS_EVENT_FLAG_PREFIX_TRUNCATED_V1
                | EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1)
                .to_le_bytes(),
        );
        bytes[32..36].copy_from_slice(&200_u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&160_u32.to_le_bytes());
        let event = decode_linux_vz_package_egress_event_v1(&bytes, 41, 1).unwrap();
        assert_eq!(event.packet_prefix_v1().len(), 160);
        assert!(event.prefix_truncated_v1());

        let mut blocked = event_bytes_v1(LinuxVzPackageEgressNetworkProtocolV1::Unsupported);
        blocked[8..12].copy_from_slice(
            &(EGRESS_EVENT_FLAG_BLOCK_V1 | EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1)
                .to_le_bytes(),
        );
        let event = decode_linux_vz_package_egress_event_v1(&blocked, 41, 2).unwrap();
        assert_eq!(event.decision_v1(), LinuxVzPackageEgressDecisionV1::Block);
        assert_eq!(
            event.protocol_v1(),
            LinuxVzPackageEgressNetworkProtocolV1::Unsupported
        );
    }

    #[test]
    fn rejects_rebinding_noncanonical_metadata_and_false_decisions() {
        let bytes = event_bytes_v1(LinuxVzPackageEgressNetworkProtocolV1::Ipv4);
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&bytes, 42, 1),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidBinding)
        );
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&bytes, 41, 0),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidSequence)
        );

        let mut reserved = bytes.clone();
        reserved[68] = 1;
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&reserved, 41, 1),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidMetadata)
        );

        let mut false_metadata_available = bytes.clone();
        false_metadata_available[8..12].copy_from_slice(&EGRESS_EVENT_FLAG_ALLOW_V1.to_le_bytes());
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&false_metadata_available, 41, 1),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket)
        );
        let mut unavailable_but_populated = bytes.clone();
        unavailable_but_populated[36..40].copy_from_slice(&48_u32.to_le_bytes());
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&unavailable_but_populated, 41, 1),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket)
        );

        let mut false_block = bytes.clone();
        false_block[8..12].copy_from_slice(
            &(EGRESS_EVENT_FLAG_BLOCK_V1 | EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1)
                .to_le_bytes(),
        );
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&false_block, 41, 1),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket)
        );

        let mut false_allow = event_bytes_v1(LinuxVzPackageEgressNetworkProtocolV1::Unsupported);
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&false_allow, 41, 1),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidPacket)
        );
        false_allow[8..12].copy_from_slice(
            &(EGRESS_EVENT_FLAG_ALLOW_V1
                | EGRESS_EVENT_FLAG_BLOCK_V1
                | EGRESS_EVENT_FLAG_WIRE_GSO_METADATA_UNAVAILABLE_V1)
                .to_le_bytes(),
        );
        assert_eq!(
            decode_linux_vz_package_egress_event_v1(&false_allow, 41, 1),
            Err(LinuxVzPackageEgressStreamErrorV1::InvalidFlags)
        );
    }

    #[test]
    fn correlation_digest_ignores_only_network_and_transport_checksums() {
        let mut bytes = event_bytes_v1(LinuxVzPackageEgressNetworkProtocolV1::Ipv4);
        let packet = [
            0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 0, 2, 2,
            192, 0, 2, 1, 0xc0, 0x00, 0x9e, 0x69, 0x00, 0x18, 0x00, 0x00, b'W', b'H', b'O', b'A',
            b'T', b'H', b'E', b'R', b'E', b'_', b'R', b'A', b'W', b'_', b'V', b'1',
        ];
        bytes[32..36].copy_from_slice(&44_u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&44_u32.to_le_bytes());
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1..EGRESS_EVENT_PREFIX_OFFSET_V1 + packet.len()]
            .copy_from_slice(&packet);
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 10] = 0x12;
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 11] = 0x34;
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 26] = 0x56;
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 27] = 0x78;
        let event = decode_linux_vz_package_egress_event_v1(&bytes, 41, 1).unwrap();
        let digest = event.packet_correlation_sha256_v1().unwrap();
        assert_eq!(
            digest.as_str(),
            "sha256:3e6baece59efbbc17f2135b6d036b7aec82ebc22f27c30e8064c756b4269f9ff"
        );

        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 10] = 0xab;
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 11] = 0xcd;
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 26] = 0xef;
        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 27] = 0x01;
        let rebound = decode_linux_vz_package_egress_event_v1(&bytes, 41, 1).unwrap();
        assert_eq!(rebound.packet_correlation_sha256_v1().unwrap(), digest);

        bytes[EGRESS_EVENT_PREFIX_OFFSET_V1 + 28] = 1;
        let changed = decode_linux_vz_package_egress_event_v1(&bytes, 41, 1).unwrap();
        assert_ne!(changed.packet_correlation_sha256_v1().unwrap(), digest);
    }
}
