#![allow(dead_code)]

use std::fmt;
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::mem::zeroed;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const KERNEL_EVENT_MAGIC_V1: &[u8; 4] = b"WTKE";
const KERNEL_EVENT_VERSION_V1: u16 = 1;
const KERNEL_EVENT_VERSION_V2: u16 = 2;
const KERNEL_EVENT_DATA_BYTES_V1: usize = 64;
const KERNEL_EVENT_ARGUMENT_COUNT_V1: usize = 6;
const KERNEL_EVENT_FLAG_DATA_TRUNCATED_V1: u32 = 1 << 0;
const KERNEL_EVENT_FLAG_RESULT_PRESENT_V1: u32 = 1 << 1;
const KERNEL_EVENT_ALLOWED_FLAGS_V1: u32 =
    KERNEL_EVENT_FLAG_DATA_TRUNCATED_V1 | KERNEL_EVENT_FLAG_RESULT_PRESENT_V1;
const MIN_RING_BUFFER_BYTES_V1: usize = 64 * 1024;
const MAX_RING_BUFFER_BYTES_V1: usize = 16 * 1024 * 1024;

pub(crate) const LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1: usize = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum LinuxVzPackageKernelEventKindV1 {
    Fork = 1,
    Exec = 2,
    Exit = 3,
    SyscallEnter = 4,
    SyscallExit = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum LinuxVzPackageSelectedSyscallV1 {
    Setgid = 144,
    Setuid = 146,
    Setgroups = 159,
    Connect = 203,
    Sendto = 206,
    Mmap = 222,
}

impl LinuxVzPackageSelectedSyscallV1 {
    pub(crate) const ALL_V1: [Self; 6] = [
        Self::Setgid,
        Self::Setuid,
        Self::Setgroups,
        Self::Connect,
        Self::Sendto,
        Self::Mmap,
    ];

    const fn from_u32_v1(value: u32) -> Result<Self, LinuxVzPackageSensorEventStreamErrorV1> {
        match value {
            144 => Ok(Self::Setgid),
            146 => Ok(Self::Setuid),
            159 => Ok(Self::Setgroups),
            203 => Ok(Self::Connect),
            206 => Ok(Self::Sendto),
            222 => Ok(Self::Mmap),
            _ => Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload),
        }
    }

    pub(crate) const fn name_v1(self) -> &'static str {
        match self {
            Self::Setgid => "setgid",
            Self::Setuid => "setuid",
            Self::Setgroups => "setgroups",
            Self::Connect => "connect",
            Self::Sendto => "sendto",
            Self::Mmap => "mmap",
        }
    }
}

impl LinuxVzPackageKernelEventKindV1 {
    fn from_u16_v1(value: u16) -> Result<Self, LinuxVzPackageSensorEventStreamErrorV1> {
        match value {
            1 => Ok(Self::Fork),
            2 => Ok(Self::Exec),
            3 => Ok(Self::Exit),
            4 => Ok(Self::SyscallEnter),
            5 => Ok(Self::SyscallExit),
            _ => Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageSensorEventStreamErrorV1 {
    InvalidMagic,
    InvalidVersion,
    InvalidKind,
    InvalidLength,
    InvalidFlags,
    InvalidBinding,
    InvalidProcess,
    InvalidSequence,
    InvalidPayload,
    InvalidDescriptor,
    InvalidMap,
    LimitExceeded,
    MappingFailed,
}

impl LinuxVzPackageSensorEventStreamErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidMagic => "linux_vz_package_sensor_event_magic_invalid",
            Self::InvalidVersion => "linux_vz_package_sensor_event_version_invalid",
            Self::InvalidKind => "linux_vz_package_sensor_event_kind_invalid",
            Self::InvalidLength => "linux_vz_package_sensor_event_length_invalid",
            Self::InvalidFlags => "linux_vz_package_sensor_event_flags_invalid",
            Self::InvalidBinding => "linux_vz_package_sensor_event_binding_invalid",
            Self::InvalidProcess => "linux_vz_package_sensor_event_process_invalid",
            Self::InvalidSequence => "linux_vz_package_sensor_event_sequence_invalid",
            Self::InvalidPayload => "linux_vz_package_sensor_event_payload_invalid",
            Self::InvalidDescriptor => "linux_vz_package_sensor_event_descriptor_invalid",
            Self::InvalidMap => "linux_vz_package_sensor_event_map_invalid",
            Self::LimitExceeded => "linux_vz_package_sensor_event_limit_exceeded",
            Self::MappingFailed => "linux_vz_package_sensor_event_mapping_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageSensorEventStreamErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageSensorEventStreamErrorV1 {}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageKernelEventV1 {
    kind: LinuxVzPackageKernelEventKindV1,
    flags: u32,
    cgroup_id: u64,
    timestamp_nanoseconds: u64,
    pid: u32,
    tgid: u32,
    parent_pid: u32,
    subject_pid: u32,
    syscall_number: u32,
    address_family: u16,
    result: i64,
    arguments: [u64; KERNEL_EVENT_ARGUMENT_COUNT_V1],
    data: Vec<u8>,
    source_sequence: u64,
    cpu: u32,
}

impl fmt::Debug for LinuxVzPackageKernelEventV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageKernelEventV1")
            .field("kind", &self.kind)
            .field("flags", &self.flags)
            .field("cgroup_id", &self.cgroup_id)
            .field("timestamp_nanoseconds", &self.timestamp_nanoseconds)
            .field("pid", &self.pid)
            .field("tgid", &self.tgid)
            .field("parent_pid", &self.parent_pid)
            .field("subject_pid", &self.subject_pid)
            .field("syscall_number", &self.syscall_number)
            .field("address_family", &self.address_family)
            .field("result", &self.result)
            .field("source_sequence", &self.source_sequence)
            .field("cpu", &self.cpu)
            .field("arguments", &"<redacted>")
            .field("data_byte_length", &self.data.len())
            .field("data", &"<redacted>")
            .finish()
    }
}

impl LinuxVzPackageKernelEventV1 {
    pub(crate) const fn kind(&self) -> LinuxVzPackageKernelEventKindV1 {
        self.kind
    }

    pub(crate) const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    pub(crate) const fn timestamp_nanoseconds(&self) -> u64 {
        self.timestamp_nanoseconds
    }

    pub(crate) const fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) const fn tgid(&self) -> u32 {
        self.tgid
    }

    pub(crate) const fn parent_pid(&self) -> u32 {
        self.parent_pid
    }

    pub(crate) const fn subject_pid(&self) -> u32 {
        self.subject_pid
    }

    pub(crate) const fn syscall_number(&self) -> u32 {
        self.syscall_number
    }

    pub(crate) fn selected_syscall_v1(
        &self,
    ) -> Result<LinuxVzPackageSelectedSyscallV1, LinuxVzPackageSensorEventStreamErrorV1> {
        LinuxVzPackageSelectedSyscallV1::from_u32_v1(self.syscall_number)
    }

    pub(crate) const fn address_family(&self) -> u16 {
        self.address_family
    }

    pub(crate) const fn result(&self) -> Option<i64> {
        if self.flags & KERNEL_EVENT_FLAG_RESULT_PRESENT_V1 != 0 {
            Some(self.result)
        } else {
            None
        }
    }

    pub(crate) fn kernel_wait_status_v1(&self) -> Option<u16> {
        if self.kind != LinuxVzPackageKernelEventKindV1::Exit {
            return None;
        }
        self.result().and_then(|result| u16::try_from(result).ok())
    }

    pub(crate) fn arguments(&self) -> &[u64; KERNEL_EVENT_ARGUMENT_COUNT_V1] {
        &self.arguments
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) const fn data_truncated(&self) -> bool {
        self.flags & KERNEL_EVENT_FLAG_DATA_TRUNCATED_V1 != 0
    }

    pub(crate) const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    pub(crate) const fn cpu(&self) -> u32 {
        self.cpu
    }
}

pub(crate) fn decode_linux_vz_package_kernel_event_v1(
    bytes: &[u8],
    expected_cgroup_id: u64,
    stream_sequence: u64,
) -> Result<LinuxVzPackageKernelEventV1, LinuxVzPackageSensorEventStreamErrorV1> {
    if bytes.len() != LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1 {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidLength);
    }
    if &bytes[0..4] != KERNEL_EVENT_MAGIC_V1 {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidMagic);
    }
    if read_u16_v1(bytes, 4)? != KERNEL_EVENT_VERSION_V2 {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidVersion);
    }
    let kind = LinuxVzPackageKernelEventKindV1::from_u16_v1(read_u16_v1(bytes, 6)?)?;
    let flags = read_u32_v1(bytes, 8)?;
    if flags & !KERNEL_EVENT_ALLOWED_FLAGS_V1 != 0 {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidFlags);
    }
    if usize::try_from(read_u32_v1(bytes, 12)?)
        .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?
        != LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1
    {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidLength);
    }
    let cgroup_id = read_u64_v1(bytes, 16)?;
    if expected_cgroup_id == 0 || cgroup_id != expected_cgroup_id {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidBinding);
    }
    let timestamp_nanoseconds = read_u64_v1(bytes, 24)?;
    let pid = read_u32_v1(bytes, 32)?;
    let tgid = read_u32_v1(bytes, 36)?;
    let parent_pid = read_u32_v1(bytes, 40)?;
    let subject_pid = read_u32_v1(bytes, 44)?;
    let syscall_number = read_u32_v1(bytes, 48)?;
    let address_family = read_u16_v1(bytes, 52)?;
    let data_length = usize::from(read_u16_v1(bytes, 54)?);
    let result = read_i64_v1(bytes, 56)?;
    let mut arguments = [0_u64; KERNEL_EVENT_ARGUMENT_COUNT_V1];
    for (index, argument) in arguments.iter_mut().enumerate() {
        *argument = read_u64_v1(bytes, 64 + index * size_of::<u64>())?;
    }
    if data_length > KERNEL_EVENT_DATA_BYTES_V1
        || (flags & KERNEL_EVENT_FLAG_DATA_TRUNCATED_V1 != 0
            && data_length != KERNEL_EVENT_DATA_BYTES_V1)
        || bytes[112 + data_length..176].iter().any(|byte| *byte != 0)
        || bytes[176..184].iter().any(|byte| *byte != 0)
        || bytes[188..192].iter().any(|byte| *byte != 0)
    {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
    }
    let cpu = read_u32_v1(bytes, 184)?;
    if timestamp_nanoseconds == 0 || pid <= 1 || tgid <= 1 {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidProcess);
    }
    if stream_sequence == 0 {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidSequence);
    }
    let result_present = flags & KERNEL_EVENT_FLAG_RESULT_PRESENT_V1 != 0;
    match kind {
        LinuxVzPackageKernelEventKindV1::Fork => {
            if parent_pid != pid
                || subject_pid <= 1
                || subject_pid == pid
                || syscall_number != 0
                || address_family != 0
                || result_present
                || result != 0
                || arguments.iter().any(|argument| *argument != 0)
                || data_length != 0
            {
                return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
            }
        }
        LinuxVzPackageKernelEventKindV1::Exec => {
            if parent_pid != 0
                || subject_pid != pid
                || syscall_number != 0
                || address_family != 0
                || result_present
                || result != 0
                || arguments.iter().any(|argument| *argument != 0)
            {
                return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
            }
        }
        LinuxVzPackageKernelEventKindV1::Exit => {
            if parent_pid != 0
                || subject_pid != pid
                || syscall_number != 0
                || address_family != 0
                || !result_present
                || !valid_kernel_wait_status_v1(result)
                || arguments.iter().any(|argument| *argument != 0)
                || data_length != 0
            {
                return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
            }
        }
        LinuxVzPackageKernelEventKindV1::SyscallEnter => {
            if parent_pid != 0
                || subject_pid != pid
                || syscall_number == 0
                || result_present
                || result != 0
                || address_family != 0
                || data_length != 0
            {
                return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
            }
            let syscall = LinuxVzPackageSelectedSyscallV1::from_u32_v1(syscall_number)?;
            if !valid_selected_syscall_arguments_v1(syscall, &arguments) {
                return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
            }
        }
        LinuxVzPackageKernelEventKindV1::SyscallExit => {
            if parent_pid != 0
                || subject_pid != pid
                || syscall_number == 0
                || !result_present
                || address_family != 0
                || data_length != 0
                || arguments.iter().any(|argument| *argument != 0)
            {
                return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
            }
            LinuxVzPackageSelectedSyscallV1::from_u32_v1(syscall_number)?;
        }
    }
    if !matches!(address_family, 0 | 2 | 10) {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload);
    }
    Ok(LinuxVzPackageKernelEventV1 {
        kind,
        flags,
        cgroup_id,
        timestamp_nanoseconds,
        pid,
        tgid,
        parent_pid,
        subject_pid,
        syscall_number,
        address_family,
        result,
        arguments,
        data: bytes[112..112 + data_length].to_vec(),
        source_sequence: stream_sequence,
        cpu,
    })
}

fn valid_kernel_wait_status_v1(result: i64) -> bool {
    let Ok(status) = u16::try_from(result) else {
        return false;
    };
    let signal = status & 0x7f;
    signal == 0 || (signal <= 64 && status & 0xff00 == 0)
}

fn valid_selected_syscall_arguments_v1(
    syscall: LinuxVzPackageSelectedSyscallV1,
    arguments: &[u64; KERNEL_EVENT_ARGUMENT_COUNT_V1],
) -> bool {
    let retained = match syscall {
        LinuxVzPackageSelectedSyscallV1::Setgid
        | LinuxVzPackageSelectedSyscallV1::Setuid
        | LinuxVzPackageSelectedSyscallV1::Setgroups => &[0][..],
        LinuxVzPackageSelectedSyscallV1::Connect => &[0, 2][..],
        LinuxVzPackageSelectedSyscallV1::Sendto => &[0, 2, 3, 5][..],
        LinuxVzPackageSelectedSyscallV1::Mmap => &[1, 2, 3, 4, 5][..],
    };
    arguments
        .iter()
        .enumerate()
        .all(|(index, argument)| *argument == 0 || retained.contains(&index))
}

fn read_u16_v1(bytes: &[u8], offset: usize) -> Result<u16, LinuxVzPackageSensorEventStreamErrorV1> {
    let value = bytes
        .get(offset..offset + size_of::<u16>())
        .ok_or(LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?
        .try_into()
        .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32_v1(bytes: &[u8], offset: usize) -> Result<u32, LinuxVzPackageSensorEventStreamErrorV1> {
    let value = bytes
        .get(offset..offset + size_of::<u32>())
        .ok_or(LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?
        .try_into()
        .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64_v1(bytes: &[u8], offset: usize) -> Result<u64, LinuxVzPackageSensorEventStreamErrorV1> {
    let value = bytes
        .get(offset..offset + size_of::<u64>())
        .ok_or(LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?
        .try_into()
        .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?;
    Ok(u64::from_le_bytes(value))
}

fn read_i64_v1(bytes: &[u8], offset: usize) -> Result<i64, LinuxVzPackageSensorEventStreamErrorV1> {
    let value = bytes
        .get(offset..offset + size_of::<i64>())
        .ok_or(LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?
        .try_into()
        .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?;
    Ok(i64::from_le_bytes(value))
}

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
pub(crate) struct LinuxVzPackageBpfRingBufferV1 {
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
impl fmt::Debug for LinuxVzPackageBpfRingBufferV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageBpfRingBufferV1")
            .field("map", &"<root-only-bpf-ring-buffer>")
            .field("capacity", &self.capacity)
            .field("last_source_sequence", &self.last_source_sequence)
            .field("discarded_record_count", &self.discarded_record_count)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageBpfRingBufferV1 {
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
impl LinuxVzPackageBpfRingBufferV1 {
    pub(crate) fn from_map_v1(
        map: OwnedFd,
        expected_capacity: usize,
    ) -> Result<Self, LinuxVzPackageSensorEventStreamErrorV1> {
        if unsafe { libc::geteuid() } != 0
            || unsafe { libc::getegid() } != 0
            || !(MIN_RING_BUFFER_BYTES_V1..=MAX_RING_BUFFER_BYTES_V1).contains(&expected_capacity)
            || !expected_capacity.is_power_of_two()
        {
            return Err(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded);
        }
        let descriptor_flags = unsafe { libc::fcntl(map.as_raw_fd(), libc::F_GETFD) };
        if descriptor_flags < 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
            return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidDescriptor);
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = usize::try_from(page_size)
            .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::MappingFailed)?;
        if page_size == 0
            || !page_size.is_power_of_two()
            || !expected_capacity.is_multiple_of(page_size)
        {
            return Err(LinuxVzPackageSensorEventStreamErrorV1::MappingFailed);
        }
        validate_ring_buffer_map_v1(map.as_raw_fd(), expected_capacity)?;
        let producer_mapping_length = page_size
            .checked_add(
                expected_capacity
                    .checked_mul(2)
                    .ok_or(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?,
            )
            .ok_or(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?;
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
            return Err(LinuxVzPackageSensorEventStreamErrorV1::MappingFailed);
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
            return Err(LinuxVzPackageSensorEventStreamErrorV1::MappingFailed);
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
    ) -> Result<Vec<LinuxVzPackageKernelEventV1>, LinuxVzPackageSensorEventStreamErrorV1> {
        if expected_cgroup_id == 0 || maximum_records == 0 {
            return Err(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded);
        }
        let consumer_position = self.consumer_mapping.cast::<AtomicU64>();
        let producer_position = self.producer_mapping.cast::<AtomicU64>();
        let mut consumer = unsafe { (*consumer_position).load(Ordering::Acquire) };
        let producer = unsafe { (*producer_position).load(Ordering::Acquire) };
        if producer < consumer
            || usize::try_from(producer - consumer)
                .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?
                > self.capacity
        {
            return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidMap);
        }
        let mut events = Vec::new();
        while consumer < producer && events.len() < maximum_records {
            let offset = usize::try_from(consumer & (self.capacity as u64 - 1))
                .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?;
            let length =
                unsafe { (*self.data.add(offset).cast::<AtomicU32>()).load(Ordering::Acquire) };
            if length & BPF_RINGBUF_BUSY_BIT_V1 != 0 {
                break;
            }
            let payload_length = usize::try_from(length & BPF_RINGBUF_LENGTH_MASK_V1)
                .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidLength)?;
            let record_length = align_ring_buffer_record_v1(
                BPF_RINGBUF_RECORD_HEADER_BYTES_V1
                    .checked_add(payload_length)
                    .ok_or(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?,
            )?;
            if payload_length != LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1
                || record_length > self.capacity
                || u64::try_from(record_length)
                    .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?
                    > producer - consumer
            {
                return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidLength);
            }
            if length & BPF_RINGBUF_DISCARD_BIT_V1 != 0 {
                self.discarded_record_count = self
                    .discarded_record_count
                    .checked_add(1)
                    .ok_or(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?;
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
                    .ok_or(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?;
                let event = decode_linux_vz_package_kernel_event_v1(
                    payload,
                    expected_cgroup_id,
                    expected_sequence,
                )?;
                self.last_source_sequence = event.source_sequence();
                events.push(event);
            }
            consumer = consumer
                .checked_add(
                    u64::try_from(record_length)
                        .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?,
                )
                .ok_or(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?;
            unsafe { (*consumer_position).store(consumer, Ordering::Release) };
        }
        Ok(events)
    }

    pub(crate) const fn last_source_sequence(&self) -> u64 {
        self.last_source_sequence
    }

    pub(crate) const fn discarded_record_count(&self) -> u64 {
        self.discarded_record_count
    }

    pub(crate) fn map_descriptor(&self) -> &OwnedFd {
        &self.map
    }
}

#[cfg(target_os = "linux")]
fn validate_ring_buffer_map_v1(
    descriptor: libc::c_int,
    expected_capacity: usize,
) -> Result<(), LinuxVzPackageSensorEventStreamErrorV1> {
    let mut info = unsafe { zeroed::<BpfMapInfoPrefixV1>() };
    let mut attributes = BpfObjectInfoAttributeV1 {
        descriptor: u32::try_from(descriptor)
            .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidDescriptor)?,
        info_length: u32::try_from(size_of::<BpfMapInfoPrefixV1>())
            .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)?,
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
            .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidMap)?
            < size_of::<BpfMapInfoPrefixV1>()
        || info.map_type != BPF_MAP_TYPE_RINGBUF_V1
        || info.key_size != 0
        || info.value_size != 0
        || usize::try_from(info.max_entries)
            .map_err(|_| LinuxVzPackageSensorEventStreamErrorV1::InvalidMap)?
            != expected_capacity
    {
        return Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidMap);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn align_ring_buffer_record_v1(
    length: usize,
) -> Result<usize, LinuxVzPackageSensorEventStreamErrorV1> {
    length
        .checked_add(7)
        .map(|value| value & !7)
        .ok_or(LinuxVzPackageSensorEventStreamErrorV1::LimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_bytes_v1(kind: LinuxVzPackageKernelEventKindV1) -> Vec<u8> {
        let mut bytes = vec![0_u8; LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1];
        bytes[0..4].copy_from_slice(KERNEL_EVENT_MAGIC_V1);
        bytes[4..6].copy_from_slice(&KERNEL_EVENT_VERSION_V2.to_le_bytes());
        bytes[6..8].copy_from_slice(&(kind as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(
            &u32::try_from(LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1)
                .expect("record length")
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&41_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&1000_u64.to_le_bytes());
        bytes[32..36].copy_from_slice(&700_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&700_u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&699_u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&700_u32.to_le_bytes());
        bytes[184..188].copy_from_slice(&3_u32.to_le_bytes());
        match kind {
            LinuxVzPackageKernelEventKindV1::Fork => {
                bytes[40..44].copy_from_slice(&700_u32.to_le_bytes());
                bytes[44..48].copy_from_slice(&701_u32.to_le_bytes());
            }
            LinuxVzPackageKernelEventKindV1::Exec => {
                bytes[40..44].copy_from_slice(&0_u32.to_le_bytes());
            }
            LinuxVzPackageKernelEventKindV1::Exit => {
                bytes[40..44].copy_from_slice(&0_u32.to_le_bytes());
                bytes[8..12].copy_from_slice(&KERNEL_EVENT_FLAG_RESULT_PRESENT_V1.to_le_bytes());
                bytes[56..64].copy_from_slice(&0_i64.to_le_bytes());
            }
            LinuxVzPackageKernelEventKindV1::SyscallEnter => {
                bytes[40..44].copy_from_slice(&0_u32.to_le_bytes());
                bytes[48..52].copy_from_slice(&203_u32.to_le_bytes());
                bytes[64..72].copy_from_slice(&7_u64.to_le_bytes());
                bytes[80..88].copy_from_slice(&16_u64.to_le_bytes());
            }
            LinuxVzPackageKernelEventKindV1::SyscallExit => {
                bytes[40..44].copy_from_slice(&0_u32.to_le_bytes());
                bytes[8..12].copy_from_slice(&KERNEL_EVENT_FLAG_RESULT_PRESENT_V1.to_le_bytes());
                bytes[48..52].copy_from_slice(&203_u32.to_le_bytes());
                bytes[56..64].copy_from_slice(&(-111_i64).to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn exact_kernel_events_decode_without_exposing_raw_debug_data() {
        for kind in [
            LinuxVzPackageKernelEventKindV1::Fork,
            LinuxVzPackageKernelEventKindV1::Exec,
            LinuxVzPackageKernelEventKindV1::Exit,
            LinuxVzPackageKernelEventKindV1::SyscallEnter,
            LinuxVzPackageKernelEventKindV1::SyscallExit,
        ] {
            let event = decode_linux_vz_package_kernel_event_v1(&event_bytes_v1(kind), 41, 1)
                .expect("event");
            assert_eq!(event.kind(), kind);
            assert_eq!(event.cgroup_id(), 41);
            assert_eq!(event.source_sequence(), 1);
            assert_eq!(event.cpu(), 3);
            if matches!(
                kind,
                LinuxVzPackageKernelEventKindV1::SyscallEnter
                    | LinuxVzPackageKernelEventKindV1::SyscallExit
            ) {
                assert_eq!(
                    event.selected_syscall_v1(),
                    Ok(LinuxVzPackageSelectedSyscallV1::Connect)
                );
            }
            if kind == LinuxVzPackageKernelEventKindV1::Exit {
                assert_eq!(event.kernel_wait_status_v1(), Some(0));
            } else {
                assert_eq!(event.kernel_wait_status_v1(), None);
            }
            let debug = format!("{event:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("[7, 0, 16"));
        }
    }

    #[test]
    fn kernel_event_decoder_rejects_header_binding_and_reserved_mutations() {
        let exact = event_bytes_v1(LinuxVzPackageKernelEventKindV1::Exec);
        let cases = [
            (0, LinuxVzPackageSensorEventStreamErrorV1::InvalidMagic),
            (5, LinuxVzPackageSensorEventStreamErrorV1::InvalidVersion),
            (7, LinuxVzPackageSensorEventStreamErrorV1::InvalidKind),
            (15, LinuxVzPackageSensorEventStreamErrorV1::InvalidLength),
            (183, LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload),
            (191, LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload),
        ];
        for (offset, expected) in cases {
            let mut mutated = exact.clone();
            mutated[offset] ^= 0xff;
            assert_eq!(
                decode_linux_vz_package_kernel_event_v1(&mutated, 41, 1),
                Err(expected)
            );
        }
        assert_eq!(
            decode_linux_vz_package_kernel_event_v1(&exact, 42, 1),
            Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidBinding)
        );
        let mut legacy_version = exact;
        legacy_version[4..6].copy_from_slice(&KERNEL_EVENT_VERSION_V1.to_le_bytes());
        assert_eq!(
            decode_linux_vz_package_kernel_event_v1(&legacy_version, 41, 1),
            Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidVersion)
        );
    }

    #[test]
    fn kernel_event_decoder_rejects_invalid_process_sequence_flags_and_tail() {
        let exact = event_bytes_v1(LinuxVzPackageKernelEventKindV1::SyscallEnter);
        for (range, value, expected) in [
            (
                32..36,
                1_u32.to_le_bytes().to_vec(),
                LinuxVzPackageSensorEventStreamErrorV1::InvalidProcess,
            ),
            (
                8..12,
                (1_u32 << 8).to_le_bytes().to_vec(),
                LinuxVzPackageSensorEventStreamErrorV1::InvalidFlags,
            ),
            (
                54..56,
                65_u16.to_le_bytes().to_vec(),
                LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload,
            ),
        ] {
            let mut mutated = exact.clone();
            mutated[range].copy_from_slice(&value);
            assert_eq!(
                decode_linux_vz_package_kernel_event_v1(&mutated, 41, 1),
                Err(expected)
            );
        }
        let mut nonzero_tail = exact;
        nonzero_tail[120] = 1;
        assert_eq!(
            decode_linux_vz_package_kernel_event_v1(&nonzero_tail, 41, 1),
            Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload)
        );
        assert_eq!(
            decode_linux_vz_package_kernel_event_v1(
                &event_bytes_v1(LinuxVzPackageKernelEventKindV1::SyscallEnter),
                41,
                0
            ),
            Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidSequence)
        );
    }

    #[test]
    fn syscall_events_accept_only_the_closed_aarch64_set_and_redacted_argument_shapes() {
        for syscall in LinuxVzPackageSelectedSyscallV1::ALL_V1 {
            let mut enter = event_bytes_v1(LinuxVzPackageKernelEventKindV1::SyscallEnter);
            enter[48..52].copy_from_slice(&(syscall as u32).to_le_bytes());
            enter[64..112].fill(0);
            let retained = match syscall {
                LinuxVzPackageSelectedSyscallV1::Setgid
                | LinuxVzPackageSelectedSyscallV1::Setuid
                | LinuxVzPackageSelectedSyscallV1::Setgroups => &[0][..],
                LinuxVzPackageSelectedSyscallV1::Connect => &[0, 2][..],
                LinuxVzPackageSelectedSyscallV1::Sendto => &[0, 2, 3, 5][..],
                LinuxVzPackageSelectedSyscallV1::Mmap => &[1, 2, 3, 4, 5][..],
            };
            for index in retained {
                enter[64 + *index * 8..72 + *index * 8]
                    .copy_from_slice(&(100_u64 + *index as u64).to_le_bytes());
            }
            let event = decode_linux_vz_package_kernel_event_v1(&enter, 41, 1)
                .expect("selected syscall enter");
            assert_eq!(event.selected_syscall_v1(), Ok(syscall));
            assert_eq!(
                syscall.name_v1(),
                match syscall {
                    LinuxVzPackageSelectedSyscallV1::Setgid => "setgid",
                    LinuxVzPackageSelectedSyscallV1::Setuid => "setuid",
                    LinuxVzPackageSelectedSyscallV1::Setgroups => "setgroups",
                    LinuxVzPackageSelectedSyscallV1::Connect => "connect",
                    LinuxVzPackageSelectedSyscallV1::Sendto => "sendto",
                    LinuxVzPackageSelectedSyscallV1::Mmap => "mmap",
                }
            );
        }

        let mut unknown = event_bytes_v1(LinuxVzPackageKernelEventKindV1::SyscallEnter);
        unknown[48..52].copy_from_slice(&204_u32.to_le_bytes());
        assert_eq!(
            decode_linux_vz_package_kernel_event_v1(&unknown, 41, 1),
            Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload)
        );

        let mut raw_pointer = event_bytes_v1(LinuxVzPackageKernelEventKindV1::SyscallEnter);
        raw_pointer[72..80].copy_from_slice(&0x7fff_1234_u64.to_le_bytes());
        assert_eq!(
            decode_linux_vz_package_kernel_event_v1(&raw_pointer, 41, 1),
            Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload)
        );
    }

    #[test]
    fn exit_event_requires_one_valid_raw_kernel_wait_status() {
        for status in [0_u16, 7_u16 << 8, 9_u16, 11_u16 | 0x80] {
            let mut exact = event_bytes_v1(LinuxVzPackageKernelEventKindV1::Exit);
            exact[56..64].copy_from_slice(&i64::from(status).to_le_bytes());
            let event = decode_linux_vz_package_kernel_event_v1(&exact, 41, 1)
                .expect("valid raw wait status");
            assert_eq!(event.kernel_wait_status_v1(), Some(status));
        }

        let exact = event_bytes_v1(LinuxVzPackageKernelEventKindV1::Exit);
        for invalid in [-1_i64, 65, 0x7f, 0xffff, 0x1_0000] {
            let mut rebound = exact.clone();
            rebound[56..64].copy_from_slice(&invalid.to_le_bytes());
            assert_eq!(
                decode_linux_vz_package_kernel_event_v1(&rebound, 41, 1),
                Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload)
            );
        }

        let mut missing = exact;
        missing[8..12].fill(0);
        assert_eq!(
            decode_linux_vz_package_kernel_event_v1(&missing, 41, 1),
            Err(LinuxVzPackageSensorEventStreamErrorV1::InvalidPayload)
        );
    }
}
