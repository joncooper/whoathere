#![allow(dead_code)]

#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_event_stream::{
    LinuxVzPackageBpfRingBufferV1, LinuxVzPackageKernelEventV1,
};
use crate::linux_vz_package_sensor_event_stream::{
    LinuxVzPackageSensorEventStreamErrorV1, LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1,
};
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_tracepoint::read_linux_vz_package_tracepoint_layout_v1;
use crate::linux_vz_package_sensor_tracepoint::{
    LinuxVzPackageTracepointErrorV1, LinuxVzPackageTracepointKindV1,
    LinuxVzPackageTracepointLayoutV1,
};
use std::collections::BTreeSet;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const MIN_RING_BUFFER_BYTES_V1: usize = 64 * 1024;
const MAX_RING_BUFFER_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_ONLINE_CPU_BYTES_V1: usize = 4096;
const MAX_ONLINE_CPUS_V1: usize = 256;
const MAX_CPU_ID_V1: u32 = 4095;

const BPF_LD_V1: u8 = 0x00;
const BPF_LDX_V1: u8 = 0x01;
const BPF_ST_V1: u8 = 0x02;
const BPF_STX_V1: u8 = 0x03;
const BPF_ALU64_V1: u8 = 0x07;
const BPF_JMP_V1: u8 = 0x05;
const BPF_W_V1: u8 = 0x00;
const BPF_H_V1: u8 = 0x08;
const BPF_DW_V1: u8 = 0x18;
const BPF_IMM_V1: u8 = 0x00;
const BPF_MEM_V1: u8 = 0x60;
const BPF_XADD_V1: u8 = 0xc0;
const BPF_K_V1: u8 = 0x00;
const BPF_X_V1: u8 = 0x08;
const BPF_ADD_V1: u8 = 0x00;
const BPF_RSH_V1: u8 = 0x70;
const BPF_MOV_V1: u8 = 0xb0;
const BPF_JEQ_V1: u8 = 0x10;
const BPF_JNE_V1: u8 = 0x50;
const BPF_CALL_V1: u8 = 0x80;
const BPF_EXIT_V1: u8 = 0x90;
const BPF_PSEUDO_MAP_FD_V1: u8 = 1;

const BPF_REG_0_V1: u8 = 0;
const BPF_REG_1_V1: u8 = 1;
const BPF_REG_2_V1: u8 = 2;
const BPF_REG_3_V1: u8 = 3;
const BPF_REG_6_V1: u8 = 6;
const BPF_REG_7_V1: u8 = 7;
const BPF_REG_8_V1: u8 = 8;
const BPF_REG_9_V1: u8 = 9;
const BPF_REG_10_V1: u8 = 10;

const BPF_FUNC_MAP_LOOKUP_ELEM_V1: i32 = 1;
const BPF_FUNC_KTIME_GET_NS_V1: i32 = 5;
const BPF_FUNC_GET_SMP_PROCESSOR_ID_V1: i32 = 8;
const BPF_FUNC_GET_CURRENT_PID_TGID_V1: i32 = 14;
const BPF_FUNC_GET_CURRENT_CGROUP_ID_V1: i32 = 80;
const BPF_FUNC_RINGBUF_RESERVE_V1: i32 = 131;
const BPF_FUNC_RINGBUF_SUBMIT_V1: i32 = 132;

const KERNEL_EVENT_MAGIC_LE_V1: i32 = 0x454b_5457;
const KERNEL_EVENT_VERSION_V1: u32 = 1;

#[cfg(target_os = "linux")]
const BPF_MAP_CREATE_V1: libc::c_long = 0;
#[cfg(target_os = "linux")]
const BPF_MAP_LOOKUP_ELEM_V1: libc::c_long = 1;
#[cfg(target_os = "linux")]
const BPF_MAP_UPDATE_ELEM_V1: libc::c_long = 2;
#[cfg(target_os = "linux")]
const BPF_PROG_LOAD_V1: libc::c_long = 5;
#[cfg(target_os = "linux")]
const BPF_MAP_TYPE_ARRAY_V1: u32 = 2;
#[cfg(target_os = "linux")]
const BPF_MAP_TYPE_RINGBUF_V1: u32 = 27;
#[cfg(target_os = "linux")]
const BPF_PROG_TYPE_TRACEPOINT_V1: u32 = 5;
#[cfg(target_os = "linux")]
const BPF_F_RDONLY_PROG_V1: u32 = 1 << 7;
#[cfg(target_os = "linux")]
const BPF_ANY_V1: u64 = 0;
#[cfg(target_os = "linux")]
const PERF_TYPE_TRACEPOINT_V1: u32 = 2;
#[cfg(target_os = "linux")]
const PERF_FLAG_FD_CLOEXEC_V1: libc::c_ulong = 1 << 3;
#[cfg(target_os = "linux")]
const PERF_EVENT_IOC_ENABLE_V1: libc::c_int = 0x2400;
#[cfg(target_os = "linux")]
const PERF_EVENT_IOC_SET_BPF_V1: libc::c_int = 0x4004_2408;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageSensorBpfErrorV1 {
    Identity,
    InvalidConfiguration,
    InvalidLayout,
    OnlineCpu,
    MapCreate,
    MapUpdate,
    ProgramLoad,
    ProgramLoadOs(i32),
    Attach,
    PerfEventOpen,
    PerfEventOpenOs(i32),
    PerfEventOpenPermissionDenied,
    PerfEventOpenInvalid,
    PerfEventOpenUnsupported,
    PerfEventSetBpf,
    PerfEventSetBpfOs(i32),
    PerfEventSetBpfPermissionDenied,
    PerfEventSetBpfInvalid,
    PerfEventSetBpfDuplicate,
    PerfEventEnable,
    PerfEventEnableOs(i32),
    PerfEventEnableInvalid,
    Descriptor,
    DropCounter,
    Tracepoint(LinuxVzPackageTracepointErrorV1),
    EventStream(LinuxVzPackageSensorEventStreamErrorV1),
}

impl LinuxVzPackageSensorBpfErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::Identity => "linux_vz_package_sensor_bpf_identity_invalid",
            Self::InvalidConfiguration => "linux_vz_package_sensor_bpf_configuration_invalid",
            Self::InvalidLayout => "linux_vz_package_sensor_bpf_layout_invalid",
            Self::OnlineCpu => "linux_vz_package_sensor_bpf_online_cpu_invalid",
            Self::MapCreate => "linux_vz_package_sensor_bpf_map_create_failed",
            Self::MapUpdate => "linux_vz_package_sensor_bpf_map_update_failed",
            Self::ProgramLoad => "linux_vz_package_sensor_bpf_program_load_failed",
            Self::ProgramLoadOs(_) => "linux_vz_package_sensor_bpf_program_load_failed",
            Self::Attach => "linux_vz_package_sensor_bpf_attach_failed",
            Self::PerfEventOpen => "linux_vz_package_sensor_bpf_perf_event_open_failed",
            Self::PerfEventOpenOs(_) => "linux_vz_package_sensor_bpf_perf_event_open_failed",
            Self::PerfEventOpenPermissionDenied => {
                "linux_vz_package_sensor_bpf_perf_event_open_permission_denied"
            }
            Self::PerfEventOpenInvalid => "linux_vz_package_sensor_bpf_perf_event_open_invalid",
            Self::PerfEventOpenUnsupported => {
                "linux_vz_package_sensor_bpf_perf_event_open_unsupported"
            }
            Self::PerfEventSetBpf => "linux_vz_package_sensor_bpf_perf_event_set_bpf_failed",
            Self::PerfEventSetBpfOs(_) => "linux_vz_package_sensor_bpf_perf_event_set_bpf_failed",
            Self::PerfEventSetBpfPermissionDenied => {
                "linux_vz_package_sensor_bpf_perf_event_set_bpf_permission_denied"
            }
            Self::PerfEventSetBpfInvalid => {
                "linux_vz_package_sensor_bpf_perf_event_set_bpf_invalid"
            }
            Self::PerfEventSetBpfDuplicate => {
                "linux_vz_package_sensor_bpf_perf_event_set_bpf_duplicate"
            }
            Self::PerfEventEnable => "linux_vz_package_sensor_bpf_perf_event_enable_failed",
            Self::PerfEventEnableOs(_) => "linux_vz_package_sensor_bpf_perf_event_enable_failed",
            Self::PerfEventEnableInvalid => "linux_vz_package_sensor_bpf_perf_event_enable_invalid",
            Self::Descriptor => "linux_vz_package_sensor_bpf_descriptor_invalid",
            Self::DropCounter => "linux_vz_package_sensor_bpf_drop_counter_failed",
            Self::Tracepoint(error) => error.reason_code(),
            Self::EventStream(error) => error.reason_code(),
        }
    }
}

impl fmt::Display for LinuxVzPackageSensorBpfErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageSensorBpfErrorV1 {}

impl From<LinuxVzPackageTracepointErrorV1> for LinuxVzPackageSensorBpfErrorV1 {
    fn from(value: LinuxVzPackageTracepointErrorV1) -> Self {
        Self::Tracepoint(value)
    }
}

impl From<LinuxVzPackageSensorEventStreamErrorV1> for LinuxVzPackageSensorBpfErrorV1 {
    fn from(value: LinuxVzPackageSensorEventStreamErrorV1) -> Self {
        Self::EventStream(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct BpfInstructionV1 {
    code: u8,
    registers: u8,
    offset: i16,
    immediate: i32,
}

impl BpfInstructionV1 {
    const fn new_v1(code: u8, destination: u8, source: u8, offset: i16, immediate: i32) -> Self {
        Self {
            code,
            registers: (destination & 0x0f) | ((source & 0x0f) << 4),
            offset,
            immediate,
        }
    }

    const fn destination_v1(self) -> u8 {
        self.registers & 0x0f
    }

    const fn source_v1(self) -> u8 {
        self.registers >> 4
    }
}

#[derive(Debug, Default)]
struct BpfProgramBuilderV1 {
    instructions: Vec<BpfInstructionV1>,
}

impl BpfProgramBuilderV1 {
    fn instruction_v1(
        &mut self,
        code: u8,
        destination: u8,
        source: u8,
        offset: i16,
        immediate: i32,
    ) {
        self.instructions.push(BpfInstructionV1::new_v1(
            code,
            destination,
            source,
            offset,
            immediate,
        ));
    }

    fn mov64_register_v1(&mut self, destination: u8, source: u8) {
        self.instruction_v1(
            BPF_ALU64_V1 | BPF_MOV_V1 | BPF_X_V1,
            destination,
            source,
            0,
            0,
        );
    }

    fn mov64_immediate_v1(&mut self, destination: u8, immediate: i32) {
        self.instruction_v1(
            BPF_ALU64_V1 | BPF_MOV_V1 | BPF_K_V1,
            destination,
            0,
            0,
            immediate,
        );
    }

    fn add64_immediate_v1(&mut self, destination: u8, immediate: i32) {
        self.instruction_v1(
            BPF_ALU64_V1 | BPF_ADD_V1 | BPF_K_V1,
            destination,
            0,
            0,
            immediate,
        );
    }

    fn rsh64_immediate_v1(&mut self, destination: u8, immediate: i32) {
        self.instruction_v1(
            BPF_ALU64_V1 | BPF_RSH_V1 | BPF_K_V1,
            destination,
            0,
            0,
            immediate,
        );
    }

    fn store_immediate_v1(&mut self, size: u8, destination: u8, offset: i16, immediate: i32) {
        self.instruction_v1(
            BPF_ST_V1 | BPF_MEM_V1 | size,
            destination,
            0,
            offset,
            immediate,
        );
    }

    fn store_register_v1(&mut self, size: u8, destination: u8, source: u8, offset: i16) {
        self.instruction_v1(
            BPF_STX_V1 | BPF_MEM_V1 | size,
            destination,
            source,
            offset,
            0,
        );
    }

    fn load_register_v1(&mut self, size: u8, destination: u8, source: u8, offset: i16) {
        self.instruction_v1(
            BPF_LDX_V1 | BPF_MEM_V1 | size,
            destination,
            source,
            offset,
            0,
        );
    }

    fn load_map_descriptor_v1(&mut self, destination: u8, descriptor: i32) {
        self.instruction_v1(
            BPF_LD_V1 | BPF_DW_V1 | BPF_IMM_V1,
            destination,
            BPF_PSEUDO_MAP_FD_V1,
            0,
            descriptor,
        );
        self.instruction_v1(0, 0, 0, 0, 0);
    }

    fn call_v1(&mut self, helper: i32) {
        self.instruction_v1(BPF_JMP_V1 | BPF_CALL_V1, 0, 0, 0, helper);
    }

    fn jump_immediate_placeholder_v1(
        &mut self,
        operation: u8,
        destination: u8,
        immediate: i32,
    ) -> usize {
        let index = self.instructions.len();
        self.instruction_v1(
            BPF_JMP_V1 | operation | BPF_K_V1,
            destination,
            0,
            0,
            immediate,
        );
        index
    }

    fn jump_register_placeholder_v1(
        &mut self,
        operation: u8,
        destination: u8,
        source: u8,
    ) -> usize {
        let index = self.instructions.len();
        self.instruction_v1(BPF_JMP_V1 | operation | BPF_X_V1, destination, source, 0, 0);
        index
    }

    fn patch_forward_jump_v1(
        &mut self,
        instruction: usize,
        target: usize,
    ) -> Result<(), LinuxVzPackageSensorBpfErrorV1> {
        let distance = target
            .checked_sub(instruction + 1)
            .ok_or(LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?;
        self.instructions
            .get_mut(instruction)
            .ok_or(LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?
            .offset =
            i16::try_from(distance).map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?;
        Ok(())
    }

    fn exit_v1(&mut self) {
        self.instruction_v1(BPF_JMP_V1 | BPF_EXIT_V1, 0, 0, 0, 0);
    }
}

fn build_lifecycle_program_v1(
    layout: &LinuxVzPackageTracepointLayoutV1,
    configuration_map: i32,
    ring_buffer_map: i32,
    drop_counter_map: i32,
) -> Result<Vec<BpfInstructionV1>, LinuxVzPackageSensorBpfErrorV1> {
    if configuration_map < 0 || ring_buffer_map < 0 || drop_counter_map < 0 {
        return Err(LinuxVzPackageSensorBpfErrorV1::Descriptor);
    }
    let kind = match layout.kind_v1() {
        LinuxVzPackageTracepointKindV1::SchedProcessFork => 1_u32,
        LinuxVzPackageTracepointKindV1::SchedProcessExec => 2_u32,
        LinuxVzPackageTracepointKindV1::SchedProcessExit => 3_u32,
        LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter
        | LinuxVzPackageTracepointKindV1::RawSyscallsSysExit => {
            return Err(LinuxVzPackageSensorBpfErrorV1::InvalidLayout);
        }
    };
    let subject = match layout.kind_v1() {
        LinuxVzPackageTracepointKindV1::SchedProcessFork => layout.child_pid_v1(),
        LinuxVzPackageTracepointKindV1::SchedProcessExec
        | LinuxVzPackageTracepointKindV1::SchedProcessExit => layout.pid_v1(),
        LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter
        | LinuxVzPackageTracepointKindV1::RawSyscallsSysExit => None,
    }
    .ok_or(LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?;
    let subject_offset = i16::try_from(subject.offset_v1())
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?;
    if subject.size_v1() != 4 || !subject.signed_v1() || subject.data_location_v1() {
        return Err(LinuxVzPackageSensorBpfErrorV1::InvalidLayout);
    }
    let parent_offset = if layout.kind_v1() == LinuxVzPackageTracepointKindV1::SchedProcessFork {
        let parent = layout
            .parent_pid_v1()
            .ok_or(LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?;
        if parent.size_v1() != 4 || !parent.signed_v1() || parent.data_location_v1() {
            return Err(LinuxVzPackageSensorBpfErrorV1::InvalidLayout);
        }
        Some(
            i16::try_from(parent.offset_v1())
                .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?,
        )
    } else {
        None
    };

    let mut program = BpfProgramBuilderV1::default();
    program.mov64_register_v1(BPF_REG_6_V1, BPF_REG_1_V1);
    program.call_v1(BPF_FUNC_GET_CURRENT_CGROUP_ID_V1);
    program.mov64_register_v1(BPF_REG_8_V1, BPF_REG_0_V1);
    program.store_immediate_v1(BPF_W_V1, BPF_REG_10_V1, -4, 0);
    program.load_map_descriptor_v1(BPF_REG_1_V1, configuration_map);
    program.mov64_register_v1(BPF_REG_2_V1, BPF_REG_10_V1);
    program.add64_immediate_v1(BPF_REG_2_V1, -4);
    program.call_v1(BPF_FUNC_MAP_LOOKUP_ELEM_V1);
    let missing_configuration = program.jump_immediate_placeholder_v1(BPF_JEQ_V1, BPF_REG_0_V1, 0);
    program.load_register_v1(BPF_DW_V1, BPF_REG_1_V1, BPF_REG_0_V1, 0);
    let wrong_cgroup = program.jump_register_placeholder_v1(BPF_JNE_V1, BPF_REG_8_V1, BPF_REG_1_V1);

    program.load_map_descriptor_v1(BPF_REG_1_V1, ring_buffer_map);
    program.mov64_immediate_v1(
        BPF_REG_2_V1,
        i32::try_from(LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1)
            .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?,
    );
    program.mov64_immediate_v1(BPF_REG_3_V1, 0);
    program.call_v1(BPF_FUNC_RINGBUF_RESERVE_V1);
    let reservation_failed = program.jump_immediate_placeholder_v1(BPF_JEQ_V1, BPF_REG_0_V1, 0);
    program.mov64_register_v1(BPF_REG_7_V1, BPF_REG_0_V1);

    for offset in (0..LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1).step_by(size_of::<u64>()) {
        program.store_immediate_v1(
            BPF_DW_V1,
            BPF_REG_7_V1,
            i16::try_from(offset).map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?,
            0,
        );
    }
    program.store_immediate_v1(BPF_W_V1, BPF_REG_7_V1, 0, KERNEL_EVENT_MAGIC_LE_V1);
    let version_and_kind = (kind << 16) | KERNEL_EVENT_VERSION_V1;
    program.store_immediate_v1(
        BPF_W_V1,
        BPF_REG_7_V1,
        4,
        i32::try_from(version_and_kind)
            .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?,
    );
    program.store_immediate_v1(
        BPF_W_V1,
        BPF_REG_7_V1,
        12,
        i32::try_from(LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1)
            .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?,
    );
    program.store_register_v1(BPF_DW_V1, BPF_REG_7_V1, BPF_REG_8_V1, 16);
    program.call_v1(BPF_FUNC_KTIME_GET_NS_V1);
    program.store_register_v1(BPF_DW_V1, BPF_REG_7_V1, BPF_REG_0_V1, 24);
    program.call_v1(BPF_FUNC_GET_CURRENT_PID_TGID_V1);
    program.mov64_register_v1(BPF_REG_9_V1, BPF_REG_0_V1);
    program.store_register_v1(BPF_W_V1, BPF_REG_7_V1, BPF_REG_9_V1, 32);
    program.rsh64_immediate_v1(BPF_REG_9_V1, 32);
    program.store_register_v1(BPF_W_V1, BPF_REG_7_V1, BPF_REG_9_V1, 36);
    if let Some(offset) = parent_offset {
        program.load_register_v1(BPF_W_V1, BPF_REG_9_V1, BPF_REG_6_V1, offset);
        program.store_register_v1(BPF_W_V1, BPF_REG_7_V1, BPF_REG_9_V1, 40);
    }
    program.load_register_v1(BPF_W_V1, BPF_REG_9_V1, BPF_REG_6_V1, subject_offset);
    program.store_register_v1(BPF_W_V1, BPF_REG_7_V1, BPF_REG_9_V1, 44);
    program.call_v1(BPF_FUNC_GET_SMP_PROCESSOR_ID_V1);
    program.store_register_v1(BPF_W_V1, BPF_REG_7_V1, BPF_REG_0_V1, 184);
    program.mov64_register_v1(BPF_REG_1_V1, BPF_REG_7_V1);
    program.mov64_immediate_v1(BPF_REG_2_V1, 0);
    program.call_v1(BPF_FUNC_RINGBUF_SUBMIT_V1);
    program.mov64_immediate_v1(BPF_REG_0_V1, 0);
    program.exit_v1();

    let drop_counter = program.instructions.len();
    program.store_immediate_v1(BPF_W_V1, BPF_REG_10_V1, -4, 0);
    program.load_map_descriptor_v1(BPF_REG_1_V1, drop_counter_map);
    program.mov64_register_v1(BPF_REG_2_V1, BPF_REG_10_V1);
    program.add64_immediate_v1(BPF_REG_2_V1, -4);
    program.call_v1(BPF_FUNC_MAP_LOOKUP_ELEM_V1);
    let missing_drop_counter = program.jump_immediate_placeholder_v1(BPF_JEQ_V1, BPF_REG_0_V1, 0);
    program.mov64_immediate_v1(BPF_REG_1_V1, 1);
    program.instruction_v1(
        BPF_STX_V1 | BPF_XADD_V1 | BPF_DW_V1,
        BPF_REG_0_V1,
        BPF_REG_1_V1,
        0,
        0,
    );
    let final_exit = program.instructions.len();
    program.mov64_immediate_v1(BPF_REG_0_V1, 0);
    program.exit_v1();

    program.patch_forward_jump_v1(missing_configuration, final_exit)?;
    program.patch_forward_jump_v1(wrong_cgroup, final_exit)?;
    program.patch_forward_jump_v1(reservation_failed, drop_counter)?;
    program.patch_forward_jump_v1(missing_drop_counter, final_exit)?;
    Ok(program.instructions)
}

fn decode_online_cpus_v1(bytes: &[u8]) -> Result<Vec<u32>, LinuxVzPackageSensorBpfErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_ONLINE_CPU_BYTES_V1 {
        return Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| LinuxVzPackageSensorBpfErrorV1::OnlineCpu)?;
    if text.contains(['\r', ' ', '\t']) || !text.ends_with('\n') || text.matches('\n').count() != 1
    {
        return Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu);
    }
    let mut observed = BTreeSet::new();
    for item in text.trim_end_matches('\n').split(',') {
        let mut limits = item.split('-');
        let first = parse_cpu_id_v1(
            limits
                .next()
                .ok_or(LinuxVzPackageSensorBpfErrorV1::OnlineCpu)?,
        )?;
        let last = match limits.next() {
            Some(value) => parse_cpu_id_v1(value)?,
            None => first,
        };
        if limits.next().is_some() || first > last {
            return Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu);
        }
        for cpu in first..=last {
            if observed.len() >= MAX_ONLINE_CPUS_V1 || !observed.insert(cpu) {
                return Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu);
            }
        }
    }
    if observed.is_empty() || observed.first() != Some(&0) {
        return Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu);
    }
    Ok(observed.into_iter().collect())
}

fn parse_cpu_id_v1(value: &str) -> Result<u32, LinuxVzPackageSensorBpfErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu);
    }
    let cpu = value
        .parse::<u32>()
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::OnlineCpu)?;
    if cpu > MAX_CPU_ID_V1 {
        return Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu);
    }
    Ok(cpu)
}

#[repr(C)]
#[derive(Default)]
struct BpfMapCreateAttributeV1 {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    maximum_entries: u32,
    map_flags: u32,
    inner_map_descriptor: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_interface_index: u32,
    btf_descriptor: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
    value_type_btf_object_descriptor: i32,
    map_token_descriptor: i32,
}

#[repr(C)]
struct BpfMapElementAttributeV1 {
    map_descriptor: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct BpfProgramLoadAttributeV1 {
    program_type: u32,
    instruction_count: u32,
    instructions: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buffer: u64,
    kernel_version: u32,
    program_flags: u32,
    program_name: [u8; 16],
    program_interface_index: u32,
    expected_attach_type: u32,
    program_btf_descriptor: u32,
    function_info_record_size: u32,
    function_info: u64,
    function_info_count: u32,
    line_info_record_size: u32,
    line_info: u64,
    line_info_count: u32,
    attach_btf_id: u32,
    attach_btf_object_descriptor: u32,
    core_relocation_count: u32,
    descriptor_array: u64,
    core_relocations: u64,
    core_relocation_record_size: u32,
    log_true_size: u32,
    program_token_descriptor: i32,
    descriptor_array_count: u32,
    signature: u64,
    signature_size: u32,
    keyring_id: i32,
}

#[repr(C)]
#[derive(Default)]
struct PerfEventAttributeV1 {
    event_type: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    breakpoint_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_registers_user: u64,
    sample_stack_user: u32,
    clock_id: i32,
    sample_registers_interrupt: u64,
    auxiliary_watermark: u32,
    sample_maximum_stack: u16,
    reserved: u16,
    auxiliary_sample_size: u32,
    reserved2: u32,
    signal_data: u64,
    config3: u64,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxVzPackageSensorBpfProducerV1 {
    links: Vec<OwnedFd>,
    programs: Vec<OwnedFd>,
    drop_counter: OwnedFd,
    configuration: OwnedFd,
    ring_buffer: LinuxVzPackageBpfRingBufferV1,
    layouts: [LinuxVzPackageTracepointLayoutV1; 3],
    online_cpus: Vec<u32>,
    attachment_cpu: u32,
    expected_cgroup_id: u64,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for LinuxVzPackageSensorBpfProducerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageSensorBpfProducerV1")
            .field("links", &self.links.len())
            .field("programs", &self.programs.len())
            .field("drop_counter", &"<root-only-bpf-map>")
            .field("configuration", &"<root-only-bpf-map>")
            .field("ring_buffer", &self.ring_buffer)
            .field("layouts", &self.layouts)
            .field("online_cpus", &self.online_cpus)
            .field("attachment_cpu", &self.attachment_cpu)
            .field("expected_cgroup_id", &self.expected_cgroup_id)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageSensorBpfProducerV1 {
    pub(crate) fn start_v1(
        expected_cgroup_id: u64,
        ring_buffer_capacity: usize,
    ) -> Result<Self, LinuxVzPackageSensorBpfErrorV1> {
        if unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0
            || unsafe { libc::getegid() } != 0
        {
            return Err(LinuxVzPackageSensorBpfErrorV1::Identity);
        }
        if expected_cgroup_id == 0
            || !(MIN_RING_BUFFER_BYTES_V1..=MAX_RING_BUFFER_BYTES_V1)
                .contains(&ring_buffer_capacity)
            || !ring_buffer_capacity.is_power_of_two()
        {
            return Err(LinuxVzPackageSensorBpfErrorV1::InvalidConfiguration);
        }
        let online_cpus = read_online_cpus_v1()?;
        let attachment_cpu = *online_cpus
            .first()
            .ok_or(LinuxVzPackageSensorBpfErrorV1::OnlineCpu)?;
        let layouts = [
            read_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::SchedProcessFork,
            )?,
            read_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::SchedProcessExec,
            )?,
            read_linux_vz_package_tracepoint_layout_v1(
                LinuxVzPackageTracepointKindV1::SchedProcessExit,
            )?,
        ];
        let configuration = create_map_v1(
            BPF_MAP_TYPE_ARRAY_V1,
            size_of::<u32>(),
            size_of::<u64>(),
            1,
            BPF_F_RDONLY_PROG_V1,
            "wt_pkg_cfg",
        )?;
        update_u64_map_value_v1(configuration.as_raw_fd(), expected_cgroup_id)?;
        let drop_counter = create_map_v1(
            BPF_MAP_TYPE_ARRAY_V1,
            size_of::<u32>(),
            size_of::<u64>(),
            1,
            0,
            "wt_pkg_drop",
        )?;
        let ring_map = create_map_v1(
            BPF_MAP_TYPE_RINGBUF_V1,
            0,
            0,
            ring_buffer_capacity,
            0,
            "wt_pkg_ring",
        )?;
        let mut programs = Vec::with_capacity(layouts.len());
        let mut links = Vec::with_capacity(layouts.len());
        for layout in &layouts {
            let instructions = build_lifecycle_program_v1(
                layout,
                configuration.as_raw_fd(),
                ring_map.as_raw_fd(),
                drop_counter.as_raw_fd(),
            )?;
            let program = load_tracepoint_program_v1(
                &instructions,
                match layout.kind_v1() {
                    LinuxVzPackageTracepointKindV1::SchedProcessFork => "wt_pkg_fork",
                    LinuxVzPackageTracepointKindV1::SchedProcessExec => "wt_pkg_exec",
                    LinuxVzPackageTracepointKindV1::SchedProcessExit => "wt_pkg_exit",
                    LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter
                    | LinuxVzPackageTracepointKindV1::RawSyscallsSysExit => {
                        return Err(LinuxVzPackageSensorBpfErrorV1::InvalidLayout);
                    }
                },
            )?;
            links.push(attach_tracepoint_program_v1(
                layout.tracepoint_id_v1(),
                attachment_cpu,
                program.as_raw_fd(),
            )?);
            programs.push(program);
        }
        let ring_buffer =
            LinuxVzPackageBpfRingBufferV1::from_map_v1(ring_map, ring_buffer_capacity)?;
        Ok(Self {
            links,
            programs,
            drop_counter,
            configuration,
            ring_buffer,
            layouts,
            online_cpus,
            attachment_cpu,
            expected_cgroup_id,
        })
    }

    pub(crate) fn drain_available_v1(
        &mut self,
        maximum_records: usize,
    ) -> Result<Vec<LinuxVzPackageKernelEventV1>, LinuxVzPackageSensorBpfErrorV1> {
        Ok(self
            .ring_buffer
            .drain_available_v1(self.expected_cgroup_id, maximum_records)?)
    }

    pub(crate) fn dropped_event_count_v1(&self) -> Result<u64, LinuxVzPackageSensorBpfErrorV1> {
        lookup_u64_map_value_v1(self.drop_counter.as_raw_fd())
    }

    pub(crate) fn discarded_record_count_v1(&self) -> u64 {
        self.ring_buffer.discarded_record_count()
    }

    pub(crate) fn last_source_sequence_v1(&self) -> u64 {
        self.ring_buffer.last_source_sequence()
    }

    pub(crate) fn layouts_v1(&self) -> &[LinuxVzPackageTracepointLayoutV1; 3] {
        &self.layouts
    }

    pub(crate) fn online_cpus_v1(&self) -> &[u32] {
        &self.online_cpus
    }

    pub(crate) const fn attachment_cpu_v1(&self) -> u32 {
        self.attachment_cpu
    }
}

#[cfg(target_os = "linux")]
fn read_online_cpus_v1() -> Result<Vec<u32>, LinuxVzPackageSensorBpfErrorV1> {
    let mut file = File::open("/sys/devices/system/cpu/online")
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::OnlineCpu)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ONLINE_CPU_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::OnlineCpu)?;
    decode_online_cpus_v1(&bytes)
}

#[cfg(target_os = "linux")]
fn create_map_v1(
    map_type: u32,
    key_size: usize,
    value_size: usize,
    maximum_entries: usize,
    map_flags: u32,
    name: &str,
) -> Result<OwnedFd, LinuxVzPackageSensorBpfErrorV1> {
    // Every byte passed to the kernel must be deterministic, including C ABI padding.
    let mut attributes = unsafe { std::mem::zeroed::<BpfMapCreateAttributeV1>() };
    attributes.map_type = map_type;
    attributes.key_size = u32::try_from(key_size)
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidConfiguration)?;
    attributes.value_size = u32::try_from(value_size)
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidConfiguration)?;
    attributes.maximum_entries = u32::try_from(maximum_entries)
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidConfiguration)?;
    attributes.map_flags = map_flags;
    copy_object_name_v1(name, &mut attributes.map_name)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE_V1,
            &attributes,
            size_of::<BpfMapCreateAttributeV1>(),
        )
    };
    owned_descriptor_v1(result, LinuxVzPackageSensorBpfErrorV1::MapCreate)
}

#[cfg(target_os = "linux")]
fn update_u64_map_value_v1(
    descriptor: RawFd,
    value: u64,
) -> Result<(), LinuxVzPackageSensorBpfErrorV1> {
    let key = 0_u32;
    let attributes = BpfMapElementAttributeV1 {
        map_descriptor: u32::try_from(descriptor)
            .map_err(|_| LinuxVzPackageSensorBpfErrorV1::Descriptor)?,
        padding: 0,
        key: (&key as *const u32) as u64,
        value: (&value as *const u64) as u64,
        flags: BPF_ANY_V1,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM_V1,
            &attributes,
            size_of::<BpfMapElementAttributeV1>(),
        )
    };
    if result != 0 {
        return Err(LinuxVzPackageSensorBpfErrorV1::MapUpdate);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn lookup_u64_map_value_v1(descriptor: RawFd) -> Result<u64, LinuxVzPackageSensorBpfErrorV1> {
    let key = 0_u32;
    let mut value = 0_u64;
    let attributes = BpfMapElementAttributeV1 {
        map_descriptor: u32::try_from(descriptor)
            .map_err(|_| LinuxVzPackageSensorBpfErrorV1::Descriptor)?,
        padding: 0,
        key: (&key as *const u32) as u64,
        value: (&mut value as *mut u64) as u64,
        flags: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_ELEM_V1,
            &attributes,
            size_of::<BpfMapElementAttributeV1>(),
        )
    };
    if result != 0 {
        return Err(LinuxVzPackageSensorBpfErrorV1::DropCounter);
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn load_tracepoint_program_v1(
    instructions: &[BpfInstructionV1],
    name: &str,
) -> Result<OwnedFd, LinuxVzPackageSensorBpfErrorV1> {
    if instructions.is_empty() {
        return Err(LinuxVzPackageSensorBpfErrorV1::InvalidLayout);
    }
    static LICENSE: &[u8] = b"GPL\0";
    // Every byte passed to the kernel must be deterministic, including C ABI padding.
    let mut attributes = unsafe { std::mem::zeroed::<BpfProgramLoadAttributeV1>() };
    attributes.program_type = BPF_PROG_TYPE_TRACEPOINT_V1;
    attributes.instruction_count = u32::try_from(instructions.len())
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::InvalidLayout)?;
    attributes.instructions = instructions.as_ptr() as u64;
    attributes.license = LICENSE.as_ptr() as u64;
    copy_object_name_v1(name, &mut attributes.program_name)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD_V1,
            &attributes,
            size_of::<BpfProgramLoadAttributeV1>(),
        )
    };
    if result < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(code) => LinuxVzPackageSensorBpfErrorV1::ProgramLoadOs(code),
            None => LinuxVzPackageSensorBpfErrorV1::ProgramLoad,
        });
    }
    owned_descriptor_v1(result, LinuxVzPackageSensorBpfErrorV1::ProgramLoad)
}

#[cfg(target_os = "linux")]
fn attach_tracepoint_program_v1(
    tracepoint_id: u32,
    cpu: u32,
    program: RawFd,
) -> Result<OwnedFd, LinuxVzPackageSensorBpfErrorV1> {
    // Every byte passed to the kernel must be deterministic, including C ABI padding.
    let mut attributes = unsafe { std::mem::zeroed::<PerfEventAttributeV1>() };
    attributes.event_type = PERF_TYPE_TRACEPOINT_V1;
    attributes.size = u32::try_from(size_of::<PerfEventAttributeV1>())
        .map_err(|_| LinuxVzPackageSensorBpfErrorV1::Attach)?;
    attributes.config = u64::from(tracepoint_id);
    attributes.sample_period = 1;
    attributes.flags = 1;
    attributes.wakeup_events = 1;
    let result = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attributes,
            -1_i32,
            i32::try_from(cpu).map_err(|_| LinuxVzPackageSensorBpfErrorV1::OnlineCpu)?,
            -1_i32,
            PERF_FLAG_FD_CLOEXEC_V1,
        )
    };
    if result < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => {
                LinuxVzPackageSensorBpfErrorV1::PerfEventOpenPermissionDenied
            }
            Some(libc::EINVAL) => LinuxVzPackageSensorBpfErrorV1::PerfEventOpenInvalid,
            Some(libc::ENOENT) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
                LinuxVzPackageSensorBpfErrorV1::PerfEventOpenUnsupported
            }
            Some(code) => LinuxVzPackageSensorBpfErrorV1::PerfEventOpenOs(code),
            None => LinuxVzPackageSensorBpfErrorV1::PerfEventOpen,
        });
    }
    let link = owned_descriptor_v1(result, LinuxVzPackageSensorBpfErrorV1::PerfEventOpen)?;
    if unsafe { libc::ioctl(link.as_raw_fd(), PERF_EVENT_IOC_SET_BPF_V1, program) } != 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => {
                LinuxVzPackageSensorBpfErrorV1::PerfEventSetBpfPermissionDenied
            }
            Some(libc::EINVAL) => LinuxVzPackageSensorBpfErrorV1::PerfEventSetBpfInvalid,
            Some(libc::EEXIST) => LinuxVzPackageSensorBpfErrorV1::PerfEventSetBpfDuplicate,
            Some(code) => LinuxVzPackageSensorBpfErrorV1::PerfEventSetBpfOs(code),
            None => LinuxVzPackageSensorBpfErrorV1::PerfEventSetBpf,
        });
    }
    if unsafe { libc::ioctl(link.as_raw_fd(), PERF_EVENT_IOC_ENABLE_V1, 0) } != 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINVAL) => LinuxVzPackageSensorBpfErrorV1::PerfEventEnableInvalid,
            Some(code) => LinuxVzPackageSensorBpfErrorV1::PerfEventEnableOs(code),
            None => LinuxVzPackageSensorBpfErrorV1::PerfEventEnable,
        });
    }
    Ok(link)
}

#[cfg(target_os = "linux")]
fn copy_object_name_v1(
    name: &str,
    target: &mut [u8; 16],
) -> Result<(), LinuxVzPackageSensorBpfErrorV1> {
    if name.is_empty()
        || name.len() >= target.len()
        || !name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(LinuxVzPackageSensorBpfErrorV1::InvalidConfiguration);
    }
    target[..name.len()].copy_from_slice(name.as_bytes());
    Ok(())
}

#[cfg(target_os = "linux")]
fn owned_descriptor_v1(
    result: libc::c_long,
    error: LinuxVzPackageSensorBpfErrorV1,
) -> Result<OwnedFd, LinuxVzPackageSensorBpfErrorV1> {
    let descriptor = i32::try_from(result).map_err(|_| error)?;
    if descriptor < 0 {
        return Err(error);
    }
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        let _ = unsafe { libc::close(descriptor) };
        return Err(LinuxVzPackageSensorBpfErrorV1::Descriptor);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_vz_package_sensor_tracepoint::decode_linux_vz_package_tracepoint_layout_v1;

    const COMMON: &str = "\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n";

    fn layout_v1(kind: LinuxVzPackageTracepointKindV1) -> LinuxVzPackageTracepointLayoutV1 {
        let fields = match kind {
            LinuxVzPackageTracepointKindV1::SchedProcessFork => {
                "\tfield:pid_t parent_pid; offset:24; size:4; signed:1;\n\
\tfield:pid_t child_pid; offset:44; size:4; signed:1;"
            }
            LinuxVzPackageTracepointKindV1::SchedProcessExec => {
                "\tfield:__data_loc char[] filename; offset:8; size:4; signed:1;\n\
\tfield:pid_t pid; offset:12; size:4; signed:1;\n\
\tfield:pid_t old_pid; offset:16; size:4; signed:1;"
            }
            LinuxVzPackageTracepointKindV1::SchedProcessExit => {
                "\tfield:pid_t pid; offset:24; size:4; signed:1;"
            }
            LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter
            | LinuxVzPackageTracepointKindV1::RawSyscallsSysExit => panic!("not lifecycle"),
        };
        let bytes = format!(
            "name: {}\nID: 220\nformat:\n{COMMON}\n{fields}\nprint fmt: \"closed\"\n",
            kind.name_v1()
        );
        decode_linux_vz_package_tracepoint_layout_v1(kind, bytes.as_bytes()).expect("layout")
    }

    #[test]
    fn lifecycle_programs_are_bounded_forward_only_and_fully_initialize_records() {
        assert_eq!(size_of::<BpfInstructionV1>(), 8);
        for kind in [
            LinuxVzPackageTracepointKindV1::SchedProcessFork,
            LinuxVzPackageTracepointKindV1::SchedProcessExec,
            LinuxVzPackageTracepointKindV1::SchedProcessExit,
        ] {
            let instructions =
                build_lifecycle_program_v1(&layout_v1(kind), 11, 12, 13).expect("program");
            assert!(instructions.len() < 128);
            assert_eq!(
                instructions
                    .iter()
                    .filter(|instruction| {
                        instruction.code == BPF_ST_V1 | BPF_MEM_V1 | BPF_DW_V1
                            && instruction.destination_v1() == BPF_REG_7_V1
                            && instruction.immediate == 0
                            && instruction.offset >= 0
                            && usize::try_from(instruction.offset)
                                .is_ok_and(|offset| offset % 8 == 0 && offset < 192)
                    })
                    .count(),
                24
            );
            assert_eq!(
                instructions
                    .iter()
                    .filter(|instruction| {
                        instruction.code == BPF_LD_V1 | BPF_DW_V1 | BPF_IMM_V1
                            && instruction.source_v1() == BPF_PSEUDO_MAP_FD_V1
                    })
                    .count(),
                3
            );
            for (index, instruction) in instructions.iter().enumerate() {
                let operation = instruction.code & 0xf0;
                if instruction.code & 0x07 == BPF_JMP_V1
                    && !matches!(operation, BPF_CALL_V1 | BPF_EXIT_V1)
                {
                    let target = isize::try_from(index).expect("index")
                        + 1
                        + isize::from(instruction.offset);
                    assert!(target > isize::try_from(index).expect("index"));
                    assert!(usize::try_from(target).is_ok_and(|target| target < instructions.len()));
                }
            }
            assert_eq!(
                instructions.last().expect("last").code,
                BPF_JMP_V1 | BPF_EXIT_V1
            );
        }
    }

    #[test]
    fn linux_uapi_prefix_layouts_are_exact() {
        assert_eq!(size_of::<BpfMapCreateAttributeV1>(), 80);
        assert_eq!(std::mem::offset_of!(BpfMapCreateAttributeV1, map_name), 28);
        assert_eq!(std::mem::offset_of!(BpfMapCreateAttributeV1, map_extra), 64);
        assert_eq!(size_of::<BpfMapElementAttributeV1>(), 32);
        assert_eq!(std::mem::offset_of!(BpfMapElementAttributeV1, key), 8);
        assert_eq!(std::mem::offset_of!(BpfMapElementAttributeV1, value), 16);
        assert_eq!(size_of::<BpfProgramLoadAttributeV1>(), 168);
        assert_eq!(
            std::mem::offset_of!(BpfProgramLoadAttributeV1, instructions),
            8
        );
        assert_eq!(
            std::mem::offset_of!(BpfProgramLoadAttributeV1, program_name),
            48
        );
        assert_eq!(
            std::mem::offset_of!(BpfProgramLoadAttributeV1, descriptor_array),
            120
        );
        assert_eq!(
            std::mem::offset_of!(BpfProgramLoadAttributeV1, descriptor_array_count),
            148
        );
        assert_eq!(
            std::mem::offset_of!(BpfProgramLoadAttributeV1, signature),
            152
        );
        assert_eq!(size_of::<PerfEventAttributeV1>(), 136);
        assert_eq!(std::mem::offset_of!(PerfEventAttributeV1, flags), 40);
        assert_eq!(std::mem::offset_of!(PerfEventAttributeV1, config3), 128);
    }

    #[test]
    fn lifecycle_programs_reject_syscall_layouts_and_bad_descriptors() {
        assert_eq!(
            build_lifecycle_program_v1(
                &layout_v1(LinuxVzPackageTracepointKindV1::SchedProcessExec),
                -1,
                12,
                13,
            ),
            Err(LinuxVzPackageSensorBpfErrorV1::Descriptor)
        );
    }

    #[test]
    fn online_cpu_lists_are_strict_bounded_and_canonical() {
        assert_eq!(
            decode_online_cpus_v1(b"0-3,8,10-11\n"),
            Ok(vec![0, 1, 2, 3, 8, 10, 11])
        );
        for invalid in [
            &b"1-2\n"[..],
            &b"0,0\n"[..],
            &b"0-2,2-3\n"[..],
            &b"00-2\n"[..],
            &b"0-\n"[..],
            &b"0-2 \n"[..],
            &b"0-5000\n"[..],
            &b"0-2\n3\n"[..],
        ] {
            assert_eq!(
                decode_online_cpus_v1(invalid),
                Err(LinuxVzPackageSensorBpfErrorV1::OnlineCpu)
            );
        }
    }
}
