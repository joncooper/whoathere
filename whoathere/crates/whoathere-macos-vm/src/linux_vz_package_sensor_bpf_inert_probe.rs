use std::fmt;

#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_control::kill_cgroup_from_descriptor_v1;
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_event_stream::{
    LinuxVzPackageKernelEventKindV1, LinuxVzPackageNetworkAddressFamilyV1,
    LinuxVzPackageSelectedSyscallV1,
};
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_file_collector::{
    LinuxVzPackageRootFileChangeKindV1, LinuxVzPackageRootFileCollectorV1,
    LinuxVzPackageRootFileEventKindV1,
};
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_process_collector::LinuxVzPackageRootProcessCollectorV1;
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_process_stream::LinuxVzPackageCorrelatedProcessObservationV1;
#[cfg(target_os = "linux")]
use crate::{
    encode_linux_vz_package_root_file_evidence_v1,
    encode_linux_vz_package_root_process_evidence_v1, LinuxVzPackageExpectedRootFileEvidenceV1,
    LinuxVzPackageExpectedRootProcessEvidenceV1, LinuxVzPackageProcessCompletionV1,
    LinuxVzPackageProcessLaunchIdentityV1, LinuxVzPackageProcessTerminalV1,
    LINUX_VZ_PACKAGE_ROOT_FILE_EVIDENCE_SCHEMA_V1,
    LINUX_VZ_PACKAGE_ROOT_PROCESS_EVIDENCE_SCHEMA_V1,
};
#[cfg(target_os = "linux")]
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::mem::zeroed;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use whoathere_artifact::Sha256Digest;

#[cfg(target_os = "linux")]
const FIXTURE_PATH_V1: &[u8] = b"/whoathere/process-fixture-child\0";
#[cfg(target_os = "linux")]
const CGROUP_ROOT_PATH_V1: &[u8] = b"/sys/fs/cgroup\0";
#[cfg(target_os = "linux")]
const CGROUP_PROCESSES_NAME_V1: &[u8] = b"cgroup.procs\0";
#[cfg(target_os = "linux")]
const PACKAGE_UID_V1: libc::uid_t = 65_534;
#[cfg(target_os = "linux")]
const PACKAGE_GID_V1: libc::gid_t = 65_534;
#[cfg(target_os = "linux")]
const MAX_FIXTURE_BYTES_V1: usize = 16 * 1024 * 1024;
#[cfg(target_os = "linux")]
const RING_BUFFER_BYTES_V1: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const FAULT_MAXIMUM_SOURCE_EVENTS_V1: usize = 8;
#[cfg(target_os = "linux")]
const CHILD_DEADLINE_V1: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const FAULT_SIGNAL_TIMEOUT_V1: Duration = Duration::from_secs(2);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageSensorBpfInertProbeErrorV1 {
    UnsupportedPlatform,
    Identity,
    Fixture,
    Cgroup,
    Producer,
    Collector,
    Fork,
    CpuAffinity,
    ChildState,
    ChildTimeout,
    ChildFailed,
    EventStream,
    EventMismatch,
    Evidence,
    LossObserved,
    Cleanup,
    Serialization,
}

impl LinuxVzPackageSensorBpfInertProbeErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "linux_vz_package_sensor_bpf_probe_platform_unsupported",
            Self::Identity => "linux_vz_package_sensor_bpf_probe_identity_invalid",
            Self::Fixture => "linux_vz_package_sensor_bpf_probe_fixture_invalid",
            Self::Cgroup => "linux_vz_package_sensor_bpf_probe_cgroup_failed",
            Self::Producer => "linux_vz_package_sensor_bpf_probe_producer_failed",
            Self::Collector => "linux_vz_package_sensor_bpf_probe_collector_failed",
            Self::Fork => "linux_vz_package_sensor_bpf_probe_fork_failed",
            Self::CpuAffinity => "linux_vz_package_sensor_bpf_probe_cpu_affinity_failed",
            Self::ChildState => "linux_vz_package_sensor_bpf_probe_child_state_invalid",
            Self::ChildTimeout => "linux_vz_package_sensor_bpf_probe_child_timeout",
            Self::ChildFailed => "linux_vz_package_sensor_bpf_probe_child_failed",
            Self::EventStream => "linux_vz_package_sensor_bpf_probe_event_stream_failed",
            Self::EventMismatch => "linux_vz_package_sensor_bpf_probe_event_mismatch",
            Self::Evidence => "linux_vz_package_sensor_bpf_probe_evidence_invalid",
            Self::LossObserved => "linux_vz_package_sensor_bpf_probe_loss_observed",
            Self::Cleanup => "linux_vz_package_sensor_bpf_probe_cleanup_failed",
            Self::Serialization => "linux_vz_package_sensor_bpf_probe_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageSensorBpfInertProbeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageSensorBpfInertProbeErrorV1 {}

pub fn run_linux_vz_package_sensor_bpf_inert_probe_v1(
) -> Result<String, LinuxVzPackageSensorBpfInertProbeErrorV1> {
    #[cfg(target_os = "linux")]
    {
        run_linux_vz_package_sensor_bpf_inert_probe_linux_v1()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(LinuxVzPackageSensorBpfInertProbeErrorV1::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct InertProbeEvidenceWireV1 {
    active_drain_poll_count: String,
    active_nonempty_drain_count: String,
    attachment_cpu: String,
    attachment_scope: &'static str,
    cgroup_id: String,
    collector_drain_mode: &'static str,
    collector_mode: &'static str,
    discarded_record_count: String,
    dropped_event_count: String,
    event_count: String,
    event_kinds: Vec<&'static str>,
    event_sequence_end: String,
    event_sequence_start: String,
    exit_attachment: &'static str,
    exit_status_source: &'static str,
    fault_cgroup_id: String,
    fault_cgroup_kill_used: bool,
    fault_fixture_pid: String,
    fault_fixture_termination_signal: String,
    fault_maximum_source_events: String,
    fault_signal_kind: &'static str,
    fault_signal_latency_microseconds: String,
    fault_signal_observed: bool,
    fault_trigger: &'static str,
    file_active_drain_poll_count: String,
    file_active_nonempty_drain_count: String,
    file_collector_declared_scope_complete: bool,
    file_collector_global_mount_coverage_complete: bool,
    file_diff_change_count: String,
    file_diff_completed_after_process_exit: bool,
    file_fanotify_overflow_count: String,
    file_fanotify_mark_scope: Vec<&'static str>,
    file_fanotify_unobserved_mounts: Vec<&'static str>,
    file_ignored_non_cgroup_event_count: String,
    file_maximum_drain_batch_event_count: String,
    file_permission_denied_count: String,
    file_permission_response_count: String,
    file_required_fanotify_mark_count: String,
    file_source_event_count: String,
    finish_drain_event_count: String,
    fixture_cpu: String,
    fixture_exit_status: String,
    fixture_pid: String,
    fixture_sha256: String,
    kernel_exit_wait_status: String,
    leader_exec_count: String,
    malware_execution: bool,
    maximum_drain_batch_record_count: String,
    network_connect_destination_class: &'static str,
    network_connect_family: &'static str,
    network_connect_port: String,
    network_connect_result: String,
    network_intent_count: String,
    network_raw_addresses_captured: bool,
    network_sendto_destination_class: &'static str,
    network_sendto_family: &'static str,
    network_sendto_port: String,
    network_sendto_result: String,
    observed_event_cpus: Vec<String>,
    online_cpus: Vec<String>,
    package_execution: bool,
    package_gid: String,
    package_uid: String,
    pre_release_event_count: String,
    process_collector_coverage_complete: bool,
    root_process_evidence_byte_length: String,
    root_process_evidence_canonical: bool,
    root_process_evidence_coverage_complete: bool,
    root_process_evidence_observation_count: String,
    root_process_evidence_raw_arguments_captured: bool,
    root_process_evidence_raw_exec_paths_captured: bool,
    root_process_evidence_schema: &'static str,
    root_process_evidence_sha256: String,
    root_process_evidence_source_event_count: String,
    root_file_evidence_baseline_snapshot_sha256: String,
    root_file_evidence_byte_length: String,
    root_file_evidence_canonical: bool,
    root_file_evidence_change_count: String,
    root_file_evidence_declared_scope_complete: bool,
    root_file_evidence_global_mount_coverage_complete: bool,
    root_file_evidence_final_snapshot_sha256: String,
    root_file_evidence_raw_paths_captured: bool,
    root_file_evidence_schema: &'static str,
    root_file_evidence_sha256: String,
    root_file_evidence_source_event_count: String,
    root_file_evidence_workspace_diff_sha256: String,
    runtime_btf_sha256: String,
    schema_version: &'static str,
    source_event_count_before_finish: String,
    sync_back: bool,
    task_exit_code_byte_offset: String,
    tracepoint_format_sha256: BTreeMap<&'static str, String>,
    waitpid_wait_status: String,
}

#[cfg(target_os = "linux")]
struct ProbeCgroupV1 {
    root: OwnedFd,
    directory: OwnedFd,
    name: CString,
    id: u64,
    removed: bool,
}

#[cfg(target_os = "linux")]
impl Drop for ProbeCgroupV1 {
    fn drop(&mut self) {
        if !self.removed {
            let _ = unsafe {
                libc::unlinkat(
                    self.root.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
        }
    }
}

#[cfg(target_os = "linux")]
impl ProbeCgroupV1 {
    fn create_v1() -> Result<Self, LinuxVzPackageSensorBpfInertProbeErrorV1> {
        let process = unsafe { libc::getpid() };
        if process <= 1 {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Identity);
        }
        let root_descriptor = unsafe {
            libc::open(
                CGROUP_ROOT_PATH_V1.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        let root = owned_descriptor_v1(root_descriptor)?;
        let name = CString::new(format!("whoathere-package-action-{process}"))
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup)?;
        if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup);
        }
        let directory_descriptor = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        let directory = match owned_descriptor_v1(directory_descriptor) {
            Ok(directory) => directory,
            Err(error) => {
                let _ =
                    unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
                return Err(error);
            }
        };
        let mut stat: libc::stat = unsafe { zeroed() };
        let mut filesystem: libc::statfs = unsafe { zeroed() };
        if unsafe { libc::fstat(directory.as_raw_fd(), &mut stat) } != 0
            || unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0
            || filesystem.f_type != 0x6367_7270
            || stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_ino == 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            let _ = unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup);
        }
        Ok(Self {
            root,
            directory,
            name,
            id: stat.st_ino,
            removed: false,
        })
    }

    fn add_process_v1(
        &self,
        process: libc::pid_t,
    ) -> Result<(), LinuxVzPackageSensorBpfInertProbeErrorV1> {
        if process <= 1 {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
        }
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                CGROUP_PROCESSES_NAME_V1.as_ptr().cast(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        let mut file = File::from(owned_descriptor_v1(descriptor)?);
        file.write_all(process.to_string().as_bytes())
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup)?;
        file.flush()
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup)
    }

    fn remove_v1(&mut self) -> Result<(), LinuxVzPackageSensorBpfInertProbeErrorV1> {
        if unsafe {
            libc::unlinkat(
                self.root.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Cleanup);
        }
        self.removed = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct FaultSignalQualificationV1 {
    cgroup_id: u64,
    fixture_pid: u32,
    latency_microseconds: u128,
    termination_signal: u8,
}

#[cfg(target_os = "linux")]
fn qualify_fault_signal_v1(
    fixture: RawFd,
    fixture_cpu: u32,
) -> Result<FaultSignalQualificationV1, LinuxVzPackageSensorBpfInertProbeErrorV1> {
    let mut cgroup = ProbeCgroupV1::create_v1()?;
    let mut collector = LinuxVzPackageRootProcessCollectorV1::arm_v1(
        cgroup.id,
        RING_BUFFER_BYTES_V1,
        FAULT_MAXIMUM_SOURCE_EVENTS_V1,
    )
    .map_err(|error| {
        eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAULT_COLLECTOR_DETAIL {error}");
        LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
    })?;
    if !collector
        .online_cpus_v1()
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Collector)?
        .contains(&fixture_cpu)
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity);
    }
    let fixture_path = CString::new("process-fixture-child")
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?;
    let fixture_case = CString::new("fault_signal")
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?;
    let environment = [
        CString::new("CI=true").map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
        CString::new("HOME=/nonexistent")
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
        CString::new("NO_COLOR=1")
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
        CString::new("PATH=/usr/bin:/bin")
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
    ];
    let arguments = [
        fixture_path.as_ptr(),
        fixture_case.as_ptr(),
        std::ptr::null(),
    ];
    let environment_pointers = [
        environment[0].as_ptr(),
        environment[1].as_ptr(),
        environment[2].as_ptr(),
        environment[3].as_ptr(),
        std::ptr::null(),
    ];
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Fork);
    }
    if child == 0 {
        unsafe { child_exec_v1(fixture, arguments.as_ptr(), environment_pointers.as_ptr()) }
    }
    let mut child_guard = ChildGuardV1 {
        process: child,
        reaped: false,
    };
    require_stopped_child_v1(child)?;
    cgroup.add_process_v1(child)?;
    pin_process_to_cpu_v1(child, fixture_cpu)?;
    collector
        .leader_attached_before_release_v1(child as u32)
        .map_err(|error| {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAULT_COLLECTOR_DETAIL {error}");
            LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
        })?;
    let fault_signal_fd = collector
        .fault_signal_fd_v1()
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Collector)?;
    let started = Instant::now();
    if unsafe { libc::kill(child, libc::SIGCONT) } != 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
    }
    let mut descriptor = libc::pollfd {
        fd: fault_signal_fd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    loop {
        let remaining = FAULT_SIGNAL_TIMEOUT_V1.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildTimeout);
        }
        let timeout_milliseconds = i32::try_from(remaining.as_millis().max(1))
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::ChildTimeout)?;
        descriptor.revents = 0;
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_milliseconds) };
        if result > 0 {
            break;
        }
        if result == 0 {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildTimeout);
        }
        if last_errno_v1() != libc::EINTR {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Collector);
        }
    }
    let latency_microseconds = started.elapsed().as_micros();
    if descriptor.revents & libc::POLLIN == 0
        || descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        || collector.require_healthy_v1().is_ok()
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch);
    }
    kill_cgroup_from_descriptor_v1(cgroup.directory.as_raw_fd())
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup)?;
    let status = wait_for_child_v1(child)?;
    child_guard.reaped = true;
    if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGKILL {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildFailed);
    }
    collector.abort_v1();
    cgroup.remove_v1()?;
    Ok(FaultSignalQualificationV1 {
        cgroup_id: cgroup.id,
        fixture_pid: child as u32,
        latency_microseconds,
        termination_signal: libc::SIGKILL as u8,
    })
}

#[cfg(target_os = "linux")]
fn run_linux_vz_package_sensor_bpf_inert_probe_linux_v1(
) -> Result<String, LinuxVzPackageSensorBpfInertProbeErrorV1> {
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0
        || unsafe { libc::getegid() } != 0
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Identity);
    }
    let (fixture, fixture_sha256) = open_and_measure_fixture_v1()?;
    relocate_descriptor_v1(fixture.as_raw_fd(), 3)?;
    let fixture = if fixture.as_raw_fd() == 3 {
        fixture
    } else {
        drop(fixture);
        unsafe { OwnedFd::from_raw_fd(3) }
    };
    let mut cgroup = ProbeCgroupV1::create_v1()?;
    let sensor_session_challenge_sha256 =
        Sha256Digest::from_bytes(b"whoathere inert probe sensor session v1");
    let launch_contract_sha256 =
        Sha256Digest::from_bytes(b"whoathere inert probe launch contract v1");
    let process_plan_sha256 = Sha256Digest::from_bytes(b"whoathere inert probe process plan v1");
    let mut collector =
        LinuxVzPackageRootProcessCollectorV1::arm_v1(cgroup.id, RING_BUFFER_BYTES_V1, 64).map_err(
            |error| {
                eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_COLLECTOR_DETAIL {error}");
                LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
            },
        )?;
    let mut file_collector = LinuxVzPackageRootFileCollectorV1::arm_v1(
        cgroup.id,
        cgroup.directory.as_raw_fd(),
        sensor_session_challenge_sha256.clone(),
        4_096,
    )
    .map_err(|error| {
        eprintln!("WHOATHERE_PACKAGE_SENSOR_FILE_INERT_COLLECTOR_DETAIL {error}");
        LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
    })?;
    file_collector.require_healthy_v1().map_err(|error| {
        eprintln!("WHOATHERE_PACKAGE_SENSOR_FILE_INERT_COLLECTOR_DETAIL {error}");
        LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
    })?;
    let fixture_cpu = *collector
        .online_cpus_v1()
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Collector)?
        .last()
        .ok_or(LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity)?;
    let attachment_cpu = collector
        .attachment_cpu_v1()
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Collector)?;
    if fixture_cpu == attachment_cpu {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity);
    }
    let fixture_path = CString::new("process-fixture-child")
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?;
    let fixture_case = CString::new("continuous_drain")
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?;
    let environment = [
        CString::new("CI=true").map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
        CString::new("HOME=/nonexistent")
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
        CString::new("NO_COLOR=1")
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
        CString::new("PATH=/usr/bin:/bin")
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
    ];
    let arguments = [
        fixture_path.as_ptr(),
        fixture_case.as_ptr(),
        std::ptr::null(),
    ];
    let environment_pointers = [
        environment[0].as_ptr(),
        environment[1].as_ptr(),
        environment[2].as_ptr(),
        environment[3].as_ptr(),
        std::ptr::null(),
    ];

    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Fork);
    }
    if child == 0 {
        unsafe {
            child_exec_v1(
                fixture.as_raw_fd(),
                arguments.as_ptr(),
                environment_pointers.as_ptr(),
            )
        }
    }
    let mut child_guard = ChildGuardV1 {
        process: child,
        reaped: false,
    };
    require_stopped_child_v1(child)?;
    cgroup.add_process_v1(child)?;
    pin_process_to_cpu_v1(child, fixture_cpu)?;
    file_collector
        .leader_attached_before_release_v1(child as u32)
        .map_err(|error| {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_FILE_INERT_COLLECTOR_DETAIL {error}");
            LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
        })?;
    collector
        .leader_attached_before_release_v1(child as u32)
        .map_err(|error| {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_COLLECTOR_DETAIL {error}");
            LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
        })?;
    let process_started_monotonic_nanoseconds = monotonic_nanoseconds_v1()?;
    if unsafe { libc::kill(child, libc::SIGCONT) } != 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
    }
    let status = wait_for_child_v1(child)?;
    let process_ended_monotonic_nanoseconds = monotonic_nanoseconds_v1()?;
    child_guard.reaped = true;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        if let Err(error) = file_collector.require_healthy_v1() {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_FILE_INERT_COLLECTOR_DETAIL {error}");
        }
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let signal = if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else {
            0
        };
        eprintln!(
            "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_CHILD_DETAIL exit_code={exit_code} signal={signal}"
        );
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildFailed);
    }
    let waitpid_wait_status =
        u16::try_from(status).map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState)?;
    let completion = LinuxVzPackageProcessCompletionV1::from_parts_v1(
        process_started_monotonic_nanoseconds,
        process_ended_monotonic_nanoseconds,
        waitpid_wait_status,
        LinuxVzPackageProcessTerminalV1::Exited,
        Some(0),
        None,
    )
    .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState)?;
    let collection = collector
        .finish_after_empty_cgroup_v1(child as u32, &completion)
        .map_err(|error| {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_COLLECTOR_DETAIL {error}");
            LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
        })?;
    let file_collection = file_collector
        .finish_after_empty_cgroup_v1(child as u32, process_ended_monotonic_nanoseconds)
        .map_err(|error| {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_FILE_INERT_COLLECTOR_DETAIL {error}");
            LinuxVzPackageSensorBpfInertProbeErrorV1::Collector
        })?;
    let correlated = collection.stream_v1();
    let correlated_exit_wait_status = correlated.observations_v1().last().and_then(|observation| {
        let LinuxVzPackageCorrelatedProcessObservationV1::Lifecycle(event) = observation else {
            return None;
        };
        (event.kind_v1() == LinuxVzPackageKernelEventKindV1::Exit)
            .then(|| event.kernel_wait_status_v1())
            .flatten()
    });
    if correlated.expected_cgroup_id_v1() != cgroup.id
        || correlated.source_event_count_v1() != 18
        || correlated.observations_v1().len() != 10
        || correlated_exit_wait_status != Some(waitpid_wait_status)
        || !correlated.coverage_complete_v1()
        || collection.leader_pid_v1() != child as u32
        || collection.leader_exec_count_v1() != 1
        || collection.leader_kernel_wait_status_v1() != waitpid_wait_status
        || collection.leader_supervisor_wait_status_v1() != waitpid_wait_status
        || collection.dropped_event_count_v1() != 0
        || collection.discarded_record_count_v1() != 0
        || !collection.continuous_drain_v1()
        || collection.active_drain_poll_count_v1() == 0
        || collection.active_nonempty_drain_count_v1() == 0
        || collection.active_nonempty_drain_count_v1() > collection.active_drain_poll_count_v1()
        || !(17..=18).contains(&collection.source_event_count_before_finish_v1())
        || collection.finish_drain_event_count_v1() > 1
        || collection
            .source_event_count_before_finish_v1()
            .checked_add(collection.finish_drain_event_count_v1())
            != Some(18)
        || !(1..=18).contains(&collection.maximum_drain_batch_record_count_v1())
        || !collection.coverage_complete_v1()
        || !matches_exact_correlated_stream_v1(
            correlated.observations_v1(),
            child as u32,
            cgroup.id,
            fixture_cpu,
            waitpid_wait_status,
        )
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch);
    }
    let file_change = file_collection.changes_v1().first();
    let file_event_kinds = file_collection
        .events_v1()
        .iter()
        .map(|event| event.kind_v1())
        .collect::<Vec<_>>();
    if file_collection.cgroup_id_v1() != cgroup.id
        || file_collection.leader_pid_v1() != child as u32
        || file_collection.process_ended_monotonic_nanoseconds_v1()
            != process_ended_monotonic_nanoseconds
        || file_collection.diff_completed_monotonic_nanoseconds_v1()
            <= process_ended_monotonic_nanoseconds
        || file_collection.events_v1().len() < 5
        || file_collection.changes_v1().len() != 1
        || file_change.map(|change| change.kind_v1())
            != Some(LinuxVzPackageRootFileChangeKindV1::Renamed)
        || !file_change.is_some_and(|change| {
            change.content_changed_v1()
                && change.metadata_changed_v1()
                && change.secondary_path_v1().is_some()
        })
        || !file_event_kinds.contains(&LinuxVzPackageRootFileEventKindV1::OpenExec)
        || !file_event_kinds.contains(&LinuxVzPackageRootFileEventKindV1::Open)
        || !file_event_kinds.contains(&LinuxVzPackageRootFileEventKindV1::Read)
        || !file_event_kinds.contains(&LinuxVzPackageRootFileEventKindV1::Write)
        || file_collection.active_drain_poll_count_v1() == 0
        || file_collection.active_nonempty_drain_count_v1() == 0
        || file_collection.active_nonempty_drain_count_v1()
            > file_collection.active_drain_poll_count_v1()
        || file_collection.maximum_drain_batch_event_count_v1() == 0
        || file_collection.permission_response_count_v1() == 0
        || file_collection.permission_denied_count_v1() != 0
        || file_collection.fanotify_overflow_count_v1() != 0
        || file_collection.required_mark_count_v1() != 5
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch);
    }
    let root_runner_pid = u32::try_from(unsafe { libc::getpid() })
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Identity)?;
    let cgroup_name = cgroup
        .name
        .to_str()
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence)?
        .to_string();
    let action_index = usize::try_from(root_runner_pid)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence)?;
    let argv = vec!["process-fixture-child", "continuous_drain"];
    let argv_bytes = serde_json_canonicalizer::to_vec(&argv)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Serialization)?;
    let launch_identity = LinuxVzPackageProcessLaunchIdentityV1::from_bound_digests_v1(
        fixture_sha256.clone(),
        Sha256Digest::from_bytes(&argv_bytes),
        argv.len(),
    )
    .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence)?;
    let root_process_expected = LinuxVzPackageExpectedRootProcessEvidenceV1::from_action_v1(
        sensor_session_challenge_sha256.clone(),
        launch_contract_sha256.clone(),
        process_plan_sha256.clone(),
        action_index,
        cgroup_name,
        cgroup.id,
        root_runner_pid,
        child as u32,
        &launch_identity,
        &completion,
    )
    .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence)?;
    let root_process_evidence =
        encode_linux_vz_package_root_process_evidence_v1(&root_process_expected, &collection)
            .map_err(|error| {
                eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_EVIDENCE_DETAIL {error}");
                LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence
            })?;
    if root_process_evidence.source_event_count() != 18
        || root_process_evidence.observations().len() != 10
        || !root_process_evidence.coverage_complete()
        || root_process_evidence.raw_arguments_captured()
        || root_process_evidence.raw_exec_paths_captured()
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence);
    }
    let root_file_expected = LinuxVzPackageExpectedRootFileEvidenceV1::from_action_v1(
        sensor_session_challenge_sha256,
        launch_contract_sha256,
        process_plan_sha256,
        action_index,
        cgroup
            .name
            .to_str()
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence)?
            .to_string(),
        cgroup.id,
        root_runner_pid,
        child as u32,
        &completion,
    )
    .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence)?;
    let root_file_evidence =
        encode_linux_vz_package_root_file_evidence_v1(&root_file_expected, &file_collection)
            .map_err(|error| {
                eprintln!("WHOATHERE_PACKAGE_SENSOR_FILE_INERT_EVIDENCE_DETAIL {error}");
                LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence
            })?;
    if root_file_evidence.events().len() != file_collection.events_v1().len()
        || root_file_evidence.changes().len() != 1
        || !root_file_evidence.declared_scope_complete()
        || root_file_evidence.global_mount_coverage_complete()
        || root_file_evidence.raw_paths_captured()
        || root_file_evidence.diff_completed_monotonic_nanoseconds()
            <= process_ended_monotonic_nanoseconds
        || root_file_evidence.permission_denied_count() != 0
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Evidence);
    }
    let mut tracepoints = BTreeMap::new();
    for (name, digest) in collection.tracepoint_format_sha256_v1() {
        tracepoints.insert(*name, digest.as_str().to_string());
    }
    cgroup.remove_v1()?;
    let fault = qualify_fault_signal_v1(fixture.as_raw_fd(), fixture_cpu)?;
    let evidence = InertProbeEvidenceWireV1 {
        active_drain_poll_count: collection.active_drain_poll_count_v1().to_string(),
        active_nonempty_drain_count: collection.active_nonempty_drain_count_v1().to_string(),
        attachment_cpu: collection.attachment_cpu_v1().to_string(),
        attachment_scope: "tracepoint_wide",
        cgroup_id: cgroup.id.to_string(),
        collector_drain_mode: "continuous_worker",
        collector_mode: "root_bpf_ring_correlator",
        discarded_record_count: collection.discarded_record_count_v1().to_string(),
        dropped_event_count: collection.dropped_event_count_v1().to_string(),
        event_count: correlated.source_event_count_v1().to_string(),
        event_kinds: vec![
            "setgroups_enter",
            "setgroups_exit",
            "setgid_enter",
            "setgid_exit",
            "setuid_enter",
            "setuid_exit",
            "exec",
            "mmap_enter",
            "mmap_exit",
            "mmap_enter",
            "mmap_exit",
            "mmap_enter",
            "mmap_exit",
            "connect_enter",
            "connect_exit",
            "sendto_enter",
            "sendto_exit",
            "exit",
        ],
        event_sequence_end: correlated.source_event_count_v1().to_string(),
        event_sequence_start: "1".to_string(),
        exit_attachment: "raw_tracepoint:sched_process_exit",
        exit_status_source: "runtime_btf:task_struct.exit_code",
        fault_cgroup_id: fault.cgroup_id.to_string(),
        fault_cgroup_kill_used: true,
        fault_fixture_pid: fault.fixture_pid.to_string(),
        fault_fixture_termination_signal: fault.termination_signal.to_string(),
        fault_maximum_source_events: FAULT_MAXIMUM_SOURCE_EVENTS_V1.to_string(),
        fault_signal_kind: "nonblocking_pipe_marker",
        fault_signal_latency_microseconds: fault.latency_microseconds.to_string(),
        fault_signal_observed: true,
        fault_trigger: "source_event_limit",
        file_active_drain_poll_count: file_collection.active_drain_poll_count_v1().to_string(),
        file_active_nonempty_drain_count: file_collection
            .active_nonempty_drain_count_v1()
            .to_string(),
        file_collector_declared_scope_complete: true,
        file_collector_global_mount_coverage_complete: false,
        file_diff_change_count: file_collection.changes_v1().len().to_string(),
        file_diff_completed_after_process_exit: file_collection
            .diff_completed_monotonic_nanoseconds_v1()
            > process_ended_monotonic_nanoseconds,
        file_fanotify_overflow_count: file_collection.fanotify_overflow_count_v1().to_string(),
        file_fanotify_mark_scope: vec![
            "dev_mount",
            "root_mount",
            "run_mount",
            "sys_mount",
            "workspace_mount",
        ],
        file_fanotify_unobserved_mounts: vec!["proc_mount"],
        file_ignored_non_cgroup_event_count: file_collection
            .ignored_non_cgroup_event_count_v1()
            .to_string(),
        file_maximum_drain_batch_event_count: file_collection
            .maximum_drain_batch_event_count_v1()
            .to_string(),
        file_permission_denied_count: file_collection.permission_denied_count_v1().to_string(),
        file_permission_response_count: file_collection.permission_response_count_v1().to_string(),
        file_required_fanotify_mark_count: file_collection.required_mark_count_v1().to_string(),
        file_source_event_count: file_collection.events_v1().len().to_string(),
        finish_drain_event_count: collection.finish_drain_event_count_v1().to_string(),
        fixture_cpu: fixture_cpu.to_string(),
        fixture_exit_status: "0".to_string(),
        fixture_pid: child.to_string(),
        fixture_sha256: fixture_sha256.as_str().to_string(),
        kernel_exit_wait_status: correlated_exit_wait_status
            .ok_or(LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch)?
            .to_string(),
        leader_exec_count: collection.leader_exec_count_v1().to_string(),
        malware_execution: false,
        maximum_drain_batch_record_count: collection
            .maximum_drain_batch_record_count_v1()
            .to_string(),
        network_connect_destination_class: "documentation",
        network_connect_family: "ipv4",
        network_connect_port: "443".to_string(),
        network_connect_result: (-libc::ENETUNREACH).to_string(),
        network_intent_count: "2".to_string(),
        network_raw_addresses_captured: false,
        network_sendto_destination_class: "documentation",
        network_sendto_family: "ipv6",
        network_sendto_port: "53".to_string(),
        network_sendto_result: (-libc::EADDRNOTAVAIL).to_string(),
        observed_event_cpus: vec![fixture_cpu.to_string()],
        online_cpus: collection
            .online_cpus_v1()
            .iter()
            .map(u32::to_string)
            .collect(),
        package_execution: false,
        package_gid: PACKAGE_GID_V1.to_string(),
        package_uid: PACKAGE_UID_V1.to_string(),
        pre_release_event_count: "0".to_string(),
        process_collector_coverage_complete: collection.coverage_complete_v1(),
        root_process_evidence_byte_length: root_process_evidence
            .canonical_json_v1()
            .len()
            .to_string(),
        root_process_evidence_canonical: true,
        root_process_evidence_coverage_complete: root_process_evidence.coverage_complete(),
        root_process_evidence_observation_count: root_process_evidence
            .observations()
            .len()
            .to_string(),
        root_process_evidence_raw_arguments_captured: root_process_evidence
            .raw_arguments_captured(),
        root_process_evidence_raw_exec_paths_captured: root_process_evidence
            .raw_exec_paths_captured(),
        root_process_evidence_schema: LINUX_VZ_PACKAGE_ROOT_PROCESS_EVIDENCE_SCHEMA_V1,
        root_process_evidence_sha256: root_process_evidence.payload_sha256().as_str().to_string(),
        root_process_evidence_source_event_count: root_process_evidence
            .source_event_count()
            .to_string(),
        root_file_evidence_baseline_snapshot_sha256: root_file_evidence
            .baseline_snapshot_sha256()
            .as_str()
            .to_string(),
        root_file_evidence_byte_length: root_file_evidence.canonical_json_v1().len().to_string(),
        root_file_evidence_canonical: true,
        root_file_evidence_change_count: root_file_evidence.changes().len().to_string(),
        root_file_evidence_declared_scope_complete: root_file_evidence.declared_scope_complete(),
        root_file_evidence_global_mount_coverage_complete: root_file_evidence
            .global_mount_coverage_complete(),
        root_file_evidence_final_snapshot_sha256: root_file_evidence
            .final_snapshot_sha256()
            .as_str()
            .to_string(),
        root_file_evidence_raw_paths_captured: root_file_evidence.raw_paths_captured(),
        root_file_evidence_schema: LINUX_VZ_PACKAGE_ROOT_FILE_EVIDENCE_SCHEMA_V1,
        root_file_evidence_sha256: root_file_evidence.payload_sha256().as_str().to_string(),
        root_file_evidence_source_event_count: root_file_evidence.events().len().to_string(),
        root_file_evidence_workspace_diff_sha256: root_file_evidence
            .workspace_diff_sha256()
            .as_str()
            .to_string(),
        runtime_btf_sha256: collection.runtime_btf_sha256_v1().as_str().to_string(),
        schema_version: "whoathere.linux_vz_package_sensor_bpf_inert_probe.v11",
        source_event_count_before_finish: collection
            .source_event_count_before_finish_v1()
            .to_string(),
        sync_back: false,
        task_exit_code_byte_offset: collection.task_exit_code_byte_offset_v1().to_string(),
        tracepoint_format_sha256: tracepoints,
        waitpid_wait_status: waitpid_wait_status.to_string(),
    };
    let canonical = serde_json_canonicalizer::to_vec(&evidence)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Serialization)?;
    String::from_utf8(canonical)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Serialization)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct InertCorrelatedContextV1 {
    leader_pid: u32,
    cgroup_id: u64,
    fixture_cpu: u32,
}

#[cfg(target_os = "linux")]
fn matches_exact_correlated_stream_v1(
    observations: &[LinuxVzPackageCorrelatedProcessObservationV1],
    leader_pid: u32,
    cgroup_id: u64,
    fixture_cpu: u32,
    wait_status: u16,
) -> bool {
    let context = InertCorrelatedContextV1 {
        leader_pid,
        cgroup_id,
        fixture_cpu,
    };
    observations.len() == 10
        && matches_correlated_syscall_v1(
            &observations[0],
            LinuxVzPackageSelectedSyscallV1::Setgroups,
            1,
            2,
            0,
            context,
        )
        && matches_correlated_syscall_v1(
            &observations[1],
            LinuxVzPackageSelectedSyscallV1::Setgid,
            3,
            4,
            u64::from(PACKAGE_GID_V1),
            context,
        )
        && matches_correlated_syscall_v1(
            &observations[2],
            LinuxVzPackageSelectedSyscallV1::Setuid,
            5,
            6,
            u64::from(PACKAGE_UID_V1),
            context,
        )
        && matches_correlated_lifecycle_v1(
            &observations[3],
            LinuxVzPackageKernelEventKindV1::Exec,
            7,
            context,
            None,
        )
        && matches_correlated_mmap_v1(&observations[4], 8, 9, context)
        && matches_correlated_mmap_v1(&observations[5], 10, 11, context)
        && matches_correlated_mmap_v1(&observations[6], 12, 13, context)
        && matches_correlated_network_v1(
            &observations[7],
            LinuxVzPackageSelectedSyscallV1::Connect,
            14,
            15,
            LinuxVzPackageNetworkAddressFamilyV1::Ipv4,
            443,
            &[192, 0, 2, 9],
            i64::from(-libc::ENETUNREACH),
            context,
        )
        && matches_correlated_network_v1(
            &observations[8],
            LinuxVzPackageSelectedSyscallV1::Sendto,
            16,
            17,
            LinuxVzPackageNetworkAddressFamilyV1::Ipv6,
            53,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            i64::from(-libc::EADDRNOTAVAIL),
            context,
        )
        && matches_correlated_lifecycle_v1(
            &observations[9],
            LinuxVzPackageKernelEventKindV1::Exit,
            18,
            context,
            Some(wait_status),
        )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn matches_correlated_network_v1(
    observation: &LinuxVzPackageCorrelatedProcessObservationV1,
    syscall: LinuxVzPackageSelectedSyscallV1,
    enter_sequence: u64,
    exit_sequence: u64,
    family: LinuxVzPackageNetworkAddressFamilyV1,
    port: u16,
    address: &[u8],
    result: i64,
    context: InertCorrelatedContextV1,
) -> bool {
    let LinuxVzPackageCorrelatedProcessObservationV1::Syscall(event) = observation else {
        return false;
    };
    let Some(target) = event.network_target_v1() else {
        return false;
    };
    let arguments = event.arguments_v1();
    let argument_shape = match syscall {
        LinuxVzPackageSelectedSyscallV1::Connect => {
            arguments[0] > 2
                && arguments[1] == 0
                && arguments[2] == 16
                && arguments[3..].iter().all(|argument| *argument == 0)
        }
        LinuxVzPackageSelectedSyscallV1::Sendto => {
            arguments[0] > 2
                && arguments[1] == 0
                && arguments[2] == 1
                && arguments[3] == 0
                && arguments[4] == 0
                && arguments[5] == 28
        }
        _ => false,
    };
    event.syscall_v1() == syscall
        && event.enter_source_sequence_v1() == enter_sequence
        && event.exit_source_sequence_v1() == exit_sequence
        && event.enter_timestamp_nanoseconds_v1() < event.exit_timestamp_nanoseconds_v1()
        && event.cgroup_id_v1() == context.cgroup_id
        && event.pid_v1() == context.leader_pid
        && event.tgid_v1() == context.leader_pid
        && argument_shape
        && event.result_v1() == result
        && event.enter_cpu_v1() == context.fixture_cpu
        && event.exit_cpu_v1() == context.fixture_cpu
        && target.family_v1() == family
        && target.port_v1() == port
        && target.address_v1() == address
}

#[cfg(target_os = "linux")]
fn matches_correlated_syscall_v1(
    observation: &LinuxVzPackageCorrelatedProcessObservationV1,
    syscall: LinuxVzPackageSelectedSyscallV1,
    enter_sequence: u64,
    exit_sequence: u64,
    first_argument: u64,
    context: InertCorrelatedContextV1,
) -> bool {
    let LinuxVzPackageCorrelatedProcessObservationV1::Syscall(event) = observation else {
        return false;
    };
    event.syscall_v1() == syscall
        && event.enter_source_sequence_v1() == enter_sequence
        && event.exit_source_sequence_v1() == exit_sequence
        && event.enter_timestamp_nanoseconds_v1() < event.exit_timestamp_nanoseconds_v1()
        && event.cgroup_id_v1() == context.cgroup_id
        && event.pid_v1() == context.leader_pid
        && event.tgid_v1() == context.leader_pid
        && event.arguments_v1()[0] == first_argument
        && event.arguments_v1()[1..]
            .iter()
            .all(|argument| *argument == 0)
        && event.network_target_v1().is_none()
        && event.result_v1() == 0
        && event.enter_cpu_v1() == context.fixture_cpu
        && event.exit_cpu_v1() == context.fixture_cpu
}

#[cfg(target_os = "linux")]
fn matches_correlated_mmap_v1(
    observation: &LinuxVzPackageCorrelatedProcessObservationV1,
    enter_sequence: u64,
    exit_sequence: u64,
    context: InertCorrelatedContextV1,
) -> bool {
    let LinuxVzPackageCorrelatedProcessObservationV1::Syscall(event) = observation else {
        return false;
    };
    event.syscall_v1() == LinuxVzPackageSelectedSyscallV1::Mmap
        && event.enter_source_sequence_v1() == enter_sequence
        && event.exit_source_sequence_v1() == exit_sequence
        && event.enter_timestamp_nanoseconds_v1() < event.exit_timestamp_nanoseconds_v1()
        && event.cgroup_id_v1() == context.cgroup_id
        && event.pid_v1() == context.leader_pid
        && event.tgid_v1() == context.leader_pid
        && event.arguments_v1()[0] == 0
        && event.arguments_v1()[1] > 0
        && event.network_target_v1().is_none()
        && event.result_v1() > 0
        && event.enter_cpu_v1() == context.fixture_cpu
        && event.exit_cpu_v1() == context.fixture_cpu
}

#[cfg(target_os = "linux")]
fn matches_correlated_lifecycle_v1(
    observation: &LinuxVzPackageCorrelatedProcessObservationV1,
    kind: LinuxVzPackageKernelEventKindV1,
    sequence: u64,
    context: InertCorrelatedContextV1,
    wait_status: Option<u16>,
) -> bool {
    let LinuxVzPackageCorrelatedProcessObservationV1::Lifecycle(event) = observation else {
        return false;
    };
    event.kind_v1() == kind
        && event.source_sequence_v1() == sequence
        && event.cgroup_id_v1() == context.cgroup_id
        && event.pid_v1() == context.leader_pid
        && event.tgid_v1() == context.leader_pid
        && event.parent_pid_v1() == 0
        && event.subject_pid_v1() == context.leader_pid
        && event.kernel_wait_status_v1() == wait_status
        && event.cpu_v1() == context.fixture_cpu
}

#[cfg(target_os = "linux")]
struct ChildGuardV1 {
    process: libc::pid_t,
    reaped: bool,
}

#[cfg(target_os = "linux")]
impl Drop for ChildGuardV1 {
    fn drop(&mut self) {
        if self.process > 1 && !self.reaped {
            let _ = unsafe { libc::kill(self.process, libc::SIGKILL) };
            let mut status = 0;
            loop {
                let result = unsafe { libc::waitpid(self.process, &mut status, 0) };
                if result == self.process || result < 0 && last_errno_v1() != libc::EINTR {
                    break;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn open_and_measure_fixture_v1(
) -> Result<(OwnedFd, Sha256Digest), LinuxVzPackageSensorBpfInertProbeErrorV1> {
    let descriptor = unsafe {
        libc::open(
            FIXTURE_PATH_V1.as_ptr().cast(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let descriptor = owned_descriptor_v1(descriptor)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?;
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || stat.st_mode & (libc::S_IWGRP | libc::S_IWOTH) != 0
        || stat.st_mode & libc::S_IXUSR == 0
        || stat.st_size <= 0
        || usize::try_from(stat.st_size).map_or(true, |size| size > MAX_FIXTURE_BYTES_V1)
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture);
    }
    let duplicate = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
    let mut file = File::from(
        owned_descriptor_v1(duplicate)
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?,
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_FIXTURE_BYTES_V1 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?;
    if bytes.len()
        != usize::try_from(stat.st_size)
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture);
    }
    Ok((descriptor, Sha256Digest::from_bytes(&bytes)))
}

#[cfg(target_os = "linux")]
fn relocate_descriptor_v1(
    source: RawFd,
    target: RawFd,
) -> Result<(), LinuxVzPackageSensorBpfInertProbeErrorV1> {
    if source == target {
        return Ok(());
    }
    if unsafe { libc::dup3(source, target, libc::O_CLOEXEC) } != target {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn owned_descriptor_v1(
    descriptor: RawFd,
) -> Result<OwnedFd, LinuxVzPackageSensorBpfInertProbeErrorV1> {
    if descriptor < 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup);
    }
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        let _ = unsafe { libc::close(descriptor) };
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn require_stopped_child_v1(
    child: libc::pid_t,
) -> Result<(), LinuxVzPackageSensorBpfInertProbeErrorV1> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(child, &mut status, libc::WUNTRACED) };
        if result == child {
            break;
        }
        if result < 0 && last_errno_v1() == libc::EINTR {
            continue;
        }
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
    }
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn monotonic_nanoseconds_v1() -> Result<u64, LinuxVzPackageSensorBpfInertProbeErrorV1> {
    let mut value: libc::timespec = unsafe { zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState)
}

#[cfg(target_os = "linux")]
fn pin_process_to_cpu_v1(
    process: libc::pid_t,
    cpu: u32,
) -> Result<(), LinuxVzPackageSensorBpfInertProbeErrorV1> {
    let cpu =
        usize::try_from(cpu).map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity)?;
    if process <= 1 || cpu >= libc::CPU_SETSIZE as usize {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity);
    }
    let mut affinity: libc::cpu_set_t = unsafe { zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut affinity);
        libc::CPU_SET(cpu, &mut affinity);
    }
    if unsafe { libc::sched_setaffinity(process, size_of::<libc::cpu_set_t>(), &affinity) } != 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_child_v1(
    child: libc::pid_t,
) -> Result<libc::c_int, LinuxVzPackageSensorBpfInertProbeErrorV1> {
    let deadline = Instant::now() + CHILD_DEADLINE_V1;
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if result == child {
            return Ok(status);
        }
        if result < 0 && last_errno_v1() != libc::EINTR {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
        }
        if Instant::now() >= deadline {
            return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildTimeout);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(target_os = "linux")]
unsafe fn child_exec_v1(
    fixture: RawFd,
    arguments: *const *const libc::c_char,
    environment: *const *const libc::c_char,
) -> ! {
    if unsafe { libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0_u32) } != 0 {
        unsafe { libc::_exit(91) };
    }
    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        unsafe { libc::_exit(92) };
    }
    let core_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_limit) } != 0 {
        unsafe { libc::_exit(93) };
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setgid(PACKAGE_GID_V1) } != 0
        || unsafe { libc::setuid(PACKAGE_UID_V1) } != 0
        // Linux resets dumpability when effective IDs change; close that pre-exec window again.
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        unsafe { libc::_exit(93) };
    }
    let empty_path = b"\0";
    let _ = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fixture,
            empty_path.as_ptr().cast::<libc::c_char>(),
            arguments,
            environment,
            libc::AT_EMPTY_PATH,
        )
    };
    unsafe { libc::_exit(94) }
}

#[cfg(target_os = "linux")]
fn last_errno_v1() -> libc::c_int {
    unsafe { *libc::__errno_location() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_probe_is_platform_closed_on_macos() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            run_linux_vz_package_sensor_bpf_inert_probe_v1(),
            Err(LinuxVzPackageSensorBpfInertProbeErrorV1::UnsupportedPlatform)
        );
    }

    #[test]
    fn inert_probe_errors_have_distinct_stable_reason_codes() {
        let errors = [
            LinuxVzPackageSensorBpfInertProbeErrorV1::UnsupportedPlatform,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Identity,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Cgroup,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Producer,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Collector,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Fork,
            LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity,
            LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState,
            LinuxVzPackageSensorBpfInertProbeErrorV1::ChildTimeout,
            LinuxVzPackageSensorBpfInertProbeErrorV1::ChildFailed,
            LinuxVzPackageSensorBpfInertProbeErrorV1::EventStream,
            LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch,
            LinuxVzPackageSensorBpfInertProbeErrorV1::LossObserved,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Cleanup,
            LinuxVzPackageSensorBpfInertProbeErrorV1::Serialization,
        ];
        let mut reason_codes = std::collections::BTreeSet::new();
        for error in errors {
            assert!(reason_codes.insert(error.reason_code()));
        }
    }
}
