use std::fmt;

#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_bpf::LinuxVzPackageSensorBpfProducerV1;
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_event_stream::{
    LinuxVzPackageKernelEventKindV1, LinuxVzPackageSelectedSyscallV1,
};
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_process_stream::{
    LinuxVzPackageCorrelatedProcessObservationV1, LinuxVzPackageProcessEventCorrelatorV1,
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
const CHILD_DEADLINE_V1: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const EVENT_DEADLINE_V1: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageSensorBpfInertProbeErrorV1 {
    UnsupportedPlatform,
    Identity,
    Fixture,
    Cgroup,
    Producer,
    Fork,
    CpuAffinity,
    ChildState,
    ChildTimeout,
    ChildFailed,
    EventStream,
    EventMismatch,
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
            Self::Fork => "linux_vz_package_sensor_bpf_probe_fork_failed",
            Self::CpuAffinity => "linux_vz_package_sensor_bpf_probe_cpu_affinity_failed",
            Self::ChildState => "linux_vz_package_sensor_bpf_probe_child_state_invalid",
            Self::ChildTimeout => "linux_vz_package_sensor_bpf_probe_child_timeout",
            Self::ChildFailed => "linux_vz_package_sensor_bpf_probe_child_failed",
            Self::EventStream => "linux_vz_package_sensor_bpf_probe_event_stream_failed",
            Self::EventMismatch => "linux_vz_package_sensor_bpf_probe_event_mismatch",
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
    attachment_cpu: String,
    attachment_scope: &'static str,
    cgroup_id: String,
    discarded_record_count: String,
    dropped_event_count: String,
    event_count: String,
    event_kinds: Vec<&'static str>,
    event_sequence_end: String,
    event_sequence_start: String,
    exit_attachment: &'static str,
    exit_status_source: &'static str,
    fixture_cpu: String,
    fixture_exit_status: String,
    fixture_pid: String,
    fixture_sha256: String,
    kernel_exit_wait_status: String,
    malware_execution: bool,
    observed_event_cpus: Vec<String>,
    online_cpus: Vec<String>,
    package_execution: bool,
    package_gid: String,
    package_uid: String,
    runtime_btf_sha256: String,
    schema_version: &'static str,
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
        let name = CString::new(format!("whoathere-package-sensor-inert-{process}"))
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
    let mut producer = LinuxVzPackageSensorBpfProducerV1::start_v1(cgroup.id, RING_BUFFER_BYTES_V1)
        .map_err(|error| {
            eprintln!("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_PRODUCER_DETAIL {error} {error:?}");
            LinuxVzPackageSensorBpfInertProbeErrorV1::Producer
        })?;
    let fixture_path = CString::new("process-fixture-child")
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Fixture)?;
    let fixture_case = CString::new("normal_exit")
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
    let fixture_cpu = *producer
        .online_cpus_v1()
        .last()
        .ok_or(LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity)?;
    if fixture_cpu == producer.attachment_cpu_v1() {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::CpuAffinity);
    }
    pin_process_to_cpu_v1(child, fixture_cpu)?;
    if unsafe { libc::kill(child, libc::SIGCONT) } != 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState);
    }
    let status = wait_for_child_v1(child)?;
    child_guard.reaped = true;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
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
    let kernel_wait_status =
        u16::try_from(status).map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::ChildState)?;

    let deadline = Instant::now() + EVENT_DEADLINE_V1;
    let mut events = Vec::new();
    loop {
        let available = producer
            .drain_available_v1(64)
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::EventStream)?;
        events.extend(available);
        if events.len() >= 14 || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    events.extend(
        producer
            .drain_available_v1(64)
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::EventStream)?,
    );
    if events.len() != 14
        || events.iter().any(|event| {
            event.pid() != child as u32
                || event.tgid() != child as u32
                || event.parent_pid() != 0
                || event.subject_pid() != child as u32
                || event.cgroup_id() != cgroup.id
                || event.cpu() != fixture_cpu
        })
        || events
            .windows(2)
            .any(|pair| pair[0].timestamp_nanoseconds() >= pair[1].timestamp_nanoseconds())
        || events.iter().enumerate().any(|(index, event)| {
            event.source_sequence() != u64::try_from(index + 1).unwrap_or(u64::MAX)
        })
        || !matches_selected_syscall_pair_v1(
            &events[0..2],
            LinuxVzPackageSelectedSyscallV1::Setgroups,
            0,
        )
        || !matches_selected_syscall_pair_v1(
            &events[2..4],
            LinuxVzPackageSelectedSyscallV1::Setgid,
            u64::from(PACKAGE_GID_V1),
        )
        || !matches_selected_syscall_pair_v1(
            &events[4..6],
            LinuxVzPackageSelectedSyscallV1::Setuid,
            u64::from(PACKAGE_UID_V1),
        )
        || events[6].kind() != LinuxVzPackageKernelEventKindV1::Exec
        || !matches_mmap_syscall_pair_v1(&events[7..9])
        || !matches_mmap_syscall_pair_v1(&events[9..11])
        || !matches_mmap_syscall_pair_v1(&events[11..13])
        || events[13].kind() != LinuxVzPackageKernelEventKindV1::Exit
        || events[13].kernel_wait_status_v1() != Some(kernel_wait_status)
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch);
    }
    let dropped = producer
        .dropped_event_count_v1()
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::EventStream)?;
    let discarded = producer.discarded_record_count_v1();
    if dropped != 0 || discarded != 0 {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::LossObserved);
    }
    let mut correlator = LinuxVzPackageProcessEventCorrelatorV1::new_v1(cgroup.id, 64)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch)?;
    for event in events.iter().cloned() {
        correlator
            .ingest_v1(event)
            .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch)?;
    }
    let correlated = correlator
        .finish_v1(dropped, discarded, producer.last_source_sequence_v1())
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch)?;
    let correlated_exit_wait_status = correlated.observations_v1().last().and_then(|observation| {
        let LinuxVzPackageCorrelatedProcessObservationV1::Lifecycle(event) = observation else {
            return None;
        };
        (event.kind_v1() == LinuxVzPackageKernelEventKindV1::Exit)
            .then(|| event.kernel_wait_status_v1())
            .flatten()
    });
    if correlated.expected_cgroup_id_v1() != cgroup.id
        || correlated.source_event_count_v1() != 14
        || correlated.observations_v1().len() != 8
        || correlated_exit_wait_status != Some(kernel_wait_status)
        || !correlated.coverage_complete_v1()
    {
        return Err(LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch);
    }
    let mut tracepoints = BTreeMap::new();
    for layout in producer.layouts_v1() {
        tracepoints.insert(
            match layout.kind_v1() {
                crate::linux_vz_package_sensor_tracepoint::LinuxVzPackageTracepointKindV1::SchedProcessFork => "sched_process_fork",
                crate::linux_vz_package_sensor_tracepoint::LinuxVzPackageTracepointKindV1::SchedProcessExec => "sched_process_exec",
                crate::linux_vz_package_sensor_tracepoint::LinuxVzPackageTracepointKindV1::SchedProcessExit => "sched_process_exit",
                crate::linux_vz_package_sensor_tracepoint::LinuxVzPackageTracepointKindV1::RawSyscallsSysEnter => "sys_enter",
                crate::linux_vz_package_sensor_tracepoint::LinuxVzPackageTracepointKindV1::RawSyscallsSysExit => "sys_exit",
            },
            layout.format_sha256_v1().as_str().to_string(),
        );
    }
    let evidence = InertProbeEvidenceWireV1 {
        attachment_cpu: producer.attachment_cpu_v1().to_string(),
        attachment_scope: "tracepoint_wide",
        cgroup_id: cgroup.id.to_string(),
        discarded_record_count: discarded.to_string(),
        dropped_event_count: dropped.to_string(),
        event_count: events.len().to_string(),
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
            "exit",
        ],
        event_sequence_end: producer.last_source_sequence_v1().to_string(),
        event_sequence_start: "1".to_string(),
        exit_attachment: "raw_tracepoint:sched_process_exit",
        exit_status_source: "runtime_btf:task_struct.exit_code",
        fixture_cpu: fixture_cpu.to_string(),
        fixture_exit_status: "0".to_string(),
        fixture_pid: child.to_string(),
        fixture_sha256: fixture_sha256.as_str().to_string(),
        kernel_exit_wait_status: correlated_exit_wait_status
            .ok_or(LinuxVzPackageSensorBpfInertProbeErrorV1::EventMismatch)?
            .to_string(),
        malware_execution: false,
        observed_event_cpus: vec![fixture_cpu.to_string()],
        online_cpus: producer
            .online_cpus_v1()
            .iter()
            .map(u32::to_string)
            .collect(),
        package_execution: false,
        package_gid: PACKAGE_GID_V1.to_string(),
        package_uid: PACKAGE_UID_V1.to_string(),
        runtime_btf_sha256: producer.runtime_btf_sha256_v1().as_str().to_string(),
        schema_version: "whoathere.linux_vz_package_sensor_bpf_inert_probe.v4",
        sync_back: false,
        task_exit_code_byte_offset: producer.task_exit_code_byte_offset_v1().to_string(),
        tracepoint_format_sha256: tracepoints,
        waitpid_wait_status: kernel_wait_status.to_string(),
    };
    drop(producer);
    cgroup.remove_v1()?;
    serde_json::to_string(&evidence)
        .map_err(|_| LinuxVzPackageSensorBpfInertProbeErrorV1::Serialization)
}

#[cfg(target_os = "linux")]
fn matches_selected_syscall_pair_v1(
    events: &[crate::linux_vz_package_sensor_event_stream::LinuxVzPackageKernelEventV1],
    syscall: LinuxVzPackageSelectedSyscallV1,
    first_argument: u64,
) -> bool {
    events.len() == 2
        && events[0].kind() == LinuxVzPackageKernelEventKindV1::SyscallEnter
        && events[1].kind() == LinuxVzPackageKernelEventKindV1::SyscallExit
        && events[0].selected_syscall_v1() == Ok(syscall)
        && events[1].selected_syscall_v1() == Ok(syscall)
        && events[0].arguments()[0] == first_argument
        && events[0].arguments()[1..]
            .iter()
            .all(|argument| *argument == 0)
        && events[0].result().is_none()
        && events[1].result() == Some(0)
        && events[1].arguments().iter().all(|argument| *argument == 0)
}

#[cfg(target_os = "linux")]
fn matches_mmap_syscall_pair_v1(
    events: &[crate::linux_vz_package_sensor_event_stream::LinuxVzPackageKernelEventV1],
) -> bool {
    events.len() == 2
        && events[0].kind() == LinuxVzPackageKernelEventKindV1::SyscallEnter
        && events[1].kind() == LinuxVzPackageKernelEventKindV1::SyscallExit
        && events[0].selected_syscall_v1() == Ok(LinuxVzPackageSelectedSyscallV1::Mmap)
        && events[1].selected_syscall_v1() == Ok(LinuxVzPackageSelectedSyscallV1::Mmap)
        && events[0].arguments()[0] == 0
        && events[0].arguments()[1] > 0
        && events[0].result().is_none()
        && events[1].result().is_some_and(|result| result > 0)
        && events[1].arguments().iter().all(|argument| *argument == 0)
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
