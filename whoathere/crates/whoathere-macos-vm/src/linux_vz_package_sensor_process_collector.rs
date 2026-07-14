#![allow(dead_code)]

#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_bpf::LinuxVzPackageSensorBpfProducerV1;
use crate::linux_vz_package_sensor_event_stream::LinuxVzPackageKernelEventKindV1;
#[cfg(any(target_os = "linux", test))]
use crate::linux_vz_package_sensor_process_stream::LinuxVzPackageProcessEventCorrelatorV1;
use crate::linux_vz_package_sensor_process_stream::{
    LinuxVzPackageCorrelatedProcessObservationV1, LinuxVzPackageCorrelatedProcessStreamV1,
};
use crate::LinuxVzPackageProcessCompletionV1;
use std::collections::BTreeMap;
use std::fmt;
use whoathere_artifact::Sha256Digest;

const MIN_ROOT_PROCESS_RING_BUFFER_BYTES_V1: usize = 64 * 1024;
const MAX_ROOT_PROCESS_RING_BUFFER_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_ROOT_PROCESS_SOURCE_EVENTS_V1: usize = 65_536;
const DRAIN_BATCH_RECORDS_V1: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageRootProcessCollectorErrorV1 {
    UnsupportedPlatform,
    InvalidConfiguration,
    InvalidState,
    Producer,
    ProcessStream,
    PreReleaseEvent,
    LeaderLifecycle,
    TerminalMismatch,
}

impl LinuxVzPackageRootProcessCollectorErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => {
                "linux_vz_package_root_process_collector_platform_unsupported"
            }
            Self::InvalidConfiguration => {
                "linux_vz_package_root_process_collector_configuration_invalid"
            }
            Self::InvalidState => "linux_vz_package_root_process_collector_state_invalid",
            Self::Producer => "linux_vz_package_root_process_collector_producer_failed",
            Self::ProcessStream => "linux_vz_package_root_process_collector_stream_invalid",
            Self::PreReleaseEvent => {
                "linux_vz_package_root_process_collector_prerelease_event_rejected"
            }
            Self::LeaderLifecycle => {
                "linux_vz_package_root_process_collector_leader_lifecycle_invalid"
            }
            Self::TerminalMismatch => "linux_vz_package_root_process_collector_terminal_mismatch",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootProcessCollectorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootProcessCollectorErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxVzPackageLeaderTerminalObservationV1 {
    exec_count: u64,
    first_exec_monotonic_nanoseconds: u64,
    exit_monotonic_nanoseconds: u64,
    kernel_wait_status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageRootProcessCollectionV1 {
    stream: LinuxVzPackageCorrelatedProcessStreamV1,
    leader_pid: u32,
    leader_exec_count: u64,
    leader_first_exec_monotonic_nanoseconds: u64,
    leader_exit_monotonic_nanoseconds: u64,
    leader_kernel_wait_status: u16,
    leader_supervisor_wait_status: u16,
    runtime_btf_sha256: Sha256Digest,
    task_exit_code_byte_offset: u32,
    tracepoint_format_sha256: BTreeMap<&'static str, Sha256Digest>,
    online_cpus: Vec<u32>,
    attachment_cpu: u32,
}

impl LinuxVzPackageRootProcessCollectionV1 {
    pub(crate) fn stream_v1(&self) -> &LinuxVzPackageCorrelatedProcessStreamV1 {
        &self.stream
    }

    pub(crate) const fn leader_pid_v1(&self) -> u32 {
        self.leader_pid
    }

    pub(crate) const fn leader_exec_count_v1(&self) -> u64 {
        self.leader_exec_count
    }

    pub(crate) const fn leader_first_exec_monotonic_nanoseconds_v1(&self) -> u64 {
        self.leader_first_exec_monotonic_nanoseconds
    }

    pub(crate) const fn leader_exit_monotonic_nanoseconds_v1(&self) -> u64 {
        self.leader_exit_monotonic_nanoseconds
    }

    pub(crate) const fn leader_kernel_wait_status_v1(&self) -> u16 {
        self.leader_kernel_wait_status
    }

    pub(crate) const fn leader_supervisor_wait_status_v1(&self) -> u16 {
        self.leader_supervisor_wait_status
    }

    pub(crate) fn runtime_btf_sha256_v1(&self) -> &Sha256Digest {
        &self.runtime_btf_sha256
    }

    pub(crate) const fn task_exit_code_byte_offset_v1(&self) -> u32 {
        self.task_exit_code_byte_offset
    }

    pub(crate) fn tracepoint_format_sha256_v1(&self) -> &BTreeMap<&'static str, Sha256Digest> {
        &self.tracepoint_format_sha256
    }

    pub(crate) fn online_cpus_v1(&self) -> &[u32] {
        &self.online_cpus
    }

    pub(crate) const fn attachment_cpu_v1(&self) -> u32 {
        self.attachment_cpu
    }

    pub(crate) const fn dropped_event_count_v1(&self) -> u64 {
        0
    }

    pub(crate) const fn discarded_record_count_v1(&self) -> u64 {
        0
    }

    pub(crate) const fn coverage_complete_v1(&self) -> bool {
        true
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxVzPackageRootProcessCollectorStateV1 {
    Armed,
    LeaderAttached,
    Finished,
    Aborted,
    Faulted,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxVzPackageRootProcessCollectorV1 {
    state: LinuxVzPackageRootProcessCollectorStateV1,
    expected_cgroup_id: u64,
    leader_pid: Option<u32>,
    producer: Option<LinuxVzPackageSensorBpfProducerV1>,
    correlator: Option<LinuxVzPackageProcessEventCorrelatorV1>,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for LinuxVzPackageRootProcessCollectorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootProcessCollectorV1")
            .field("state", &self.state)
            .field("expected_cgroup_id", &self.expected_cgroup_id)
            .field("leader_pid", &self.leader_pid)
            .field("producer_present", &self.producer.is_some())
            .field("correlator_present", &self.correlator.is_some())
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootProcessCollectorV1 {
    pub(crate) fn arm_v1(
        expected_cgroup_id: u64,
        ring_buffer_capacity: usize,
        maximum_source_events: usize,
    ) -> Result<Self, LinuxVzPackageRootProcessCollectorErrorV1> {
        if expected_cgroup_id == 0
            || !(MIN_ROOT_PROCESS_RING_BUFFER_BYTES_V1..=MAX_ROOT_PROCESS_RING_BUFFER_BYTES_V1)
                .contains(&ring_buffer_capacity)
            || !ring_buffer_capacity.is_power_of_two()
            || maximum_source_events == 0
            || maximum_source_events > MAX_ROOT_PROCESS_SOURCE_EVENTS_V1
        {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidConfiguration);
        }
        let producer =
            LinuxVzPackageSensorBpfProducerV1::start_v1(expected_cgroup_id, ring_buffer_capacity)
                .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        let correlator = LinuxVzPackageProcessEventCorrelatorV1::new_v1(
            expected_cgroup_id,
            maximum_source_events,
        )
        .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream)?;
        Ok(Self {
            state: LinuxVzPackageRootProcessCollectorStateV1::Armed,
            expected_cgroup_id,
            leader_pid: None,
            producer: Some(producer),
            correlator: Some(correlator),
        })
    }

    pub(crate) fn leader_attached_before_release_v1(
        &mut self,
        leader_pid: u32,
    ) -> Result<(), LinuxVzPackageRootProcessCollectorErrorV1> {
        if self.state != LinuxVzPackageRootProcessCollectorStateV1::Armed
            || self.leader_pid.is_some()
            || leader_pid <= 1
        {
            return self.fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        if let Err(error) = self.require_prerelease_quiet_v1() {
            return self.fault_v1(error);
        }
        self.leader_pid = Some(leader_pid);
        self.state = LinuxVzPackageRootProcessCollectorStateV1::LeaderAttached;
        Ok(())
    }

    pub(crate) fn online_cpus_v1(
        &self,
    ) -> Result<&[u32], LinuxVzPackageRootProcessCollectorErrorV1> {
        if self.state != LinuxVzPackageRootProcessCollectorStateV1::Armed {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        self.producer
            .as_ref()
            .map(LinuxVzPackageSensorBpfProducerV1::online_cpus_v1)
            .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState)
    }

    pub(crate) fn attachment_cpu_v1(
        &self,
    ) -> Result<u32, LinuxVzPackageRootProcessCollectorErrorV1> {
        if self.state != LinuxVzPackageRootProcessCollectorStateV1::Armed {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        self.producer
            .as_ref()
            .map(LinuxVzPackageSensorBpfProducerV1::attachment_cpu_v1)
            .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState)
    }

    fn require_prerelease_quiet_v1(
        &mut self,
    ) -> Result<(), LinuxVzPackageRootProcessCollectorErrorV1> {
        let producer = self
            .producer
            .as_mut()
            .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState)?;
        let events = producer
            .drain_available_v1(DRAIN_BATCH_RECORDS_V1)
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        let dropped = producer
            .dropped_event_count_v1()
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        if !events.is_empty()
            || dropped != 0
            || producer.discarded_record_count_v1() != 0
            || producer.last_source_sequence_v1() != 0
        {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::PreReleaseEvent);
        }
        Ok(())
    }

    /// Finalizes only after the protected caller has proved the cgroup empty and reaped the leader.
    pub(crate) fn finish_after_empty_cgroup_v1(
        &mut self,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<LinuxVzPackageRootProcessCollectionV1, LinuxVzPackageRootProcessCollectorErrorV1>
    {
        if self.state != LinuxVzPackageRootProcessCollectorStateV1::LeaderAttached
            || self.leader_pid != Some(leader_pid)
        {
            return self.fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        let result = self.finish_inner_v1(leader_pid, completion);
        self.producer.take();
        self.correlator.take();
        self.state = if result.is_ok() {
            LinuxVzPackageRootProcessCollectorStateV1::Finished
        } else {
            LinuxVzPackageRootProcessCollectorStateV1::Faulted
        };
        result
    }

    fn finish_inner_v1(
        &mut self,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<LinuxVzPackageRootProcessCollectionV1, LinuxVzPackageRootProcessCollectorErrorV1>
    {
        let producer = self
            .producer
            .as_mut()
            .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState)?;
        let correlator = self
            .correlator
            .as_mut()
            .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState)?;
        loop {
            let events = producer
                .drain_available_v1(DRAIN_BATCH_RECORDS_V1)
                .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
            if events.is_empty() {
                break;
            }
            for event in events {
                correlator
                    .ingest_v1(event)
                    .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream)?;
            }
        }
        let dropped_event_count = producer
            .dropped_event_count_v1()
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        let discarded_record_count = producer.discarded_record_count_v1();
        let producer_last_source_sequence = producer.last_source_sequence_v1();
        let runtime_btf_sha256 = producer.runtime_btf_sha256_v1().clone();
        let task_exit_code_byte_offset = producer.task_exit_code_byte_offset_v1();
        let tracepoint_format_sha256: BTreeMap<&'static str, Sha256Digest> = producer
            .layouts_v1()
            .iter()
            .map(|layout| {
                (
                    layout.kind_v1().name_v1(),
                    layout.format_sha256_v1().clone(),
                )
            })
            .collect();
        if tracepoint_format_sha256.len() != 5 {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::Producer);
        }
        let online_cpus = producer.online_cpus_v1().to_vec();
        let attachment_cpu = producer.attachment_cpu_v1();
        let correlator = self
            .correlator
            .take()
            .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState)?;
        let stream = correlator
            .finish_v1(
                dropped_event_count,
                discarded_record_count,
                producer_last_source_sequence,
            )
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream)?;
        let terminal = validate_leader_terminal_v1(&stream, leader_pid, completion)?;
        Ok(LinuxVzPackageRootProcessCollectionV1 {
            stream,
            leader_pid,
            leader_exec_count: terminal.exec_count,
            leader_first_exec_monotonic_nanoseconds: terminal.first_exec_monotonic_nanoseconds,
            leader_exit_monotonic_nanoseconds: terminal.exit_monotonic_nanoseconds,
            leader_kernel_wait_status: terminal.kernel_wait_status,
            leader_supervisor_wait_status: completion.supervisor_wait_status(),
            runtime_btf_sha256,
            task_exit_code_byte_offset,
            tracepoint_format_sha256,
            online_cpus,
            attachment_cpu,
        })
    }

    pub(crate) fn abort_v1(&mut self) {
        self.producer.take();
        self.correlator.take();
        self.leader_pid = None;
        if self.state != LinuxVzPackageRootProcessCollectorStateV1::Finished {
            self.state = LinuxVzPackageRootProcessCollectorStateV1::Aborted;
        }
    }

    fn fault_v1<T>(
        &mut self,
        error: LinuxVzPackageRootProcessCollectorErrorV1,
    ) -> Result<T, LinuxVzPackageRootProcessCollectorErrorV1> {
        self.producer.take();
        self.correlator.take();
        self.state = LinuxVzPackageRootProcessCollectorStateV1::Faulted;
        Err(error)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageRootProcessCollectorV1 {
    fn drop(&mut self) {
        self.abort_v1();
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) struct LinuxVzPackageRootProcessCollectorV1;

#[cfg(not(target_os = "linux"))]
impl LinuxVzPackageRootProcessCollectorV1 {
    pub(crate) fn arm_v1(
        _expected_cgroup_id: u64,
        _ring_buffer_capacity: usize,
        _maximum_source_events: usize,
    ) -> Result<Self, LinuxVzPackageRootProcessCollectorErrorV1> {
        Err(LinuxVzPackageRootProcessCollectorErrorV1::UnsupportedPlatform)
    }
}

fn validate_leader_terminal_v1(
    stream: &LinuxVzPackageCorrelatedProcessStreamV1,
    leader_pid: u32,
    completion: &LinuxVzPackageProcessCompletionV1,
) -> Result<LinuxVzPackageLeaderTerminalObservationV1, LinuxVzPackageRootProcessCollectorErrorV1> {
    if leader_pid <= 1 || stream.expected_cgroup_id_v1() == 0 || !stream.coverage_complete_v1() {
        return Err(LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle);
    }
    let mut exec_count = 0_u64;
    let mut first_exec_monotonic_nanoseconds = None;
    let mut leader_exit = None;
    for observation in stream.observations_v1() {
        let LinuxVzPackageCorrelatedProcessObservationV1::Lifecycle(event) = observation else {
            continue;
        };
        if event.cgroup_id_v1() != stream.expected_cgroup_id_v1() {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle);
        }
        let exact_leader = event.pid_v1() == leader_pid
            && event.tgid_v1() == leader_pid
            && event.subject_pid_v1() == leader_pid;
        match event.kind_v1() {
            LinuxVzPackageKernelEventKindV1::Exec if exact_leader => {
                exec_count = exec_count
                    .checked_add(1)
                    .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle)?;
                first_exec_monotonic_nanoseconds.get_or_insert(event.timestamp_nanoseconds_v1());
            }
            LinuxVzPackageKernelEventKindV1::Exit if exact_leader => {
                let wait_status = event
                    .kernel_wait_status_v1()
                    .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::TerminalMismatch)?;
                if leader_exit
                    .replace((event.timestamp_nanoseconds_v1(), wait_status))
                    .is_some()
                {
                    return Err(LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle);
                }
            }
            _ => {}
        }
    }
    let first_exec_monotonic_nanoseconds = first_exec_monotonic_nanoseconds
        .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle)?;
    let (exit_monotonic_nanoseconds, kernel_wait_status) =
        leader_exit.ok_or(LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle)?;
    if first_exec_monotonic_nanoseconds < completion.process_started_monotonic_nanoseconds()
        || first_exec_monotonic_nanoseconds >= exit_monotonic_nanoseconds
        || exit_monotonic_nanoseconds > completion.process_ended_monotonic_nanoseconds()
        || kernel_wait_status != completion.supervisor_wait_status()
    {
        return Err(LinuxVzPackageRootProcessCollectorErrorV1::TerminalMismatch);
    }
    Ok(LinuxVzPackageLeaderTerminalObservationV1 {
        exec_count,
        first_exec_monotonic_nanoseconds,
        exit_monotonic_nanoseconds,
        kernel_wait_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_vz_package_sensor_event_stream::{
        decode_linux_vz_package_kernel_event_v1, LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1,
    };
    use crate::LinuxVzPackageProcessTerminalV1;

    const CGROUP_ID_V1: u64 = 71;
    const LEADER_PID_V1: u32 = 401;

    fn lifecycle_event_v1(
        kind: LinuxVzPackageKernelEventKindV1,
        sequence: u64,
        timestamp: u64,
        wait_status: Option<u16>,
    ) -> crate::linux_vz_package_sensor_event_stream::LinuxVzPackageKernelEventV1 {
        let mut bytes = [0_u8; LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1];
        bytes[0..4].copy_from_slice(b"WTKE");
        bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&(kind as u16).to_le_bytes());
        if wait_status.is_some() {
            bytes[8..12].copy_from_slice(&(1_u32 << 1).to_le_bytes());
        }
        bytes[12..16].copy_from_slice(
            &u32::try_from(LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1)
                .expect("event bytes")
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&CGROUP_ID_V1.to_le_bytes());
        bytes[24..32].copy_from_slice(&timestamp.to_le_bytes());
        bytes[32..36].copy_from_slice(&LEADER_PID_V1.to_le_bytes());
        bytes[36..40].copy_from_slice(&LEADER_PID_V1.to_le_bytes());
        bytes[44..48].copy_from_slice(&LEADER_PID_V1.to_le_bytes());
        bytes[56..64].copy_from_slice(&i64::from(wait_status.unwrap_or_default()).to_le_bytes());
        bytes[184..188].copy_from_slice(&1_u32.to_le_bytes());
        decode_linux_vz_package_kernel_event_v1(&bytes, CGROUP_ID_V1, sequence)
            .expect("lifecycle event")
    }

    fn stream_v1(wait_status: u16) -> LinuxVzPackageCorrelatedProcessStreamV1 {
        let mut correlator =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        correlator
            .ingest_v1(lifecycle_event_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                1,
                100,
                None,
            ))
            .expect("exec");
        correlator
            .ingest_v1(lifecycle_event_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                2,
                200,
                Some(wait_status),
            ))
            .expect("exit");
        correlator.finish_v1(0, 0, 2).expect("stream")
    }

    fn completion_v1(
        wait_status: u16,
        terminal: LinuxVzPackageProcessTerminalV1,
        exit_status: Option<u8>,
        termination_signal: Option<u8>,
    ) -> LinuxVzPackageProcessCompletionV1 {
        LinuxVzPackageProcessCompletionV1::from_parts_v1(
            50,
            250,
            wait_status,
            terminal,
            exit_status,
            termination_signal,
        )
        .expect("completion")
    }

    #[test]
    fn exact_leader_exec_and_exit_reconcile_kernel_and_supervisor_status() {
        let stream = stream_v1(0);
        let completion = completion_v1(0, LinuxVzPackageProcessTerminalV1::Exited, Some(0), None);
        let observation =
            validate_leader_terminal_v1(&stream, LEADER_PID_V1, &completion).expect("terminal");
        assert_eq!(observation.exec_count, 1);
        assert_eq!(observation.first_exec_monotonic_nanoseconds, 100);
        assert_eq!(observation.exit_monotonic_nanoseconds, 200);
        assert_eq!(observation.kernel_wait_status, 0);
    }

    #[test]
    fn core_dump_bit_is_preserved_in_exact_terminal_reconciliation() {
        let raw_wait_status = 0x80 | libc::SIGSEGV as u16;
        let stream = stream_v1(raw_wait_status);
        let completion = completion_v1(
            raw_wait_status,
            LinuxVzPackageProcessTerminalV1::Signaled,
            None,
            Some(libc::SIGSEGV as u8),
        );
        assert_eq!(
            validate_leader_terminal_v1(&stream, LEADER_PID_V1, &completion)
                .expect("core-dump terminal")
                .kernel_wait_status,
            raw_wait_status
        );
    }

    #[test]
    fn missing_lifecycle_and_terminal_rebinding_fail_closed() {
        let stream = stream_v1(0);
        let rebound = completion_v1(
            7 << 8,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(7),
            None,
        );
        assert_eq!(
            validate_leader_terminal_v1(&stream, LEADER_PID_V1, &rebound),
            Err(LinuxVzPackageRootProcessCollectorErrorV1::TerminalMismatch)
        );
        assert_eq!(
            validate_leader_terminal_v1(&stream, LEADER_PID_V1 + 1, &rebound),
            Err(LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle)
        );
    }

    #[test]
    fn collector_is_platform_closed_and_errors_are_stable() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            LinuxVzPackageRootProcessCollectorV1::arm_v1(CGROUP_ID_V1, 64 * 1024, 8)
                .expect_err("macOS is closed"),
            LinuxVzPackageRootProcessCollectorErrorV1::UnsupportedPlatform
        );
        let errors = [
            LinuxVzPackageRootProcessCollectorErrorV1::UnsupportedPlatform,
            LinuxVzPackageRootProcessCollectorErrorV1::InvalidConfiguration,
            LinuxVzPackageRootProcessCollectorErrorV1::InvalidState,
            LinuxVzPackageRootProcessCollectorErrorV1::Producer,
            LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream,
            LinuxVzPackageRootProcessCollectorErrorV1::PreReleaseEvent,
            LinuxVzPackageRootProcessCollectorErrorV1::LeaderLifecycle,
            LinuxVzPackageRootProcessCollectorErrorV1::TerminalMismatch,
        ];
        let mut codes = std::collections::BTreeSet::new();
        for error in errors {
            assert!(codes.insert(error.reason_code()));
            assert_eq!(error.to_string(), error.reason_code());
        }
    }
}
