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
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
#[cfg(target_os = "linux")]
use std::thread::JoinHandle;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};
use whoathere_artifact::Sha256Digest;

const MIN_ROOT_PROCESS_RING_BUFFER_BYTES_V1: usize = 64 * 1024;
const MAX_ROOT_PROCESS_RING_BUFFER_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_ROOT_PROCESS_SOURCE_EVENTS_V1: usize = 65_536;
const DRAIN_BATCH_RECORDS_V1: usize = 4_096;
#[cfg(target_os = "linux")]
const CONTINUOUS_DRAIN_POLL_INTERVAL_V1: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageRootProcessCollectorErrorV1 {
    UnsupportedPlatform,
    InvalidConfiguration,
    InvalidState,
    Worker,
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
            Self::Worker => "linux_vz_package_root_process_collector_worker_failed",
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
    active_drain_poll_count: u64,
    active_nonempty_drain_count: u64,
    source_event_count_before_finish: u64,
    finish_drain_event_count: u64,
    maximum_drain_batch_record_count: u64,
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

    pub(crate) const fn active_drain_poll_count_v1(&self) -> u64 {
        self.active_drain_poll_count
    }

    pub(crate) const fn active_nonempty_drain_count_v1(&self) -> u64 {
        self.active_nonempty_drain_count
    }

    pub(crate) const fn source_event_count_before_finish_v1(&self) -> u64 {
        self.source_event_count_before_finish
    }

    pub(crate) const fn finish_drain_event_count_v1(&self) -> u64 {
        self.finish_drain_event_count
    }

    pub(crate) const fn maximum_drain_batch_record_count_v1(&self) -> u64 {
        self.maximum_drain_batch_record_count
    }

    pub(crate) const fn continuous_drain_v1(&self) -> bool {
        true
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

    #[cfg(test)]
    pub(crate) fn from_test_stream_v1(
        stream: LinuxVzPackageCorrelatedProcessStreamV1,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<Self, LinuxVzPackageRootProcessCollectorErrorV1> {
        let terminal = validate_leader_terminal_v1(&stream, leader_pid, completion)?;
        let tracepoint_format_sha256 = [
            "sched_process_exec",
            "sched_process_exit",
            "sched_process_fork",
            "sys_enter",
            "sys_exit",
        ]
        .into_iter()
        .map(|name| (name, Sha256Digest::from_bytes(name.as_bytes())))
        .collect();
        let source_event_count = stream.source_event_count_v1();
        Ok(Self {
            stream,
            leader_pid,
            leader_exec_count: terminal.exec_count,
            leader_first_exec_monotonic_nanoseconds: terminal.first_exec_monotonic_nanoseconds,
            leader_exit_monotonic_nanoseconds: terminal.exit_monotonic_nanoseconds,
            leader_kernel_wait_status: terminal.kernel_wait_status,
            leader_supervisor_wait_status: completion.supervisor_wait_status(),
            runtime_btf_sha256: Sha256Digest::from_bytes(b"test runtime btf"),
            task_exit_code_byte_offset: 96,
            tracepoint_format_sha256,
            online_cpus: vec![0, 1],
            attachment_cpu: 1,
            active_drain_poll_count: 1,
            active_nonempty_drain_count: 1,
            source_event_count_before_finish: source_event_count,
            finish_drain_event_count: 0,
            maximum_drain_batch_record_count: source_event_count,
        })
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
#[derive(Debug)]
struct LinuxVzPackageRootProcessWorkerReadyV1 {
    online_cpus: Vec<u32>,
    attachment_cpu: u32,
}

#[cfg(target_os = "linux")]
enum LinuxVzPackageRootProcessWorkerCommandV1 {
    LeaderAttached {
        leader_pid: u32,
        response: SyncSender<Result<(), LinuxVzPackageRootProcessCollectorErrorV1>>,
    },
    Finish {
        leader_pid: u32,
        completion: LinuxVzPackageProcessCompletionV1,
        response: SyncSender<
            Result<
                LinuxVzPackageRootProcessCollectionV1,
                LinuxVzPackageRootProcessCollectorErrorV1,
            >,
        >,
    },
    Abort,
}

#[cfg(target_os = "linux")]
struct LinuxVzPackageRootProcessWorkerV1 {
    producer: LinuxVzPackageSensorBpfProducerV1,
    correlator: LinuxVzPackageProcessEventCorrelatorV1,
    fault_signal_write: OwnedFd,
    leader_pid: Option<u32>,
    fault: Option<LinuxVzPackageRootProcessCollectorErrorV1>,
    ingested_source_event_count: u64,
    active_drain_poll_count: u64,
    active_nonempty_drain_count: u64,
    maximum_drain_batch_record_count: u64,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxVzPackageRootProcessCollectorV1 {
    state: LinuxVzPackageRootProcessCollectorStateV1,
    expected_cgroup_id: u64,
    leader_pid: Option<u32>,
    online_cpus: Vec<u32>,
    attachment_cpu: u32,
    fault_signal_read: OwnedFd,
    command_sender: Option<SyncSender<LinuxVzPackageRootProcessWorkerCommandV1>>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for LinuxVzPackageRootProcessCollectorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootProcessCollectorV1")
            .field("state", &self.state)
            .field("expected_cgroup_id", &self.expected_cgroup_id)
            .field("leader_pid", &self.leader_pid)
            .field("online_cpus", &self.online_cpus)
            .field("attachment_cpu", &self.attachment_cpu)
            .field("worker_present", &self.worker.is_some())
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
        let (command_sender, command_receiver) = mpsc::sync_channel(1);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (fault_signal_read, fault_signal_write) = create_fault_signal_pipe_v1()?;
        let worker = std::thread::Builder::new()
            .name("whoathere-root-process-sensor-v1".to_string())
            .spawn(move || {
                run_linux_vz_package_root_process_worker_v1(
                    expected_cgroup_id,
                    ring_buffer_capacity,
                    maximum_source_events,
                    fault_signal_write,
                    ready_sender,
                    command_receiver,
                );
            })
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Worker)?;
        let ready = match ready_receiver.recv() {
            Ok(Ok(ready)) => ready,
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(error);
            }
            Err(_) => {
                let _ = worker.join();
                return Err(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
            }
        };
        Ok(Self {
            state: LinuxVzPackageRootProcessCollectorStateV1::Armed,
            expected_cgroup_id,
            leader_pid: None,
            online_cpus: ready.online_cpus,
            attachment_cpu: ready.attachment_cpu,
            fault_signal_read,
            command_sender: Some(command_sender),
            worker: Some(worker),
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
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        let sender = match self.command_sender.as_ref() {
            Some(sender) => sender.clone(),
            None => return self.fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState),
        };
        if sender
            .send(LinuxVzPackageRootProcessWorkerCommandV1::LeaderAttached {
                leader_pid,
                response: response_sender,
            })
            .is_err()
        {
            return self.fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
        }
        match response_receiver.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return self.fault_v1(error),
            Err(_) => {
                return self.fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
            }
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
        Ok(&self.online_cpus)
    }

    pub(crate) fn attachment_cpu_v1(
        &self,
    ) -> Result<u32, LinuxVzPackageRootProcessCollectorErrorV1> {
        if self.state != LinuxVzPackageRootProcessCollectorStateV1::Armed {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        Ok(self.attachment_cpu)
    }

    pub(crate) fn fault_signal_fd_v1(
        &self,
    ) -> Result<RawFd, LinuxVzPackageRootProcessCollectorErrorV1> {
        if !matches!(
            self.state,
            LinuxVzPackageRootProcessCollectorStateV1::Armed
                | LinuxVzPackageRootProcessCollectorStateV1::LeaderAttached
        ) {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        Ok(self.fault_signal_read.as_raw_fd())
    }

    pub(crate) fn require_healthy_v1(
        &self,
    ) -> Result<(), LinuxVzPackageRootProcessCollectorErrorV1> {
        let descriptor = self.fault_signal_fd_v1()?;
        let mut poll_descriptor = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut poll_descriptor, 1, 0) };
            if result == 0 {
                return Ok(());
            }
            if result > 0 {
                return Err(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
            }
        }
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
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        let sender = match self.command_sender.as_ref() {
            Some(sender) => sender.clone(),
            None => return self.fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState),
        };
        if sender
            .send(LinuxVzPackageRootProcessWorkerCommandV1::Finish {
                leader_pid,
                completion: *completion,
                response: response_sender,
            })
            .is_err()
        {
            return self.fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
        }
        let result = response_receiver
            .recv()
            .unwrap_or(Err(LinuxVzPackageRootProcessCollectorErrorV1::Worker));
        self.command_sender.take();
        let joined = match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Worker),
            None => Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState),
        };
        let result = match (result, joined) {
            (Ok(collection), Ok(())) => Ok(collection),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        };
        self.state = if result.is_ok() {
            LinuxVzPackageRootProcessCollectorStateV1::Finished
        } else {
            LinuxVzPackageRootProcessCollectorStateV1::Faulted
        };
        result
    }

    pub(crate) fn abort_v1(&mut self) {
        self.shutdown_worker_v1();
        self.leader_pid = None;
        if self.state != LinuxVzPackageRootProcessCollectorStateV1::Finished {
            self.state = LinuxVzPackageRootProcessCollectorStateV1::Aborted;
        }
    }

    fn fault_v1<T>(
        &mut self,
        error: LinuxVzPackageRootProcessCollectorErrorV1,
    ) -> Result<T, LinuxVzPackageRootProcessCollectorErrorV1> {
        self.shutdown_worker_v1();
        self.state = LinuxVzPackageRootProcessCollectorStateV1::Faulted;
        Err(error)
    }

    fn shutdown_worker_v1(&mut self) {
        if let Some(sender) = self.command_sender.take() {
            let _ = sender.send(LinuxVzPackageRootProcessWorkerCommandV1::Abort);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn run_linux_vz_package_root_process_worker_v1(
    expected_cgroup_id: u64,
    ring_buffer_capacity: usize,
    maximum_source_events: usize,
    fault_signal_write: OwnedFd,
    ready_sender: SyncSender<
        Result<LinuxVzPackageRootProcessWorkerReadyV1, LinuxVzPackageRootProcessCollectorErrorV1>,
    >,
    command_receiver: Receiver<LinuxVzPackageRootProcessWorkerCommandV1>,
) {
    let producer =
        match LinuxVzPackageSensorBpfProducerV1::start_v1(expected_cgroup_id, ring_buffer_capacity)
        {
            Ok(producer) => producer,
            Err(_) => {
                let _ = ready_sender.send(Err(LinuxVzPackageRootProcessCollectorErrorV1::Producer));
                return;
            }
        };
    let correlator = match LinuxVzPackageProcessEventCorrelatorV1::new_v1(
        expected_cgroup_id,
        maximum_source_events,
    ) {
        Ok(correlator) => correlator,
        Err(_) => {
            let _ = ready_sender.send(Err(
                LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream,
            ));
            return;
        }
    };
    let ready = LinuxVzPackageRootProcessWorkerReadyV1 {
        online_cpus: producer.online_cpus_v1().to_vec(),
        attachment_cpu: producer.attachment_cpu_v1(),
    };
    if ready_sender.send(Ok(ready)).is_err() {
        return;
    }
    LinuxVzPackageRootProcessWorkerV1 {
        producer,
        correlator,
        fault_signal_write,
        leader_pid: None,
        fault: None,
        ingested_source_event_count: 0,
        active_drain_poll_count: 0,
        active_nonempty_drain_count: 0,
        maximum_drain_batch_record_count: 0,
    }
    .run_v1(command_receiver);
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootProcessWorkerV1 {
    fn run_v1(mut self, command_receiver: Receiver<LinuxVzPackageRootProcessWorkerCommandV1>) {
        loop {
            match command_receiver.recv_timeout(CONTINUOUS_DRAIN_POLL_INTERVAL_V1) {
                Ok(LinuxVzPackageRootProcessWorkerCommandV1::LeaderAttached {
                    leader_pid,
                    response,
                }) => {
                    let result = self.leader_attached_v1(leader_pid);
                    let _ = response.send(result);
                }
                Ok(LinuxVzPackageRootProcessWorkerCommandV1::Finish {
                    leader_pid,
                    completion,
                    response,
                }) => {
                    let result = self.finish_v1(leader_pid, &completion);
                    let _ = response.send(result);
                    return;
                }
                Ok(LinuxVzPackageRootProcessWorkerCommandV1::Abort)
                | Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => self.poll_v1(),
            }
        }
    }

    fn leader_attached_v1(
        &mut self,
        leader_pid: u32,
    ) -> Result<(), LinuxVzPackageRootProcessCollectorErrorV1> {
        if self.leader_pid.is_some() || leader_pid <= 1 {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        if let Some(error) = self.fault {
            return Err(error);
        }
        self.require_prerelease_quiet_v1()?;
        self.leader_pid = Some(leader_pid);
        Ok(())
    }

    fn poll_v1(&mut self) {
        if self.leader_pid.is_none() {
            if self.fault.is_none() {
                if let Err(error) = self.require_prerelease_quiet_v1() {
                    self.record_fault_v1(error);
                }
            } else {
                self.drain_after_fault_v1();
            }
            return;
        }
        self.active_drain_poll_count = match self.active_drain_poll_count.checked_add(1) {
            Some(value) => value,
            None => {
                self.record_fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
                return;
            }
        };
        if self.fault.is_none() {
            match self.drain_correlated_until_empty_v1() {
                Ok(drained) if drained > 0 => {
                    self.active_nonempty_drain_count = match self
                        .active_nonempty_drain_count
                        .checked_add(1)
                    {
                        Some(value) => value,
                        None => {
                            self.record_fault_v1(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
                            return;
                        }
                    };
                }
                Ok(_) => {}
                Err(error) => self.record_fault_v1(error),
            }
        } else {
            self.drain_after_fault_v1();
        }
    }

    fn require_prerelease_quiet_v1(
        &mut self,
    ) -> Result<(), LinuxVzPackageRootProcessCollectorErrorV1> {
        let events = self
            .producer
            .drain_available_v1(DRAIN_BATCH_RECORDS_V1)
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        let dropped = self
            .producer
            .dropped_event_count_v1()
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        if !events.is_empty()
            || dropped != 0
            || self.producer.discarded_record_count_v1() != 0
            || self.producer.last_source_sequence_v1() != 0
        {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::PreReleaseEvent);
        }
        Ok(())
    }

    fn drain_correlated_until_empty_v1(
        &mut self,
    ) -> Result<u64, LinuxVzPackageRootProcessCollectorErrorV1> {
        let mut drained = 0_u64;
        loop {
            let events = self
                .producer
                .drain_available_v1(DRAIN_BATCH_RECORDS_V1)
                .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
            let batch_count = u64::try_from(events.len())
                .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Worker)?;
            self.maximum_drain_batch_record_count =
                self.maximum_drain_batch_record_count.max(batch_count);
            if events.is_empty() {
                break;
            }
            for event in events {
                self.correlator
                    .ingest_v1(event)
                    .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream)?;
                drained = drained
                    .checked_add(1)
                    .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::Worker)?;
                self.ingested_source_event_count = self
                    .ingested_source_event_count
                    .checked_add(1)
                    .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::Worker)?;
            }
        }
        let dropped = self
            .producer
            .dropped_event_count_v1()
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        if dropped != 0 || self.producer.discarded_record_count_v1() != 0 {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream);
        }
        Ok(drained)
    }

    fn drain_after_fault_v1(&mut self) {
        loop {
            match self.producer.drain_available_v1(DRAIN_BATCH_RECORDS_V1) {
                Ok(events) if events.is_empty() => return,
                Ok(_) => {}
                Err(_) => return,
            }
        }
    }

    fn record_fault_v1(&mut self, error: LinuxVzPackageRootProcessCollectorErrorV1) {
        if self.fault.is_some() {
            return;
        }
        self.fault = Some(error);
        let marker = [1_u8];
        loop {
            let written = unsafe {
                libc::write(
                    self.fault_signal_write.as_raw_fd(),
                    marker.as_ptr().cast(),
                    marker.len(),
                )
            };
            if written == marker.len() as isize {
                break;
            }
            if written < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }

    fn finish_v1(
        mut self,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<LinuxVzPackageRootProcessCollectionV1, LinuxVzPackageRootProcessCollectorErrorV1>
    {
        if self.leader_pid != Some(leader_pid) {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::InvalidState);
        }
        if let Some(error) = self.fault {
            return Err(error);
        }
        let source_event_count_before_finish = self.ingested_source_event_count;
        let finish_drain_event_count = self.drain_correlated_until_empty_v1()?;
        let dropped_event_count = self
            .producer
            .dropped_event_count_v1()
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::Producer)?;
        let discarded_record_count = self.producer.discarded_record_count_v1();
        let producer_last_source_sequence = self.producer.last_source_sequence_v1();
        let runtime_btf_sha256 = self.producer.runtime_btf_sha256_v1().clone();
        let task_exit_code_byte_offset = self.producer.task_exit_code_byte_offset_v1();
        let tracepoint_format_sha256: BTreeMap<&'static str, Sha256Digest> = self
            .producer
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
        let online_cpus = self.producer.online_cpus_v1().to_vec();
        let attachment_cpu = self.producer.attachment_cpu_v1();
        let stream = self
            .correlator
            .finish_v1(
                dropped_event_count,
                discarded_record_count,
                producer_last_source_sequence,
            )
            .map_err(|_| LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream)?;
        if stream.source_event_count_v1() != self.ingested_source_event_count
            || stream.source_event_count_v1()
                != source_event_count_before_finish
                    .checked_add(finish_drain_event_count)
                    .ok_or(LinuxVzPackageRootProcessCollectorErrorV1::Worker)?
        {
            return Err(LinuxVzPackageRootProcessCollectorErrorV1::ProcessStream);
        }
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
            active_drain_poll_count: self.active_drain_poll_count,
            active_nonempty_drain_count: self.active_nonempty_drain_count,
            source_event_count_before_finish,
            finish_drain_event_count,
            maximum_drain_batch_record_count: self.maximum_drain_batch_record_count,
        })
    }
}

#[cfg(target_os = "linux")]
fn create_fault_signal_pipe_v1(
) -> Result<(OwnedFd, OwnedFd), LinuxVzPackageRootProcessCollectorErrorV1> {
    let mut descriptors = [-1_i32; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
    }
    if descriptors[0] < 0 || descriptors[1] < 0 || descriptors[0] == descriptors[1] {
        for descriptor in descriptors {
            if descriptor >= 0 {
                let _ = unsafe { libc::close(descriptor) };
            }
        }
        return Err(LinuxVzPackageRootProcessCollectorErrorV1::Worker);
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
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
            LinuxVzPackageRootProcessCollectorErrorV1::Worker,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn fault_signal_pipe_is_nonblocking_close_on_exec_and_level_triggered() {
        let (read, write) = create_fault_signal_pipe_v1().expect("fault signal pipe");
        for descriptor in [read.as_raw_fd(), write.as_raw_fd()] {
            let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            let status_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
            assert!(descriptor_flags >= 0);
            assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
            assert!(status_flags >= 0);
            assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        }
        let mut poll_descriptor = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll_descriptor, 1, 0) }, 0);
        assert_eq!(
            unsafe { libc::write(write.as_raw_fd(), [1_u8].as_ptr().cast(), 1) },
            1
        );
        poll_descriptor.revents = 0;
        assert_eq!(unsafe { libc::poll(&mut poll_descriptor, 1, 0) }, 1);
        assert_ne!(poll_descriptor.revents & libc::POLLIN, 0);
        drop(write);
        poll_descriptor.revents = 0;
        assert_eq!(unsafe { libc::poll(&mut poll_descriptor, 1, 0) }, 1);
        assert_ne!(poll_descriptor.revents & (libc::POLLIN | libc::POLLHUP), 0);
    }
}
