#![allow(dead_code)]

use crate::linux_vz_package_sensor_event_stream::{
    LinuxVzPackageKernelEventKindV1, LinuxVzPackageKernelEventV1, LinuxVzPackageNetworkTargetV1,
    LinuxVzPackageSelectedSyscallV1,
};
use std::collections::BTreeMap;
use std::fmt;

const MAX_CORRELATED_SOURCE_EVENTS_V1: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageProcessStreamErrorV1 {
    InvalidConfiguration,
    InvalidState,
    InvalidBinding,
    InvalidSequence,
    InvalidTimestamp,
    InvalidPair,
    IncompletePair,
    UnconsumedDetail,
    LossDetected,
    LimitExceeded,
}

impl LinuxVzPackageProcessStreamErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "linux_vz_package_process_stream_configuration_invalid",
            Self::InvalidState => "linux_vz_package_process_stream_state_invalid",
            Self::InvalidBinding => "linux_vz_package_process_stream_binding_invalid",
            Self::InvalidSequence => "linux_vz_package_process_stream_sequence_invalid",
            Self::InvalidTimestamp => "linux_vz_package_process_stream_timestamp_invalid",
            Self::InvalidPair => "linux_vz_package_process_stream_syscall_pair_invalid",
            Self::IncompletePair => "linux_vz_package_process_stream_syscall_pair_incomplete",
            Self::UnconsumedDetail => "linux_vz_package_process_stream_unconsumed_detail_rejected",
            Self::LossDetected => "linux_vz_package_process_stream_loss_detected",
            Self::LimitExceeded => "linux_vz_package_process_stream_limit_exceeded",
        }
    }
}

impl fmt::Display for LinuxVzPackageProcessStreamErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageProcessStreamErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageCorrelatedLifecycleEventV1 {
    kind: LinuxVzPackageKernelEventKindV1,
    source_sequence: u64,
    timestamp_nanoseconds: u64,
    cgroup_id: u64,
    pid: u32,
    tgid: u32,
    parent_pid: u32,
    subject_pid: u32,
    kernel_wait_status: Option<u16>,
    cpu: u32,
}

impl LinuxVzPackageCorrelatedLifecycleEventV1 {
    pub(crate) const fn kind_v1(&self) -> LinuxVzPackageKernelEventKindV1 {
        self.kind
    }

    pub(crate) const fn source_sequence_v1(&self) -> u64 {
        self.source_sequence
    }

    pub(crate) const fn timestamp_nanoseconds_v1(&self) -> u64 {
        self.timestamp_nanoseconds
    }

    pub(crate) const fn cgroup_id_v1(&self) -> u64 {
        self.cgroup_id
    }

    pub(crate) const fn pid_v1(&self) -> u32 {
        self.pid
    }

    pub(crate) const fn tgid_v1(&self) -> u32 {
        self.tgid
    }

    pub(crate) const fn parent_pid_v1(&self) -> u32 {
        self.parent_pid
    }

    pub(crate) const fn subject_pid_v1(&self) -> u32 {
        self.subject_pid
    }

    pub(crate) const fn kernel_wait_status_v1(&self) -> Option<u16> {
        self.kernel_wait_status
    }

    pub(crate) const fn cpu_v1(&self) -> u32 {
        self.cpu
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageCorrelatedSyscallV1 {
    syscall: LinuxVzPackageSelectedSyscallV1,
    enter_source_sequence: u64,
    exit_source_sequence: u64,
    enter_timestamp_nanoseconds: u64,
    exit_timestamp_nanoseconds: u64,
    cgroup_id: u64,
    pid: u32,
    tgid: u32,
    arguments: [u64; 6],
    network_target: Option<LinuxVzPackageNetworkTargetV1>,
    result: i64,
    enter_cpu: u32,
    exit_cpu: u32,
}

impl fmt::Debug for LinuxVzPackageCorrelatedSyscallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageCorrelatedSyscallV1")
            .field("syscall", &self.syscall)
            .field("enter_source_sequence", &self.enter_source_sequence)
            .field("exit_source_sequence", &self.exit_source_sequence)
            .field(
                "enter_timestamp_nanoseconds",
                &self.enter_timestamp_nanoseconds,
            )
            .field(
                "exit_timestamp_nanoseconds",
                &self.exit_timestamp_nanoseconds,
            )
            .field("cgroup_id", &self.cgroup_id)
            .field("pid", &self.pid)
            .field("tgid", &self.tgid)
            .field("arguments", &"<redacted>")
            .field(
                "network_target",
                &self.network_target.as_ref().map(|_| "<redacted>"),
            )
            .field("result", &self.result)
            .field("enter_cpu", &self.enter_cpu)
            .field("exit_cpu", &self.exit_cpu)
            .finish()
    }
}

impl LinuxVzPackageCorrelatedSyscallV1 {
    pub(crate) const fn syscall_v1(&self) -> LinuxVzPackageSelectedSyscallV1 {
        self.syscall
    }

    pub(crate) const fn enter_source_sequence_v1(&self) -> u64 {
        self.enter_source_sequence
    }

    pub(crate) const fn exit_source_sequence_v1(&self) -> u64 {
        self.exit_source_sequence
    }

    pub(crate) const fn enter_timestamp_nanoseconds_v1(&self) -> u64 {
        self.enter_timestamp_nanoseconds
    }

    pub(crate) const fn exit_timestamp_nanoseconds_v1(&self) -> u64 {
        self.exit_timestamp_nanoseconds
    }

    pub(crate) const fn cgroup_id_v1(&self) -> u64 {
        self.cgroup_id
    }

    pub(crate) const fn pid_v1(&self) -> u32 {
        self.pid
    }

    pub(crate) const fn tgid_v1(&self) -> u32 {
        self.tgid
    }

    pub(crate) fn arguments_v1(&self) -> &[u64; 6] {
        &self.arguments
    }

    pub(crate) fn network_target_v1(&self) -> Option<&LinuxVzPackageNetworkTargetV1> {
        self.network_target.as_ref()
    }

    pub(crate) const fn result_v1(&self) -> i64 {
        self.result
    }

    pub(crate) const fn enter_cpu_v1(&self) -> u32 {
        self.enter_cpu
    }

    pub(crate) const fn exit_cpu_v1(&self) -> u32 {
        self.exit_cpu
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageCorrelatedProcessObservationV1 {
    Lifecycle(LinuxVzPackageCorrelatedLifecycleEventV1),
    Syscall(LinuxVzPackageCorrelatedSyscallV1),
}

impl LinuxVzPackageCorrelatedProcessObservationV1 {
    pub(crate) const fn first_source_sequence_v1(&self) -> u64 {
        match self {
            Self::Lifecycle(event) => event.source_sequence,
            Self::Syscall(event) => event.enter_source_sequence,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PendingSyscallV1 {
    syscall: LinuxVzPackageSelectedSyscallV1,
    enter_source_sequence: u64,
    enter_timestamp_nanoseconds: u64,
    cgroup_id: u64,
    pid: u32,
    tgid: u32,
    arguments: [u64; 6],
    network_target: Option<LinuxVzPackageNetworkTargetV1>,
    enter_cpu: u32,
}

impl fmt::Debug for PendingSyscallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSyscallV1")
            .field("syscall", &self.syscall)
            .field("enter_source_sequence", &self.enter_source_sequence)
            .field(
                "enter_timestamp_nanoseconds",
                &self.enter_timestamp_nanoseconds,
            )
            .field("cgroup_id", &self.cgroup_id)
            .field("pid", &self.pid)
            .field("tgid", &self.tgid)
            .field("arguments", &"<redacted>")
            .field(
                "network_target",
                &self.network_target.as_ref().map(|_| "<redacted>"),
            )
            .field("enter_cpu", &self.enter_cpu)
            .finish()
    }
}

pub(crate) struct LinuxVzPackageProcessEventCorrelatorV1 {
    expected_cgroup_id: u64,
    maximum_source_events: usize,
    next_source_sequence: u64,
    last_timestamp_nanoseconds: u64,
    pending_syscalls: BTreeMap<(u32, u32), PendingSyscallV1>,
    observations: Vec<LinuxVzPackageCorrelatedProcessObservationV1>,
    faulted: bool,
}

impl fmt::Debug for LinuxVzPackageProcessEventCorrelatorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageProcessEventCorrelatorV1")
            .field("expected_cgroup_id", &self.expected_cgroup_id)
            .field("maximum_source_events", &self.maximum_source_events)
            .field("next_source_sequence", &self.next_source_sequence)
            .field(
                "last_timestamp_nanoseconds",
                &self.last_timestamp_nanoseconds,
            )
            .field("pending_syscall_count", &self.pending_syscalls.len())
            .field("observation_count", &self.observations.len())
            .field("faulted", &self.faulted)
            .finish()
    }
}

impl LinuxVzPackageProcessEventCorrelatorV1 {
    pub(crate) fn new_v1(
        expected_cgroup_id: u64,
        maximum_source_events: usize,
    ) -> Result<Self, LinuxVzPackageProcessStreamErrorV1> {
        if expected_cgroup_id == 0
            || maximum_source_events == 0
            || maximum_source_events > MAX_CORRELATED_SOURCE_EVENTS_V1
        {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            expected_cgroup_id,
            maximum_source_events,
            next_source_sequence: 1,
            last_timestamp_nanoseconds: 0,
            pending_syscalls: BTreeMap::new(),
            observations: Vec::new(),
            faulted: false,
        })
    }

    pub(crate) fn ingest_v1(
        &mut self,
        event: LinuxVzPackageKernelEventV1,
    ) -> Result<(), LinuxVzPackageProcessStreamErrorV1> {
        if self.faulted {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidState);
        }
        let result = self.ingest_checked_v1(event);
        if result.is_err() {
            self.faulted = true;
        }
        result
    }

    fn ingest_checked_v1(
        &mut self,
        event: LinuxVzPackageKernelEventV1,
    ) -> Result<(), LinuxVzPackageProcessStreamErrorV1> {
        if event.cgroup_id() != self.expected_cgroup_id {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidBinding);
        }
        if event.source_sequence() != self.next_source_sequence {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidSequence);
        }
        if event.timestamp_nanoseconds() <= self.last_timestamp_nanoseconds {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidTimestamp);
        }
        let observed_source_events = usize::try_from(event.source_sequence())
            .map_err(|_| LinuxVzPackageProcessStreamErrorV1::LimitExceeded)?;
        if observed_source_events > self.maximum_source_events {
            return Err(LinuxVzPackageProcessStreamErrorV1::LimitExceeded);
        }
        let network_target = event
            .network_target_v1()
            .map_err(|_| LinuxVzPackageProcessStreamErrorV1::UnconsumedDetail)?;
        if (!event.data().is_empty() || event.data_truncated()) && network_target.is_none() {
            return Err(LinuxVzPackageProcessStreamErrorV1::UnconsumedDetail);
        }

        let key = (event.tgid(), event.pid());
        match event.kind() {
            LinuxVzPackageKernelEventKindV1::SyscallEnter => {
                let syscall = event
                    .selected_syscall_v1()
                    .map_err(|_| invalid_syscall_pair_v1("enter_syscall_invalid"))?;
                if let Some(pending) = self.pending_syscalls.get(&key) {
                    eprintln!(
                        "WHOATHERE_PACKAGE_PROCESS_STREAM_FAILED stage=syscall_pair reason=duplicate_enter existing_syscall={} observed_syscall={} pending_count={}",
                        pending.syscall.name_v1(),
                        syscall.name_v1(),
                        self.pending_syscalls.len()
                    );
                    return Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair);
                }
                self.pending_syscalls.insert(
                    key,
                    PendingSyscallV1 {
                        syscall,
                        enter_source_sequence: event.source_sequence(),
                        enter_timestamp_nanoseconds: event.timestamp_nanoseconds(),
                        cgroup_id: event.cgroup_id(),
                        pid: event.pid(),
                        tgid: event.tgid(),
                        arguments: *event.arguments(),
                        network_target,
                        enter_cpu: event.cpu(),
                    },
                );
            }
            LinuxVzPackageKernelEventKindV1::SyscallExit => {
                let syscall = event
                    .selected_syscall_v1()
                    .map_err(|_| invalid_syscall_pair_v1("exit_syscall_invalid"))?;
                let Some(pending) = self.pending_syscalls.get(&key) else {
                    eprintln!(
                        "WHOATHERE_PACKAGE_PROCESS_STREAM_FAILED stage=syscall_pair reason=exit_without_enter observed_syscall={} pending_count={}",
                        syscall.name_v1(),
                        self.pending_syscalls.len()
                    );
                    return Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair);
                };
                if pending.syscall != syscall
                    || pending.cgroup_id != event.cgroup_id()
                    || pending.pid != event.pid()
                    || pending.tgid != event.tgid()
                    || pending.enter_source_sequence >= event.source_sequence()
                    || pending.enter_timestamp_nanoseconds >= event.timestamp_nanoseconds()
                {
                    eprintln!(
                        "WHOATHERE_PACKAGE_PROCESS_STREAM_FAILED stage=syscall_pair reason=exit_binding_mismatch existing_syscall={} observed_syscall={} pending_count={} sequence_ordered={} timestamp_ordered={}",
                        pending.syscall.name_v1(),
                        syscall.name_v1(),
                        self.pending_syscalls.len(),
                        pending.enter_source_sequence < event.source_sequence(),
                        pending.enter_timestamp_nanoseconds < event.timestamp_nanoseconds()
                    );
                    return Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair);
                }
                let Some(result) = event.result() else {
                    eprintln!(
                        "WHOATHERE_PACKAGE_PROCESS_STREAM_FAILED stage=syscall_pair reason=exit_result_missing observed_syscall={} pending_count={}",
                        syscall.name_v1(),
                        self.pending_syscalls.len()
                    );
                    return Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair);
                };
                let Some(pending) = self.pending_syscalls.remove(&key) else {
                    eprintln!(
                        "WHOATHERE_PACKAGE_PROCESS_STREAM_FAILED stage=syscall_pair reason=pending_remove_failed observed_syscall={} pending_count={}",
                        syscall.name_v1(),
                        self.pending_syscalls.len()
                    );
                    return Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair);
                };
                self.observations
                    .push(LinuxVzPackageCorrelatedProcessObservationV1::Syscall(
                        LinuxVzPackageCorrelatedSyscallV1 {
                            syscall,
                            enter_source_sequence: pending.enter_source_sequence,
                            exit_source_sequence: event.source_sequence(),
                            enter_timestamp_nanoseconds: pending.enter_timestamp_nanoseconds,
                            exit_timestamp_nanoseconds: event.timestamp_nanoseconds(),
                            cgroup_id: event.cgroup_id(),
                            pid: event.pid(),
                            tgid: event.tgid(),
                            arguments: pending.arguments,
                            network_target: pending.network_target,
                            result,
                            enter_cpu: pending.enter_cpu,
                            exit_cpu: event.cpu(),
                        },
                    ));
            }
            LinuxVzPackageKernelEventKindV1::Fork
            | LinuxVzPackageKernelEventKindV1::Exec
            | LinuxVzPackageKernelEventKindV1::Exit => {
                if event.kind() == LinuxVzPackageKernelEventKindV1::Exit
                    && self.pending_syscalls.contains_key(&key)
                {
                    return Err(LinuxVzPackageProcessStreamErrorV1::IncompletePair);
                }
                self.observations
                    .push(LinuxVzPackageCorrelatedProcessObservationV1::Lifecycle(
                        LinuxVzPackageCorrelatedLifecycleEventV1 {
                            kind: event.kind(),
                            source_sequence: event.source_sequence(),
                            timestamp_nanoseconds: event.timestamp_nanoseconds(),
                            cgroup_id: event.cgroup_id(),
                            pid: event.pid(),
                            tgid: event.tgid(),
                            parent_pid: event.parent_pid(),
                            subject_pid: event.subject_pid(),
                            kernel_wait_status: event.kernel_wait_status_v1(),
                            cpu: event.cpu(),
                        },
                    ));
            }
        }
        self.next_source_sequence = self
            .next_source_sequence
            .checked_add(1)
            .ok_or(LinuxVzPackageProcessStreamErrorV1::LimitExceeded)?;
        self.last_timestamp_nanoseconds = event.timestamp_nanoseconds();
        Ok(())
    }

    pub(crate) fn finish_v1(
        mut self,
        dropped_event_count: u64,
        discarded_record_count: u64,
        producer_last_source_sequence: u64,
    ) -> Result<LinuxVzPackageCorrelatedProcessStreamV1, LinuxVzPackageProcessStreamErrorV1> {
        if self.faulted {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidState);
        }
        let source_event_count = self.next_source_sequence.saturating_sub(1);
        if dropped_event_count != 0 || discarded_record_count != 0 {
            return Err(LinuxVzPackageProcessStreamErrorV1::LossDetected);
        }
        if source_event_count == 0 || producer_last_source_sequence != source_event_count {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidSequence);
        }
        if !self.pending_syscalls.is_empty() {
            return Err(LinuxVzPackageProcessStreamErrorV1::IncompletePair);
        }
        self.observations.sort_unstable_by_key(
            LinuxVzPackageCorrelatedProcessObservationV1::first_source_sequence_v1,
        );
        if self
            .observations
            .windows(2)
            .any(|pair| pair[0].first_source_sequence_v1() >= pair[1].first_source_sequence_v1())
        {
            return Err(LinuxVzPackageProcessStreamErrorV1::InvalidSequence);
        }
        Ok(LinuxVzPackageCorrelatedProcessStreamV1 {
            expected_cgroup_id: self.expected_cgroup_id,
            source_event_count,
            last_timestamp_nanoseconds: self.last_timestamp_nanoseconds,
            observations: self.observations,
        })
    }
}

fn invalid_syscall_pair_v1(reason: &'static str) -> LinuxVzPackageProcessStreamErrorV1 {
    eprintln!("WHOATHERE_PACKAGE_PROCESS_STREAM_FAILED stage=syscall_pair reason={reason}");
    LinuxVzPackageProcessStreamErrorV1::InvalidPair
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageCorrelatedProcessStreamV1 {
    expected_cgroup_id: u64,
    source_event_count: u64,
    last_timestamp_nanoseconds: u64,
    observations: Vec<LinuxVzPackageCorrelatedProcessObservationV1>,
}

impl LinuxVzPackageCorrelatedProcessStreamV1 {
    pub(crate) const fn expected_cgroup_id_v1(&self) -> u64 {
        self.expected_cgroup_id
    }

    pub(crate) const fn source_event_count_v1(&self) -> u64 {
        self.source_event_count
    }

    pub(crate) const fn last_timestamp_nanoseconds_v1(&self) -> u64 {
        self.last_timestamp_nanoseconds
    }

    pub(crate) fn observations_v1(&self) -> &[LinuxVzPackageCorrelatedProcessObservationV1] {
        &self.observations
    }

    pub(crate) const fn coverage_complete_v1(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_vz_package_sensor_event_stream::{
        decode_linux_vz_package_kernel_event_v1, LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1,
    };

    const CGROUP_ID_V1: u64 = 41;

    #[derive(Clone, Copy)]
    struct EventSpecV1 {
        kind: LinuxVzPackageKernelEventKindV1,
        sequence: u64,
        timestamp: u64,
        pid: u32,
        tgid: u32,
        syscall: Option<LinuxVzPackageSelectedSyscallV1>,
        arguments: [u64; 6],
        result: Option<i64>,
        data: Option<&'static [u8]>,
    }

    fn event_v1(spec: EventSpecV1) -> LinuxVzPackageKernelEventV1 {
        event_in_cgroup_v1(spec, CGROUP_ID_V1)
    }

    fn event_in_cgroup_v1(spec: EventSpecV1, cgroup_id: u64) -> LinuxVzPackageKernelEventV1 {
        let mut bytes = [0_u8; LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1];
        bytes[0..4].copy_from_slice(b"WTKE");
        bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&(spec.kind as u16).to_le_bytes());
        if spec.result.is_some() {
            bytes[8..12].copy_from_slice(&(1_u32 << 1).to_le_bytes());
        }
        bytes[12..16].copy_from_slice(
            &u32::try_from(LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1)
                .expect("event bytes")
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&cgroup_id.to_le_bytes());
        bytes[24..32].copy_from_slice(&spec.timestamp.to_le_bytes());
        bytes[32..36].copy_from_slice(&spec.pid.to_le_bytes());
        bytes[36..40].copy_from_slice(&spec.tgid.to_le_bytes());
        let parent_pid = if spec.kind == LinuxVzPackageKernelEventKindV1::Fork {
            spec.pid
        } else {
            0
        };
        let subject_pid = if spec.kind == LinuxVzPackageKernelEventKindV1::Fork {
            spec.pid + 1
        } else {
            spec.pid
        };
        bytes[40..44].copy_from_slice(&parent_pid.to_le_bytes());
        bytes[44..48].copy_from_slice(&subject_pid.to_le_bytes());
        bytes[48..52]
            .copy_from_slice(&(spec.syscall.map_or(0, |value| value as u32)).to_le_bytes());
        bytes[56..64].copy_from_slice(&spec.result.unwrap_or_default().to_le_bytes());
        for (index, argument) in spec.arguments.iter().enumerate() {
            bytes[64 + index * 8..72 + index * 8].copy_from_slice(&argument.to_le_bytes());
        }
        if let Some(data) = spec.data {
            assert!(data.len() <= 64);
            if matches!(
                spec.syscall,
                Some(
                    LinuxVzPackageSelectedSyscallV1::Connect
                        | LinuxVzPackageSelectedSyscallV1::Sendto
                )
            ) && data.len() >= 2
            {
                bytes[52..54].copy_from_slice(&data[..2]);
            }
            bytes[54..56].copy_from_slice(&(data.len() as u16).to_le_bytes());
            bytes[112..112 + data.len()].copy_from_slice(data);
        }
        bytes[184..188].copy_from_slice(&(spec.sequence as u32 % 2).to_le_bytes());
        decode_linux_vz_package_kernel_event_v1(&bytes, cgroup_id, spec.sequence)
            .expect("valid test event")
    }

    fn syscall_spec_v1(
        kind: LinuxVzPackageKernelEventKindV1,
        sequence: u64,
        timestamp: u64,
        thread: (u32, u32),
        syscall: LinuxVzPackageSelectedSyscallV1,
        arguments: [u64; 6],
        result: Option<i64>,
    ) -> EventSpecV1 {
        EventSpecV1 {
            kind,
            sequence,
            timestamp,
            pid: thread.0,
            tgid: thread.1,
            syscall: Some(syscall),
            arguments,
            result,
            data: None,
        }
    }

    fn lifecycle_spec_v1(
        kind: LinuxVzPackageKernelEventKindV1,
        sequence: u64,
        timestamp: u64,
        pid: u32,
    ) -> EventSpecV1 {
        EventSpecV1 {
            kind,
            sequence,
            timestamp,
            pid,
            tgid: pid,
            syscall: None,
            arguments: [0; 6],
            result: (kind == LinuxVzPackageKernelEventKindV1::Exit).then_some(0),
            data: None,
        }
    }

    #[test]
    fn interleaved_threads_pair_exact_syscalls_and_preserve_source_order() {
        let mut correlator =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 32).expect("correlator");
        correlator
            .ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                1,
                100,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Setuid,
                [65_534, 0, 0, 0, 0, 0],
                None,
            )))
            .expect("setuid enter");
        assert!(!format!("{correlator:?}").contains("65534"));
        let mut connect_enter = syscall_spec_v1(
            LinuxVzPackageKernelEventKindV1::SyscallEnter,
            2,
            200,
            (42, 41),
            LinuxVzPackageSelectedSyscallV1::Connect,
            [7, 0, 16, 0, 0, 0],
            None,
        );
        connect_enter.data = Some(&[2, 0, 1, 187, 192, 0, 2, 9, 0, 0, 0, 0, 0, 0, 0, 0]);
        correlator
            .ingest_v1(event_v1(connect_enter))
            .expect("connect enter");
        correlator
            .ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallExit,
                3,
                300,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Setuid,
                [0; 6],
                Some(0),
            )))
            .expect("setuid exit");
        correlator
            .ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                4,
                400,
                41,
            )))
            .expect("exec");
        correlator
            .ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallExit,
                5,
                500,
                (42, 41),
                LinuxVzPackageSelectedSyscallV1::Connect,
                [0; 6],
                Some(-115),
            )))
            .expect("connect exit");
        correlator
            .ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                6,
                600,
                41,
            )))
            .expect("exit");

        let stream = correlator.finish_v1(0, 0, 6).expect("complete stream");
        assert_eq!(stream.expected_cgroup_id_v1(), CGROUP_ID_V1);
        assert_eq!(stream.source_event_count_v1(), 6);
        assert_eq!(stream.last_timestamp_nanoseconds_v1(), 600);
        assert!(stream.coverage_complete_v1());
        assert_eq!(stream.observations_v1().len(), 4);
        assert_eq!(
            stream
                .observations_v1()
                .iter()
                .map(LinuxVzPackageCorrelatedProcessObservationV1::first_source_sequence_v1)
                .collect::<Vec<_>>(),
            vec![1, 2, 4, 6]
        );
        let LinuxVzPackageCorrelatedProcessObservationV1::Syscall(setuid) =
            &stream.observations_v1()[0]
        else {
            panic!("setuid pair");
        };
        assert_eq!(setuid.syscall_v1(), LinuxVzPackageSelectedSyscallV1::Setuid);
        assert_eq!(setuid.enter_source_sequence_v1(), 1);
        assert_eq!(setuid.exit_source_sequence_v1(), 3);
        assert_eq!(setuid.arguments_v1()[0], 65_534);
        assert_eq!(setuid.result_v1(), 0);
        assert!(!format!("{setuid:?}").contains("65534"));

        let LinuxVzPackageCorrelatedProcessObservationV1::Syscall(connect) =
            &stream.observations_v1()[1]
        else {
            panic!("connect pair");
        };
        assert_eq!(
            connect.syscall_v1(),
            LinuxVzPackageSelectedSyscallV1::Connect
        );
        assert_eq!(connect.enter_source_sequence_v1(), 2);
        assert_eq!(connect.exit_source_sequence_v1(), 5);
        assert_eq!(connect.result_v1(), -115);
        assert_eq!(connect.tgid_v1(), 41);
        assert_eq!(connect.pid_v1(), 42);
        assert_eq!(connect.enter_cpu_v1(), 0);
        assert_eq!(connect.exit_cpu_v1(), 1);
        let target = connect.network_target_v1().expect("network target");
        assert_eq!(target.port_v1(), 443);
        assert_eq!(target.address_v1(), &[192, 0, 2, 9]);
        assert!(!format!("{connect:?}").contains("192"));
        let LinuxVzPackageCorrelatedProcessObservationV1::Lifecycle(exit) =
            &stream.observations_v1()[3]
        else {
            panic!("exit lifecycle");
        };
        assert_eq!(exit.kind_v1(), LinuxVzPackageKernelEventKindV1::Exit);
        assert_eq!(exit.kernel_wait_status_v1(), Some(0));
    }

    #[test]
    fn mismatched_missing_and_duplicate_syscall_pairs_fail_closed() {
        let exit = event_v1(syscall_spec_v1(
            LinuxVzPackageKernelEventKindV1::SyscallExit,
            1,
            100,
            (41, 41),
            LinuxVzPackageSelectedSyscallV1::Setuid,
            [0; 6],
            Some(0),
        ));
        assert_eq!(
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8)
                .expect("correlator")
                .ingest_v1(exit),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair)
        );

        let mut mismatch =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        mismatch
            .ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                1,
                100,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Setuid,
                [65_534, 0, 0, 0, 0, 0],
                None,
            )))
            .expect("enter");
        assert_eq!(
            mismatch.ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallExit,
                2,
                200,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Setgid,
                [0; 6],
                Some(0),
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair)
        );
        assert_eq!(
            mismatch.ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallExit,
                2,
                200,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Setuid,
                [0; 6],
                Some(0),
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidState)
        );

        let mut duplicate =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        duplicate
            .ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                1,
                100,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Setuid,
                [65_534, 0, 0, 0, 0, 0],
                None,
            )))
            .expect("enter");
        assert_eq!(
            duplicate.ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                2,
                200,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Setgid,
                [65_534, 0, 0, 0, 0, 0],
                None,
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidPair)
        );
    }

    #[test]
    fn sequence_timestamp_binding_limits_and_loss_are_fail_closed() {
        assert!(matches!(
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(0, 8),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidConfiguration)
        ));
        assert!(matches!(
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 0),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidConfiguration)
        ));

        let mut sequence =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        assert_eq!(
            sequence.ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                2,
                100,
                41,
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidSequence)
        );

        let mut timestamp =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        timestamp
            .ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                1,
                100,
                41,
            )))
            .expect("exec");
        assert_eq!(
            timestamp.ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                2,
                100,
                41,
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidTimestamp)
        );

        let mut binding =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        assert_eq!(
            binding.ingest_v1(event_in_cgroup_v1(
                lifecycle_spec_v1(LinuxVzPackageKernelEventKindV1::Exec, 1, 100, 41),
                CGROUP_ID_V1 + 1,
            )),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidBinding)
        );

        let mut limit =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 1).expect("correlator");
        limit
            .ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                1,
                100,
                41,
            )))
            .expect("first event");
        assert_eq!(
            limit.ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                2,
                200,
                41,
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::LimitExceeded)
        );

        let mut detail =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        let mut detail_spec = lifecycle_spec_v1(LinuxVzPackageKernelEventKindV1::Exec, 1, 100, 41);
        detail_spec.data = Some(b"unconsumed-exec-detail");
        assert_eq!(
            detail.ingest_v1(event_v1(detail_spec)),
            Err(LinuxVzPackageProcessStreamErrorV1::UnconsumedDetail)
        );

        for (dropped, discarded, last, expected) in [
            (1, 0, 1, LinuxVzPackageProcessStreamErrorV1::LossDetected),
            (0, 1, 1, LinuxVzPackageProcessStreamErrorV1::LossDetected),
            (0, 0, 2, LinuxVzPackageProcessStreamErrorV1::InvalidSequence),
        ] {
            let mut correlator = LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8)
                .expect("correlator");
            correlator
                .ingest_v1(event_v1(lifecycle_spec_v1(
                    LinuxVzPackageKernelEventKindV1::Exec,
                    1,
                    100,
                    41,
                )))
                .expect("exec");
            assert_eq!(
                correlator.finish_v1(dropped, discarded, last),
                Err(expected)
            );
        }
    }

    #[test]
    fn pending_syscall_cannot_cross_process_exit_or_finish() {
        let mut exit =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        exit.ingest_v1(event_v1(syscall_spec_v1(
            LinuxVzPackageKernelEventKindV1::SyscallEnter,
            1,
            100,
            (41, 41),
            LinuxVzPackageSelectedSyscallV1::Mmap,
            [0, 4096, 3, 2, u64::MAX, 0],
            None,
        )))
        .expect("mmap enter");
        assert_eq!(
            exit.ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                2,
                200,
                41,
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::IncompletePair)
        );

        let mut finish =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        finish
            .ingest_v1(event_v1(syscall_spec_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                1,
                100,
                (41, 41),
                LinuxVzPackageSelectedSyscallV1::Mmap,
                [0, 4096, 3, 2, u64::MAX, 0],
                None,
            )))
            .expect("mmap enter");
        assert_eq!(
            finish.finish_v1(0, 0, 1),
            Err(LinuxVzPackageProcessStreamErrorV1::IncompletePair)
        );

        let mut faulted =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        assert_eq!(
            faulted.ingest_v1(event_v1(lifecycle_spec_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                2,
                100,
                41,
            ))),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidSequence)
        );
        assert_eq!(
            faulted.finish_v1(0, 0, 0),
            Err(LinuxVzPackageProcessStreamErrorV1::InvalidState)
        );
    }
}
