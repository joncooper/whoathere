use std::fmt;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(any(target_os = "linux", test))]
use std::os::fd::{FromRawFd, IntoRawFd};
use zeroize::{Zeroize, Zeroizing};

const SIGNING_SEED_BYTES_V1: usize = 32;
const CUSTODY_IO_TIMEOUT_MILLISECONDS_V1: i32 = 10_000;
#[cfg(target_os = "linux")]
const RUNNER_HARDENED_READY_V1: u8 = 0xa5;
#[cfg(target_os = "linux")]
const SERVICE_VERIFIED_RELEASE_V1: u8 = 0x5a;
#[cfg(target_os = "linux")]
const RUNNER_RELEASE_ACK_V1: u8 = 0xc3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootCoordinatorErrorV1 {
    UnsupportedPlatform,
    PrivilegeBoundary,
    ThreadBoundary,
    SigningSeedDescriptorInvalid,
    ControlChannelFailed,
    ReadinessChannelFailed,
    ForkFailed,
    RunnerHardeningFailed,
    RunnerReadinessFailed,
    SigningSeedReadFailed,
    SigningSeedInvalid,
}

impl LinuxVzPackageRootCoordinatorErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "linux_vz_package_root_coordinator_platform_unsupported",
            Self::PrivilegeBoundary => {
                "linux_vz_package_root_coordinator_privilege_boundary_invalid"
            }
            Self::ThreadBoundary => "linux_vz_package_root_coordinator_thread_boundary_invalid",
            Self::SigningSeedDescriptorInvalid => {
                "linux_vz_package_root_coordinator_signing_seed_descriptor_invalid"
            }
            Self::ControlChannelFailed => {
                "linux_vz_package_root_coordinator_control_channel_failed"
            }
            Self::ReadinessChannelFailed => {
                "linux_vz_package_root_coordinator_readiness_channel_failed"
            }
            Self::ForkFailed => "linux_vz_package_root_coordinator_fork_failed",
            Self::RunnerHardeningFailed => {
                "linux_vz_package_root_coordinator_runner_hardening_failed"
            }
            Self::RunnerReadinessFailed => {
                "linux_vz_package_root_coordinator_runner_readiness_failed"
            }
            Self::SigningSeedReadFailed => {
                "linux_vz_package_root_coordinator_signing_seed_read_failed"
            }
            Self::SigningSeedInvalid => "linux_vz_package_root_coordinator_signing_seed_invalid",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootCoordinatorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootCoordinatorErrorV1 {}

/// Parent-observed runner state captured while the hardened child is held behind the split
/// barrier and before the service branch can read the signing seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxVzPackageRunnerCustodyBoundaryV1 {
    runner_pid: u32,
    thread_count: u32,
    open_descriptor_count: u32,
    inheritable_capabilities: u64,
    permitted_capabilities: u64,
    effective_capabilities: u64,
    bounding_capabilities: u64,
    ambient_capabilities: u64,
}

impl LinuxVzPackageRunnerCustodyBoundaryV1 {
    pub const fn runner_pid(&self) -> u32 {
        self.runner_pid
    }

    pub const fn thread_count(&self) -> u32 {
        self.thread_count
    }

    pub const fn open_descriptor_count(&self) -> u32 {
        self.open_descriptor_count
    }

    pub const fn inheritable_capabilities(&self) -> u64 {
        self.inheritable_capabilities
    }

    pub const fn permitted_capabilities(&self) -> u64 {
        self.permitted_capabilities
    }

    pub const fn effective_capabilities(&self) -> u64 {
        self.effective_capabilities
    }

    pub const fn bounding_capabilities(&self) -> u64 {
        self.bounding_capabilities
    }

    pub const fn ambient_capabilities(&self) -> u64 {
        self.ambient_capabilities
    }

    pub const fn ptrace_capability_present(&self) -> bool {
        let mask = 1_u64 << 19;
        self.inheritable_capabilities & mask != 0
            || self.permitted_capabilities & mask != 0
            || self.effective_capabilities & mask != 0
            || self.bounding_capabilities & mask != 0
            || self.ambient_capabilities & mask != 0
    }

    pub const fn root_credentials_verified(&self) -> bool {
        true
    }

    pub const fn tracer_absent(&self) -> bool {
        true
    }

    pub const fn no_new_privileges(&self) -> bool {
        true
    }

    pub const fn unexpected_descriptor_count(&self) -> u32 {
        0
    }
}

/// The only signing-seed handle returned by the root-coordinator split.
///
/// This value is constructed in the sensor-service branch only after the runner has closed its
/// inherited descriptor, dropped ptrace authority, enabled no-new-privileges, and completed the
/// readiness handshake. It is non-clonable and reading consumes it.
pub struct LinuxVzPackagePostForkSigningSeedV1 {
    descriptor: OwnedFd,
}

impl fmt::Debug for LinuxVzPackagePostForkSigningSeedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackagePostForkSigningSeedV1")
            .field("descriptor", &"<service-only-one-use>")
            .finish()
    }
}

impl LinuxVzPackagePostForkSigningSeedV1 {
    pub fn read_once_v1(
        self,
    ) -> Result<Zeroizing<[u8; SIGNING_SEED_BYTES_V1]>, LinuxVzPackageRootCoordinatorErrorV1> {
        let mut seed = Zeroizing::new([0_u8; SIGNING_SEED_BYTES_V1]);
        read_exact_with_eof_v1(self.descriptor.as_raw_fd(), &mut seed)?;
        if seed.iter().all(|byte| *byte == 0) {
            seed.zeroize();
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedInvalid);
        }
        Ok(seed)
    }
}

pub struct LinuxVzPackageRootSensorServiceBranchV1 {
    control_fd: OwnedFd,
    signing_seed: LinuxVzPackagePostForkSigningSeedV1,
    runner_custody_boundary: LinuxVzPackageRunnerCustodyBoundaryV1,
    service_pid: u32,
    runner_pid: u32,
}

impl fmt::Debug for LinuxVzPackageRootSensorServiceBranchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootSensorServiceBranchV1")
            .field("service_pid", &self.service_pid)
            .field("runner_pid", &self.runner_pid)
            .field("control_fd", &"<root-only-socket>")
            .field("signing_seed", &"<service-only-one-use>")
            .field("runner_custody_boundary", &self.runner_custody_boundary)
            .field("runner_hardening_complete", &true)
            .finish()
    }
}

impl LinuxVzPackageRootSensorServiceBranchV1 {
    pub const fn service_pid(&self) -> u32 {
        self.service_pid
    }

    pub const fn runner_pid(&self) -> u32 {
        self.runner_pid
    }

    pub const fn runner_hardening_complete(&self) -> bool {
        true
    }

    pub const fn runner_custody_boundary(&self) -> &LinuxVzPackageRunnerCustodyBoundaryV1 {
        &self.runner_custody_boundary
    }

    pub fn into_control_and_signing_seed_v1(
        self,
    ) -> (OwnedFd, LinuxVzPackagePostForkSigningSeedV1) {
        (self.control_fd, self.signing_seed)
    }
}

pub struct LinuxVzPackageRootRunnerBranchV1 {
    control_fd: OwnedFd,
    service_pid: u32,
    runner_pid: u32,
}

impl fmt::Debug for LinuxVzPackageRootRunnerBranchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootRunnerBranchV1")
            .field("service_pid", &self.service_pid)
            .field("runner_pid", &self.runner_pid)
            .field("control_fd", &"<root-only-socket>")
            .field("signing_seed_descriptor_closed", &true)
            .field("ptrace_capability_present", &false)
            .field("dumpable", &false)
            .field("no_new_privileges", &true)
            .finish()
    }
}

impl LinuxVzPackageRootRunnerBranchV1 {
    pub const fn service_pid(&self) -> u32 {
        self.service_pid
    }

    pub const fn runner_pid(&self) -> u32 {
        self.runner_pid
    }

    pub const fn signing_seed_descriptor_closed(&self) -> bool {
        true
    }

    pub const fn ptrace_capability_present(&self) -> bool {
        false
    }

    pub const fn dumpable(&self) -> bool {
        false
    }

    pub const fn no_new_privileges(&self) -> bool {
        true
    }

    pub fn into_control_fd_v1(self) -> OwnedFd {
        self.control_fd
    }
}

pub enum LinuxVzPackageRootCoordinatorBranchV1 {
    SensorService(LinuxVzPackageRootSensorServiceBranchV1),
    RootRunner(LinuxVzPackageRootRunnerBranchV1),
}

impl fmt::Debug for LinuxVzPackageRootCoordinatorBranchV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SensorService(branch) => branch.fmt(formatter),
            Self::RootRunner(branch) => branch.fmt(formatter),
        }
    }
}

/// Splits one single-threaded root coordinator into a sensor-service parent and a root-runner
/// child without reading the signing seed before the split.
///
/// The child closes the seed descriptor using raw syscalls before returning to Rust, drops
/// `CAP_SYS_PTRACE` from its effective, permitted, inheritable, ambient, and bounding sets, becomes
/// non-dumpable and no-new-privileges, and binds its lifetime to the service parent. The service
/// branch receives the one-use seed handle only after the child acknowledges those checks.
///
/// A hardening failure in the post-fork child terminates that child with `_exit(78)`; the service
/// parent kills/reaps it and returns an error. Call this before creating any collector threads.
#[cfg(target_os = "linux")]
pub fn split_linux_vz_package_root_coordinator_v1(
    signing_seed_fd: OwnedFd,
) -> Result<LinuxVzPackageRootCoordinatorBranchV1, LinuxVzPackageRootCoordinatorErrorV1> {
    linux::split_v1(signing_seed_fd)
}

#[cfg(not(target_os = "linux"))]
pub fn split_linux_vz_package_root_coordinator_v1(
    _signing_seed_fd: OwnedFd,
) -> Result<LinuxVzPackageRootCoordinatorBranchV1, LinuxVzPackageRootCoordinatorErrorV1> {
    Err(LinuxVzPackageRootCoordinatorErrorV1::UnsupportedPlatform)
}

fn read_exact_with_eof_v1(
    descriptor: RawFd,
    output: &mut [u8; SIGNING_SEED_BYTES_V1],
) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
    let mut offset = 0_usize;
    while offset < output.len() {
        wait_for_seed_descriptor_v1(descriptor)?;
        let count = unsafe {
            libc::read(
                descriptor,
                output[offset..].as_mut_ptr().cast(),
                output.len() - offset,
            )
        };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count == 0 {
            output.zeroize();
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed);
        }
        let error = std::io::Error::last_os_error().raw_os_error();
        if error == Some(libc::EINTR) || error == Some(libc::EAGAIN) {
            continue;
        }
        output.zeroize();
        return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed);
    }

    wait_for_seed_descriptor_v1(descriptor)?;
    let mut trailing = 0_u8;
    loop {
        let count = unsafe { libc::read(descriptor, (&mut trailing as *mut u8).cast(), 1) };
        if count == 0 {
            return Ok(());
        }
        if count > 0 {
            output.zeroize();
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedInvalid);
        }
        let error = std::io::Error::last_os_error().raw_os_error();
        if error == Some(libc::EINTR) || error == Some(libc::EAGAIN) {
            wait_for_seed_descriptor_v1(descriptor)?;
            continue;
        }
        output.zeroize();
        return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed);
    }
}

fn wait_for_seed_descriptor_v1(
    descriptor: RawFd,
) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
    let mut poll = libc::pollfd {
        fd: descriptor,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut poll, 1, CUSTODY_IO_TIMEOUT_MILLISECONDS_V1) };
        if result > 0 {
            if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0
                || poll.revents & (libc::POLLIN | libc::POLLHUP) == 0
            {
                return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed);
            }
            return Ok(());
        }
        if result == 0 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::Read;
    use std::mem::MaybeUninit;

    const LINUX_CAPABILITY_VERSION_3_V1: u32 = 0x2008_0522;
    const CAP_SYS_PTRACE_V1: u32 = 19;
    const CAPABILITY_WORD_BITS_V1: u32 = 32;
    const RUNNER_FAILURE_EXIT_V1: i32 = 78;

    #[repr(C)]
    struct CapabilityHeaderV1 {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityDataV1 {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    struct RawFdGuardV1 {
        descriptor: RawFd,
    }

    impl RawFdGuardV1 {
        fn new(descriptor: RawFd) -> Self {
            Self { descriptor }
        }

        fn take(&mut self) -> RawFd {
            let descriptor = self.descriptor;
            self.descriptor = -1;
            descriptor
        }
    }

    impl Drop for RawFdGuardV1 {
        fn drop(&mut self) {
            close_raw_v1(self.descriptor);
        }
    }

    pub(super) fn split_v1(
        signing_seed_fd: OwnedFd,
    ) -> Result<LinuxVzPackageRootCoordinatorBranchV1, LinuxVzPackageRootCoordinatorErrorV1> {
        require_root_single_threaded_v1()?;
        validate_seed_descriptor_v1(signing_seed_fd.as_raw_fd())?;
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::PrivilegeBoundary);
        }

        let (service_control, runner_control) = socket_pair_v1()?;
        let (readiness_read, readiness_write) = pipe_v1()?;
        let mut seed = RawFdGuardV1::new(signing_seed_fd.into_raw_fd());
        let mut service_control = RawFdGuardV1::new(service_control);
        let mut runner_control = RawFdGuardV1::new(runner_control);
        let mut readiness_read = RawFdGuardV1::new(readiness_read);
        let mut readiness_write = RawFdGuardV1::new(readiness_write);
        let service_pid_raw = unsafe { libc::getpid() };
        if service_pid_raw <= 1 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::PrivilegeBoundary);
        }

        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::ForkFailed);
        }
        if child == 0 {
            let closed_seed_descriptor = seed.take();
            let closed_service_control_descriptor = service_control.take();
            let closed_readiness_descriptor = readiness_read.take();
            let runner_control_fd = runner_control.take();
            let readiness_write_fd = readiness_write.take();
            if close_all_except_runner_descriptors_v1(runner_control_fd, readiness_write_fd)
                .is_err()
                || harden_runner_v1(
                    service_pid_raw,
                    closed_seed_descriptor,
                    closed_service_control_descriptor,
                    closed_readiness_descriptor,
                )
                .is_err()
                || write_ready_v1(readiness_write_fd).is_err()
            {
                close_raw_v1(runner_control_fd);
                close_raw_v1(readiness_write_fd);
                unsafe { libc::_exit(RUNNER_FAILURE_EXIT_V1) }
            }
            close_raw_v1(readiness_write_fd);
            if read_control_byte_v1(runner_control_fd) != Ok(SERVICE_VERIFIED_RELEASE_V1)
                || write_control_byte_v1(runner_control_fd, RUNNER_RELEASE_ACK_V1).is_err()
            {
                close_raw_v1(runner_control_fd);
                unsafe { libc::_exit(RUNNER_FAILURE_EXIT_V1) }
            }
            let runner_pid = unsafe { libc::getpid() };
            if runner_pid <= 1 {
                close_raw_v1(runner_control_fd);
                unsafe { libc::_exit(RUNNER_FAILURE_EXIT_V1) }
            }
            let service_pid = service_pid_raw as u32;
            let runner_pid = runner_pid as u32;
            return Ok(LinuxVzPackageRootCoordinatorBranchV1::RootRunner(
                LinuxVzPackageRootRunnerBranchV1 {
                    control_fd: unsafe { OwnedFd::from_raw_fd(runner_control_fd) },
                    service_pid,
                    runner_pid,
                },
            ));
        }

        let runner_control_descriptor = runner_control.take();
        close_raw_v1(runner_control_descriptor);
        close_raw_v1(readiness_write.take());
        let readiness_read_fd = readiness_read.take();
        let ready = read_ready_v1(readiness_read_fd);
        close_raw_v1(readiness_read_fd);
        if ready.is_err() {
            terminate_and_reap_v1(child);
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
        }
        let runner_custody_boundary =
            match observe_runner_custody_boundary_v1(child, runner_control_descriptor) {
                Ok(boundary) => boundary,
                Err(error) => {
                    terminate_and_reap_v1(child);
                    return Err(error);
                }
            };
        if write_control_byte_v1(service_control.descriptor, SERVICE_VERIFIED_RELEASE_V1).is_err()
            || read_control_byte_v1(service_control.descriptor) != Ok(RUNNER_RELEASE_ACK_V1)
        {
            terminate_and_reap_v1(child);
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
        }
        let service_pid = service_pid_raw as u32;
        let runner_pid = child as u32;
        Ok(LinuxVzPackageRootCoordinatorBranchV1::SensorService(
            LinuxVzPackageRootSensorServiceBranchV1 {
                control_fd: unsafe { OwnedFd::from_raw_fd(service_control.take()) },
                signing_seed: LinuxVzPackagePostForkSigningSeedV1 {
                    descriptor: unsafe { OwnedFd::from_raw_fd(seed.take()) },
                },
                runner_custody_boundary,
                service_pid,
                runner_pid,
            },
        ))
    }

    fn require_root_single_threaded_v1() -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        if unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0
            || unsafe { libc::getegid() } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::PrivilegeBoundary);
        }
        let tasks = fs::read_dir("/proc/self/task")
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::ThreadBoundary)?;
        let mut task_count = 0_usize;
        for task in tasks {
            let task = task.map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::ThreadBoundary)?;
            if !task.file_name().to_str().is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                return Err(LinuxVzPackageRootCoordinatorErrorV1::ThreadBoundary);
            }
            task_count += 1;
            if task_count > 1 {
                return Err(LinuxVzPackageRootCoordinatorErrorV1::ThreadBoundary);
            }
        }
        if task_count != 1 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::ThreadBoundary);
        }
        Ok(())
    }

    fn validate_seed_descriptor_v1(
        descriptor: RawFd,
    ) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        if descriptor <= libc::STDERR_FILENO {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid);
        }
        let status_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        if status_flags < 0
            || status_flags & libc::O_ACCMODE != libc::O_RDONLY
            || descriptor_flags < 0
            || descriptor_flags & libc::FD_CLOEXEC == 0
            || unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid);
        }
        let metadata = unsafe { metadata.assume_init() };
        let kind = metadata.st_mode & libc::S_IFMT;
        if kind != libc::S_IFIFO
            || metadata.st_uid != 0
            || metadata.st_gid != 0
            || seed_descriptor_is_duplicated_v1(descriptor, &metadata)?
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid);
        }
        Ok(())
    }

    fn observe_runner_custody_boundary_v1(
        runner_pid: libc::pid_t,
        runner_control_descriptor: RawFd,
    ) -> Result<LinuxVzPackageRunnerCustodyBoundaryV1, LinuxVzPackageRootCoordinatorErrorV1> {
        if runner_pid <= 1 || runner_control_descriptor <= libc::STDERR_FILENO {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        let status_path = format!("/proc/{runner_pid}/status");
        let mut status_file = fs::File::open(status_path)
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
        let mut status_bytes = Vec::new();
        status_file
            .by_ref()
            .take(65_537)
            .read_to_end(&mut status_bytes)
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
        if status_bytes.is_empty() || status_bytes.len() > 65_536 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        let status = std::str::from_utf8(&status_bytes)
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
        let mut fields = BTreeMap::new();
        for line in status.lines() {
            let (key, value) = line
                .split_once(':')
                .ok_or(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
            if key.is_empty() || fields.insert(key, value.trim()).is_some() {
                return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
            }
        }
        require_root_status_ids_v1(fields.get("Uid").copied())?;
        require_root_status_ids_v1(fields.get("Gid").copied())?;
        if parse_status_decimal_v1(fields.get("TracerPid").copied())? != 0
            || parse_status_decimal_v1(fields.get("Threads").copied())? != 1
            || parse_status_decimal_v1(fields.get("NoNewPrivs").copied())? != 1
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        let inheritable_capabilities = parse_status_capabilities_v1(fields.get("CapInh").copied())?;
        let permitted_capabilities = parse_status_capabilities_v1(fields.get("CapPrm").copied())?;
        let effective_capabilities = parse_status_capabilities_v1(fields.get("CapEff").copied())?;
        let bounding_capabilities = parse_status_capabilities_v1(fields.get("CapBnd").copied())?;
        let ambient_capabilities = parse_status_capabilities_v1(fields.get("CapAmb").copied())?;
        let ptrace_mask = 1_u64 << CAP_SYS_PTRACE_V1;
        if inheritable_capabilities & ptrace_mask != 0
            || permitted_capabilities & ptrace_mask != 0
            || effective_capabilities & ptrace_mask != 0
            || bounding_capabilities & ptrace_mask != 0
            || ambient_capabilities != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }

        let descriptor_path = format!("/proc/{runner_pid}/fd");
        let descriptors = fs::read_dir(descriptor_path)
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
        let mut observed = BTreeSet::new();
        for descriptor in descriptors {
            let descriptor = descriptor
                .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<RawFd>().ok())
                .ok_or(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
            if !observed.insert(descriptor) {
                return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
            }
        }
        let expected = BTreeSet::from([
            libc::STDIN_FILENO,
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            runner_control_descriptor,
        ]);
        if observed != expected {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        Ok(LinuxVzPackageRunnerCustodyBoundaryV1 {
            runner_pid: runner_pid as u32,
            thread_count: 1,
            open_descriptor_count: observed.len() as u32,
            inheritable_capabilities,
            permitted_capabilities,
            effective_capabilities,
            bounding_capabilities,
            ambient_capabilities,
        })
    }

    fn require_root_status_ids_v1(
        value: Option<&str>,
    ) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        let values = value
            .ok_or(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        if values.as_slice() != ["0", "0", "0", "0"] {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        Ok(())
    }

    fn parse_status_decimal_v1(
        value: Option<&str>,
    ) -> Result<u32, LinuxVzPackageRootCoordinatorErrorV1> {
        let value = value.ok_or(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
        let parsed = value
            .parse::<u32>()
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
        if value != parsed.to_string() {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        Ok(parsed)
    }

    fn parse_status_capabilities_v1(
        value: Option<&str>,
    ) -> Result<u64, LinuxVzPackageRootCoordinatorErrorV1> {
        let value = value.ok_or(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)?;
        if value.len() != 16
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        u64::from_str_radix(value, 16)
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed)
    }

    fn seed_descriptor_is_duplicated_v1(
        seed_descriptor: RawFd,
        seed_metadata: &libc::stat,
    ) -> Result<bool, LinuxVzPackageRootCoordinatorErrorV1> {
        let descriptors = fs::read_dir("/proc/self/fd")
            .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid)?;
        for entry in descriptors {
            let entry = entry
                .map_err(|_| LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid)?;
            let descriptor = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<RawFd>().ok())
                .ok_or(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid)?;
            if descriptor == seed_descriptor {
                continue;
            }
            let mut metadata = MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                return Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid);
            }
            let metadata = unsafe { metadata.assume_init() };
            if metadata.st_dev == seed_metadata.st_dev && metadata.st_ino == seed_metadata.st_ino {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn socket_pair_v1() -> Result<(RawFd, RawFd), LinuxVzPackageRootCoordinatorErrorV1> {
        let mut descriptors = [-1_i32; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                descriptors.as_mut_ptr(),
            )
        } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::ControlChannelFailed);
        }
        let enabled: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                descriptors[0],
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } != 0
        {
            close_raw_v1(descriptors[0]);
            close_raw_v1(descriptors[1]);
            return Err(LinuxVzPackageRootCoordinatorErrorV1::ControlChannelFailed);
        }
        Ok((descriptors[0], descriptors[1]))
    }

    fn pipe_v1() -> Result<(RawFd, RawFd), LinuxVzPackageRootCoordinatorErrorV1> {
        let mut descriptors = [-1_i32; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::ReadinessChannelFailed);
        }
        Ok((descriptors[0], descriptors[1]))
    }

    fn close_all_except_runner_descriptors_v1(
        runner_control_descriptor: RawFd,
        readiness_write_descriptor: RawFd,
    ) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        if runner_control_descriptor <= libc::STDERR_FILENO
            || readiness_write_descriptor <= libc::STDERR_FILENO
            || runner_control_descriptor == readiness_write_descriptor
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        let first_kept = runner_control_descriptor.min(readiness_write_descriptor) as u32;
        let second_kept = runner_control_descriptor.max(readiness_write_descriptor) as u32;
        close_range_v1(libc::STDERR_FILENO as u32 + 1, first_kept - 1)?;
        close_range_v1(first_kept + 1, second_kept - 1)?;
        close_range_v1(second_kept + 1, u32::MAX)
    }

    fn close_range_v1(first: u32, last: u32) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        if first > last {
            return Ok(());
        }
        if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) } != 0 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        Ok(())
    }

    fn harden_runner_v1(
        service_pid: libc::pid_t,
        closed_seed_descriptor: RawFd,
        closed_service_control_descriptor: RawFd,
        closed_readiness_descriptor: RawFd,
    ) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        if !descriptor_is_closed_v1(closed_seed_descriptor)
            || !descriptor_is_closed_v1(closed_service_control_descriptor)
            || !descriptor_is_closed_v1(closed_readiness_descriptor)
            || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
            || unsafe { libc::getppid() } != service_pid
            || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        drop_ptrace_capability_v1()?;
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
            || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
            || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_CAPBSET_READ, CAP_SYS_PTRACE_V1, 0, 0, 0) } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        require_ptrace_capability_absent_v1()
    }

    fn descriptor_is_closed_v1(descriptor: RawFd) -> bool {
        (unsafe { libc::fcntl(descriptor, libc::F_GETFD) }) < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    }

    fn drop_ptrace_capability_v1() -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        let mut header = CapabilityHeaderV1 {
            version: LINUX_CAPABILITY_VERSION_3_V1,
            pid: 0,
        };
        let mut data = [CapabilityDataV1 {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if unsafe {
            libc::syscall(
                libc::SYS_capget,
                (&mut header as *mut CapabilityHeaderV1).cast::<libc::c_void>(),
                data.as_mut_ptr().cast::<libc::c_void>(),
            )
        } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        let word = (CAP_SYS_PTRACE_V1 / CAPABILITY_WORD_BITS_V1) as usize;
        let mask = 1_u32 << (CAP_SYS_PTRACE_V1 % CAPABILITY_WORD_BITS_V1);
        data[word].effective &= !mask;
        data[word].permitted &= !mask;
        data[word].inheritable &= !mask;
        if unsafe {
            libc::syscall(
                libc::SYS_capset,
                (&mut header as *mut CapabilityHeaderV1).cast::<libc::c_void>(),
                data.as_ptr().cast::<libc::c_void>(),
            )
        } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        let bounding = unsafe { libc::prctl(libc::PR_CAPBSET_READ, CAP_SYS_PTRACE_V1, 0, 0, 0) };
        if bounding < 0
            || (bounding == 1
                && unsafe { libc::prctl(libc::PR_CAPBSET_DROP, CAP_SYS_PTRACE_V1, 0, 0, 0) } != 0)
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        Ok(())
    }

    fn require_ptrace_capability_absent_v1() -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        let mut header = CapabilityHeaderV1 {
            version: LINUX_CAPABILITY_VERSION_3_V1,
            pid: 0,
        };
        let mut data = [CapabilityDataV1 {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if unsafe {
            libc::syscall(
                libc::SYS_capget,
                (&mut header as *mut CapabilityHeaderV1).cast::<libc::c_void>(),
                data.as_mut_ptr().cast::<libc::c_void>(),
            )
        } != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        let word = (CAP_SYS_PTRACE_V1 / CAPABILITY_WORD_BITS_V1) as usize;
        let mask = 1_u32 << (CAP_SYS_PTRACE_V1 % CAPABILITY_WORD_BITS_V1);
        if data[word].effective & mask != 0
            || data[word].permitted & mask != 0
            || data[word].inheritable & mask != 0
        {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
        Ok(())
    }

    fn write_ready_v1(descriptor: RawFd) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        write_control_byte_v1(descriptor, RUNNER_HARDENED_READY_V1)
    }

    fn write_control_byte_v1(
        descriptor: RawFd,
        value: u8,
    ) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        let byte = [value];
        loop {
            let count = unsafe { libc::write(descriptor, byte.as_ptr().cast(), byte.len()) };
            if count == 1 {
                return Ok(());
            }
            if count < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed);
        }
    }

    fn read_ready_v1(descriptor: RawFd) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        let mut byte = 0_u8;
        wait_for_readiness_descriptor_v1(descriptor)?;
        let count = read_readiness_byte_v1(descriptor, &mut byte)?;
        if count != 1 || byte != RUNNER_HARDENED_READY_V1 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
        }
        wait_for_readiness_descriptor_v1(descriptor)?;
        let trailing = read_readiness_byte_v1(descriptor, &mut byte)?;
        if trailing != 0 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
        }
        Ok(())
    }

    fn read_control_byte_v1(descriptor: RawFd) -> Result<u8, LinuxVzPackageRootCoordinatorErrorV1> {
        wait_for_readiness_descriptor_v1(descriptor)?;
        let mut byte = 0_u8;
        if read_readiness_byte_v1(descriptor, &mut byte)? != 1 {
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
        }
        Ok(byte)
    }

    fn wait_for_readiness_descriptor_v1(
        descriptor: RawFd,
    ) -> Result<(), LinuxVzPackageRootCoordinatorErrorV1> {
        let mut poll = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut poll, 1, CUSTODY_IO_TIMEOUT_MILLISECONDS_V1) };
            if result == 0 {
                return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
            }
            if result < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
            }
            if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0
                || poll.revents & (libc::POLLIN | libc::POLLHUP) == 0
            {
                return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
            }
            return Ok(());
        }
    }

    fn read_readiness_byte_v1(
        descriptor: RawFd,
        byte: &mut u8,
    ) -> Result<isize, LinuxVzPackageRootCoordinatorErrorV1> {
        loop {
            let count = unsafe { libc::read(descriptor, (byte as *mut u8).cast(), 1) };
            if count >= 0 {
                return Ok(count);
            }
            let error = std::io::Error::last_os_error().raw_os_error();
            if error == Some(libc::EINTR) || error == Some(libc::EAGAIN) {
                wait_for_readiness_descriptor_v1(descriptor)?;
                continue;
            }
            return Err(LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed);
        }
    }

    fn terminate_and_reap_v1(child: libc::pid_t) {
        let _ = unsafe { libc::kill(child, libc::SIGKILL) };
        let mut status = 0_i32;
        loop {
            let result = unsafe { libc::waitpid(child, &mut status, 0) };
            if result == child {
                break;
            }
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
    }

    fn close_raw_v1(descriptor: RawFd) {
        if descriptor >= 0 {
            let _ = unsafe { libc::close(descriptor) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    fn seed_token_v1(bytes: &[u8]) -> LinuxVzPackagePostForkSigningSeedV1 {
        let (reader, mut writer) = UnixStream::pair().expect("seed socket pair");
        writer.write_all(bytes).expect("seed bytes");
        writer
            .shutdown(std::net::Shutdown::Write)
            .expect("seed EOF");
        LinuxVzPackagePostForkSigningSeedV1 {
            descriptor: unsafe { OwnedFd::from_raw_fd(reader.into_raw_fd()) },
        }
    }

    #[test]
    fn post_fork_seed_reader_requires_exact_nonzero_bytes_and_eof() {
        let expected = [7_u8; SIGNING_SEED_BYTES_V1];
        let seed = seed_token_v1(&expected).read_once_v1().expect("exact seed");
        assert_eq!(*seed, expected);

        assert_eq!(
            seed_token_v1(&[0_u8; SIGNING_SEED_BYTES_V1]).read_once_v1(),
            Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedInvalid)
        );
        assert_eq!(
            seed_token_v1(&[8_u8; SIGNING_SEED_BYTES_V1 - 1]).read_once_v1(),
            Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed)
        );
        assert_eq!(
            seed_token_v1(&[9_u8; SIGNING_SEED_BYTES_V1 + 1]).read_once_v1(),
            Err(LinuxVzPackageRootCoordinatorErrorV1::SigningSeedInvalid)
        );
    }

    #[test]
    fn coordinator_errors_have_stable_distinct_reason_codes() {
        let variants = [
            LinuxVzPackageRootCoordinatorErrorV1::UnsupportedPlatform,
            LinuxVzPackageRootCoordinatorErrorV1::PrivilegeBoundary,
            LinuxVzPackageRootCoordinatorErrorV1::ThreadBoundary,
            LinuxVzPackageRootCoordinatorErrorV1::SigningSeedDescriptorInvalid,
            LinuxVzPackageRootCoordinatorErrorV1::ControlChannelFailed,
            LinuxVzPackageRootCoordinatorErrorV1::ReadinessChannelFailed,
            LinuxVzPackageRootCoordinatorErrorV1::ForkFailed,
            LinuxVzPackageRootCoordinatorErrorV1::RunnerHardeningFailed,
            LinuxVzPackageRootCoordinatorErrorV1::RunnerReadinessFailed,
            LinuxVzPackageRootCoordinatorErrorV1::SigningSeedReadFailed,
            LinuxVzPackageRootCoordinatorErrorV1::SigningSeedInvalid,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for variant in variants {
            assert!(seen.insert(variant.reason_code()));
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn coordinator_split_is_platform_closed_off_linux() {
        let (reader, _writer) = UnixStream::pair().expect("seed socket pair");
        let result = split_linux_vz_package_root_coordinator_v1(unsafe {
            OwnedFd::from_raw_fd(reader.into_raw_fd())
        });
        assert!(matches!(
            result,
            Err(LinuxVzPackageRootCoordinatorErrorV1::UnsupportedPlatform)
        ));
    }
}
