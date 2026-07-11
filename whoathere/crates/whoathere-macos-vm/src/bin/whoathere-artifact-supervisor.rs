#[cfg(target_os = "macos")]
mod macos {
    use serde::{Deserialize, Serialize};
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::mem;
    use std::os::fd::RawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use whoathere_artifact::Sha256Digest;
    use whoathere_macos_vm::{
        run_macos_artifact_guest_nonexecuting_session_v1, MacosArtifactGuestAuthClaimsV1,
        MacosArtifactGuestStagingPolicyV1,
    };
    use zeroize::Zeroizing;

    const CONFIG_SCHEMA_V1: &str = "whoathere.artifact_guest_supervisor_config.v1";
    const CONFIG_PATH: &str = "/Library/Application Support/WhoaThere/artifact-supervisor.json";
    const SIGNING_SEED_PATH: &str =
        "/Library/Application Support/WhoaThere/artifact-supervisor-ed25519.seed";
    const STAGING_ROOT: &str = "/var/db/whoathere/artifact-staging";
    const ARTIFACT_VSOCK_PORT: u32 = 47_079;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    const SESSION_TIMEOUT: Duration = Duration::from_secs(90);
    const MAX_CONFIG_BYTES: usize = 4 * 1024;
    const MAX_SUPERVISOR_BYTES: usize = 64 * 1024 * 1024;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SupervisorConfigWireV1 {
        schema_version: String,
        package_uid: String,
        package_gid: String,
    }

    struct SupervisorConfigV1 {
        package_uid: u32,
        package_gid: u32,
        canonical_sha256: Sha256Digest,
    }

    struct VsockConnection {
        descriptor: RawFd,
    }

    impl VsockConnection {
        fn connect_host(port: u32, timeout: Duration) -> io::Result<Self> {
            let descriptor = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut connection = Self { descriptor };
            connection.set_close_on_exec()?;
            connection.set_nonblocking(true)?;

            let mut address: libc::sockaddr_vm = unsafe { mem::zeroed() };
            address.svm_len = u8::try_from(mem::size_of::<libc::sockaddr_vm>())
                .map_err(|_| io::Error::other("artifact supervisor socket address invalid"))?;
            address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            address.svm_port = port;
            address.svm_cid = libc::VMADDR_CID_HOST;
            let result = unsafe {
                libc::connect(
                    descriptor,
                    (&raw const address).cast::<libc::sockaddr>(),
                    mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINPROGRESS) {
                    return Err(error);
                }
                poll_descriptor(descriptor, libc::POLLOUT, Instant::now() + timeout)?;
                let mut socket_error = 0_i32;
                let mut length = mem::size_of::<i32>() as libc::socklen_t;
                if unsafe {
                    libc::getsockopt(
                        descriptor,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&raw mut socket_error).cast(),
                        &mut length,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if socket_error != 0 {
                    return Err(io::Error::from_raw_os_error(socket_error));
                }
            }
            Ok(connection)
        }

        fn set_close_on_exec(&mut self) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(self.descriptor, libc::F_GETFD) };
            if flags < 0
                || unsafe { libc::fcntl(self.descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) }
                    < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn set_nonblocking(&mut self, enabled: bool) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(self.descriptor, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let updated = if enabled {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            if unsafe { libc::fcntl(self.descriptor, libc::F_SETFL, updated) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn shutdown_write(&self) -> io::Result<()> {
            if unsafe { libc::shutdown(self.descriptor, libc::SHUT_WR) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for VsockConnection {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.descriptor);
            }
        }
    }

    struct DeadlineReader {
        descriptor: RawFd,
        deadline: Instant,
    }

    impl Read for DeadlineReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            loop {
                poll_descriptor(self.descriptor, libc::POLLIN | libc::POLLHUP, self.deadline)?;
                let count = unsafe {
                    libc::recv(self.descriptor, buffer.as_mut_ptr().cast(), buffer.len(), 0)
                };
                if count >= 0 {
                    return Ok(count as usize);
                }
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted
                    || error.kind() == io::ErrorKind::WouldBlock
                {
                    continue;
                }
                return Err(error);
            }
        }
    }

    struct DeadlineWriter {
        descriptor: RawFd,
        deadline: Instant,
    }

    impl Write for DeadlineWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            loop {
                poll_descriptor(self.descriptor, libc::POLLOUT, self.deadline)?;
                let count = unsafe {
                    libc::send(
                        self.descriptor,
                        buffer.as_ptr().cast(),
                        buffer.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if count >= 0 {
                    return Ok(count as usize);
                }
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted
                    || error.kind() == io::ErrorKind::WouldBlock
                {
                    continue;
                }
                return Err(error);
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn poll_descriptor(descriptor: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "artifact supervisor deadline exceeded",
                ));
            }
            let remaining = deadline.duration_since(now);
            let millis = remaining.as_millis().min(i32::MAX as u128).max(1) as i32;
            let mut descriptor = libc::pollfd {
                fd: descriptor,
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if result > 0 {
                if descriptor.revents & libc::POLLNVAL != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "artifact supervisor socket invalid",
                    ));
                }
                if descriptor.revents & libc::POLLERR != 0 {
                    return Err(io::Error::other("artifact supervisor socket error"));
                }
                if descriptor.revents & (events | libc::POLLHUP) != 0 {
                    return Ok(());
                }
                continue;
            }
            if result == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "artifact supervisor deadline exceeded",
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    pub fn run() -> Result<(), &'static str> {
        if std::env::args_os().len() != 1 {
            return Err("artifact_guest_supervisor_arguments_rejected");
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err("artifact_guest_supervisor_root_required");
        }
        let config_bytes =
            read_trusted_file(Path::new(CONFIG_PATH), 0, MAX_CONFIG_BYTES, Some(0o400))
                .map_err(|_| "artifact_guest_supervisor_config_untrusted")?;
        let config =
            decode_config(&config_bytes).map_err(|_| "artifact_guest_supervisor_config_invalid")?;
        let seed_bytes = Zeroizing::new(
            read_trusted_file(Path::new(SIGNING_SEED_PATH), 0, 32, Some(0o400))
                .map_err(|_| "artifact_guest_supervisor_key_untrusted")?,
        );
        let seed_array: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "artifact_guest_supervisor_key_invalid")?;
        let signing_seed = Zeroizing::new(seed_array);
        let executable = std::env::current_exe()
            .map_err(|_| "artifact_guest_supervisor_identity_unavailable")?;
        let supervisor_bytes = read_trusted_file(&executable, 0, MAX_SUPERVISOR_BYTES, None)
            .map_err(|_| "artifact_guest_supervisor_identity_untrusted")?;
        let claims = MacosArtifactGuestAuthClaimsV1::new(
            Sha256Digest::from_bytes(&supervisor_bytes),
            config.canonical_sha256,
            config.package_uid,
            config.package_gid,
        )
        .map_err(|_| "artifact_guest_supervisor_claims_invalid")?;
        let policy = MacosArtifactGuestStagingPolicyV1::for_current_supervisor(
            PathBuf::from(STAGING_ROOT),
            config.package_uid,
        )
        .map_err(|_| "artifact_guest_supervisor_staging_policy_invalid")?;
        let connection = VsockConnection::connect_host(ARTIFACT_VSOCK_PORT, CONNECT_TIMEOUT)
            .map_err(|_| "artifact_guest_supervisor_vsock_connect_failed")?;
        let deadline = Instant::now() + SESSION_TIMEOUT;
        let mut reader = DeadlineReader {
            descriptor: connection.descriptor,
            deadline,
        };
        let mut writer = DeadlineWriter {
            descriptor: connection.descriptor,
            deadline,
        };
        run_macos_artifact_guest_nonexecuting_session_v1(
            &mut reader,
            &mut writer,
            *signing_seed,
            &claims,
            &policy,
        )
        .map_err(|failure| failure.reason_code())?;
        connection
            .shutdown_write()
            .map_err(|_| "artifact_guest_supervisor_shutdown_failed")?;
        Ok(())
    }

    fn decode_config(bytes: &[u8]) -> Result<SupervisorConfigV1, ()> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let wire = SupervisorConfigWireV1::deserialize(&mut deserializer).map_err(|_| ())?;
        deserializer.end().map_err(|_| ())?;
        let canonical = serde_json_canonicalizer::to_vec(&wire).map_err(|_| ())?;
        if canonical != bytes || wire.schema_version != CONFIG_SCHEMA_V1 {
            return Err(());
        }
        let package_uid = canonical_nonzero_u32(&wire.package_uid).ok_or(())?;
        let package_gid = canonical_nonzero_u32(&wire.package_gid).ok_or(())?;
        Ok(SupervisorConfigV1 {
            package_uid,
            package_gid,
            canonical_sha256: Sha256Digest::from_bytes(bytes),
        })
    }

    fn canonical_nonzero_u32(value: &str) -> Option<u32> {
        if value.is_empty()
            || value.len() > 10
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let parsed = value.parse::<u32>().ok()?;
        (parsed != 0).then_some(parsed)
    }

    fn read_trusted_file(
        path: &Path,
        expected_uid: u32,
        maximum_bytes: usize,
        exact_mode: Option<u32>,
    ) -> io::Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let descriptor = file.metadata()?;
        let path_before = fs::symlink_metadata(path)?;
        validate_file_metadata(&descriptor, expected_uid, maximum_bytes, exact_mode)?;
        validate_file_metadata(&path_before, expected_uid, maximum_bytes, exact_mode)?;
        if descriptor.dev() != path_before.dev() || descriptor.ino() != path_before.ino() {
            return Err(io::Error::other("trusted file identity changed"));
        }
        let capacity = usize::try_from(descriptor.len())
            .map_err(|_| io::Error::other("trusted file too large"))?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > maximum_bytes || bytes.len() != capacity {
            return Err(io::Error::other("trusted file length changed"));
        }
        let descriptor_after = file.metadata()?;
        let path_after = fs::symlink_metadata(path)?;
        validate_file_metadata(&descriptor_after, expected_uid, maximum_bytes, exact_mode)?;
        validate_file_metadata(&path_after, expected_uid, maximum_bytes, exact_mode)?;
        if descriptor.dev() != descriptor_after.dev()
            || descriptor.ino() != descriptor_after.ino()
            || descriptor.len() != descriptor_after.len()
            || descriptor_after.dev() != path_after.dev()
            || descriptor_after.ino() != path_after.ino()
        {
            return Err(io::Error::other("trusted file changed during read"));
        }
        Ok(bytes)
    }

    fn validate_file_metadata(
        metadata: &fs::Metadata,
        expected_uid: u32,
        maximum_bytes: usize,
        exact_mode: Option<u32>,
    ) -> io::Result<()> {
        let mode = metadata.mode() & 0o777;
        if !metadata.file_type().is_file()
            || metadata.uid() != expected_uid
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > maximum_bytes as u64
            || mode & 0o022 != 0
            || exact_mode.is_some_and(|expected| mode != expected)
        {
            return Err(io::Error::other("trusted file metadata invalid"));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::SigningKey;

        #[test]
        fn supervisor_config_is_closed_canonical_and_nonzero() {
            let bytes = br#"{"package_gid":"502","package_uid":"502","schema_version":"whoathere.artifact_guest_supervisor_config.v1"}"#;
            let decoded = decode_config(bytes).expect("valid config");
            assert_eq!(decoded.package_uid, 502);
            assert_eq!(decoded.package_gid, 502);
            assert_eq!(decoded.canonical_sha256, Sha256Digest::from_bytes(bytes));

            let mut noncanonical = b" ".to_vec();
            noncanonical.extend_from_slice(bytes);
            assert!(decode_config(&noncanonical).is_err());
            let zero = br#"{"package_gid":"502","package_uid":"0","schema_version":"whoathere.artifact_guest_supervisor_config.v1"}"#;
            assert!(decode_config(zero).is_err());
            let unknown = br#"{"extra":false,"package_gid":"502","package_uid":"502","schema_version":"whoathere.artifact_guest_supervisor_config.v1"}"#;
            assert!(decode_config(unknown).is_err());
        }

        #[test]
        fn configured_seed_derives_a_real_ed25519_key() {
            let seed = Zeroizing::new([7_u8; 32]);
            let key = SigningKey::from_bytes(&seed);
            assert_eq!(key.verifying_key().to_bytes().len(), 32);
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(reason) = macos::run() {
        eprintln!("{reason}");
        std::process::exit(70);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("artifact_guest_supervisor_macos_required");
    std::process::exit(70);
}
