#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("whoathere_linux_vz_runtime_qualification_agent_requires_linux");
    std::process::exit(69);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("WHOATHERE_RUNTIME_QUALIFICATION_FAILED reason={error}");
        std::process::exit(70);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::mem::{size_of, zeroed};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use whoathere_artifact::Sha256Digest;
    use whoathere_macos_vm::{
        decode_linux_vz_package_runtime_qualification_request_v1,
        decode_linux_vz_process_evidence_from_serial_v1,
        decode_macos_linux_vz_package_runtime_qualification_request_v1,
        encode_linux_vz_package_runtime_qualification_response_v1,
        sign_macos_linux_vz_package_runtime_qualification_guest_receipt_v1,
        LinuxVzTelemetryConformanceCaseV1, MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
        MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1,
        MAX_LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_BYTES_V1,
    };
    use zeroize::Zeroize;

    const AGENT_PORT: u32 = 40_554;
    const SEED_PATH: &str = "/whoathere/guest-ed25519.seed";
    const INIT_PATH: &str = "/init";
    const MODULE_BUNDLE_PATH: &str = "/whoathere/runtime-module-bundle.json";
    const RUNTIME_MANIFEST_PATH: &str = "/whoathere/runtime-manifest.json";
    const SENSOR_PATH: &str = "/whoathere/process-sensor-probe";
    const ROOTFS_DEVICE_PATH: &str = "/dev/vda";
    const RUNTIME_MOUNT_PATH: &str = "/runtime";
    const RUNNER_PATH: &str = "/runtime/whoathere/package-runtime-probe";
    const MAX_AGENT_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_INIT_BYTES: u64 = 1024 * 1024;
    const MAX_MODULE_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
    const MAX_RUNNER_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_SENSOR_OUTPUT_BYTES: usize =
        MAX_LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_BYTES_V1 + 32 * 1024;
    const BLKGETSIZE64_IOCTL: libc::c_int = 0x8008_1272_u32 as libc::c_int;
    const EXT2_SUPER_MAGIC: i64 = 0xef53;
    const EXT_SUPERBLOCK_OFFSET: u64 = 1024;
    const EXT_SUPERBLOCK_BYTES: usize = 1024;
    const EXT_MAGIC_OFFSET: usize = 56;
    const EXT_UUID_OFFSET: usize = 104;
    const RUNTIME_MANIFEST_ROOTFS_UUID: &str = "57484f41-5448-4552-5254-554e54494d45";
    const ROOTFS_UUID_BYTES: [u8; 16] = [
        0x57, 0x48, 0x4f, 0x41, 0x54, 0x48, 0x45, 0x52, 0x52, 0x54, 0x55, 0x4e, 0x54, 0x49, 0x4d,
        0x45,
    ];

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RuntimeModuleBundleV1 {
        kernel_release: String,
        modules: Vec<RuntimeModuleV1>,
        schema_version: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RuntimeModuleV1 {
        load_order: String,
        path: String,
        sha256: Sha256Digest,
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
            return Err("runtime_qualification_agent_not_root".into());
        }
        let listener = VsockListener::bind_one_shot(AGENT_PORT)?;
        println!("WHOATHERE_RUNTIME_QUALIFICATION_READY port={AGENT_PORT}");
        let mut stream = listener.accept_host()?;
        let mut request_frame = Vec::new();
        Read::by_ref(&mut stream)
            .take(MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1 as u64 + 1)
            .read_to_end(&mut request_frame)?;
        if request_frame.len() > MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1 {
            return Err("runtime_qualification_request_limit_exceeded".into());
        }
        let request_bytes =
            decode_linux_vz_package_runtime_qualification_request_v1(&request_frame)?;
        let request =
            decode_macos_linux_vz_package_runtime_qualification_request_v1(&request_bytes)?;
        if request.package_execution_authority_permitted() || request.sync_back_permitted() {
            return Err("runtime_qualification_request_authority_invalid".into());
        }

        require_self_digest(request.runtime_qualification_guest_agent_sha256())?;
        require_regular_digest(
            INIT_PATH,
            request.runtime_qualification_guest_init_sha256(),
            MAX_INIT_BYTES,
            0o755,
        )?;
        require_regular_digest(
            SENSOR_PATH,
            request.qualified_protected_sensor_sha256(),
            MAX_AGENT_BYTES,
            0o700,
        )?;
        require_module_bundle(request.runtime_qualification_module_bundle_sha256())?;
        require_runtime_manifest(
            request.candidate_runtime_manifest_sha256(),
            request.candidate_runtime_rootfs_sha256(),
            request.candidate_runtime_rootfs_byte_length(),
            request.candidate_package_runner_sha256(),
            request.package_uid(),
            request.package_gid(),
        )?;
        require_no_external_network_configuration()?;

        let rootfs_sha256 = hash_and_validate_rootfs(
            ROOTFS_DEVICE_PATH,
            request.candidate_runtime_rootfs_byte_length(),
        )?;
        if rootfs_sha256 != *request.candidate_runtime_rootfs_sha256() {
            return Err("runtime_qualification_rootfs_digest_mismatch".into());
        }

        let mut mounted = MountedRoot::mount_read_only()?;
        require_regular_digest(
            RUNNER_PATH,
            request.candidate_package_runner_sha256(),
            MAX_RUNNER_BYTES,
            0o555,
        )?;
        let sensor_output = run_fixed_probe()?;
        mounted.unmount()?;

        let process_evidence = decode_linux_vz_process_evidence_from_serial_v1(&sensor_output)?;
        if process_evidence.fixture_case() != LinuxVzTelemetryConformanceCaseV1::ForkExecExit
            || process_evidence.package_uid() != request.package_uid()
            || process_evidence.package_gid() != request.package_gid()
        {
            return Err("runtime_qualification_process_binding_mismatch".into());
        }
        let process_claims = process_evidence.guest_observation_claims_v1()?;
        let claims = MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1::new(
            &request,
            process_claims,
            MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
            rootfs_sha256,
        )?;
        let seed = read_root_seed(SEED_PATH)?;
        let receipt = sign_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
            &request, &claims, seed,
        )?;
        let response = encode_linux_vz_package_runtime_qualification_response_v1(
            MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
            process_evidence.canonical_json_v1(),
            &receipt,
        )?;
        stream.write_all(&response)?;
        stream.flush()?;
        unsafe {
            libc::shutdown(stream.raw_fd(), libc::SHUT_WR);
        }
        println!(
            "WHOATHERE_RUNTIME_QUALIFICATION_RECEIPT_OK request_sha256={} receipt_sha256={} execution_authority=false package_execution=false sync_back=false",
            request.request_sha256(),
            Sha256Digest::from_bytes(&receipt)
        );
        Ok(())
    }

    fn require_self_digest(expected: &Sha256Digest) -> Result<(), Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.len() == 0
            || metadata.len() > MAX_AGENT_BYTES
        {
            return Err("runtime_qualification_agent_metadata_invalid".into());
        }
        let actual = hash_reader_exact(file, metadata.len())?;
        if actual != *expected {
            return Err("runtime_qualification_agent_digest_mismatch".into());
        }
        Ok(())
    }

    fn require_regular_digest(
        path: &str,
        expected: &Sha256Digest,
        maximum: u64,
        expected_mode: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != expected_mode
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err("runtime_qualification_input_metadata_invalid".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len()
            || bytes.len() as u64 > maximum
            || Sha256Digest::from_bytes(&bytes) != *expected
        {
            return Err("runtime_qualification_input_digest_mismatch".into());
        }
        Ok(bytes)
    }

    fn require_module_bundle(expected: &Sha256Digest) -> Result<(), Box<dyn std::error::Error>> {
        let bytes =
            require_regular_digest(MODULE_BUNDLE_PATH, expected, MAX_MANIFEST_BYTES, 0o400)?;
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let bundle = RuntimeModuleBundleV1::deserialize(&mut deserializer)?;
        deserializer.end()?;
        if serde_json_canonicalizer::to_vec(&bundle)? != bytes
            || bundle.schema_version != "whoathere.linux_vz_runtime_module_bundle.v1"
            || bundle.kernel_release != "6.18.35-0-virt"
        {
            return Err("runtime_qualification_module_bundle_invalid".into());
        }
        let expected_paths = [
            "/whoathere/modules/vsock.ko",
            "/whoathere/modules/vmw_vsock_virtio_transport_common.ko",
            "/whoathere/modules/vmw_vsock_virtio_transport.ko",
            "/whoathere/modules/virtio_blk.ko",
            "/whoathere/modules/crc16.ko",
            "/whoathere/modules/mbcache.ko",
            "/whoathere/modules/jbd2.ko",
            "/whoathere/modules/ext4.ko",
        ];
        if bundle.modules.len() != expected_paths.len() {
            return Err("runtime_qualification_module_bundle_invalid".into());
        }
        for (index, (module, expected_path)) in
            bundle.modules.iter().zip(expected_paths).enumerate()
        {
            if module.load_order != (index + 1).to_string() || module.path != expected_path {
                return Err("runtime_qualification_module_bundle_invalid".into());
            }
            require_regular_digest(expected_path, &module.sha256, MAX_MODULE_BYTES, 0o400)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn require_runtime_manifest(
        expected: &Sha256Digest,
        rootfs_sha256: &Sha256Digest,
        rootfs_byte_length: u64,
        runner_sha256: &Sha256Digest,
        package_uid: u32,
        package_gid: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes =
            require_regular_digest(RUNTIME_MANIFEST_PATH, expected, MAX_MANIFEST_BYTES, 0o400)?;
        let canonical_input = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        if canonical_input.is_empty() || canonical_input.contains(&b'\n') {
            return Err("runtime_qualification_runtime_manifest_noncanonical".into());
        }
        let value: Value = serde_json::from_slice(canonical_input)?;
        if serde_json_canonicalizer::to_vec(&value)? != canonical_input {
            return Err("runtime_qualification_runtime_manifest_noncanonical".into());
        }
        let object = value
            .as_object()
            .ok_or("runtime_qualification_runtime_manifest_invalid")?;
        let string = |key: &str| object.get(key).and_then(Value::as_str);
        let boolean = |key: &str| object.get(key).and_then(Value::as_bool);
        if string("schema_version") != Some("whoathere.linux_vz_package_runtime_manifest.v1")
            || string("candidate_runtime_qualification") != Some("required")
            || string("image_state")
                != Some("candidate_exact_bytes_not_yet_independently_qualified")
            || string("external_network") != Some("structurally_absent")
            || boolean("package_execution") != Some(false)
            || boolean("sync_back") != Some(false)
            || string("rootfs_format") != Some("raw_ext2_block_image_v1")
            || string("rootfs_uuid") != Some(RUNTIME_MANIFEST_ROOTFS_UUID)
            || string("rootfs_sha256") != Some(rootfs_sha256.as_str())
            || string("rootfs_byte_length") != Some(rootfs_byte_length.to_string().as_str())
            || string("package_runner_sha256") != Some(runner_sha256.as_str())
            || string("package_runner_mode")
                != Some("nonexecuting_runtime_probe_with_closed_sensor_alias")
            || string("package_uid") != Some(package_uid.to_string().as_str())
            || string("package_gid") != Some(package_gid.to_string().as_str())
        {
            return Err("runtime_qualification_runtime_manifest_binding_mismatch".into());
        }
        Ok(())
    }

    fn hash_and_validate_rootfs(
        path: &str,
        expected_length: u64,
    ) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_block_device() || metadata.uid() != 0 || metadata.gid() != 0 {
            return Err("runtime_qualification_rootfs_device_invalid".into());
        }
        let mut device_length = 0_u64;
        if unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64_IOCTL, &mut device_length) } != 0
            || device_length != expected_length
        {
            return Err("runtime_qualification_rootfs_device_length_mismatch".into());
        }
        let mut superblock = [0_u8; EXT_SUPERBLOCK_BYTES];
        file.read_exact_at(&mut superblock, EXT_SUPERBLOCK_OFFSET)?;
        if u16::from_le_bytes([
            superblock[EXT_MAGIC_OFFSET],
            superblock[EXT_MAGIC_OFFSET + 1],
        ]) != 0xef53
            || superblock[EXT_UUID_OFFSET..EXT_UUID_OFFSET + 16] != ROOTFS_UUID_BYTES
        {
            return Err("runtime_qualification_rootfs_superblock_invalid".into());
        }
        file.seek(SeekFrom::Start(0))?;
        hash_reader_exact(file, expected_length)
    }

    fn hash_reader_exact(
        mut reader: impl Read,
        expected_length: u64,
    ) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        let mut hasher = Sha256::new();
        let mut remaining = expected_length;
        let mut buffer = vec![0_u8; 1024 * 1024];
        while remaining > 0 {
            let requested = usize::try_from(remaining.min(buffer.len() as u64))?;
            let count = reader.read(&mut buffer[..requested])?;
            if count == 0 {
                return Err("runtime_qualification_stream_truncated".into());
            }
            hasher.update(&buffer[..count]);
            remaining -= count as u64;
        }
        let mut trailing = [0_u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err("runtime_qualification_stream_trailing_bytes".into());
        }
        digest_from_output(&hasher.finalize())
    }

    fn digest_from_output(bytes: &[u8]) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(71);
        value.push_str("sha256:");
        for byte in bytes {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Ok(Sha256Digest::parse(value)?)
    }

    fn run_fixed_probe() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = Command::new(SENSOR_PATH)
            .arg(RUNNER_PATH)
            .arg("fork_exec_exit")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !output.status.success()
            || !output.stderr.is_empty()
            || output.stdout.len() > MAX_SENSOR_OUTPUT_BYTES
            || !output
                .stdout
                .starts_with(MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1)
        {
            return Err("runtime_qualification_fixed_probe_failed".into());
        }
        const REQUIRED_SENSOR_MARKERS: &[u8] = b"WHOATHERE_SENSOR process_cgroup_filter=observed\n\
WHOATHERE_SENSOR process_fork=observed\n\
WHOATHERE_SENSOR process_exec=observed\n\
WHOATHERE_SENSOR process_exit=observed\n\
WHOATHERE_SENSOR unprivileged_fixture=uid_65534_gid_65534\n\
WHOATHERE_SENSOR protected_sensor_read=denied\n\
WHOATHERE_SENSOR protected_sensor_write=denied\n\
WHOATHERE_SENSOR_PROCESS_PROBE_OK\n";
        let sensor_output = &output.stdout[MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1.len()..];
        if !sensor_output.starts_with(REQUIRED_SENSOR_MARKERS) {
            return Err("runtime_qualification_fixed_probe_sensor_markers_invalid".into());
        }
        let evidence = &sensor_output[REQUIRED_SENSOR_MARKERS.len()..];
        if evidence.is_empty() {
            return Err("runtime_qualification_fixed_probe_evidence_empty".into());
        }
        if !evidence.starts_with(b"WHOATHERE_GUEST_PROCESS_EVIDENCE ") {
            return Err("runtime_qualification_fixed_probe_evidence_prefix_invalid".into());
        }
        if !evidence.ends_with(b"\n") {
            return Err("runtime_qualification_fixed_probe_evidence_terminator_invalid".into());
        }
        if evidence.iter().filter(|byte| **byte == b'\n').count() != 1 {
            return Err("runtime_qualification_fixed_probe_evidence_line_count_invalid".into());
        }
        decode_linux_vz_process_evidence_from_serial_v1(evidence)
            .map_err(|_| "runtime_qualification_fixed_probe_evidence_payload_invalid")?;
        Ok(evidence.to_vec())
    }

    fn require_no_external_network_configuration() -> Result<(), Box<dyn std::error::Error>> {
        let ipv4 = read_virtual_bounded_allow_empty("/proc/net/route", 64 * 1024)?;
        let ipv4 = std::str::from_utf8(&ipv4)?;
        for line in ipv4.lines().skip(1) {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.first().copied() != Some("lo") {
                return Err("runtime_qualification_nonloopback_ipv4_route_present".into());
            }
        }
        let ipv6 = read_virtual_bounded_allow_empty("/proc/net/ipv6_route", 64 * 1024)?;
        let ipv6 = std::str::from_utf8(&ipv6)?;
        for line in ipv6.lines() {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.last().copied() != Some("lo") {
                return Err("runtime_qualification_nonloopback_ipv6_route_present".into());
            }
        }
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/etc/resolv.conf")
        {
            Ok(file) => {
                let metadata = file.metadata()?;
                if !metadata.file_type().is_file()
                    || metadata.uid() != 0
                    || metadata.gid() != 0
                    || metadata.len() != 0
                {
                    return Err("runtime_qualification_resolver_configuration_present".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn read_virtual_bounded_allow_empty(
        path: &str,
        maximum: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err("runtime_qualification_virtual_input_invalid".into());
        }
        let mut bytes = Vec::new();
        file.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err("runtime_qualification_virtual_input_limit_exceeded".into());
        }
        Ok(bytes)
    }

    fn read_root_seed(path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(Path::new(path))?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != 32
        {
            return Err("runtime_qualification_seed_metadata_invalid".into());
        }
        let mut bytes = Vec::with_capacity(32);
        file.take(33).read_to_end(&mut bytes)?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err("runtime_qualification_seed_length_invalid".into());
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(seed)
    }

    struct MountedRoot {
        mounted: bool,
    }

    impl MountedRoot {
        fn mount_read_only() -> Result<Self, Box<dyn std::error::Error>> {
            let target_metadata = std::fs::symlink_metadata(RUNTIME_MOUNT_PATH)?;
            if !target_metadata.file_type().is_dir()
                || target_metadata.uid() != 0
                || target_metadata.gid() != 0
                || target_metadata.mode() & 0o777 != 0o700
            {
                return Err("runtime_qualification_mountpoint_invalid".into());
            }
            let source = CString::new(ROOTFS_DEVICE_PATH)?;
            let target = CString::new(RUNTIME_MOUNT_PATH)?;
            let filesystem = CString::new("ext2")?;
            let flags = libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID;
            if unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    filesystem.as_ptr(),
                    flags,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let value = Self { mounted: true };
            value.validate_mount()?;
            Ok(value)
        }

        fn validate_mount(&self) -> Result<(), Box<dyn std::error::Error>> {
            let target = CString::new(RUNTIME_MOUNT_PATH)?;
            let mut filesystem: libc::statfs = unsafe { zeroed() };
            if unsafe { libc::statfs(target.as_ptr(), &mut filesystem) } != 0
                || filesystem.f_type as i64 != EXT2_SUPER_MAGIC
            {
                return Err("runtime_qualification_mounted_filesystem_invalid".into());
            }
            let mountinfo = read_virtual_bounded_allow_empty("/proc/self/mountinfo", 1024 * 1024)?;
            let mountinfo = std::str::from_utf8(&mountinfo)?;
            let mut matches = 0;
            for line in mountinfo.lines() {
                let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
                let Some(separator) = fields.iter().position(|field| *field == "-") else {
                    continue;
                };
                if fields.get(4) != Some(&RUNTIME_MOUNT_PATH) {
                    continue;
                }
                matches += 1;
                let options = fields.get(5).copied().unwrap_or_default();
                let option = |expected: &str| options.split(',').any(|value| value == expected);
                let super_options = fields.get(separator + 3).copied().unwrap_or_default();
                let super_option =
                    |expected: &str| super_options.split(',').any(|value| value == expected);
                if fields.get(separator + 1) != Some(&"ext2")
                    || fields.get(separator + 2) != Some(&ROOTFS_DEVICE_PATH)
                    || !option("ro")
                    || !option("nodev")
                    || !option("nosuid")
                    || option("rw")
                    || !super_option("ro")
                    || super_option("rw")
                {
                    return Err("runtime_qualification_mount_policy_invalid".into());
                }
            }
            if matches != 1 {
                return Err("runtime_qualification_mount_binding_invalid".into());
            }
            Ok(())
        }

        fn unmount(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            if !self.mounted {
                return Err("runtime_qualification_mount_not_active".into());
            }
            let target = CString::new(RUNTIME_MOUNT_PATH)?;
            if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            self.mounted = false;
            Ok(())
        }
    }

    impl Drop for MountedRoot {
        fn drop(&mut self) {
            if self.mounted {
                if let Ok(target) = CString::new(RUNTIME_MOUNT_PATH) {
                    unsafe {
                        libc::umount2(target.as_ptr(), 0);
                    }
                }
            }
        }
    }

    struct VsockListener(RawFd);

    impl VsockListener {
        fn bind_one_shot(port: u32) -> Result<Self, Box<dyn std::error::Error>> {
            let descriptor =
                unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let listener = Self(descriptor);
            let address = libc::sockaddr_vm {
                svm_family: libc::AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: libc::VMADDR_CID_ANY,
                svm_zero: [0; 4],
            };
            if unsafe {
                libc::bind(
                    descriptor,
                    (&address as *const libc::sockaddr_vm).cast(),
                    size_of::<libc::sockaddr_vm>() as libc::socklen_t,
                )
            } != 0
                || unsafe { libc::listen(descriptor, 1) } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(listener)
        }

        fn accept_host(&self) -> Result<VsockStream, Box<dyn std::error::Error>> {
            let descriptor = unsafe {
                libc::accept4(
                    self.0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let stream = VsockStream(unsafe { File::from_raw_fd(descriptor) });
            stream.require_host_peer()?;
            stream.set_timeouts()?;
            Ok(stream)
        }
    }

    impl Drop for VsockListener {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    struct VsockStream(File);

    impl VsockStream {
        fn raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }

        fn require_host_peer(&self) -> Result<(), Box<dyn std::error::Error>> {
            let mut address: libc::sockaddr_vm = unsafe { zeroed() };
            let mut length = size_of::<libc::sockaddr_vm>() as libc::socklen_t;
            if unsafe {
                libc::getpeername(
                    self.raw_fd(),
                    (&mut address as *mut libc::sockaddr_vm).cast(),
                    &mut length,
                )
            } != 0
                || length as usize != size_of::<libc::sockaddr_vm>()
                || address.svm_family != libc::AF_VSOCK as libc::sa_family_t
                || address.svm_cid != libc::VMADDR_CID_HOST
            {
                return Err("runtime_qualification_peer_not_host".into());
            }
            Ok(())
        }

        fn set_timeouts(&self) -> Result<(), Box<dyn std::error::Error>> {
            let timeout = libc::timeval {
                tv_sec: 30,
                tv_usec: 0,
            };
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                if unsafe {
                    libc::setsockopt(
                        self.raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&timeout as *const libc::timeval).cast(),
                        size_of::<libc::timeval>() as libc::socklen_t,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            Ok(())
        }
    }

    impl Read for VsockStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl Write for VsockStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
}
