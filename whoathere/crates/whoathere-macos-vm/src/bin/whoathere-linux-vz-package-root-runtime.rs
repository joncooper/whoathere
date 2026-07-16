#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("whoathere_linux_vz_package_root_runtime_requires_linux");
    std::process::exit(69);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!(
            "WHOATHERE_PACKAGE_ROOT_RUNTIME_FAILED reason={}",
            error.reason_code()
        );
        std::process::exit(error.exit_code());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};
    use whoathere_artifact::Sha256Digest;
    use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
    use whoathere_macos_vm::{
        decode_qualified_macos_linux_vz_telemetry_backend_v1,
        decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
        prepare_linux_vz_package_root_runtime_execution_v1,
        run_linux_vz_package_execution_runtime_qualification_probe_v1,
        run_linux_vz_package_root_runtime_execution_v1,
        structurally_decode_macos_linux_vz_package_authority_request_v1,
        write_linux_vz_package_root_runtime_result_v1,
        LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1, LinuxVzPackageRootRuntimeErrorV1,
        MacosLinuxVzPackageExecutionRuntimeGrantBindingsV1,
        MacosLinuxVzPackageExecutionRuntimeGrantVerifierV1,
        MAX_MACOS_LINUX_VZ_PACKAGE_AUTHORITY_REQUEST_BYTES_V1,
        MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_BYTES_V1,
        MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
    };

    const MAXIMUM_ARTIFACT_BYTES_V1: usize = 256 * 1024 * 1024;
    const MAXIMUM_SCENARIO_BYTES_V1: usize = 4 * 1024 * 1024;
    const MAXIMUM_RUNTIME_QUALIFICATION_RECORD_BYTES_V1: usize = 1024 * 1024;
    const MAXIMUM_SELF_BYTES_V1: u64 = 32 * 1024 * 1024;

    const REQUIRED_DESCRIPTOR_FLAGS_V1: [&str; 13] = [
        "--seed-fd",
        "--backend-identity-fd",
        "--backend-qualification-fd",
        "--authority-request-fd",
        "--execution-grant-fd",
        "--artifact-fd",
        "--scenario-plan-fd",
        "--scenario-template-fd",
        "--guest-evidence-public-key-fd",
        "--host-evidence-public-key-fd",
        "--grant-issuer-public-key-fd",
        "--execution-runtime-qualification-record-fd",
        "--result-fd",
    ];
    const OPTIONAL_BUILD_CLOSURE_FLAG_V1: &str = "--build-closure-fd";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum RuntimeEntrypointErrorV1 {
        Usage,
        PrivilegeBoundary,
        DescriptorBoundary,
        InputInvalid,
        BackendInvalid,
        AuthorityRequestInvalid,
        RuntimeIdentityInvalid,
        QualificationFailed(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1),
        GrantInvalid,
        PreparationFailed,
        ExecutionFailed(LinuxVzPackageRootRuntimeErrorV1),
        ResultFailed,
        OutputFailed,
    }

    impl RuntimeEntrypointErrorV1 {
        pub(super) const fn reason_code(self) -> &'static str {
            match self {
                Self::Usage => "linux_vz_package_root_runtime_usage_invalid",
                Self::PrivilegeBoundary => {
                    "linux_vz_package_root_runtime_privilege_boundary_invalid"
                }
                Self::DescriptorBoundary => {
                    "linux_vz_package_root_runtime_descriptor_boundary_invalid"
                }
                Self::InputInvalid => "linux_vz_package_root_runtime_input_invalid",
                Self::BackendInvalid => "linux_vz_package_root_runtime_backend_invalid",
                Self::AuthorityRequestInvalid => {
                    "linux_vz_package_root_runtime_authority_request_invalid"
                }
                Self::RuntimeIdentityInvalid => "linux_vz_package_root_runtime_identity_invalid",
                Self::QualificationFailed(error) => error.reason_code(),
                Self::GrantInvalid => "linux_vz_package_root_runtime_grant_invalid",
                Self::PreparationFailed => "linux_vz_package_root_runtime_preparation_failed",
                Self::ExecutionFailed(error) => error.reason_code(),
                Self::ResultFailed => "linux_vz_package_root_runtime_result_failed",
                Self::OutputFailed => "linux_vz_package_root_runtime_output_failed",
            }
        }

        pub(super) const fn exit_code(self) -> i32 {
            match self {
                Self::Usage => 64,
                Self::InputInvalid
                | Self::BackendInvalid
                | Self::AuthorityRequestInvalid
                | Self::RuntimeIdentityInvalid
                | Self::QualificationFailed(_)
                | Self::GrantInvalid
                | Self::PreparationFailed => 65,
                Self::PrivilegeBoundary | Self::DescriptorBoundary => 77,
                Self::ExecutionFailed(_) => 70,
                Self::ResultFailed | Self::OutputFailed => 74,
            }
        }
    }

    struct OptionsV1 {
        descriptors: BTreeMap<String, RawFd>,
    }

    impl OptionsV1 {
        fn descriptor(&self, name: &str) -> Result<RawFd, RuntimeEntrypointErrorV1> {
            self.descriptors
                .get(name)
                .copied()
                .ok_or(RuntimeEntrypointErrorV1::Usage)
        }

        fn optional_descriptor(&self, name: &str) -> Option<RawFd> {
            self.descriptors.get(name).copied()
        }
    }

    pub(super) fn run() -> Result<(), RuntimeEntrypointErrorV1> {
        let arguments = std::env::args().collect::<Vec<_>>();
        if arguments
            .get(1)
            .is_some_and(|value| value == "--qualification-probe")
        {
            require_root_v1()?;
            return run_qualification_probe_v1(&arguments);
        }
        require_root_v1()?;
        let options = parse_options_v1(&arguments)?;

        let signing_seed_fd = take_owned_fd_v1(options.descriptor("--seed-fd")?)?;
        let backend_identity = read_regular_input_v1(
            options.descriptor("--backend-identity-fd")?,
            MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
        )?;
        let backend_qualification = read_regular_input_v1(
            options.descriptor("--backend-qualification-fd")?,
            MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
        )?;
        let authority_request_bytes = read_regular_input_v1(
            options.descriptor("--authority-request-fd")?,
            MAX_MACOS_LINUX_VZ_PACKAGE_AUTHORITY_REQUEST_BYTES_V1,
        )?;
        let execution_grant_bytes = read_regular_input_v1(
            options.descriptor("--execution-grant-fd")?,
            MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_BYTES_V1,
        )?;
        let mut artifact = take_regular_input_v1(
            options.descriptor("--artifact-fd")?,
            MAXIMUM_ARTIFACT_BYTES_V1,
        )?;
        let artifact_bytes = read_and_reset_v1(&mut artifact, MAXIMUM_ARTIFACT_BYTES_V1)?;
        let scenario_plan = read_regular_input_v1(
            options.descriptor("--scenario-plan-fd")?,
            MAXIMUM_SCENARIO_BYTES_V1,
        )?;
        let scenario_template = read_regular_input_v1(
            options.descriptor("--scenario-template-fd")?,
            MAXIMUM_SCENARIO_BYTES_V1,
        )?;
        let guest_evidence_public_key =
            read_exact_key_v1(options.descriptor("--guest-evidence-public-key-fd")?)?;
        let host_evidence_public_key =
            read_exact_key_v1(options.descriptor("--host-evidence-public-key-fd")?)?;
        let grant_issuer_public_key =
            read_exact_key_v1(options.descriptor("--grant-issuer-public-key-fd")?)?;
        let runtime_qualification_record = read_regular_input_v1(
            options.descriptor("--execution-runtime-qualification-record-fd")?,
            MAXIMUM_RUNTIME_QUALIFICATION_RECORD_BYTES_V1,
        )?;
        require_canonical_json_v1(&runtime_qualification_record)?;
        let mut result_output = take_result_output_v1(options.descriptor("--result-fd")?)?;
        let build_closure = options
            .optional_descriptor(OPTIONAL_BUILD_CLOSURE_FLAG_V1)
            .map(|descriptor| take_regular_input_v1(descriptor, MAXIMUM_ARTIFACT_BYTES_V1))
            .transpose()?;

        let telemetry_requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
        let unqualified_backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
            &backend_identity,
            &telemetry_requirements,
        )
        .map_err(|_| RuntimeEntrypointErrorV1::BackendInvalid)?;
        let qualified_backend = decode_qualified_macos_linux_vz_telemetry_backend_v1(
            &backend_qualification,
            &unqualified_backend,
        )
        .map_err(|_| RuntimeEntrypointErrorV1::BackendInvalid)?;
        let authority_request = structurally_decode_macos_linux_vz_package_authority_request_v1(
            &authority_request_bytes,
            &qualified_backend,
            &artifact_bytes,
            &scenario_plan,
            &scenario_template,
        )
        .map_err(|_| RuntimeEntrypointErrorV1::AuthorityRequestInvalid)?;
        if self_digest_v1()? != *authority_request.candidate_package_runner_sha256() {
            return Err(RuntimeEntrypointErrorV1::RuntimeIdentityInvalid);
        }

        let bindings = MacosLinuxVzPackageExecutionRuntimeGrantBindingsV1::new(
            Sha256Digest::from_bytes(&runtime_qualification_record),
            Sha256Digest::from_bytes(&guest_evidence_public_key),
            Sha256Digest::from_bytes(&host_evidence_public_key),
            Sha256Digest::from_bytes(&grant_issuer_public_key),
        )
        .map_err(|_| RuntimeEntrypointErrorV1::RuntimeIdentityInvalid)?;
        let grant_verifier = MacosLinuxVzPackageExecutionRuntimeGrantVerifierV1::new(
            bindings,
            grant_issuer_public_key,
        )
        .map_err(|_| RuntimeEntrypointErrorV1::GrantInvalid)?;
        let observed_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeEntrypointErrorV1::GrantInvalid)?
            .as_secs();
        let grant = grant_verifier
            .verify_and_consume(
                execution_grant_bytes,
                &authority_request,
                observed_unix_seconds,
            )
            .map_err(|_| RuntimeEntrypointErrorV1::GrantInvalid)?;
        let prepared = prepare_linux_vz_package_root_runtime_execution_v1(
            &authority_request,
            &grant,
            &artifact_bytes,
            &scenario_plan,
            &scenario_template,
        )
        .map_err(|_| RuntimeEntrypointErrorV1::PreparationFailed)?;
        drop(artifact_bytes);
        let result = run_linux_vz_package_root_runtime_execution_v1(
            prepared,
            signing_seed_fd,
            &qualified_backend,
            guest_evidence_public_key,
            artifact,
            build_closure,
        )
        .map_err(RuntimeEntrypointErrorV1::ExecutionFailed)?;
        write_linux_vz_package_root_runtime_result_v1(&mut result_output, &result)
            .map_err(|_| RuntimeEntrypointErrorV1::ResultFailed)?;
        let mut serial = std::io::stdout().lock();
        serial
            .write_all(b"WHOATHERE_PACKAGE_ROOT_RUNTIME_SUMMARY ")
            .and_then(|()| serial.write_all(result.summary_v1()))
            .and_then(|()| serial.write_all(b"\n"))
            .and_then(|()| serial.flush())
            .map_err(|_| RuntimeEntrypointErrorV1::OutputFailed)
    }

    fn run_qualification_probe_v1(arguments: &[String]) -> Result<(), RuntimeEntrypointErrorV1> {
        if arguments.len() != 8
            || arguments[1] != "--qualification-probe"
            || arguments[2] != "--seed-fd"
            || arguments[4] != "--expected-runtime-sha256"
            || arguments[6] != "--expected-public-key-sha256"
        {
            return Err(RuntimeEntrypointErrorV1::Usage);
        }
        let seed_descriptor = arguments[3]
            .parse::<RawFd>()
            .ok()
            .filter(|value| *value > libc::STDERR_FILENO)
            .filter(|value| arguments[3] == value.to_string())
            .ok_or(RuntimeEntrypointErrorV1::Usage)?;
        let expected_runtime_sha256 =
            Sha256Digest::parse(&arguments[5]).map_err(|_| RuntimeEntrypointErrorV1::Usage)?;
        let expected_public_key_sha256 =
            Sha256Digest::parse(&arguments[7]).map_err(|_| RuntimeEntrypointErrorV1::Usage)?;
        let runtime_sha256 = self_digest_v1()?;
        if runtime_sha256 != expected_runtime_sha256 {
            return Err(RuntimeEntrypointErrorV1::RuntimeIdentityInvalid);
        }
        let evidence = run_linux_vz_package_execution_runtime_qualification_probe_v1(
            take_owned_fd_v1(seed_descriptor)?,
            runtime_sha256,
            &expected_public_key_sha256,
        )
        .map_err(RuntimeEntrypointErrorV1::QualificationFailed)?;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(b"WHOATHERE_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_EVIDENCE ")
            .and_then(|()| stdout.write_all(evidence.canonical_json_v1()))
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush())
            .map_err(|_| RuntimeEntrypointErrorV1::OutputFailed)
    }

    fn require_root_v1() -> Result<(), RuntimeEntrypointErrorV1> {
        if unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0
            || unsafe { libc::getegid() } != 0
        {
            return Err(RuntimeEntrypointErrorV1::PrivilegeBoundary);
        }
        Ok(())
    }

    fn parse_options_v1(arguments: &[String]) -> Result<OptionsV1, RuntimeEntrypointErrorV1> {
        if arguments.len() < 4
            || arguments[1] != "--execute"
            || !(arguments.len() - 2).is_multiple_of(2)
        {
            return Err(RuntimeEntrypointErrorV1::Usage);
        }
        let allowed = REQUIRED_DESCRIPTOR_FLAGS_V1
            .into_iter()
            .chain([OPTIONAL_BUILD_CLOSURE_FLAG_V1])
            .collect::<BTreeSet<_>>();
        let mut descriptors = BTreeMap::new();
        for pair in arguments[2..].chunks_exact(2) {
            let flag = pair[0].as_str();
            let descriptor = pair[1]
                .parse::<RawFd>()
                .ok()
                .filter(|value| *value > libc::STDERR_FILENO)
                .filter(|value| pair[1] == value.to_string())
                .ok_or(RuntimeEntrypointErrorV1::Usage)?;
            if !allowed.contains(flag) || descriptors.insert(flag.to_string(), descriptor).is_some()
            {
                return Err(RuntimeEntrypointErrorV1::Usage);
            }
        }
        if REQUIRED_DESCRIPTOR_FLAGS_V1
            .iter()
            .any(|flag| !descriptors.contains_key(*flag))
            || descriptors.values().copied().collect::<BTreeSet<_>>().len() != descriptors.len()
        {
            return Err(RuntimeEntrypointErrorV1::Usage);
        }
        Ok(OptionsV1 { descriptors })
    }

    fn take_owned_fd_v1(descriptor: RawFd) -> Result<OwnedFd, RuntimeEntrypointErrorV1> {
        set_and_require_cloexec_v1(descriptor)?;
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    fn take_regular_input_v1(
        descriptor: RawFd,
        maximum: usize,
    ) -> Result<File, RuntimeEntrypointErrorV1> {
        set_and_require_cloexec_v1(descriptor)?;
        let file = unsafe { File::from_raw_fd(descriptor) };
        let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let metadata = file
            .metadata()
            .map_err(|_| RuntimeEntrypointErrorV1::DescriptorBoundary)?;
        if maximum == 0
            || access < 0
            || access & libc::O_ACCMODE != libc::O_RDONLY
            || !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o444
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > maximum as u64
        {
            return Err(RuntimeEntrypointErrorV1::DescriptorBoundary);
        }
        Ok(file)
    }

    fn read_regular_input_v1(
        descriptor: RawFd,
        maximum: usize,
    ) -> Result<Vec<u8>, RuntimeEntrypointErrorV1> {
        let mut file = take_regular_input_v1(descriptor, maximum)?;
        read_and_reset_v1(&mut file, maximum)
    }

    fn read_and_reset_v1(
        file: &mut File,
        maximum: usize,
    ) -> Result<Vec<u8>, RuntimeEntrypointErrorV1> {
        file.seek(SeekFrom::Start(0))
            .map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)?;
        let expected = usize::try_from(
            file.metadata()
                .map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)?
                .len(),
        )
        .map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)?;
        let mut bytes = Vec::with_capacity(expected);
        Read::by_ref(file)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)?;
        if bytes.len() != expected || bytes.is_empty() || bytes.len() > maximum {
            return Err(RuntimeEntrypointErrorV1::InputInvalid);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)?;
        Ok(bytes)
    }

    fn read_exact_key_v1(descriptor: RawFd) -> Result<[u8; 32], RuntimeEntrypointErrorV1> {
        let bytes = read_regular_input_v1(descriptor, 32)?;
        bytes
            .try_into()
            .map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)
    }

    fn take_result_output_v1(descriptor: RawFd) -> Result<File, RuntimeEntrypointErrorV1> {
        set_and_require_cloexec_v1(descriptor)?;
        let file = unsafe { File::from_raw_fd(descriptor) };
        let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        if access < 0
            || access & libc::O_ACCMODE != libc::O_WRONLY
            || unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) } != 0
        {
            return Err(RuntimeEntrypointErrorV1::DescriptorBoundary);
        }
        let metadata = unsafe { metadata.assume_init() };
        let kind = metadata.st_mode & libc::S_IFMT;
        if (kind != libc::S_IFIFO && kind != libc::S_IFSOCK)
            || metadata.st_uid != 0
            || metadata.st_gid != 0
        {
            return Err(RuntimeEntrypointErrorV1::DescriptorBoundary);
        }
        Ok(file)
    }

    fn set_and_require_cloexec_v1(descriptor: RawFd) -> Result<(), RuntimeEntrypointErrorV1> {
        let initial = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if initial < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, initial | libc::FD_CLOEXEC) } != 0
        {
            return Err(RuntimeEntrypointErrorV1::DescriptorBoundary);
        }
        let verified = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if verified < 0 || verified & libc::FD_CLOEXEC == 0 {
            return Err(RuntimeEntrypointErrorV1::DescriptorBoundary);
        }
        Ok(())
    }

    fn require_canonical_json_v1(bytes: &[u8]) -> Result<(), RuntimeEntrypointErrorV1> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)?;
        let canonical = serde_json_canonicalizer::to_vec(&value)
            .map_err(|_| RuntimeEntrypointErrorV1::InputInvalid)?;
        if canonical != bytes {
            return Err(RuntimeEntrypointErrorV1::InputInvalid);
        }
        Ok(())
    }

    fn self_digest_v1() -> Result<Sha256Digest, RuntimeEntrypointErrorV1> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")
            .map_err(|_| RuntimeEntrypointErrorV1::RuntimeIdentityInvalid)?;
        let metadata = file
            .metadata()
            .map_err(|_| RuntimeEntrypointErrorV1::RuntimeIdentityInvalid)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.len() == 0
            || metadata.len() > MAXIMUM_SELF_BYTES_V1
        {
            return Err(RuntimeEntrypointErrorV1::RuntimeIdentityInvalid);
        }
        let mut hasher = Sha256::new();
        let mut remaining = metadata.len();
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let requested = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| RuntimeEntrypointErrorV1::RuntimeIdentityInvalid)?;
            file.read_exact(&mut buffer[..requested])
                .map_err(|_| RuntimeEntrypointErrorV1::RuntimeIdentityInvalid)?;
            hasher.update(&buffer[..requested]);
            remaining -= requested as u64;
        }
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| RuntimeEntrypointErrorV1::RuntimeIdentityInvalid)?
            != 0
        {
            return Err(RuntimeEntrypointErrorV1::RuntimeIdentityInvalid);
        }
        let digest = hasher.finalize();
        let text = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Sha256Digest::parse(format!("sha256:{text}"))
            .map_err(|_| RuntimeEntrypointErrorV1::RuntimeIdentityInvalid)
    }
}
