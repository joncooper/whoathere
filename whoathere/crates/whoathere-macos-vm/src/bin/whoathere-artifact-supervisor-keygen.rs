use ed25519_dalek::SigningKey;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Artifact,
    Wheel,
    Sdist,
}

impl KeyKind {
    fn compiled() -> Result<Self, &'static str> {
        match env!("CARGO_BIN_NAME") {
            "whoathere-artifact-supervisor-keygen" => Ok(Self::Artifact),
            "whoathere-wheel-supervisor-keygen" => Ok(Self::Wheel),
            "whoathere-sdist-supervisor-keygen" => Ok(Self::Sdist),
            _ => Err("guest_supervisor_keygen_binary_identity_invalid"),
        }
    }

    const fn seed_name(self) -> &'static str {
        match self {
            Self::Artifact => "artifact-supervisor-ed25519.seed",
            Self::Wheel => "wheel-supervisor-ed25519.seed",
            Self::Sdist => "sdist-supervisor-ed25519.seed",
        }
    }

    const fn public_key_name(self) -> &'static str {
        match self {
            Self::Artifact => "artifact-supervisor-public-key.bin",
            Self::Wheel => "wheel-supervisor-public-key.bin",
            Self::Sdist => "sdist-supervisor-public-key.bin",
        }
    }

    const fn reason(
        self,
        artifact: &'static str,
        wheel: &'static str,
        sdist: &'static str,
    ) -> &'static str {
        match self {
            Self::Artifact => artifact,
            Self::Wheel => wheel,
            Self::Sdist => sdist,
        }
    }
}

fn main() {
    if let Err(reason) = run() {
        eprintln!("{reason}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), &'static str> {
    let kind = KeyKind::compiled()?;
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let output = arguments.next().ok_or(kind.reason(
        "artifact_supervisor_keygen_output_required",
        "wheel_supervisor_keygen_output_required",
        "sdist_supervisor_keygen_output_required",
    ))?;
    if arguments.next().is_some() {
        return Err(kind.reason(
            "artifact_supervisor_keygen_arguments_invalid",
            "wheel_supervisor_keygen_arguments_invalid",
            "sdist_supervisor_keygen_arguments_invalid",
        ));
    }
    generate_key_pair(Path::new(&output), kind).map_err(|_| {
        kind.reason(
            "artifact_supervisor_keygen_failed",
            "wheel_supervisor_keygen_failed",
            "sdist_supervisor_keygen_failed",
        )
    })
}

fn generate_key_pair(output: &Path, kind: KeyKind) -> io::Result<()> {
    let metadata = fs::symlink_metadata(output)?;
    if !output.is_absolute()
        || !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::other("key output directory unsafe"));
    }
    let seed_path = output.join(kind.seed_name());
    let public_key_path = output.join(kind.public_key_name());
    if fs::symlink_metadata(&seed_path).is_ok() || fs::symlink_metadata(&public_key_path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "key output already exists",
        ));
    }

    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| io::Error::other("key entropy unavailable"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let result = write_new_key_file(&seed_path, &seed, 0o600)
        .and_then(|()| write_new_key_file(&public_key_path, &public_key, 0o600));
    seed.zeroize();
    if result.is_err() {
        let _ = fs::remove_file(&seed_path);
        let _ = fs::remove_file(&public_key_path);
        return result;
    }
    Ok(())
}

fn write_new_key_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != mode
        || metadata.len() != bytes.len() as u64
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err(io::Error::other("key output verification failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn keygen_writes_one_matching_pair_and_refuses_overwrite() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "whoathere-artifact-keygen-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create keygen root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect keygen root");
        generate_key_pair(&root, KeyKind::Artifact).expect("generate key pair");
        let mut seed = fs::read(root.join(KeyKind::Artifact.seed_name())).expect("read seed");
        let public_key =
            fs::read(root.join(KeyKind::Artifact.public_key_name())).expect("read public key");
        assert_eq!(seed.len(), 32);
        assert_eq!(public_key.len(), 32);
        let seed_array: [u8; 32] = seed.as_slice().try_into().expect("seed array");
        assert_eq!(
            SigningKey::from_bytes(&seed_array)
                .verifying_key()
                .to_bytes()
                .as_slice(),
            public_key
        );
        assert!(generate_key_pair(&root, KeyKind::Artifact).is_err());
        seed.zeroize();
        fs::remove_file(root.join(KeyKind::Artifact.seed_name())).expect("remove seed");
        fs::remove_file(root.join(KeyKind::Artifact.public_key_name())).expect("remove public key");
        generate_key_pair(&root, KeyKind::Wheel).expect("generate wheel key pair");
        assert!(root.join(KeyKind::Wheel.seed_name()).is_file());
        assert!(root.join(KeyKind::Wheel.public_key_name()).is_file());
        fs::remove_file(root.join(KeyKind::Wheel.seed_name())).expect("remove wheel seed");
        fs::remove_file(root.join(KeyKind::Wheel.public_key_name()))
            .expect("remove wheel public key");
        generate_key_pair(&root, KeyKind::Sdist).expect("generate sdist key pair");
        assert!(root.join(KeyKind::Sdist.seed_name()).is_file());
        assert!(root.join(KeyKind::Sdist.public_key_name()).is_file());
        fs::remove_file(root.join(KeyKind::Sdist.seed_name())).expect("remove sdist seed");
        fs::remove_file(root.join(KeyKind::Sdist.public_key_name()))
            .expect("remove sdist public key");
        fs::remove_dir(root).expect("remove keygen root");
    }
}
