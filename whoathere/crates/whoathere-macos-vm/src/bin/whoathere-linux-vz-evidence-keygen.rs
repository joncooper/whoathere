use ed25519_dalek::SigningKey;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroize;

fn main() {
    if run().is_err() {
        eprintln!("whoathere_linux_vz_evidence_keygen_failed");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 2 || !arguments[1].starts_with('/') {
        return Err("absolute protected output directory required".into());
    }
    let root = Path::new(&arguments[1]);
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("unsafe key output directory".into());
    }
    generate_pair(root, "guest")?;
    if let Err(error) = generate_pair(root, "host") {
        for name in ["guest-ed25519.seed", "guest-ed25519-public-key.bin"] {
            let _ = fs::remove_file(root.join(name));
        }
        return Err(error);
    }
    Ok(())
}

fn generate_pair(root: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public = signing_key.verifying_key().to_bytes();
    let seed_path = root.join(format!("{label}-ed25519.seed"));
    let public_path = root.join(format!("{label}-ed25519-public-key.bin"));
    let result = write_new(&seed_path, &seed).and_then(|()| write_new(&public_path, &public));
    seed.zeroize();
    if result.is_err() {
        let _ = fs::remove_file(seed_path);
        let _ = fs::remove_file(public_path);
    }
    result.map_err(Into::into)
}

fn write_new(path: &Path, value: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(value)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 32
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err(std::io::Error::other("key file verification failed"));
    }
    Ok(())
}
