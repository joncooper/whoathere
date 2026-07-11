use ed25519_dalek::SigningKey;
use whoathere_artifact::Sha256Digest;
use whoathere_macos_vm::{
    sign_macos_artifact_guest_auth_response_v1, MacosArtifactGuestAuthChallengeV1,
    MacosArtifactGuestAuthClaimsV1,
};

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [7_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let challenge = MacosArtifactGuestAuthChallengeV1::new(
        [9_u8; 32],
        digest(b"execution binding"),
        digest(b"run spec"),
        digest(b"clone binding"),
        Sha256Digest::from_bytes(&verifying_key),
    )?;
    let claims = MacosArtifactGuestAuthClaimsV1::new(
        digest(b"guest supervisor"),
        digest(b"runner configuration"),
        502,
        502,
    )?;
    let response = sign_macos_artifact_guest_auth_response_v1(&challenge, seed, &claims)?;
    println!("{}", std::str::from_utf8(challenge.canonical_json_v1())?);
    println!("{}", std::str::from_utf8(&response)?);
    Ok(())
}
