use std::fmt;

pub const LINUX_VZ_GUEST_SIGNER_REQUEST_MAGIC_V1: &[u8; 8] = b"WHVZGSQ1";
pub const LINUX_VZ_GUEST_SIGNER_RESPONSE_MAGIC_V1: &[u8; 8] = b"WHVZGSP1";
pub const MAX_LINUX_VZ_GUEST_SIGNER_RUN_SPEC_BYTES_V1: usize = 256 * 1024;
pub const MAX_LINUX_VZ_GUEST_SIGNER_CHALLENGE_BYTES_V1: usize = 64 * 1024;
pub const MAX_LINUX_VZ_GUEST_SIGNER_RECEIPT_BYTES_V1: usize = 1024 * 1024;
pub const MAX_LINUX_VZ_GUEST_SIGNER_REQUEST_FRAME_BYTES_V1: usize =
    16 + MAX_LINUX_VZ_GUEST_SIGNER_RUN_SPEC_BYTES_V1 + MAX_LINUX_VZ_GUEST_SIGNER_CHALLENGE_BYTES_V1;
pub const MAX_LINUX_VZ_GUEST_SIGNER_RESPONSE_FRAME_BYTES_V1: usize =
    12 + MAX_LINUX_VZ_GUEST_SIGNER_RECEIPT_BYTES_V1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzGuestSignerTransportErrorV1 {
    Empty,
    LimitExceeded,
    InvalidMagic,
    InvalidLength,
    TrailingBytes,
}

impl fmt::Display for LinuxVzGuestSignerTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Empty => "linux_vz_guest_signer_transport_empty",
            Self::LimitExceeded => "linux_vz_guest_signer_transport_limit_exceeded",
            Self::InvalidMagic => "linux_vz_guest_signer_transport_magic_invalid",
            Self::InvalidLength => "linux_vz_guest_signer_transport_length_invalid",
            Self::TrailingBytes => "linux_vz_guest_signer_transport_trailing_bytes",
        };
        formatter.write_str(value)
    }
}

impl std::error::Error for LinuxVzGuestSignerTransportErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzGuestSignerRequestV1 {
    run_spec: Vec<u8>,
    challenge: Vec<u8>,
}

impl LinuxVzGuestSignerRequestV1 {
    pub fn run_spec(&self) -> &[u8] {
        &self.run_spec
    }

    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }
}

pub fn encode_linux_vz_guest_signer_request_v1(
    run_spec: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>, LinuxVzGuestSignerTransportErrorV1> {
    validate_nonempty_length_v1(run_spec.len(), MAX_LINUX_VZ_GUEST_SIGNER_RUN_SPEC_BYTES_V1)?;
    validate_nonempty_length_v1(
        challenge.len(),
        MAX_LINUX_VZ_GUEST_SIGNER_CHALLENGE_BYTES_V1,
    )?;
    let mut frame = Vec::with_capacity(16 + run_spec.len() + challenge.len());
    frame.extend_from_slice(LINUX_VZ_GUEST_SIGNER_REQUEST_MAGIC_V1);
    frame.extend_from_slice(&(run_spec.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(challenge.len() as u32).to_be_bytes());
    frame.extend_from_slice(run_spec);
    frame.extend_from_slice(challenge);
    Ok(frame)
}

pub fn decode_linux_vz_guest_signer_request_v1(
    frame: &[u8],
) -> Result<LinuxVzGuestSignerRequestV1, LinuxVzGuestSignerTransportErrorV1> {
    if frame.is_empty() {
        return Err(LinuxVzGuestSignerTransportErrorV1::Empty);
    }
    if frame.len() > MAX_LINUX_VZ_GUEST_SIGNER_REQUEST_FRAME_BYTES_V1 {
        return Err(LinuxVzGuestSignerTransportErrorV1::LimitExceeded);
    }
    if frame.len() < 16 || &frame[..8] != LINUX_VZ_GUEST_SIGNER_REQUEST_MAGIC_V1 {
        return Err(LinuxVzGuestSignerTransportErrorV1::InvalidMagic);
    }
    let run_spec_length = u32::from_be_bytes(
        frame[8..12]
            .try_into()
            .map_err(|_| LinuxVzGuestSignerTransportErrorV1::InvalidLength)?,
    ) as usize;
    let challenge_length = u32::from_be_bytes(
        frame[12..16]
            .try_into()
            .map_err(|_| LinuxVzGuestSignerTransportErrorV1::InvalidLength)?,
    ) as usize;
    validate_nonempty_length_v1(run_spec_length, MAX_LINUX_VZ_GUEST_SIGNER_RUN_SPEC_BYTES_V1)?;
    validate_nonempty_length_v1(
        challenge_length,
        MAX_LINUX_VZ_GUEST_SIGNER_CHALLENGE_BYTES_V1,
    )?;
    let expected = 16_usize
        .checked_add(run_spec_length)
        .and_then(|value| value.checked_add(challenge_length))
        .ok_or(LinuxVzGuestSignerTransportErrorV1::InvalidLength)?;
    if frame.len() < expected {
        return Err(LinuxVzGuestSignerTransportErrorV1::InvalidLength);
    }
    if frame.len() > expected {
        return Err(LinuxVzGuestSignerTransportErrorV1::TrailingBytes);
    }
    Ok(LinuxVzGuestSignerRequestV1 {
        run_spec: frame[16..16 + run_spec_length].to_vec(),
        challenge: frame[16 + run_spec_length..expected].to_vec(),
    })
}

pub fn encode_linux_vz_guest_signer_response_v1(
    receipt: &[u8],
) -> Result<Vec<u8>, LinuxVzGuestSignerTransportErrorV1> {
    validate_nonempty_length_v1(receipt.len(), MAX_LINUX_VZ_GUEST_SIGNER_RECEIPT_BYTES_V1)?;
    let mut frame = Vec::with_capacity(12 + receipt.len());
    frame.extend_from_slice(LINUX_VZ_GUEST_SIGNER_RESPONSE_MAGIC_V1);
    frame.extend_from_slice(&(receipt.len() as u32).to_be_bytes());
    frame.extend_from_slice(receipt);
    Ok(frame)
}

pub fn decode_linux_vz_guest_signer_response_v1(
    frame: &[u8],
) -> Result<Vec<u8>, LinuxVzGuestSignerTransportErrorV1> {
    if frame.is_empty() {
        return Err(LinuxVzGuestSignerTransportErrorV1::Empty);
    }
    if frame.len() > MAX_LINUX_VZ_GUEST_SIGNER_RESPONSE_FRAME_BYTES_V1 {
        return Err(LinuxVzGuestSignerTransportErrorV1::LimitExceeded);
    }
    if frame.len() < 12 || &frame[..8] != LINUX_VZ_GUEST_SIGNER_RESPONSE_MAGIC_V1 {
        return Err(LinuxVzGuestSignerTransportErrorV1::InvalidMagic);
    }
    let receipt_length = u32::from_be_bytes(
        frame[8..12]
            .try_into()
            .map_err(|_| LinuxVzGuestSignerTransportErrorV1::InvalidLength)?,
    ) as usize;
    validate_nonempty_length_v1(receipt_length, MAX_LINUX_VZ_GUEST_SIGNER_RECEIPT_BYTES_V1)?;
    let expected = 12_usize
        .checked_add(receipt_length)
        .ok_or(LinuxVzGuestSignerTransportErrorV1::InvalidLength)?;
    if frame.len() < expected {
        return Err(LinuxVzGuestSignerTransportErrorV1::InvalidLength);
    }
    if frame.len() > expected {
        return Err(LinuxVzGuestSignerTransportErrorV1::TrailingBytes);
    }
    Ok(frame[12..expected].to_vec())
}

fn validate_nonempty_length_v1(
    length: usize,
    maximum: usize,
) -> Result<(), LinuxVzGuestSignerTransportErrorV1> {
    if length == 0 {
        return Err(LinuxVzGuestSignerTransportErrorV1::Empty);
    }
    if length > maximum || length > u32::MAX as usize {
        return Err(LinuxVzGuestSignerTransportErrorV1::LimitExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_frames_round_trip_exact_bytes() {
        let request = encode_linux_vz_guest_signer_request_v1(b"run-spec", b"challenge")
            .expect("request frame");
        let decoded = decode_linux_vz_guest_signer_request_v1(&request).expect("request decode");
        assert_eq!(decoded.run_spec(), b"run-spec");
        assert_eq!(decoded.challenge(), b"challenge");

        let response =
            encode_linux_vz_guest_signer_response_v1(b"receipt").expect("response frame");
        assert_eq!(
            decode_linux_vz_guest_signer_response_v1(&response).expect("response decode"),
            b"receipt"
        );
    }

    #[test]
    fn transport_rejects_empty_truncated_and_trailing_frames() {
        assert_eq!(
            decode_linux_vz_guest_signer_request_v1(&[]),
            Err(LinuxVzGuestSignerTransportErrorV1::Empty)
        );
        let request =
            encode_linux_vz_guest_signer_request_v1(b"run", b"challenge").expect("request frame");
        assert_eq!(
            decode_linux_vz_guest_signer_request_v1(&request[..request.len() - 1]),
            Err(LinuxVzGuestSignerTransportErrorV1::InvalidLength)
        );
        let mut trailing = request;
        trailing.push(0);
        assert_eq!(
            decode_linux_vz_guest_signer_request_v1(&trailing),
            Err(LinuxVzGuestSignerTransportErrorV1::TrailingBytes)
        );

        let response =
            encode_linux_vz_guest_signer_response_v1(b"receipt").expect("response frame");
        assert_eq!(
            decode_linux_vz_guest_signer_response_v1(&response[..response.len() - 1]),
            Err(LinuxVzGuestSignerTransportErrorV1::InvalidLength)
        );
    }

    #[test]
    fn transport_rejects_wrong_magic_and_declared_limits() {
        let mut request =
            encode_linux_vz_guest_signer_request_v1(b"run", b"challenge").expect("request frame");
        request[0] ^= 1;
        assert_eq!(
            decode_linux_vz_guest_signer_request_v1(&request),
            Err(LinuxVzGuestSignerTransportErrorV1::InvalidMagic)
        );

        let mut oversized = Vec::from(*LINUX_VZ_GUEST_SIGNER_RESPONSE_MAGIC_V1);
        oversized.extend_from_slice(
            &((MAX_LINUX_VZ_GUEST_SIGNER_RECEIPT_BYTES_V1 as u32) + 1).to_be_bytes(),
        );
        assert_eq!(
            decode_linux_vz_guest_signer_response_v1(&oversized),
            Err(LinuxVzGuestSignerTransportErrorV1::LimitExceeded)
        );
    }
}
