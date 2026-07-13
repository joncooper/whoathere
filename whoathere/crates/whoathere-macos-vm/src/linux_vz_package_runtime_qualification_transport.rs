use std::fmt;

pub const LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_MAGIC_V1: &[u8; 8] = b"WHVZRQQ1";
pub const LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_MAGIC_V1: &[u8; 8] = b"WHVZRQP1";
pub const MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1: usize = 64 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROBE_REPORT_BYTES_V1: usize = 4 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROCESS_EVIDENCE_BYTES_V1: usize = 1024 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECEIPT_BYTES_V1: usize = 1024 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1: usize =
    12 + MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1;
pub const MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1: usize = 20
    + MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROBE_REPORT_BYTES_V1
    + MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROCESS_EVIDENCE_BYTES_V1
    + MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECEIPT_BYTES_V1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRuntimeQualificationTransportErrorV1 {
    Empty,
    LimitExceeded,
    InvalidMagic,
    InvalidLength,
    TrailingBytes,
}

impl fmt::Display for LinuxVzPackageRuntimeQualificationTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "linux_vz_runtime_qualification_transport_empty",
            Self::LimitExceeded => "linux_vz_runtime_qualification_transport_limit_exceeded",
            Self::InvalidMagic => "linux_vz_runtime_qualification_transport_magic_invalid",
            Self::InvalidLength => "linux_vz_runtime_qualification_transport_length_invalid",
            Self::TrailingBytes => "linux_vz_runtime_qualification_transport_trailing_bytes",
        })
    }
}

impl std::error::Error for LinuxVzPackageRuntimeQualificationTransportErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRuntimeQualificationResponseV1 {
    probe_report: Vec<u8>,
    process_evidence: Vec<u8>,
    guest_receipt: Vec<u8>,
}

impl LinuxVzPackageRuntimeQualificationResponseV1 {
    pub fn probe_report(&self) -> &[u8] {
        &self.probe_report
    }

    pub fn process_evidence(&self) -> &[u8] {
        &self.process_evidence
    }

    pub fn guest_receipt(&self) -> &[u8] {
        &self.guest_receipt
    }
}

pub fn encode_linux_vz_package_runtime_qualification_request_v1(
    request: &[u8],
) -> Result<Vec<u8>, LinuxVzPackageRuntimeQualificationTransportErrorV1> {
    validate_length_v1(
        request.len(),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1,
    )?;
    let mut frame = Vec::with_capacity(12 + request.len());
    frame.extend_from_slice(LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_MAGIC_V1);
    frame.extend_from_slice(&(request.len() as u32).to_be_bytes());
    frame.extend_from_slice(request);
    Ok(frame)
}

pub fn decode_linux_vz_package_runtime_qualification_request_v1(
    frame: &[u8],
) -> Result<Vec<u8>, LinuxVzPackageRuntimeQualificationTransportErrorV1> {
    if frame.is_empty() {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::Empty);
    }
    if frame.len() > MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1 {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::LimitExceeded);
    }
    if frame.len() < 12 || &frame[..8] != LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_MAGIC_V1 {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidMagic);
    }
    let length = frame_u32_v1(frame, 8)? as usize;
    validate_length_v1(
        length,
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1,
    )?;
    let expected = 12_usize
        .checked_add(length)
        .ok_or(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength)?;
    if frame.len() < expected {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength);
    }
    if frame.len() > expected {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::TrailingBytes);
    }
    Ok(frame[12..expected].to_vec())
}

pub fn encode_linux_vz_package_runtime_qualification_response_v1(
    probe_report: &[u8],
    process_evidence: &[u8],
    guest_receipt: &[u8],
) -> Result<Vec<u8>, LinuxVzPackageRuntimeQualificationTransportErrorV1> {
    validate_length_v1(
        probe_report.len(),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROBE_REPORT_BYTES_V1,
    )?;
    validate_length_v1(
        process_evidence.len(),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROCESS_EVIDENCE_BYTES_V1,
    )?;
    validate_length_v1(
        guest_receipt.len(),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECEIPT_BYTES_V1,
    )?;
    let mut frame =
        Vec::with_capacity(20 + probe_report.len() + process_evidence.len() + guest_receipt.len());
    frame.extend_from_slice(LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_MAGIC_V1);
    frame.extend_from_slice(&(probe_report.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(process_evidence.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(guest_receipt.len() as u32).to_be_bytes());
    frame.extend_from_slice(probe_report);
    frame.extend_from_slice(process_evidence);
    frame.extend_from_slice(guest_receipt);
    Ok(frame)
}

pub fn decode_linux_vz_package_runtime_qualification_response_v1(
    frame: &[u8],
) -> Result<
    LinuxVzPackageRuntimeQualificationResponseV1,
    LinuxVzPackageRuntimeQualificationTransportErrorV1,
> {
    if frame.is_empty() {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::Empty);
    }
    if frame.len() > MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1 {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::LimitExceeded);
    }
    if frame.len() < 20 || &frame[..8] != LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_MAGIC_V1 {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidMagic);
    }
    let probe_length = frame_u32_v1(frame, 8)? as usize;
    let evidence_length = frame_u32_v1(frame, 12)? as usize;
    let receipt_length = frame_u32_v1(frame, 16)? as usize;
    validate_length_v1(
        probe_length,
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROBE_REPORT_BYTES_V1,
    )?;
    validate_length_v1(
        evidence_length,
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_PROCESS_EVIDENCE_BYTES_V1,
    )?;
    validate_length_v1(
        receipt_length,
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECEIPT_BYTES_V1,
    )?;
    let probe_end = 20_usize
        .checked_add(probe_length)
        .ok_or(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength)?;
    let evidence_end = probe_end
        .checked_add(evidence_length)
        .ok_or(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength)?;
    let expected = evidence_end
        .checked_add(receipt_length)
        .ok_or(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength)?;
    if frame.len() < expected {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength);
    }
    if frame.len() > expected {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::TrailingBytes);
    }
    Ok(LinuxVzPackageRuntimeQualificationResponseV1 {
        probe_report: frame[20..probe_end].to_vec(),
        process_evidence: frame[probe_end..evidence_end].to_vec(),
        guest_receipt: frame[evidence_end..expected].to_vec(),
    })
}

fn frame_u32_v1(
    frame: &[u8],
    offset: usize,
) -> Result<u32, LinuxVzPackageRuntimeQualificationTransportErrorV1> {
    frame
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength)
}

fn validate_length_v1(
    length: usize,
    maximum: usize,
) -> Result<(), LinuxVzPackageRuntimeQualificationTransportErrorV1> {
    if length == 0 {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::Empty);
    }
    if length > maximum || length > u32::MAX as usize {
        return Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::LimitExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_one_request_and_three_part_response_round_trip() {
        let request = encode_linux_vz_package_runtime_qualification_request_v1(b"request")
            .expect("request frame");
        assert_eq!(
            decode_linux_vz_package_runtime_qualification_request_v1(&request)
                .expect("request decode"),
            b"request"
        );
        let response = encode_linux_vz_package_runtime_qualification_response_v1(
            b"probe\n",
            b"evidence",
            b"receipt",
        )
        .expect("response frame");
        let decoded = decode_linux_vz_package_runtime_qualification_response_v1(&response)
            .expect("response decode");
        assert_eq!(decoded.probe_report(), b"probe\n");
        assert_eq!(decoded.process_evidence(), b"evidence");
        assert_eq!(decoded.guest_receipt(), b"receipt");
    }

    #[test]
    fn transport_rejects_wrong_magic_truncation_trailing_and_empty_parts() {
        assert_eq!(
            decode_linux_vz_package_runtime_qualification_request_v1(&[]),
            Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::Empty)
        );
        let mut request = encode_linux_vz_package_runtime_qualification_request_v1(b"request")
            .expect("request frame");
        request[0] ^= 1;
        assert_eq!(
            decode_linux_vz_package_runtime_qualification_request_v1(&request),
            Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidMagic)
        );
        let response = encode_linux_vz_package_runtime_qualification_response_v1(
            b"probe",
            b"evidence",
            b"receipt",
        )
        .expect("response frame");
        assert_eq!(
            decode_linux_vz_package_runtime_qualification_response_v1(
                &response[..response.len() - 1]
            ),
            Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::InvalidLength)
        );
        let mut trailing = response;
        trailing.push(0);
        assert_eq!(
            decode_linux_vz_package_runtime_qualification_response_v1(&trailing),
            Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::TrailingBytes)
        );
        assert_eq!(
            encode_linux_vz_package_runtime_qualification_response_v1(b"", b"evidence", b"receipt"),
            Err(LinuxVzPackageRuntimeQualificationTransportErrorV1::Empty)
        );
    }
}
