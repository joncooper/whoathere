use std::fmt;
use std::io::{self, Read, Write};

pub const MACOS_WHEEL_GUEST_CONTROL_MAGIC_V1: [u8; 8] = *b"WHOWCTL1";
pub const MACOS_WHEEL_GUEST_CONTROL_VERSION_V1: u16 = 1;
pub const MACOS_WHEEL_GUEST_CONTROL_PREFIX_BYTES_V1: usize = 16;
pub const MAX_MACOS_WHEEL_GUEST_CONTROL_BODY_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MacosWheelGuestControlFrameTypeV1 {
    AuthenticationChallenge = 1,
    AuthenticationResponse = 2,
    StagingReceipt = 3,
}

impl TryFrom<u16> for MacosWheelGuestControlFrameTypeV1 {
    type Error = MacosWheelGuestControlErrorV1;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AuthenticationChallenge),
            2 => Ok(Self::AuthenticationResponse),
            3 => Ok(Self::StagingReceipt),
            _ => Err(MacosWheelGuestControlErrorV1::UnsupportedFrameType),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosWheelGuestControlErrorV1 {
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedFrameType,
    UnexpectedFrameType,
    BodyLimitExceeded,
    Truncated,
    TrailingData,
    IoFailed,
}

impl MacosWheelGuestControlErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidMagic => "macos_wheel_guest_control_magic_invalid",
            Self::UnsupportedVersion => "macos_wheel_guest_control_version_unsupported",
            Self::UnsupportedFrameType => "macos_wheel_guest_control_type_unsupported",
            Self::UnexpectedFrameType => "macos_wheel_guest_control_type_unexpected",
            Self::BodyLimitExceeded => "macos_wheel_guest_control_body_limit_exceeded",
            Self::Truncated => "macos_wheel_guest_control_truncated",
            Self::TrailingData => "macos_wheel_guest_control_trailing_data",
            Self::IoFailed => "macos_wheel_guest_control_io_failed",
        }
    }
}

impl fmt::Display for MacosWheelGuestControlErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosWheelGuestControlErrorV1 {}

pub fn write_macos_wheel_guest_control_frame_v1<W: Write>(
    writer: &mut W,
    frame_type: MacosWheelGuestControlFrameTypeV1,
    body: &[u8],
) -> Result<(), MacosWheelGuestControlErrorV1> {
    if body.is_empty() || body.len() > MAX_MACOS_WHEEL_GUEST_CONTROL_BODY_BYTES_V1 {
        return Err(MacosWheelGuestControlErrorV1::BodyLimitExceeded);
    }
    let body_len =
        u32::try_from(body.len()).map_err(|_| MacosWheelGuestControlErrorV1::BodyLimitExceeded)?;
    writer
        .write_all(&MACOS_WHEEL_GUEST_CONTROL_MAGIC_V1)
        .map_err(|_| MacosWheelGuestControlErrorV1::IoFailed)?;
    writer
        .write_all(&MACOS_WHEEL_GUEST_CONTROL_VERSION_V1.to_be_bytes())
        .map_err(|_| MacosWheelGuestControlErrorV1::IoFailed)?;
    writer
        .write_all(&(frame_type as u16).to_be_bytes())
        .map_err(|_| MacosWheelGuestControlErrorV1::IoFailed)?;
    writer
        .write_all(&body_len.to_be_bytes())
        .map_err(|_| MacosWheelGuestControlErrorV1::IoFailed)?;
    writer
        .write_all(body)
        .map_err(|_| MacosWheelGuestControlErrorV1::IoFailed)?;
    writer
        .flush()
        .map_err(|_| MacosWheelGuestControlErrorV1::IoFailed)
}

pub fn read_macos_wheel_guest_control_frame_v1<R: Read>(
    reader: &mut R,
    expected_type: MacosWheelGuestControlFrameTypeV1,
    maximum_body_bytes: usize,
) -> Result<Vec<u8>, MacosWheelGuestControlErrorV1> {
    if maximum_body_bytes == 0 || maximum_body_bytes > MAX_MACOS_WHEEL_GUEST_CONTROL_BODY_BYTES_V1 {
        return Err(MacosWheelGuestControlErrorV1::BodyLimitExceeded);
    }
    let mut prefix = [0_u8; MACOS_WHEEL_GUEST_CONTROL_PREFIX_BYTES_V1];
    read_exact_wheel_control_v1(reader, &mut prefix)?;
    if prefix[..8] != MACOS_WHEEL_GUEST_CONTROL_MAGIC_V1 {
        return Err(MacosWheelGuestControlErrorV1::InvalidMagic);
    }
    if u16::from_be_bytes(
        prefix[8..10]
            .try_into()
            .map_err(|_| MacosWheelGuestControlErrorV1::Truncated)?,
    ) != MACOS_WHEEL_GUEST_CONTROL_VERSION_V1
    {
        return Err(MacosWheelGuestControlErrorV1::UnsupportedVersion);
    }
    let observed_type = MacosWheelGuestControlFrameTypeV1::try_from(u16::from_be_bytes(
        prefix[10..12]
            .try_into()
            .map_err(|_| MacosWheelGuestControlErrorV1::Truncated)?,
    ))?;
    if observed_type != expected_type {
        return Err(MacosWheelGuestControlErrorV1::UnexpectedFrameType);
    }
    let body_len = u32::from_be_bytes(
        prefix[12..16]
            .try_into()
            .map_err(|_| MacosWheelGuestControlErrorV1::Truncated)?,
    ) as usize;
    if body_len == 0 || body_len > maximum_body_bytes {
        return Err(MacosWheelGuestControlErrorV1::BodyLimitExceeded);
    }
    let mut body = vec![0_u8; body_len];
    read_exact_wheel_control_v1(reader, &mut body)?;
    Ok(body)
}

pub fn require_macos_wheel_guest_control_eof_v1<R: Read>(
    reader: &mut R,
) -> Result<(), MacosWheelGuestControlErrorV1> {
    let mut trailing = [0_u8; 1];
    loop {
        match reader.read(&mut trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(MacosWheelGuestControlErrorV1::TrailingData),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(MacosWheelGuestControlErrorV1::IoFailed),
        }
    }
}

fn read_exact_wheel_control_v1<R: Read>(
    reader: &mut R,
    mut destination: &mut [u8],
) -> Result<(), MacosWheelGuestControlErrorV1> {
    while !destination.is_empty() {
        match reader.read(destination) {
            Ok(0) => return Err(MacosWheelGuestControlErrorV1::Truncated),
            Ok(count) => destination = &mut destination[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(MacosWheelGuestControlErrorV1::IoFailed),
        }
    }
    Ok(())
}
