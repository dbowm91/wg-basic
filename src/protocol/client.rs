//! The one-shot local protocol client used by the `serve` and `doctor` roles.
//!
//! One connection carries one request. The response must match both the protocol
//! version and the request id, so a stale or mismatched reply is refused rather
//! than accepted. Protocol errors are projected onto typed `io` errors.

use super::framing::{read_frame, write_frame};
use super::wire::{
    ProtocolError, RequestEnvelope, RequestOperation, ResponseBody, ResponseEnvelope,
    PROTOCOL_VERSION,
};
use std::{io, os::unix::net::UnixStream, path::Path, time::Duration};

/// Per-connection read and write bound.
const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub fn request(
    path: impl AsRef<Path>,
    operation: RequestOperation,
    request_id: u64,
) -> io::Result<ResponseBody> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = RequestEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        operation,
    };
    let payload = serde_json::to_vec(&request)
        .map_err(|_| io::Error::other("could not encode protocol request"))?;
    write_frame(&mut stream, &payload)?;
    let payload = read_frame(&mut stream)?;
    let response = serde_json::from_slice::<ResponseEnvelope>(&payload)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed protocol response"))?;
    if response.protocol_version != PROTOCOL_VERSION || response.request_id != request_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol response correlation failed",
        ));
    }
    // Each wire refusal keeps its `ErrorKind` *and* the original
    // `ProtocolError` as the error payload, so a caller can classify on what
    // netd actually said instead of guessing from a lossy transport kind.
    match response.result {
        Ok(body) => Ok(body),
        Err(error) => Err(io::Error::new(io_error_kind(error), error)),
    }
}

/// The transport kind that best summarizes a wire refusal.
///
/// `AlreadyExists` for `Conflict` is load-bearing: it is the historical
/// mapping several callers assert on.
fn io_error_kind(error: ProtocolError) -> io::ErrorKind {
    match error {
        ProtocolError::Unauthorized | ProtocolError::PermissionDenied => {
            io::ErrorKind::PermissionDenied
        }
        ProtocolError::UnsupportedBackend => io::ErrorKind::Unsupported,
        ProtocolError::UnsupportedVersion | ProtocolError::MalformedRequest => {
            io::ErrorKind::InvalidData
        }
        ProtocolError::InternalFailure | ProtocolError::KernelRejected => io::ErrorKind::Other,
        ProtocolError::NotFound => io::ErrorKind::NotFound,
        ProtocolError::Conflict => io::ErrorKind::AlreadyExists,
        ProtocolError::InvalidInput => io::ErrorKind::InvalidInput,
        ProtocolError::BackendFailure => io::ErrorKind::Other,
    }
}
