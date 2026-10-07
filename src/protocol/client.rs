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
    match response.result {
        Ok(body) => Ok(body),
        Err(ProtocolError::Unauthorized) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "network service rejected caller",
        )),
        Err(ProtocolError::PermissionDenied) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "network service lacks permission for the operation",
        )),
        Err(ProtocolError::UnsupportedBackend) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "network backend does not support the operation",
        )),
        Err(ProtocolError::KernelRejected) => {
            Err(io::Error::other("kernel rejected the network operation"))
        }
        Err(ProtocolError::UnsupportedVersion | ProtocolError::MalformedRequest) => {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "network service rejected protocol version or request",
            ))
        }
        Err(ProtocolError::InternalFailure) => {
            Err(io::Error::other("network service request failed"))
        }
        Err(ProtocolError::NotFound) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "network resource was not found",
        )),
        Err(ProtocolError::Conflict) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "network resource conflicts with current state",
        )),
        Err(ProtocolError::InvalidInput) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "network request validation failed",
        )),
        Err(ProtocolError::BackendFailure) => {
            Err(io::Error::other("network backend rejected the request"))
        }
    }
}
