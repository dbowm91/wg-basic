//! One-shot named-pipe client. The frame and the correlation rules are the
//! same ones the Unix client uses.

use super::framing::{read_frame, write_frame};
use super::wire::{
    ProtocolError, RequestEnvelope, RequestOperation, ResponseBody, ResponseEnvelope,
    PROTOCOL_VERSION,
};
use std::{io, path::Path};

pub fn request(
    path: impl AsRef<Path>,
    operation: RequestOperation,
    request_id: u64,
) -> io::Result<ResponseBody> {
    let name = path
        .as_ref()
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "pipe name is not Unicode"))?;
    let mut stream = wg_basic_win32_sys::connect_pipe(name)?;
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
        Err(error) => Err(io::Error::new(io_error_kind(error), error)),
    }
}

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
