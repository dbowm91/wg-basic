//! Named-pipe listener. Peer identity is the token SID read at accept time.
//! A pipe this process did not create is left in place.

use super::auth_windows::AuthorizationPolicy;
use super::dispatch::{dispatch, DispatchTargets};
use super::framing::{read_frame, write_frame};
use super::wire::RequestEnvelope;
use crate::{
    firewall::FirewallService, reconcile::ReconciliationService, wireguard::WireGuardBackend,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

const ACCEPT_POLL: Duration = Duration::from_millis(20);

pub struct SocketServer {
    listener: wg_basic_win32_sys::PipeListener,
    socket_path: PathBuf,
    runtime_directory: PathBuf,
    authorization: AuthorizationPolicy,
    wireguard: WireGuardBackend,
    reconciliation: ReconciliationService,
    firewall: FirewallService,
    aggregate: crate::aggregate::AggregateCoordinator,
}

impl SocketServer {
    pub fn bind(path: impl AsRef<Path>, authorization: AuthorizationPolicy) -> io::Result<Self> {
        let name = path.as_ref().to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "pipe name is not Unicode")
        })?;
        if !crate::platform::windows::pipe_name_allowed(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipe name is outside \\\\.\\pipe\\wg-basic-",
            ));
        }
        if wg_basic_win32_sys::pipe_exists(name).unwrap_or(true) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a pipe with this name already exists and was left in place",
            ));
        }
        let serve = authorization.serve_sid().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "netd requires the serve account in --allow-user",
            )
        })?;
        let sid = wg_basic_win32_sys::Sid::from_canonical(serve)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let listener = wg_basic_win32_sys::PipeListener::bind(name, &sid)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrInUse, error.to_string()))?;
        let runtime_directory = PathBuf::from(crate::platform::windows::RUNTIME_DIR);
        Ok(Self {
            listener,
            socket_path: PathBuf::from(name),
            runtime_directory,
            authorization,
            wireguard: WireGuardBackend::default(),
            reconciliation: ReconciliationService::default(),
            firewall: FirewallService::default(),
            aggregate: crate::aggregate::AggregateCoordinator::default(),
        })
    }

    pub fn run_until_shutdown(&self, shutdown: &AtomicBool) -> io::Result<()> {
        while !shutdown.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok(accepted) => {
                    if !accepted.high_integrity
                        || !self.authorization.permits(accepted.peer_sid.as_str())
                    {
                        self.listener.disconnect();
                        continue;
                    }
                    let mut stream = accepted.io;
                    if self.handle_connection(&mut stream).is_err() {
                        crate::operational::emit(
                            "netd.request_rejected",
                            crate::operational::Severity::Warn,
                            "netd",
                            "request",
                            "rejected",
                            None,
                            None,
                            Some("pipe_connection"),
                        );
                    }
                    drop(stream);
                    self.listener.disconnect();
                }
                Err(error) if error.is_timeout() => thread::sleep(ACCEPT_POLL),
                Err(error) => {
                    return Err(io::Error::other(error.to_string()));
                }
            }
        }
        Ok(())
    }

    fn handle_connection(&self, stream: &mut (impl io::Read + io::Write)) -> io::Result<()> {
        let payload = read_frame(stream)?;
        let request = serde_json::from_slice::<RequestEnvelope>(&payload).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed protocol request")
        })?;
        let response = dispatch(
            &DispatchTargets {
                runtime_directory: &self.runtime_directory,
                wireguard: &self.wireguard,
                reconciliation: &self.reconciliation,
                firewall: &self.firewall,
                aggregate: &self.aggregate,
            },
            request,
        );
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| io::Error::other("could not encode protocol response"))?;
        write_frame(stream, &encoded)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}
