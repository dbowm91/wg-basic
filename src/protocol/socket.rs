//! Socket bind, stale-path handling, connection lifecycle, and shutdown.
//!
//! The socket parent must already exist, be a real directory owned by the
//! effective netd UID, and not be group/world writable. The socket is created
//! with mode `0660`. Existing files, symlinks, active sockets, and foreign-owned
//! sockets are preserved and treated as conflicts. A stale netd-owned socket may
//! be removed only after a failed connect plus an inode/owner recheck. Shutdown
//! removes the socket only if device, inode, and owner still match.

use super::auth::AuthorizationPolicy;
use super::framing::{read_frame, write_frame};
use super::wire::RequestEnvelope;
use crate::{
    firewall::FirewallService, reconcile::ReconciliationService, wireguard::WireGuardBackend,
};
use nix::sys::socket::{getsockopt, listen, sockopt::PeerCredentials, Backlog};
use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

/// Per-connection read and write bound.
const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Shutdown poll interval while idle.
const ACCEPT_POLL: Duration = Duration::from_millis(20);
/// Listener backlog; one connection is served at a time.
const MAX_QUEUED_CONNECTIONS: i32 = 16;

pub struct SocketServer {
    pub(crate) listener: UnixListener,
    pub(crate) socket_path: PathBuf,
    pub(crate) identity: SocketIdentity,
    pub(crate) runtime_directory: PathBuf,
    pub(crate) authorization: AuthorizationPolicy,
    pub(crate) wireguard: WireGuardBackend,
    pub(crate) reconciliation: ReconciliationService,
    pub(crate) firewall: FirewallService,
    pub(crate) aggregate: crate::aggregate::AggregateCoordinator,
}

#[derive(Clone, Copy)]
pub(crate) struct SocketIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) uid: u32,
}

impl SocketServer {
    pub fn bind(path: impl AsRef<Path>, authorization: AuthorizationPolicy) -> io::Result<Self> {
        let socket_path = path.as_ref().to_path_buf();
        let runtime_directory = socket_path
            .parent()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket path must have a parent directory",
                )
            })?
            .to_path_buf();
        let directory = fs::symlink_metadata(&runtime_directory)?;
        let uid = nix::unistd::geteuid().as_raw();
        if !directory.file_type().is_dir()
            || directory.uid() != uid
            || directory.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime directory ownership or permissions are unsafe",
            ));
        }

        remove_stale_owned_socket(&socket_path, uid)?;
        let listener = UnixListener::bind(&socket_path)?;
        let backlog = Backlog::new(MAX_QUEUED_CONNECTIONS)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket backlog"))?;
        listen(&listener, backlog).map_err(io::Error::from)?;
        if let Err(error) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660)) {
            drop(listener);
            let _ = fs::remove_file(&socket_path);
            return Err(error);
        }
        listener.set_nonblocking(true)?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        let identity = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        };
        if !metadata.file_type().is_socket() || identity.uid != uid {
            drop(listener);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "created socket has unexpected ownership or type",
            ));
        }
        Ok(Self {
            listener,
            socket_path,
            identity,
            runtime_directory,
            authorization,
            wireguard: WireGuardBackend,
            reconciliation: ReconciliationService::default(),
            firewall: FirewallService::default(),
            aggregate: crate::aggregate::AggregateCoordinator::default(),
        })
    }

    /// Accepts one request at a time. The listen backlog and one-frame connection
    /// contract bound queued work; no per-connection tasks are spawned.
    pub fn run_until_shutdown(&self, shutdown: &AtomicBool) -> io::Result<()> {
        while !shutdown.load(Ordering::Acquire) {
            match self.listener.accept() {
                // A malformed or unauthorized peer is isolated to its connection;
                // it must not terminate the long-lived network service.
                Ok((stream, _)) => {
                    if self.handle_connection(stream).is_err() {
                        crate::operational::emit(
                            "netd.request_rejected",
                            crate::operational::Severity::Warn,
                            "netd",
                            "request",
                            "rejected",
                            None,
                            None,
                            Some("uds_connection"),
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL)
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn handle_connection(&self, mut stream: UnixStream) -> io::Result<()> {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let credentials = getsockopt(&stream, PeerCredentials).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "could not verify local peer credentials",
            )
        })?;
        if !self.authorization.permits(credentials.uid()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local peer is not authorized",
            ));
        }

        let payload = read_frame(&mut stream)?;
        let request = match serde_json::from_slice::<RequestEnvelope>(&payload) {
            Ok(request) => request,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed protocol request",
                ))
            }
        };
        let response = self.dispatch(request);
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| io::Error::other("could not encode protocol response"))?;
        write_frame(&mut stream, &encoded)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path) {
            if metadata.file_type().is_socket()
                && metadata.dev() == self.identity.device
                && metadata.ino() == self.identity.inode
                && metadata.uid() == self.identity.uid
            {
                let _ = fs::remove_file(&self.socket_path);
            }
        }
    }
}

fn remove_stale_owned_socket(path: &Path, uid: u32) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "socket path exists and is not an owned socket",
        ));
    }
    match UnixStream::connect(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "an active socket already owns this path",
            ))
        }
        Err(error)
            if error.kind() == io::ErrorKind::ConnectionRefused
                || error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let current = fs::symlink_metadata(path)?;
    if current.file_type().is_socket()
        && current.dev() == metadata.dev()
        && current.ino() == metadata.ino()
        && current.uid() == uid
    {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CapabilityState;
    use crate::protocol::{
        request, ProtocolError, RequestOperation, ResponseBody, ResponseEnvelope, MAX_FRAME_SIZE,
        PROTOCOL_VERSION,
    };
    use std::{
        io::{Read, Write},
        os::unix::fs::PermissionsExt,
        sync::{atomic::AtomicBool, Arc},
        time::Instant,
    };
    static FIXTURE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct Fixture {
        directory: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "wg-basic-m002-{}-{}-{}",
                nix::unistd::geteuid(),
                std::process::id(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            Self { directory }
        }
        fn socket(&self) -> PathBuf {
            self.directory.join("netd.sock")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn start_server(
        path: PathBuf,
        authorization: AuthorizationPolicy,
    ) -> (Arc<AtomicBool>, thread::JoinHandle<io::Result<()>>) {
        let server = Arc::new(SocketServer::bind(path, authorization).unwrap());
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let handle = thread::spawn(move || server.run_until_shutdown(&thread_shutdown));
        (shutdown, handle)
    }

    #[test]
    fn kernel_peer_credentials_authorize_ping_and_capability_snapshot() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let (shutdown, handle) =
            start_server(path.clone(), AuthorizationPolicy::current_user_and_root());

        let pong = request(&path, RequestOperation::Ping, 11).unwrap();
        assert!(matches!(pong, ResponseBody::Pong { service, .. } if service == "wg-basic-netd"));
        let response = request(&path, RequestOperation::InspectCapabilities, 12).unwrap();
        let ResponseBody::Capabilities(snapshot) = response else {
            panic!("unexpected response")
        };
        assert_eq!(snapshot.effective_uid, nix::unistd::geteuid().as_raw());
        assert!(snapshot.runtime_directory_safe);
        assert_eq!(snapshot.wireguard_control, CapabilityState::Unknown);
        assert_eq!(snapshot.nftables, CapabilityState::Unknown);

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn denied_peer_is_rejected_before_request_data_is_read() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let denied_uid = if nix::unistd::geteuid().as_raw() == u32::MAX {
            u32::MAX - 1
        } else {
            u32::MAX
        };
        let (shutdown, handle) = start_server(path.clone(), AuthorizationPolicy::new([denied_uid]));
        let mut stream = UnixStream::connect(&path).unwrap();
        let payload = serde_json::to_vec(&RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: 1,
            operation: RequestOperation::Ping,
        })
        .unwrap();
        // The peer may close after checking credentials before this small frame
        // reaches the socket; either outcome is consistent with early rejection.
        let _ = write_frame(&mut stream, &payload);
        let mut response = [0_u8; 1];
        match stream.read(&mut response) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("unauthorized connection was not closed: {other:?}"),
        }
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn unknown_version_is_rejected_with_request_correlation() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let (shutdown, handle) =
            start_server(path.clone(), AuthorizationPolicy::current_user_and_root());
        let mut stream = UnixStream::connect(&path).unwrap();
        let request = RequestEnvelope {
            protocol_version: PROTOCOL_VERSION + 1,
            request_id: 991,
            operation: RequestOperation::Ping,
        };
        write_frame(&mut stream, &serde_json::to_vec(&request).unwrap()).unwrap();
        let response: ResponseEnvelope =
            serde_json::from_slice(&read_frame(&mut stream).unwrap()).unwrap();
        assert_eq!(response.request_id, 991);
        assert_eq!(response.result, Err(ProtocolError::UnsupportedVersion));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn invalid_wireguard_patch_is_rejected_before_opening_netlink() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let (shutdown, handle) =
            start_server(path.clone(), AuthorizationPolicy::current_user_and_root());
        let patch = crate::wireguard::WireGuardDevicePatch {
            private_key: crate::wireguard::FieldUpdate::Keep,
            listen_port: crate::wireguard::FieldUpdate::Set(0),
            peer: None,
        };
        let error = request(
            &path,
            RequestOperation::ApplyWireGuardDevice {
                interface: "wg0".parse().unwrap(),
                patch,
            },
            55,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn client_rejects_response_with_wrong_request_id() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let listener = UnixListener::bind(&path).unwrap();
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request: RequestEnvelope =
                serde_json::from_slice(&read_frame(&mut stream).unwrap()).unwrap();
            let response = ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id: request.request_id + 1,
                result: Ok(ResponseBody::Pong {
                    service: "wg-basic-netd".into(),
                    version: "0.1.0".into(),
                }),
            };
            write_frame(&mut stream, &serde_json::to_vec(&response).unwrap()).unwrap();
        });
        assert_eq!(
            request(&path, RequestOperation::Ping, 77)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        responder.join().unwrap();
    }

    #[test]
    fn socket_path_conflicts_fail_closed_and_cleanup_is_inode_owned() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        fs::write(&path, b"keep me").unwrap();
        assert_eq!(
            SocketServer::bind(&path, AuthorizationPolicy::current_user_and_root())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
        fs::remove_file(&path).unwrap();

        let active = UnixListener::bind(&path).unwrap();
        assert_eq!(
            SocketServer::bind(&path, AuthorizationPolicy::current_user_and_root())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(path.exists());
        drop(active);

        assert!(
            path.exists(),
            "a crash-style stale socket path should remain"
        );
        let server =
            SocketServer::bind(&path, AuthorizationPolicy::current_user_and_root()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
        drop(server);
        assert!(!path.exists());

        let server =
            SocketServer::bind(&path, AuthorizationPolicy::current_user_and_root()).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement must survive cleanup").unwrap();
        drop(server);
        assert_eq!(fs::read(path).unwrap(), b"replacement must survive cleanup");
    }

    #[test]
    fn idle_client_is_bounded_and_shutdown_completes() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let (shutdown, handle) =
            start_server(path.clone(), AuthorizationPolicy::current_user_and_root());
        let stream = UnixStream::connect(&path).unwrap();
        thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
        assert!(started.elapsed() < IO_TIMEOUT + Duration::from_secs(1));
        drop(stream);
    }

    #[test]
    fn authorized_slow_peer_blocks_one_at_a_time_service_for_at_most_io_timeout() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let (shutdown, handle) =
            start_server(path.clone(), AuthorizationPolicy::current_user_and_root());
        let _slow = UnixStream::connect(&path).unwrap();
        // Let the single accept loop take the authorized connection and block
        // while it waits for the four-byte frame header.
        thread::sleep(Duration::from_millis(50));

        let mut ordinary = UnixStream::connect(&path).unwrap();
        ordinary
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let request = RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: 700,
            operation: RequestOperation::Ping,
        };
        let payload = serde_json::to_vec(&request).unwrap();
        let started = std::time::Instant::now();
        write_frame(&mut ordinary, &payload).unwrap();
        let response: ResponseEnvelope =
            serde_json::from_slice(&read_frame(&mut ordinary).unwrap()).unwrap();
        let denial_window = started.elapsed();
        assert_eq!(response.request_id, request.request_id);
        assert!(
            denial_window >= IO_TIMEOUT - Duration::from_millis(250),
            "the queued request should wait for the authorized slow peer's timeout: {denial_window:?}"
        );
        assert!(
            denial_window < IO_TIMEOUT + Duration::from_secs(1),
            "the measured denial window must remain bounded by the 2s read timeout: {denial_window:?}"
        );
        eprintln!("authorized netd slow-peer denial window: {denial_window:?} (IO_TIMEOUT={IO_TIMEOUT:?})");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn malformed_frame_does_not_leak_payload() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let (shutdown, handle) =
            start_server(path.clone(), AuthorizationPolicy::current_user_and_root());
        let mut stream = UnixStream::connect(&path).unwrap();
        write_frame(&mut stream, br#"{"secret":"never echo me"}"#).unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        assert!(!String::from_utf8_lossy(&response).contains("never echo me"));
        let pong = request(&path, RequestOperation::Ping, 5).unwrap();
        assert!(matches!(pong, ResponseBody::Pong { .. }));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn malformed_peer_burst_does_not_prevent_a_later_authorized_request() {
        let fixture = Fixture::new();
        let path = fixture.socket();
        let (shutdown, handle) =
            start_server(path.clone(), AuthorizationPolicy::current_user_and_root());

        for index in 0..128_u32 {
            let mut stream = UnixStream::connect(&path).unwrap();
            match index % 3 {
                0 => stream.write_all(&0_u32.to_be_bytes()).unwrap(),
                1 => stream
                    .write_all(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes())
                    .unwrap(),
                _ => write_frame(&mut stream, b"{ malformed json").unwrap(),
            }
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response);
            assert!(response.is_empty(), "malformed input must not be reflected");
        }

        let response = request(&path, RequestOperation::Ping, 801).unwrap();
        assert!(matches!(response, ResponseBody::Pong { .. }));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap().unwrap();
    }
}
