use super::{
    read_frame, write_frame, NetworkCapabilitySnapshot, ProtocolError, RequestEnvelope,
    RequestOperation, ResponseBody, ResponseEnvelope, PROTOCOL_VERSION,
};
use crate::firewall::{FirewallError, FirewallService};
use crate::reconcile::{ReconcileError, ReconciliationService};
use crate::wireguard::{WireGuardBackend, WireGuardValidationError};
use nix::sys::socket::{getsockopt, listen, sockopt::PeerCredentials, Backlog};
use std::{
    collections::HashSet,
    fs, io,
    os::{
        unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL: Duration = Duration::from_millis(20);
const MAX_QUEUED_CONNECTIONS: i32 = 16;

#[derive(Clone, Debug)]
pub struct AuthorizationPolicy {
    allowed_uids: HashSet<u32>,
}

impl AuthorizationPolicy {
    pub fn new(allowed_uids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            allowed_uids: allowed_uids.into_iter().collect(),
        }
    }

    pub fn current_user_and_root() -> Self {
        Self::new([nix::unistd::geteuid().as_raw(), 0])
    }

    pub fn extend(&mut self, allowed_uids: impl IntoIterator<Item = u32>) {
        self.allowed_uids.extend(allowed_uids);
    }

    fn permits(&self, uid: u32) -> bool {
        self.allowed_uids.contains(&uid)
    }
}

pub struct SocketServer {
    listener: UnixListener,
    socket_path: PathBuf,
    identity: SocketIdentity,
    runtime_directory: PathBuf,
    authorization: AuthorizationPolicy,
    wireguard: WireGuardBackend,
    reconciliation: ReconciliationService,
    firewall: FirewallService,
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
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
                    let _ = self.handle_connection(stream);
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

    fn dispatch(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if request.protocol_version != PROTOCOL_VERSION {
            return ResponseEnvelope::failure(
                request.request_id,
                ProtocolError::UnsupportedVersion,
            );
        }
        let result = match request.operation {
            RequestOperation::Ping => Ok(ResponseBody::Pong {
                service: "wg-basic-netd".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            }),
            RequestOperation::InspectCapabilities => Ok(ResponseBody::Capabilities(
                NetworkCapabilitySnapshot::observe(&self.runtime_directory),
            )),
            RequestOperation::ObserveWireGuardDevice { interface } => self
                .wireguard
                .observe_device(&interface)
                .map(ResponseBody::WireGuardDevice)
                .map_err(map_wireguard_error),
            RequestOperation::ApplyWireGuardDevice { interface, patch } => self
                .wireguard
                .apply_patch(&interface, patch)
                .map(ResponseBody::WireGuardApplied)
                .map_err(map_wireguard_error),
            RequestOperation::PlanManagedInterface { desired } => self
                .reconciliation
                .plan(&desired)
                .map(ResponseBody::ManagedInterfacePlan)
                .map_err(map_reconcile_error),
            RequestOperation::ApplyManagedInterface { desired } => self
                .reconciliation
                .apply(&desired)
                .map(ResponseBody::ManagedInterfaceApplied)
                .map_err(map_reconcile_error),
            RequestOperation::PlanNetworkPolicy {
                wireguard_interface,
                policy,
            } => self
                .firewall
                .plan(&wireguard_interface, policy.as_ref())
                .map(ResponseBody::NetworkPolicyPlan)
                .map_err(map_firewall_error),
            RequestOperation::ApplyNetworkPolicy {
                wireguard_interface,
                policy,
            } => self
                .firewall
                .apply(&wireguard_interface, policy.as_ref())
                .map(ResponseBody::NetworkPolicyApplied)
                .map_err(map_firewall_error),
        };
        ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id,
            result,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn map_firewall_error(error: FirewallError) -> ProtocolError {
    match error {
        FirewallError::InvalidPolicy | FirewallError::ResourceLimitExceeded => {
            ProtocolError::InvalidInput
        }
        FirewallError::TableOwnershipConflict => ProtocolError::Conflict,
        FirewallError::PermissionDenied => ProtocolError::PermissionDenied,
        FirewallError::Unsupported => ProtocolError::UnsupportedBackend,
        FirewallError::BackendFailure => ProtocolError::BackendFailure,
    }
}

fn map_reconcile_error(error: ReconcileError) -> ProtocolError {
    match error {
        ReconcileError::InvalidDesiredState
        | ReconcileError::ResourceLimitExceeded
        | ReconcileError::DuplicateResource => ProtocolError::InvalidInput,
        ReconcileError::OwnershipRequired
        | ReconcileError::WrongLinkKind
        | ReconcileError::Conflict
        | ReconcileError::UnlistedResourceOnDelete => ProtocolError::Conflict,
        ReconcileError::BackendFailure => ProtocolError::BackendFailure,
        ReconcileError::WireGuard(error) => map_wireguard_error(error),
    }
}

fn map_wireguard_error(error: WireGuardValidationError) -> ProtocolError {
    match error {
        WireGuardValidationError::PeerNotFound | WireGuardValidationError::InterfaceUnavailable => {
            ProtocolError::NotFound
        }
        WireGuardValidationError::PeerAlreadyExists
        | WireGuardValidationError::ConflictingAllowedIps => ProtocolError::Conflict,
        WireGuardValidationError::PermissionDenied => ProtocolError::PermissionDenied,
        WireGuardValidationError::UnsupportedBackend => ProtocolError::UnsupportedBackend,
        WireGuardValidationError::KernelRejected => ProtocolError::KernelRejected,
        WireGuardValidationError::InvalidKey | WireGuardValidationError::InvalidBackendInput => {
            ProtocolError::InvalidInput
        }
        WireGuardValidationError::BackendFailure => ProtocolError::BackendFailure,
        _ => ProtocolError::InvalidInput,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CapabilityState;
    use std::{
        io::Read,
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
        write_frame(&mut stream, &payload).unwrap();
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
}
