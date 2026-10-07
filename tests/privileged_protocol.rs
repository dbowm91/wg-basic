#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};
use wg_basic::protocol::{
    request, AuthorizationPolicy, RequestOperation, ResponseBody, SocketServer,
};

struct RuntimeDir(PathBuf);
impl RuntimeDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-protocol-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("netd.sock")
    }
}
impl Drop for RuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[test]
fn local_peer_credentials_authorize_capability_request_and_shutdown_cleans_socket() {
    let runtime = RuntimeDir::new();
    let socket = runtime.socket();
    let server = Arc::new(
        SocketServer::bind(&socket, AuthorizationPolicy::current_user_and_root()).unwrap(),
    );
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = shutdown.clone();
    let worker = thread::spawn(move || server.run_until_shutdown(&thread_shutdown));

    let result = request(&socket, RequestOperation::InspectCapabilities, 500).unwrap();
    let ResponseBody::Capabilities(snapshot) = result else {
        panic!("expected capability snapshot")
    };
    assert_eq!(snapshot.effective_uid, nix::unistd::geteuid().as_raw());
    assert_eq!(snapshot.effective_gid, nix::unistd::getegid().as_raw());
    assert!(snapshot.runtime_directory_safe);
    assert!(snapshot.cap_net_admin.is_some());

    shutdown.store(true, Ordering::Release);
    worker.join().unwrap().unwrap();
    assert!(!socket.exists());
}

#[test]
fn runtime_parent_and_socket_collisions_fail_closed() {
    let runtime = RuntimeDir::new();
    let socket = runtime.socket();
    fs::set_permissions(&runtime.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        SocketServer::bind(&socket, AuthorizationPolicy::current_user_and_root())
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    fs::set_permissions(&runtime.0, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&socket, b"preserve").unwrap();
    assert_eq!(
        SocketServer::bind(&socket, AuthorizationPolicy::current_user_and_root())
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(socket).unwrap(), b"preserve");
}
