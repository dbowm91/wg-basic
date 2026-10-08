use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    process::Command,
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

fn command(args: &[&str]) -> std::process::Output {
    Command::new(BINARY).args(args).output().unwrap()
}

fn output_text(output: &std::process::Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
#[ignore = "mutates system users, /usr/local/bin, /etc/systemd, /var/lib, and systemd services"]
fn systemd_installation_ownership_reinstall_and_service_credentials() {
    assert_eq!(
        nix::unistd::geteuid().as_raw(),
        0,
        "run this qualification as root"
    );
    assert!(
        Path::new("/run/systemd/system").is_dir(),
        "systemd system manager is required"
    );
    assert!(
        !Path::new("/var/lib/wg-basic-system/install.json").exists(),
        "use a clean disposable Linux VM"
    );

    assert!(!Path::new("/etc/sysusers.d/wg-basic.conf").exists());
    assert!(!Path::new("/var/lib/wg-basic").exists());
    fs::write(
        "/etc/sysusers.d/wg-basic.conf",
        wg_basic::distribution::SYSUSERS,
    )
    .unwrap();
    fs::set_permissions(
        "/etc/sysusers.d/wg-basic.conf",
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let sysusers = Command::new("/usr/bin/systemd-sysusers")
        .arg("/etc/sysusers.d/wg-basic.conf")
        .output()
        .unwrap();
    assert!(sysusers.status.success(), "{}", output_text(&sysusers));
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let service_group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    fs::create_dir("/var/lib/wg-basic").unwrap();
    nix::unistd::chown(
        "/var/lib/wg-basic",
        Some(management.uid),
        Some(service_group.gid),
    )
    .unwrap();
    fs::set_permissions("/var/lib/wg-basic", fs::Permissions::from_mode(0o700)).unwrap();
    let seeded = run_as_service_user(
        management.uid.as_raw(),
        service_group.gid.as_raw(),
        &["state", "init", "--state", "/var/lib/wg-basic/state.db"],
    );
    assert!(seeded.status.success(), "{}", output_text(&seeded));
    let before = run_as_service_user(
        management.uid.as_raw(),
        service_group.gid.as_raw(),
        &["state", "status", "--state", "/var/lib/wg-basic/state.db"],
    );
    assert!(before.status.success(), "{}", output_text(&before));

    fs::copy("/bin/true", "/usr/local/bin/wg-basic").unwrap();
    fs::set_permissions("/usr/local/bin/wg-basic", fs::Permissions::from_mode(0o755)).unwrap();
    let foreign = command(&["system", "install", "--candidate", BINARY]);
    assert!(
        !foreign.status.success(),
        "foreign binary must refuse installation"
    );
    fs::remove_file("/usr/local/bin/wg-basic").unwrap();

    let install = command(&["system", "install", "--candidate", BINARY]);
    assert!(install.status.success(), "{}", output_text(&install));
    let status = command(&["system", "status"]);
    assert!(status.status.success(), "{}", output_text(&status));

    let management_uid = management.uid.as_raw();
    let group = service_group.gid.as_raw();
    let after = run_as_service_user(
        management_uid,
        group,
        &["state", "status", "--state", "/var/lib/wg-basic/state.db"],
    );
    assert!(after.status.success(), "{}", output_text(&after));
    assert_eq!(
        state_identity(&String::from_utf8_lossy(&before.stdout)),
        state_identity(&String::from_utf8_lossy(&after.stdout)),
        "installation must preserve pre-existing state identity"
    );
    let netd_uid = nix::unistd::User::from_name("wg-basic-netd")
        .unwrap()
        .unwrap()
        .uid
        .as_raw();
    let state_directory = fs::symlink_metadata("/var/lib/wg-basic").unwrap();
    let database = fs::symlink_metadata("/var/lib/wg-basic/state.db").unwrap();
    assert_eq!(state_directory.uid(), management_uid);
    assert_eq!(state_directory.mode() & 0o777, 0o700);
    assert_eq!(database.uid(), management_uid);
    assert_eq!(database.mode() & 0o777, 0o600);
    let socket = fs::symlink_metadata("/run/wg-basic/netd.sock").unwrap();
    assert_eq!(socket.uid(), netd_uid);
    assert_eq!(socket.gid(), group);
    assert_eq!(socket.mode() & 0o777, 0o660);

    let netd = systemd_property("wg-basic-netd.service", "MainPID");
    let serve = systemd_property("wg-basic.service", "MainPID");
    assert_eq!(
        proc_field(&netd, "CapEff"),
        0x1000,
        "netd must have only CAP_NET_ADMIN effective"
    );
    assert_eq!(proc_field(&netd, "CapBnd"), 0x1000);
    assert_eq!(proc_field(&netd, "CapAmb"), 0x1000);
    assert_eq!(
        proc_field(&serve, "CapEff"),
        0,
        "serve must have no effective capabilities"
    );
    assert_eq!(proc_field(&serve, "CapBnd"), 0);
    assert_eq!(proc_field(&serve, "CapAmb"), 0);
    assert_eq!(proc_field(&netd, "Uid"), u64::from(netd_uid));
    assert_eq!(proc_field(&serve, "Uid"), u64::from(management_uid));

    let test_binary = std::env::current_exe().unwrap();
    let unrelated = Command::new("/usr/bin/setpriv")
        .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
        .arg(test_binary)
        .args([
            "--exact",
            "unrelated_uid_cannot_connect_to_netd_socket",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(unrelated.status.success(), "{}", output_text(&unrelated));

    let reinstall = command(&["system", "install", "--candidate", BINARY]);
    assert!(reinstall.status.success(), "{}", output_text(&reinstall));
    let unit = Path::new("/etc/systemd/system/wg-basic.service");
    let original = fs::read(unit).unwrap();
    fs::write(
        unit,
        [original.as_slice(), b"# local operator change\n"].concat(),
    )
    .unwrap();
    let refused = command(&["system", "install", "--candidate", BINARY]);
    fs::write(unit, original).unwrap();
    assert!(
        !refused.status.success(),
        "modified unit must refuse refresh"
    );
    let final_status = command(&["system", "status"]);
    assert!(
        final_status.status.success(),
        "{}",
        output_text(&final_status)
    );
}

fn systemd_property(unit: &str, property: &str) -> String {
    let output = Command::new("systemctl")
        .args(["--system", "show", unit, "--property", property, "--value"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn run_as_service_user(uid: u32, gid: u32, args: &[&str]) -> std::process::Output {
    Command::new("/usr/bin/setpriv")
        .args([
            format!("--reuid={uid}"),
            format!("--regid={gid}"),
            "--clear-groups".to_owned(),
        ])
        .arg(BINARY)
        .args(args)
        .output()
        .unwrap()
}

fn state_identity(output: &str) -> &str {
    output
        .lines()
        .find_map(|line| line.strip_prefix("installation id:    "))
        .expect("state status should report the installation identity")
}

fn proc_field(pid: &str, key: &str) -> u64 {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .unwrap_or_else(|| panic!("missing {key} in process status"));
    if key == "Uid" {
        return value.split_whitespace().next().unwrap().parse().unwrap();
    }
    u64::from_str_radix(value.trim(), 16).unwrap()
}

#[test]
#[ignore = "run as an unrelated account after the systemd installation fixture"]
fn unrelated_uid_cannot_connect_to_netd_socket() {
    assert_eq!(
        UnixStream::connect("/run/wg-basic/netd.sock")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
