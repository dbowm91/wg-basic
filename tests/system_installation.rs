use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    process::{Command, Stdio},
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

    if !Path::new("/etc/sysusers.d").exists() {
        fs::create_dir("/etc/sysusers.d").unwrap();
        fs::set_permissions("/etc/sysusers.d", fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(!Path::new("/etc/sysusers.d/wg-basic.conf").exists());
    assert!(!Path::new("/var/lib/wg-basic").exists());
    let release_candidate = std::env::var("WGB_CANDIDATE_BINARY").unwrap_or_else(|_| BINARY.into());
    let version = Command::new(&release_candidate)
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success(), "{}", output_text(&version));
    let digest = Command::new("/usr/bin/sha256sum")
        .arg(&release_candidate)
        .output()
        .unwrap();
    assert!(digest.status.success(), "{}", output_text(&digest));
    let systemd = Command::new("/usr/bin/systemctl")
        .arg("--version")
        .output()
        .unwrap();
    assert!(systemd.status.success(), "{}", output_text(&systemd));
    let kernel = Command::new("/usr/bin/uname").arg("-a").output().unwrap();
    assert!(kernel.status.success(), "{}", output_text(&kernel));
    let ldd = Command::new("/usr/bin/ldd")
        .arg(&release_candidate)
        .output()
        .unwrap();
    assert!(ldd.status.success(), "{}", output_text(&ldd));
    println!(
        "M005 lifecycle artifact/host: version={} bytes={} sha256={} kernel={} systemd={} dependencies={}",
        String::from_utf8_lossy(&version.stdout).trim(),
        fs::metadata(&release_candidate).unwrap().len(),
        String::from_utf8_lossy(&digest.stdout)
            .split_whitespace()
            .next()
            .unwrap(),
        String::from_utf8_lossy(&kernel.stdout).trim(),
        String::from_utf8_lossy(&systemd.stdout)
            .lines()
            .next().unwrap_or("unknown"),
        String::from_utf8_lossy(&ldd.stdout).replace('\n', "; ")
    );
    fs::copy("/bin/true", "/usr/local/bin/wg-basic").unwrap();
    fs::set_permissions("/usr/local/bin/wg-basic", fs::Permissions::from_mode(0o755)).unwrap();
    let foreign = command(&["system", "install", "--candidate", BINARY]);
    assert!(
        !foreign.status.success(),
        "foreign binary must refuse installation"
    );
    fs::remove_file("/usr/local/bin/wg-basic").unwrap();

    let install_started = std::time::Instant::now();
    let install = command(&["system", "install", "--candidate", &release_candidate]);
    let install_elapsed = install_started.elapsed();
    assert!(
        install.status.success(),
        "{}\n{}",
        output_text(&install),
        service_journal("wg-basic.service")
    );
    let journal = service_journal("wg-basic.service");
    assert!(
        journal.contains("\"overall\": \"pass\""),
        "fresh empty-state doctor preflight must pass:\n{journal}"
    );
    let status = command(&["system", "status"]);
    assert!(status.status.success(), "{}", output_text(&status));
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("doctor (last install): pass"),
        "fresh install must record the observed empty-state doctor result: {}",
        output_text(&status)
    );

    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let service_group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    let management_uid = management.uid.as_raw();
    let group = service_group.gid.as_raw();
    let before = run_as_service_user(
        management_uid,
        group,
        &["state", "status", "--state", "/var/lib/wg-basic/state.db"],
    );
    assert!(before.status.success(), "{}", output_text(&before));
    set_admin_password_as_service_user();
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
    println!(
        "M005 fresh install footprint: binary_bytes={} unit_bytes={} idle_rss_kib={{serve:{},netd:{}}} install_elapsed_ms={}",
        fs::metadata("/usr/local/bin/wg-basic").unwrap().len(),
        fs::metadata("/etc/systemd/system/wg-basic.service").unwrap().len()
            + fs::metadata("/etc/systemd/system/wg-basic-netd.service").unwrap().len()
            + fs::metadata("/etc/sysusers.d/wg-basic.conf").unwrap().len(),
        proc_rss_kib(&serve),
        proc_rss_kib(&netd),
        install_elapsed.as_millis()
    );
    for (unit, expected) in [
        (
            "wg-basic.service",
            [
                ("User", "wg-basic"),
                ("Group", "wg-basic"),
                ("NoNewPrivileges", "yes"),
                ("ProtectSystem", "strict"),
                ("ProtectHome", "yes"),
                ("PrivateTmp", "yes"),
                ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
                ("StateDirectory", "wg-basic"),
                ("TasksMax", "64"),
                ("MemoryMax", "268435456"),
                ("LimitCORE", "0"),
                ("Restart", "on-failure"),
                ("CapabilityBoundingSet", ""),
                ("AmbientCapabilities", ""),
            ],
        ),
        (
            "wg-basic-netd.service",
            [
                ("User", "wg-basic-netd"),
                ("Group", "wg-basic"),
                ("NoNewPrivileges", "yes"),
                ("ProtectSystem", "strict"),
                ("ProtectHome", "yes"),
                ("PrivateTmp", "yes"),
                ("RestrictAddressFamilies", "AF_UNIX AF_NETLINK"),
                ("TasksMax", "32"),
                ("MemoryMax", "134217728"),
                ("LimitCORE", "0"),
                ("Restart", "on-failure"),
                ("CapabilityBoundingSet", "CAP_NET_ADMIN"),
                ("AmbientCapabilities", "CAP_NET_ADMIN"),
                ("ProtectKernelTunables", "no"),
            ],
        ),
    ] {
        for (property, value) in expected {
            assert_eq!(
                systemd_property(unit, property),
                value,
                "unexpected effective {property} on {unit}"
            );
        }
    }
    assert!(
        systemd_property("wg-basic.service", "ExecStart")
            .contains("/usr/local/bin/wg-basic serve --state /var/lib/wg-basic/state.db --socket /run/wg-basic/netd.sock"),
        "effective serve argv differs from the product contract"
    );
    assert!(
        systemd_property("wg-basic-netd.service", "ExecStart").contains(
            "/usr/local/bin/wg-basic netd --socket /run/wg-basic/netd.sock --allow-user wg-basic"
        ),
        "effective netd argv differs from the product contract"
    );
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

    let reinstall = command(&["system", "install", "--candidate", &release_candidate]);
    assert!(reinstall.status.success(), "{}", output_text(&reinstall));
    let unit = Path::new("/etc/systemd/system/wg-basic.service");
    let original = fs::read(unit).unwrap();
    fs::write(
        unit,
        [original.as_slice(), b"# local operator change\n"].concat(),
    )
    .unwrap();
    let refused = command(&["system", "install", "--candidate", &release_candidate]);
    fs::write(unit, &original).unwrap();
    assert!(
        !refused.status.success(),
        "modified unit must refuse refresh"
    );

    // Every file whose digest is registered in the install receipt must be
    // checked before uninstall stops services or removes any owned material.
    for path in [
        "/usr/local/bin/wg-basic",
        "/etc/systemd/system/wg-basic.service",
        "/etc/systemd/system/wg-basic-netd.service",
        "/etc/sysusers.d/wg-basic.conf",
        "/var/lib/wg-basic-system/install.json",
    ] {
        let path = Path::new(path);
        let original = fs::read(path).unwrap();
        fs::write(
            path,
            [original.as_slice(), b"# local operator change\n"].concat(),
        )
        .unwrap();
        let uninstall_refused = command(&["system", "uninstall"]);
        fs::write(path, original).unwrap();
        assert!(
            !uninstall_refused.status.success(),
            "modified {} must refuse uninstall: {}",
            path.display(),
            output_text(&uninstall_refused)
        );
        assert!(Path::new("/usr/local/bin/wg-basic").is_file());
        for service in ["wg-basic.service", "wg-basic-netd.service"] {
            let active = Command::new("/usr/bin/systemctl")
                .args(["is-active", service])
                .output()
                .unwrap();
            assert!(
                active.status.success(),
                "refusal for {} must leave {service} running: {}",
                path.display(),
                output_text(&active)
            );
        }
    }
    let final_status = command(&["system", "status"]);
    assert!(
        final_status.status.success(),
        "{}",
        output_text(&final_status)
    );

    let state_before_uninstall = run_as_service_user(
        management_uid,
        group,
        &["state", "status", "--state", "/var/lib/wg-basic/state.db"],
    );
    assert!(
        state_before_uninstall.status.success(),
        "{}",
        output_text(&state_before_uninstall)
    );
    let uninstall = command(&["system", "uninstall"]);
    assert!(uninstall.status.success(), "{}", output_text(&uninstall));
    assert!(!Path::new("/usr/local/bin/wg-basic").exists());
    assert!(!Path::new("/etc/systemd/system/wg-basic.service").exists());
    assert!(!Path::new("/etc/systemd/system/wg-basic-netd.service").exists());
    assert!(!Path::new("/etc/sysusers.d/wg-basic.conf").exists());
    assert!(!Path::new("/var/lib/wg-basic-system/install.json").exists());
    assert!(Path::new("/var/lib/wg-basic/state.db").is_file());
    assert_eq!(
        state_identity(&String::from_utf8_lossy(&state_before_uninstall.stdout)),
        state_identity(&String::from_utf8_lossy(
            &run_as_service_user(
                management_uid,
                group,
                &["state", "status", "--state", "/var/lib/wg-basic/state.db"],
            )
            .stdout
        )),
        "default uninstall must retain the same installation identity"
    );
    assert_eq!(
        nix::unistd::User::from_name("wg-basic")
            .unwrap()
            .unwrap()
            .uid,
        management.uid
    );
    assert_eq!(
        nix::unistd::Group::from_name("wg-basic")
            .unwrap()
            .unwrap()
            .gid,
        service_group.gid
    );
    assert_eq!(
        nix::unistd::User::from_name("wg-basic-netd")
            .unwrap()
            .unwrap()
            .uid
            .as_raw(),
        netd_uid
    );

    let reinstall = command(&["system", "install", "--candidate", &release_candidate]);
    assert!(reinstall.status.success(), "{}", output_text(&reinstall));
    let state_after_reinstall = run_as_service_user(
        management_uid,
        group,
        &["state", "status", "--state", "/var/lib/wg-basic/state.db"],
    );
    assert!(
        state_after_reinstall.status.success(),
        "{}",
        output_text(&state_after_reinstall)
    );
    assert_eq!(
        state_identity(&String::from_utf8_lossy(&state_before_uninstall.stdout)),
        state_identity(&String::from_utf8_lossy(&state_after_reinstall.stdout)),
        "reinstall must reuse preserved state"
    );
    assert!(command(&["system", "status"]).status.success());
}

fn set_admin_password_as_service_user() {
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    let mut child = Command::new("/usr/bin/setpriv")
        .args([
            format!("--reuid={}", management.uid.as_raw()),
            format!("--regid={}", group.gid.as_raw()),
            "--clear-groups".to_owned(),
        ])
        .arg(BINARY)
        .args([
            "admin",
            "set-password",
            "--password-stdin",
            "--state",
            "/var/lib/wg-basic/state.db",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"M005 disposable lifecycle password\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "{}", output_text(&result));
}

fn systemd_property(unit: &str, property: &str) -> String {
    let output = Command::new("systemctl")
        .args(["--system", "show", unit, "--property", property, "--value"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn service_journal(unit: &str) -> String {
    let output = Command::new("/usr/bin/journalctl")
        .args(["-u", unit, "-n", "240", "--no-pager", "--output=cat"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
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

fn proc_rss_kib(pid: &str) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .expect("service process should report VmRSS")
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
