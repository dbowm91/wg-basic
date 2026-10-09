#![cfg(all(
    target_os = "linux",
    feature = "linux-integration",
    feature = "update-test-fixtures"
))]

//! Destructive updater qualification. Run only on a clean disposable systemd VM.

use std::{
    fs,
    io::Cursor,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Command, Output},
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");
const FIXTURE: &str = "/run/wg-basic-update-fixture";
const CANDIDATE_VERSION: &str = "0.1.1";

fn command(args: &[&str]) -> Output {
    Command::new(BINARY).args(args).output().unwrap()
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn database_identity() -> (i64, String, i64, i64) {
    let connection = rusqlite::Connection::open_with_flags(
        distribution_state_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let schema: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let (installation, generation): (String, i64) = connection
        .query_row(
            "SELECT installation_id, desired_generation FROM installation WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let clients: i64 = connection
        .query_row("SELECT count(*) FROM clients", [], |row| row.get(0))
        .unwrap();
    (schema, installation, generation, clients)
}

fn typed_state_identity() -> serde_json::Value {
    let identity = Command::new("/usr/sbin/runuser")
        .args([
            "--user",
            "wg-basic",
            "--",
            wg_basic::distribution::BINARY_PATH,
            "state",
            "identity",
            "--state",
            distribution_state_path(),
        ])
        .output()
        .unwrap();
    assert!(identity.status.success(), "{}", output_text(&identity));
    serde_json::from_slice(&identity.stdout).unwrap()
}

fn qualification_environment() -> String {
    let kernel = Command::new("/usr/bin/uname").arg("-r").output().unwrap();
    let systemd = Command::new("/usr/bin/systemctl")
        .arg("--version")
        .output()
        .unwrap();
    format!(
        "kernel={} systemd={} architecture={}",
        String::from_utf8_lossy(&kernel.stdout)
            .lines()
            .next()
            .unwrap_or("unknown"),
        String::from_utf8_lossy(&systemd.stdout)
            .lines()
            .next()
            .unwrap_or("unknown"),
        std::env::consts::ARCH
    )
}

fn distribution_state_path() -> &'static str {
    wg_basic::distribution::STATE_PATH
}

fn kill_update_at_phase(phase: &str, expected_identity: &(i64, String, i64, i64)) {
    interrupt_update_at_phase(phase);

    for _ in 0..2 {
        let recovery = command(&["update", "recover"]);
        assert!(
            recovery.status.success(),
            "recovery after {phase} failed: {}\n{}",
            output_text(&recovery),
            recovery_diagnostics()
        );
    }
    assert_eq!(database_identity(), *expected_identity);
    assert!(
        eggup_core::MutationLock::observe(Path::new("/usr/local/bin"))
            .unwrap()
            .is_none(),
        "recovery must resolve its journal-proven Eggup lock record"
    );
}

fn interrupt_update_at_phase(phase: &str) {
    use std::{
        os::unix::process::CommandExt,
        thread,
        time::{Duration, Instant},
    };

    let gate = format!("/run/wg-basic-update-gate-{phase}");
    fs::create_dir(&gate).unwrap();
    let mut child = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .env("WGB_UPDATE_TEST_GATE_PHASE", phase)
        .env("WGB_UPDATE_TEST_GATE_DIR", &gate)
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let entered = Path::new(&gate).join(format!("{phase}.entered"));
    let deadline = Instant::now() + Duration::from_secs(120);
    while !entered.exists() && Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "updater exited before {phase}"
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        entered.exists(),
        "updater did not reach durable phase {phase}"
    );
    kill_process_group(&mut child);
    let _ = fs::remove_dir_all(gate);
}

fn assert_recovery_refuses_tampering(label: &str) {
    let recovery = command(&["update", "recover"]);
    assert!(
        !recovery.status.success(),
        "recovery must refuse tampered {label}: {}",
        output_text(&recovery)
    );
    for service in ["wg-basic.service", "wg-basic-netd.service"] {
        let active = Command::new("/usr/bin/systemctl")
            .args(["is-active", service])
            .output()
            .unwrap();
        assert_ne!(
            String::from_utf8_lossy(&active.stdout).trim(),
            "active",
            "tampered {label} must not leave {service} running"
        );
    }
}

fn qualify_tampered_recovery_refusal(expected_identity: &(i64, String, i64, i64)) {
    use std::io::Write;

    interrupt_update_at_phase("BinaryCommitted");
    let journal_path = Path::new(wg_basic::update::UPDATE_JOURNAL_PATH);
    let journal_bytes = fs::read(journal_path).unwrap();
    let journal: serde_json::Value = serde_json::from_slice(&journal_bytes).unwrap();
    let transaction = Path::new(journal["transaction_dir"].as_str().unwrap());

    for artifact in ["old-wg-basic", "state-pre-update.db"] {
        let path = transaction.join(artifact);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"tampered recovery evidence").unwrap();
        assert_recovery_refuses_tampering(artifact);
        fs::write(&path, original).unwrap();
        fs::File::open(&path).unwrap().sync_all().unwrap();
    }

    let unit = Path::new(wg_basic::distribution::SERVE_UNIT_PATH);
    let original_unit = fs::read(unit).unwrap();
    let mut changed_unit = fs::OpenOptions::new().append(true).open(unit).unwrap();
    changed_unit
        .write_all(b"\n# altered during updater recovery qualification\n")
        .unwrap();
    changed_unit.sync_all().unwrap();
    let reload = Command::new("/usr/bin/systemctl")
        .args(["daemon-reload"])
        .status()
        .unwrap();
    assert!(reload.success());
    assert_recovery_refuses_tampering("service unit");
    fs::write(unit, original_unit).unwrap();
    let reload = Command::new("/usr/bin/systemctl")
        .args(["daemon-reload"])
        .status()
        .unwrap();
    assert!(reload.success());

    let valid_journal = fs::read(journal_path).unwrap();
    fs::write(journal_path, b"{").unwrap();
    assert_recovery_refuses_tampering("journal");
    fs::write(journal_path, valid_journal).unwrap();
    fs::File::open(journal_path).unwrap().sync_all().unwrap();

    for _ in 0..2 {
        let recovery = command(&["update", "recover"]);
        assert!(
            recovery.status.success(),
            "{}\n{}",
            output_text(&recovery),
            recovery_diagnostics()
        );
    }
    assert_eq!(database_identity(), *expected_identity);
}

fn recovery_diagnostics() -> String {
    let status = Command::new("/usr/bin/systemctl")
        .args([
            "status",
            "--no-pager",
            "-l",
            "wg-basic.service",
            "wg-basic-netd.service",
        ])
        .output()
        .unwrap();
    let journal = Command::new("/usr/bin/journalctl")
        .args([
            "-u",
            "wg-basic.service",
            "-u",
            "wg-basic-netd.service",
            "--no-pager",
            "-n",
            "100",
        ])
        .output()
        .unwrap();
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    let uid = management.uid.to_string();
    let gid = group.gid.to_string();
    let doctor = Command::new("/usr/bin/setpriv")
        .args([
            "--reuid",
            uid.as_str(),
            "--regid",
            gid.as_str(),
            "--clear-groups",
            BINARY,
            "doctor",
            "--state",
            distribution_state_path(),
            "--socket",
            wg_basic::distribution::SOCKET_PATH,
            "--json",
            "--allow-warnings",
        ])
        .output()
        .unwrap();
    let identity = Command::new("/usr/sbin/runuser")
        .args([
            "--user",
            "wg-basic",
            "--",
            wg_basic::distribution::BINARY_PATH,
            "state",
            "identity",
            "--state",
            distribution_state_path(),
        ])
        .output()
        .unwrap();
    format!(
        "systemctl={}\njournalctl={}\ndoctor={}\nidentity={}",
        output_text(&status),
        output_text(&journal),
        output_text(&doctor),
        output_text(&identity)
    )
}

fn kill_process_group(child: &mut std::process::Child) {
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .status()
        .unwrap();
    assert!(killed.success(), "could not SIGKILL updater process group");
    let _ = child.wait();
}

fn private_file(path: &Path, bytes: &[u8], owner: u32) {
    fs::write(path, bytes).unwrap();
    nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(owner)), None).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn make_signed_fixture() {
    use sha2::{Digest, Sha256};
    let candidate = std::env::var("WGB_CANDIDATE_BINARY").expect("candidate binary");
    let artifact = fs::read(candidate).unwrap();
    let target = if std::env::consts::ARCH == "x86_64" {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-unknown-linux-gnu"
    };
    let name = format!("wg-basic-{target}");
    let digest = Sha256::digest(&artifact)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "fixtures/release-auth/release-manifest.json"
    ))
    .unwrap();
    manifest["release_id"] = CANDIDATE_VERSION.into();
    manifest["targets"] = serde_json::json!([{
        "target": target,
        "form": { "kind": "direct", "artifact": {
            "name": name, "size": artifact.len(), "sha256": digest
        }, "install": "wg-basic" }
    }]);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let minisign::KeyPair { pk, sk } = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let signature = minisign::sign(
        Some(&pk),
        &sk,
        Cursor::new(&bytes),
        Some("wg-basic C001a disposable fixture"),
        Some("ephemeral qualification key"),
    )
    .unwrap()
    .to_string();
    fs::create_dir(FIXTURE).unwrap();
    fs::set_permissions(FIXTURE, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        Path::new(FIXTURE).join("discovery.json"),
        format!(r#"{{"tag_name":"v{CANDIDATE_VERSION}","prerelease":false,"draft":false}}"#),
    )
    .unwrap();
    fs::write(Path::new(FIXTURE).join("release-manifest.json"), bytes).unwrap();
    fs::write(
        Path::new(FIXTURE).join("release-manifest.json.minisig"),
        signature,
    )
    .unwrap();
    fs::write(
        Path::new(FIXTURE).join("public.key"),
        pk.to_box().unwrap().into_string(),
    )
    .unwrap();
    fs::write(Path::new(FIXTURE).join(name), artifact).unwrap();
    for entry in fs::read_dir(FIXTURE).unwrap() {
        fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
#[ignore = "mutates canonical installation paths and systemd; disposable systemd VM only"]
fn signed_systemd_update_rolls_back_and_retries() {
    use wg_basic::distribution;

    assert_eq!(nix::unistd::geteuid().as_raw(), 0, "run as root");
    println!(
        "C001a qualification environment: {}",
        qualification_environment()
    );
    assert!(
        Path::new("/run/systemd/system").is_dir(),
        "systemd is required"
    );
    for path in [
        distribution::BINARY_PATH,
        distribution::SYSTEM_DIR,
        distribution::STATE_DIR,
        distribution::SYSUSERS_PATH,
        distribution::SERVE_UNIT_PATH,
        distribution::NETD_UNIT_PATH,
        FIXTURE,
    ] {
        assert!(
            !Path::new(path).exists(),
            "disposable host is not clean: {path}"
        );
    }
    make_signed_fixture();

    if !Path::new("/etc/sysusers.d").exists() {
        fs::create_dir("/etc/sysusers.d").unwrap();
        fs::set_permissions("/etc/sysusers.d", fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write("/etc/sysusers.d/wg-basic.conf", distribution::SYSUSERS).unwrap();
    fs::set_permissions(
        "/etc/sysusers.d/wg-basic.conf",
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let sysusers = Command::new("/usr/bin/systemd-sysusers")
        .arg(distribution::SYSUSERS_PATH)
        .output()
        .unwrap();
    assert!(sysusers.status.success(), "{}", output_text(&sysusers));
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    fs::create_dir(distribution::STATE_DIR).unwrap();
    nix::unistd::chown(
        distribution::STATE_DIR,
        Some(management.uid),
        Some(group.gid),
    )
    .unwrap();
    fs::set_permissions(distribution::STATE_DIR, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(
        &Path::new(distribution::STATE_DIR).join(".update-fixture-schema-v4"),
        b"0.1.0\n",
        management.uid.as_raw(),
    );
    let init = Command::new("/usr/bin/setpriv")
        .args([
            "--reuid",
            &management.uid.to_string(),
            "--regid",
            &group.gid.to_string(),
            "--clear-groups",
            BINARY,
            "state",
            "init",
            "--state",
            distribution::STATE_PATH,
        ])
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", output_text(&init));

    let install = command(&["system", "install", "--candidate", BINARY]);
    assert!(install.status.success(), "{}", output_text(&install));
    let before = database_identity();
    let typed_before = typed_state_identity();
    assert_eq!(before.0, 4);

    for phase in [
        "BackupVerified",
        "ServicesStopped",
        "BinaryCommitted",
        "CandidateStarted",
        "CandidateHealthy",
    ] {
        kill_update_at_phase(phase, &before);
    }
    qualify_tampered_recovery_refusal(&before);

    private_file(
        &Path::new(distribution::STATE_DIR).join(".update-fixture-fail-start"),
        format!("{CANDIDATE_VERSION}\n").as_bytes(),
        management.uid.as_raw(),
    );
    private_file(
        &Path::new(distribution::STATE_DIR).join(".update-fixture-restore-gate"),
        b"pause",
        management.uid.as_raw(),
    );
    let mut interrupted_restore = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let restore_entered =
        Path::new(distribution::STATE_DIR).join(".update-fixture-restore-entered");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !restore_entered.exists() && std::time::Instant::now() < deadline {
        assert!(
            interrupted_restore.try_wait().unwrap().is_none(),
            "update exited before restore staging paused"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        restore_entered.exists(),
        "rollback did not enter SQLite restore staging"
    );
    kill_process_group(&mut interrupted_restore);
    fs::remove_file(Path::new(distribution::STATE_DIR).join(".update-fixture-restore-gate"))
        .unwrap();
    fs::remove_file(restore_entered).unwrap();
    for _ in 0..2 {
        let recovery = command(&["update", "recover"]);
        assert!(
            recovery.status.success(),
            "{}\n{}",
            output_text(&recovery),
            recovery_diagnostics()
        );
    }
    let after = database_identity();
    assert_eq!(after, before, "rollback must restore exact state identity");
    assert_eq!(typed_state_identity(), typed_before);
    assert!(Path::new(distribution::BINARY_PATH).exists());

    fs::remove_file(Path::new(distribution::STATE_DIR).join(".update-fixture-fail-start")).unwrap();
    let retry = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .output()
        .unwrap();
    assert!(retry.status.success(), "{}", output_text(&retry));
    let committed = command(&["update", "recover"]);
    assert!(committed.status.success(), "{}", output_text(&committed));
    let after_retry = database_identity();
    assert_eq!(after_retry.0, 5);
    assert_eq!(after_retry.1, before.1);
    assert_eq!(after_retry.2, before.2);
    assert_eq!(after_retry.3, before.3);
    let typed_after_retry = typed_state_identity();
    for field in [
        "installation_id",
        "desired_generation",
        "network_enabled",
        "product_identity_sha256",
    ] {
        assert_eq!(
            typed_after_retry.get(field),
            typed_before.get(field),
            "successful migration must preserve typed state field {field}"
        );
    }
    assert_eq!(
        typed_after_retry
            .get("schema_version")
            .and_then(serde_json::Value::as_i64),
        Some(5)
    );

    let stop = Command::new("/usr/bin/systemctl")
        .args([
            "disable",
            "--now",
            "wg-basic.service",
            "wg-basic-netd.service",
        ])
        .status()
        .unwrap();
    assert!(stop.success());
}
