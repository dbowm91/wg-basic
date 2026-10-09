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

fn distribution_state_path() -> &'static str {
    wg_basic::distribution::STATE_PATH
}

fn kill_update_at_phase(phase: &str, expected_identity: &(i64, String, i64, i64)) {
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

    for _ in 0..2 {
        let recovery = command(&["update", "recover"]);
        assert!(
            recovery.status.success(),
            "recovery after {phase} failed: {}",
            output_text(&recovery)
        );
    }
    assert_eq!(database_identity(), *expected_identity);
    let _ = fs::remove_dir_all(gate);
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
        assert!(recovery.status.success(), "{}", output_text(&recovery));
    }
    let after = database_identity();
    assert_eq!(after, before, "rollback must restore exact state identity");
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
