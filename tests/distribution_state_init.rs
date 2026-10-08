use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

fn temp_root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "wg-basic-state-init-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn state_init_creates_once_then_validates_existing_state() {
    let root = temp_root();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let database = root.join("state.db");

    for expected in ["state initialized:", "state ready:"] {
        let output = Command::new(BINARY)
            .args(["state", "init", "--state"])
            .arg(&database)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(expected));
    }

    let _ = fs::remove_dir_all(root);
}
