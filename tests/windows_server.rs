//! Live Windows Server checks. They run only on `windows-2025` with
//! `WGB_WINDOWS_LIVE=1` after `scripts/fetch-wireguard-nt.ps1`.
//! Compilation of this file is not kernel evidence.

#![cfg(windows)]

use std::time::{Duration, Instant};
use wg_basic::platform::windows;

fn live() {
    assert_eq!(
        std::env::var("WGB_WINDOWS_LIVE").ok().as_deref(),
        Some("1"),
        "set WGB_WINDOWS_LIVE=1 to run the windows-2025 checks"
    );
}

#[test]
#[ignore]
fn sku_is_server_2025_amd64() {
    live();
    let facts = wg_basic_win32_sys::os_facts().expect("os facts");
    windows::sku_allowed(&facts.installation_type, &facts.architecture, facts.build)
        .unwrap_or_else(|reason| panic!("{} ({})", reason.as_str(), facts.caption));
}

#[test]
#[ignore]
fn pinned_dll_handshakes_between_two_local_adapters() {
    live();
    let dll = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("wireguard.dll");
    assert!(
        windows::dll_matches_pin(&dll),
        "wireguard.dll beside the test binary does not match the pin"
    );
    wg_basic_win32_sys::load_wireguard(&dll).unwrap();
    let server_keys = wg_basic::wireguard::generate_keypair().unwrap();
    let client_keys = wg_basic::wireguard::generate_keypair().unwrap();
    let server_guid = windows::adapter_guid(
        "00000000-0000-4000-8000-0000000000a1".parse().unwrap(),
        "00000000-0000-4000-8000-0000000000b2".parse().unwrap(),
    );
    let client_guid = windows::adapter_guid(
        "00000000-0000-4000-8000-0000000000a1".parse().unwrap(),
        "00000000-0000-4000-8000-0000000000b3".parse().unwrap(),
    );
    let server = wg_basic_win32_sys::Adapter::create("wgb-live-a", &server_guid).unwrap();
    let client = wg_basic_win32_sys::Adapter::create("wgb-live-b", &client_guid).unwrap();
    let server_public = key_bytes(server_keys.public_key.expose());
    let client_public = key_bytes(client_keys.public_key.expose());
    server
        .set_config(&wg_basic_win32_sys::DeviceConfig {
            private_key: Some(key_bytes(server_keys.private_key.expose_secret())),
            public_key: Some(server_public),
            listen_port: 51821,
            peers: vec![wg_basic_win32_sys::PeerConfig {
                public_key: client_public,
                preshared_key: None,
                persistent_keepalive: 1,
                endpoint: None,
                allowed_ips: vec![("10.88.0.2".parse().unwrap(), 32)],
                tx_bytes: 0,
                rx_bytes: 0,
                last_handshake: 0,
            }],
        })
        .unwrap();
    client
        .set_config(&wg_basic_win32_sys::DeviceConfig {
            private_key: Some(key_bytes(client_keys.private_key.expose_secret())),
            public_key: Some(client_public),
            listen_port: 0,
            peers: vec![wg_basic_win32_sys::PeerConfig {
                public_key: server_public,
                preshared_key: None,
                persistent_keepalive: 1,
                endpoint: Some("127.0.0.1:51821".parse().unwrap()),
                allowed_ips: vec![("10.88.0.1".parse().unwrap(), 32)],
                tx_bytes: 0,
                rx_bytes: 0,
                last_handshake: 0,
            }],
        })
        .unwrap();
    server.set_up(true).unwrap();
    client.set_up(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut shook = false;
    while Instant::now() < deadline {
        let config = client.get_config().unwrap();
        if config
            .peers
            .iter()
            .any(|peer| peer.last_handshake != 0 && (peer.tx_bytes > 0 || peer.rx_bytes > 0))
        {
            shook = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(client);
    drop(server);
    assert!(shook, "the two local adapters did not complete a handshake");
}

#[test]
#[ignore]
fn foreign_nat_is_refused_and_left_in_place() {
    live();
    let existing = wg_basic_win32_sys::list_nats().expect("Get-NetNat equivalent");
    let owned = windows::owned_nat_name("00000000-0000-4000-8000-0000000000c4".parse().unwrap());
    let observed: Vec<_> = existing
        .iter()
        .map(|nat| windows::ObservedNat {
            name: nat.name.clone(),
            internal_prefix: nat.internal_prefix.clone(),
        })
        .collect();
    if observed.is_empty() {
        wg_basic_win32_sys::create_nat(&owned, "10.88.0.0/24").unwrap();
        let after = wg_basic_win32_sys::list_nats().unwrap();
        assert!(after.iter().any(|nat| nat.name == owned));
        wg_basic_win32_sys::delete_nat(&owned).unwrap();
        return;
    }
    let before = observed.clone();
    let decision = windows::decide_nat(&observed, &owned, "10.88.0.0/24");
    assert!(matches!(decision, windows::NatDecision::Refuse { .. }));
    let after = wg_basic_win32_sys::list_nats().unwrap();
    assert_eq!(before.len(), after.len());
}

#[test]
#[ignore]
fn an_existing_pipe_is_left_in_place_and_the_peer_sid_is_the_caller() {
    live();
    let name = r"\\.\pipe\wg-basic-live";
    let sid = wg_basic_win32_sys::current_user_sid().unwrap();
    let listener = wg_basic_win32_sys::PipeListener::bind(name, &sid).unwrap();
    assert!(wg_basic_win32_sys::PipeListener::bind(name, &sid).is_err());
    let expected = sid.as_str().to_string();
    let client = std::thread::spawn(|| wg_basic_win32_sys::connect_pipe(name));
    let mut accepted = None;
    for _ in 0..25 {
        match listener.accept() {
            Ok(pipe) => {
                accepted = Some(pipe);
                break;
            }
            Err(error) if error.is_timeout() => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => panic!("accept failed: {error}"),
        }
    }
    let accepted = accepted.expect("the client never connected");
    assert_eq!(accepted.peer_sid.as_str(), expected);
    assert!(accepted.high_integrity);
    drop(accepted);
    client.join().unwrap().unwrap();
}

fn key_bytes(text: &str) -> [u8; 32] {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap();
    bytes.try_into().unwrap()
}
