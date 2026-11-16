//! Loopback fake OIDC authorization server for M003 qualification.

use base64::Engine;
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest as _, Sha256 as Sha256Hasher};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const CLIENT_SECRET: &str = "fake-oidc-client-secret";
const CLIENT_ID: &str = "wg-basic-test";
const KID: &str = "test-key";

#[derive(Clone)]
struct FlowRecord {
    code_challenge: String,
    nonce: String,
    redirect_uri: String,
}

pub struct FakeOidcIdp {
    issuer: String,
}

impl FakeOidcIdp {
    pub fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://127.0.0.1:{}", addr.port());
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key");
        let signing = SigningKey::<Sha256>::new(private.clone());
        let public = private.to_public_key();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let n_b64 = engine.encode(public.n().to_bytes_be());
        let e_b64 = engine.encode(public.e().to_bytes_be());
        let flows = Arc::new(Mutex::new(HashMap::<String, FlowRecord>::new()));
        let issuer_thread = issuer.clone();
        thread::spawn(move || serve(listener, issuer_thread, flows, signing, n_b64, e_b64));
        Self { issuer }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn client_id(&self) -> &'static str {
        CLIENT_ID
    }

    pub fn client_secret(&self) -> &'static str {
        CLIENT_SECRET
    }
}

fn serve(
    listener: TcpListener,
    issuer: String,
    flows: Arc<Mutex<HashMap<String, FlowRecord>>>,
    signing: SigningKey<Sha256>,
    n_b64: String,
    e_b64: String,
) {
    for stream in listener.incoming().flatten() {
        let _ = handle_connection(stream, &issuer, &flows, &signing, &n_b64, &e_b64);
    }
}

fn handle_connection(
    mut stream: std::net::TcpStream,
    issuer: &str,
    flows: &Arc<Mutex<HashMap<String, FlowRecord>>>,
    signing: &SigningKey<Sha256>,
    n_b64: &str,
    e_b64: &str,
) -> std::io::Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024];
    let read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let mut lines = request.lines();
    let Some(request_line) = lines.next() else {
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");
    let (path, query) = target
        .split_once('?')
        .map(|(path, query)| (path, Some(query)))
        .unwrap_or((target, None));
    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
    let response = match (method, path) {
        ("GET", "/.well-known/openid-configuration") => discovery(issuer),
        ("GET", "/jwks") => jwks(n_b64, e_b64),
        ("GET", "/authorize") => authorize(query, flows),
        ("POST", "/token") => token(body, issuer, flows, signing),
        _ => respond(404, "text/plain", "not found"),
    };
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn discovery(issuer: &str) -> String {
    let json = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    });
    respond(200, "application/json", &json.to_string())
}

fn jwks(n_b64: &str, e_b64: &str) -> String {
    let json = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": KID,
            "use": "sig",
            "alg": "RS256",
            "n": n_b64,
            "e": e_b64,
        }]
    });
    respond(200, "application/json", &json.to_string())
}

fn authorize(query: Option<&str>, flows: &Arc<Mutex<HashMap<String, FlowRecord>>>) -> String {
    let params = parse_query(query);
    let Some(state) = params.get("state") else {
        return respond(400, "text/plain", "missing state");
    };
    let Some(redirect_uri) = params.get("redirect_uri") else {
        return respond(400, "text/plain", "missing redirect");
    };
    let code = format!("auth-code-{state}");
    flows.lock().unwrap().insert(
        code.clone(),
        FlowRecord {
            code_challenge: params.get("code_challenge").cloned().unwrap_or_default(),
            nonce: params.get("nonce").cloned().unwrap_or_default(),
            redirect_uri: redirect_uri.clone(),
        },
    );
    let location = format!(
        "{redirect_uri}?code={}&state={}",
        percent_encode(&code),
        percent_encode(state)
    );
    respond_redirect(&location)
}

fn token(
    body: &str,
    issuer: &str,
    flows: &Arc<Mutex<HashMap<String, FlowRecord>>>,
    signing: &SigningKey<Sha256>,
) -> String {
    let params = parse_query(Some(body));
    if params.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return respond(
            400,
            "application/json",
            r#"{"error":"unsupported_grant_type"}"#,
        );
    }
    if params.get("client_id").map(String::as_str) != Some(CLIENT_ID) {
        return respond(401, "application/json", r#"{"error":"invalid_client"}"#);
    }
    if params.get("client_secret").map(String::as_str) != Some(CLIENT_SECRET) {
        return respond(401, "application/json", r#"{"error":"invalid_client"}"#);
    }
    let Some(code) = params.get("code") else {
        return respond(400, "application/json", r#"{"error":"invalid_request"}"#);
    };
    let Some(flow) = flows.lock().unwrap().remove(code) else {
        return respond(400, "application/json", r#"{"error":"invalid_grant"}"#);
    };
    if params
        .get("redirect_uri")
        .map(String::as_str)
        .is_some_and(|value| value != flow.redirect_uri)
    {
        return respond(400, "application/json", r#"{"error":"invalid_grant"}"#);
    }
    let verifier = params.get("code_verifier").cloned().unwrap_or_default();
    if !pkce_matches(&verifier, &flow.code_challenge) {
        return respond(400, "application/json", r#"{"error":"invalid_grant"}"#);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let id_token = sign_id_token(
        signing,
        issuer,
        CLIENT_ID,
        "admin",
        "admin@example.com",
        &flow.nonce,
        now + 300,
    );
    let json = serde_json::json!({
        "access_token": "fake-access",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    });
    respond(200, "application/json", &json.to_string())
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    if challenge.is_empty() {
        return true;
    }
    let digest = Sha256Hasher::digest(verifier.as_bytes());
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine.encode(digest) == *challenge
}

fn sign_id_token(
    signing: &SigningKey<Sha256>,
    issuer: &str,
    audience: &str,
    subject: &str,
    email: &str,
    nonce: &str,
    exp: i64,
) -> String {
    let header = serde_json::json!({"alg":"RS256","kid":KID,"typ":"JWT"});
    let payload = serde_json::json!({
        "iss": issuer,
        "aud": [audience],
        "sub": subject,
        "email": email,
        "email_verified": true,
        "nonce": nonce,
        "exp": exp,
        "iat": exp - 60,
    });
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = engine.encode(header.to_string());
    let payload_b64 = engine.encode(payload.to_string());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing.sign(signing_input.as_bytes());
    let sig_b64 = engine.encode(signature.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(query) = query else {
        return map;
    };
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            map.insert(percent_decode(key), percent_decode(value));
        }
    }
    map
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Ok(hi), Ok(lo)) = (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2])) {
                decoded.push((hi << 4) | lo);
                index += 3;
                continue;
            }
        } else if bytes[index] == b'+' {
            decoded.push(b' ');
            index += 1;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

fn respond(status: u16, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn respond_redirect(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}
