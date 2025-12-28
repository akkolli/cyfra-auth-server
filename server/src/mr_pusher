//! auth_server.rs
//!
//! Auth websocket server for auth.cyfra.org
//! - User WS port: clients authenticate via your existing nonce/signature flow, then can register Expo push tokens.
//! - Service WS port: pluto connects as a trusted service (shared secret) and asks auth to send push notifications.
//!
//! DB storage layout (key/value):
//!   1) longterm_id -> enc_pubkey                (you already do this; kept here)
//!   2) [longterm_id | "push" | device_id] -> PushTokenRecord JSON
//!
//! Env vars:
//!   AUTH_USER_ADDR="0.0.0.0:9001"         (default)
//!   AUTH_SERVICE_ADDR="0.0.0.0:9002"      (default)
//!   PLUTO_SERVICE_TOKEN="supersecret"     (required for service port)
//!   EXPO_PUSH_URL="https://exp.host/--/api/v2/push/send" (default)
//!
//! Cargo.toml deps (minimum):
//!   tokio = { version="1", features=["full"] }
//!   tokio-tungstenite = "0.23"
//!   tungstenite = "0.23"
//!   futures-util = "0.3"
//!   serde = { version="1", features=["derive"] }
//!   serde_json = "1"
//!   rand = "0.8"
//!   reqwest = { version="0.12", features=["json", "rustls-tls"] }
//!
//! Notes:
//! - This uses Expo Push Service (you said you already have Expo push token in the mobile app).
//! - This keeps everything WS-only for internal control plane, but auth still must do outbound HTTPS to Expo.

use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use shared::{encryption, storage};
use std::{str::FromStr, sync::Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    RwLock,
};
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message, WebSocketStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthWsMsg {
    // From mobile client (over user port) AFTER verify_connection()
    RegisterPushToken {
        expo_push_token: String,
        platform: String, // "ios"
        device_id: String,
        app_build: Option<String>,
    },

    // From pluto service (over service port) AFTER service auth
    PushSend {
        to_user_id_hex: String, // hex encoding of longterm_id bytes
        title: String,
        body: String,
        data: serde_json::Value,
    },

    // First message on service port only
    ServiceAuth { token: String },

    Ok { request_id: Option<String> },
    Err { message: String, request_id: Option<String> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PushTokenRecord {
    pub expo_push_token: String,
    pub platform: String,
    pub device_id: String,
    pub app_build: Option<String>,
    pub enabled: bool,
    pub updated_at: u64,
}

/// --- Helpers: hex encoding (no extra crate) ---
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
fn from_hex(s: &str) -> Result<Vec<u8>, BoxError> {
    if s.len() % 2 != 0 {
        return Err("hex string length must be even".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let hi = chars[i].to_digit(16).ok_or("bad hex")?;
        let lo = chars[i + 1].to_digit(16).ok_or("bad hex")?;
        out.push(((hi << 4) + lo) as u8);
    }
    Ok(out)
}

/// --- DB key helpers ---
fn db_key_push_token(longterm_id: &[u8], device_id: &str) -> Vec<u8> {
    // [longterm_id | "push" | device_id]
    let mut key = Vec::with_capacity(longterm_id.len() + 4 + device_id.len());
    key.extend_from_slice(longterm_id);
    key.extend_from_slice(b"push");
    key.extend_from_slice(device_id.as_bytes());
    key
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// --- Your existing auth handshake (copied from your pluto code, unchanged except small formatting) ---
pub async fn verify_connection(
    conn: &mut WebSocketStream<TcpStream>,
    db: Arc<RwLock<storage::DB>>,
) -> Result<Vec<u8>, BoxError> {
    // send a nonce
    let nonce = rand::random::<u32>().to_ne_bytes();
    conn.send(Message::binary(nonce.to_vec())).await?;

    // receive signature with timeout
    let signature_msg = timeout(AUTH_TIMEOUT, conn.next())
        .await
        .map_err(|_| "Timed out waiting for signature")?
        .ok_or("Connection closed waiting for signature")??;

    if let Message::Binary(signature) = signature_msg {
        // receive longterm_id with timeout
        let longterm_id_msg = timeout(AUTH_TIMEOUT, conn.next())
            .await
            .map_err(|_| "Timed out waiting for public key")?
            .ok_or("Connection closed waiting for public key")??;

        if let Message::Binary(longterm_id) = longterm_id_msg {
            if encryption::verify(&nonce, &longterm_id, &signature).is_ok() {
                // send confirm verified
                conn.send(Message::text(shared::get_verification_message()))
                    .await?;

                // Receive enc pubkey with timeout
                let enc_pubkey_msg = timeout(AUTH_TIMEOUT, conn.next())
                    .await
                    .map_err(|_| "Timed out waiting for enc pubkey")?
                    .ok_or("Connection closed waiting for enc pubkey")??;

                if let Message::Binary(enc_pubkey) = enc_pubkey_msg {
                    // store key in database: longterm_id -> enc_pubkey
                    storage::async_set_value_in_db(&longterm_id, &enc_pubkey, db.clone()).await?;

                    // tell client key update
                    conn.send(Message::text(shared::get_key_updated_message()))
                        .await?;

                    return Ok(longterm_id.to_vec());
                }
            } else {
                return Err("Signature verification failed".into());
            }
        }
    }

    conn.close(None).await.ok();
    Err("Failed to verify connection: unexpected message sequence".into())
}

/// --- Expo push sender ---
#[derive(Debug, Serialize)]
struct ExpoPushMessage<'a> {
    to: &'a str,
    title: &'a str,
    body: &'a str,
    data: &'a serde_json::Value,
    // You can add "sound", "badge", "priority", etc. later if you want
}

#[derive(Debug, Deserialize)]
struct ExpoPushResponse {
    data: Vec<ExpoPushTicket>,
}
#[derive(Debug, Deserialize)]
struct ExpoPushTicket {
    status: String, // "ok" or "error"
    id: Option<String>,
    message: Option<String>,
    details: Option<serde_json::Value>,
}

async fn send_expo_push_batch(
    expo_url: &str,
    messages: &[serde_json::Value],
) -> Result<ExpoPushResponse, BoxError> {
    let client = reqwest::Client::new();
    let resp = client
        .post(expo_url)
        .json(&serde_json::json!({ "messages": messages }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Expo push HTTP error: {} {}", resp.status(), text).into());
    }

    Ok(resp.json::<ExpoPushResponse>().await?)
}

fn chunked<T>(v: &[T], chunk: usize) -> impl Iterator<Item = &[T]> {
    v.chunks(chunk)
}

/// --- Core: store push token record ---
async fn store_push_token(
    user_longterm_id: &[u8],
    device_id: &str,
    expo_push_token: &str,
    platform: &str,
    app_build: Option<&str>,
    db: Arc<RwLock<storage::DB>>,
) -> Result<(), BoxError> {
    // Basic sanity check to avoid junk
    if !expo_push_token.starts_with("ExponentPushToken[") && !expo_push_token.starts_with("ExpoPushToken[") {
        // still allow if you want, but this catches most accidental tokens
        eprintln!("Warning: token does not look like an Expo push token");
    }

    let rec = PushTokenRecord {
        expo_push_token: expo_push_token.to_string(),
        platform: platform.to_string(),
        device_id: device_id.to_string(),
        app_build: app_build.map(|s| s.to_string()),
        enabled: true,
        updated_at: now_unix(),
    };

    let key = db_key_push_token(user_longterm_id, device_id);
    let val = serde_json::to_vec(&rec)?;
    storage::async_set_value_in_db(key.as_ref(), val.as_ref(), db).await?;
    Ok(())
}

/// --- Core: load all tokens for a user ---
/// Since your DB is key-value and we don't see a prefix-scan API, we do something practical:
/// - You can either maintain a "device index" key per user, OR
/// - If your DB supports prefix scans, implement it there.
///
/// For now, we implement a small index:
///   key: [longterm_id | "push_devices"] -> JSON Vec<String> of device_ids
fn db_key_push_devices(longterm_id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(longterm_id.len() + 12);
    key.extend_from_slice(longterm_id);
    key.extend_from_slice(b"push_devices");
    key
}

async fn upsert_device_index(
    user_longterm_id: &[u8],
    device_id: &str,
    db: Arc<RwLock<storage::DB>>,
) -> Result<(), BoxError> {
    let idx_key = db_key_push_devices(user_longterm_id);
    let existing = storage::async_get_value_from_db(idx_key.as_ref(), db.clone()).await?;
    let mut devices: Vec<String> = if let Some(b) = existing {
        serde_json::from_slice(&b)?
    } else {
        Vec::new()
    };

    if !devices.iter().any(|d| d == device_id) {
        devices.push(device_id.to_string());
        let v = serde_json::to_vec(&devices)?;
        storage::async_set_value_in_db(idx_key.as_ref(), v.as_ref(), db).await?;
    }
    Ok(())
}

async fn load_push_tokens_for_user(
    user_longterm_id: &[u8],
    db: Arc<RwLock<storage::DB>>,
) -> Result<Vec<PushTokenRecord>, BoxError> {
    let idx_key = db_key_push_devices(user_longterm_id);
    let existing = storage::async_get_value_from_db(idx_key.as_ref(), db.clone()).await?;

    let devices: Vec<String> = if let Some(b) = existing {
        serde_json::from_slice(&b)?
    } else {
        Vec::new()
    };

    let mut out = Vec::new();
    for device_id in devices {
        let key = db_key_push_token(user_longterm_id, &device_id);
        if let Some(b) = storage::async_get_value_from_db(key.as_ref(), db.clone()).await? {
            if let Ok(rec) = serde_json::from_slice::<PushTokenRecord>(&b) {
                if rec.enabled {
                    out.push(rec);
                }
            }
        }
    }
    Ok(out)
}

async fn disable_push_token(
    user_longterm_id: &[u8],
    device_id: &str,
    db: Arc<RwLock<storage::DB>>,
) -> Result<(), BoxError> {
    let key = db_key_push_token(user_longterm_id, device_id);
    if let Some(b) = storage::async_get_value_from_db(key.as_ref(), db.clone()).await? {
        let mut rec: PushTokenRecord = serde_json::from_slice(&b)?;
        rec.enabled = false;
        rec.updated_at = now_unix();
        let v = serde_json::to_vec(&rec)?;
        storage::async_set_value_in_db(key.as_ref(), v.as_ref(), db).await?;
    }
    Ok(())
}

/// --- WS plumbing: inbox/outbox loops ---
async fn respond_to_requests(
    read: &mut SplitStream<WebSocketStream<TcpStream>>,
    tx: &mut Sender<Message>,
) -> Result<(), BoxError> {
    while let Some(msg_result) = read.next().await {
        match msg_result {
            Ok(msg) => {
                if tx.send(msg).await.is_err() {
                    break;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

async fn send_outgoing(
    write: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    rx: &mut Receiver<Message>,
) {
    while let Some(message) = rx.recv().await {
        if let Err(e) = write.send(message).await {
            println!("Write error (disconnected?): {}", e);
            break;
        }
    }
}

/// --- User connection handler (mobile clients) ---
async fn handle_user_ws(mut ws: WebSocketStream<TcpStream>, db: Arc<RwLock<storage::DB>>) -> Result<(), BoxError> {
    let user_longterm_id = verify_connection(&mut ws, db.clone()).await?;
    println!(
        "User verified: longterm_id(hex)={}",
        to_hex(&user_longterm_id)
    );

    let (mut write, mut read) = ws.split();
    let (mut inbox_tx, mut inbox_rx) = tokio::sync::mpsc::channel::<Message>(256);
    let (mut outbox_tx, mut outbox_rx) = tokio::sync::mpsc::channel::<Message>(256);

    let mut read_handle = tokio::spawn(async move {
        if let Err(e) = respond_to_requests(&mut read, &mut inbox_tx).await {
            println!("User read loop ended: {}", e);
        }
    });

    let mut write_handle = tokio::spawn(async move {
        send_outgoing(&mut write, &mut outbox_rx).await;
    });

    // Process messages
    while let Some(msg) = inbox_rx.recv().await {
        match msg {
            Message::Text(txt) => {
                let parsed = serde_json::from_str::<AuthWsMsg>(&txt);
                match parsed {
                    Ok(AuthWsMsg::RegisterPushToken {
                        expo_push_token,
                        platform,
                        device_id,
                        app_build,
                    }) => {
                        // store token record
                        store_push_token(
                            &user_longterm_id,
                            &device_id,
                            &expo_push_token,
                            &platform,
                            app_build.as_deref(),
                            db.clone(),
                        )
                        .await?;

                        // maintain device index
                        upsert_device_index(&user_longterm_id, &device_id, db.clone()).await?;

                        let ok = AuthWsMsg::Ok { request_id: None };
                        let s = serde_json::to_string(&ok)?;
                        let _ = outbox_tx.send(Message::Text(s)).await;
                    }
                    Ok(other) => {
                        let err = AuthWsMsg::Err {
                            message: format!("Unsupported message on user socket: {:?}", other),
                            request_id: None,
                        };
                        let _ = outbox_tx
                            .send(Message::Text(serde_json::to_string(&err)?))
                            .await;
                    }
                    Err(e) => {
                        let err = AuthWsMsg::Err {
                            message: format!("Bad JSON: {}", e),
                            request_id: None,
                        };
                        let _ = outbox_tx
                            .send(Message::Text(serde_json::to_string(&err)?))
                            .await;
                    }
                }
            }
            Message::Close(_) => break,
            _ => {
                // ignore binary/ping/pong etc for now
            }
        }
    }

    // Cleanup
    read_handle.abort();
    write_handle.abort();
    Ok(())
}

/// --- Service connection handler (pluto -> auth) ---
async fn handle_service_ws(mut ws: WebSocketStream<TcpStream>, db: Arc<RwLock<storage::DB>>) -> Result<(), BoxError> {
    // First frame must be ServiceAuth
    let first = timeout(AUTH_TIMEOUT, ws.next())
        .await
        .map_err(|_| "Timed out waiting for service auth")?
        .ok_or("Service connection closed")??;

    let token = match first {
        Message::Text(txt) => {
            let msg = serde_json::from_str::<AuthWsMsg>(&txt)?;
            match msg {
                AuthWsMsg::ServiceAuth { token } => token,
                _ => return Err("First message must be service_auth".into()),
            }
        }
        _ => return Err("First message must be text service_auth".into()),
    };

    let expected = std::env::var("PLUTO_SERVICE_TOKEN")
        .map_err(|_| "Missing PLUTO_SERVICE_TOKEN env var")?;
    if token != expected {
        ws.send(Message::Text(
            serde_json::to_string(&AuthWsMsg::Err {
                message: "Bad service token".into(),
                request_id: None,
            })?,
        ))
        .await
        .ok();
        ws.close(None).await.ok();
        return Err("Bad service token".into());
    }

    ws.send(Message::Text(
        serde_json::to_string(&AuthWsMsg::Ok { request_id: None })?,
    ))
    .await?;

    println!("Pluto service authenticated");

    let expo_url = std::env::var("EXPO_PUSH_URL")
        .unwrap_or_else(|_| "https://exp.host/--/api/v2/push/send".to_string());

    // Main loop: receive PushSend requests
    while let Some(msg) = ws.next().await {
        let msg = msg?;
        if let Message::Text(txt) = msg {
            let parsed = serde_json::from_str::<AuthWsMsg>(&txt);
            match parsed {
                Ok(AuthWsMsg::PushSend {
                    to_user_id_hex,
                    title,
                    body,
                    data,
                }) => {
                    let user_id = from_hex(&to_user_id_hex)?;
                    let tokens = load_push_tokens_for_user(&user_id, db.clone()).await?;

                    if tokens.is_empty() {
                        // no tokens registered; not an error
                        continue;
                    }

                    // Build Expo messages (batch up to 100 at a time; Expo supports batching)
                    let mut msg_values: Vec<serde_json::Value> = Vec::with_capacity(tokens.len());
                    for t in &tokens {
                        msg_values.push(serde_json::to_value(ExpoPushMessage {
                            to: &t.expo_push_token,
                            title: &title,
                            body: &body,
                            data: &data,
                        })?);
                    }

                    // Send in chunks (safe)
                    for chunk in chunked(&msg_values, 100) {
                        let resp = send_expo_push_batch(&expo_url, chunk).await;

                        match resp {
                            Ok(r) => {
                                // If any tickets are errors indicating unregistered device, disable token.
                                // Note: Expo often returns error details including "DeviceNotRegistered"
                                // We'll do a simple heuristic on "details".
                                for (i, ticket) in r.data.iter().enumerate() {
                                    if ticket.status == "error" {
                                        let idx = i; // index in this chunk
                                        // Find the token corresponding to this message
                                        // We can map by order: chunk[idx] corresponds to tokens[...]
                                        // Determine global token index:
                                        // This is a little annoying; easiest is to send one chunk aligned to tokens.
                                        // We do it by reconstructing a slice offset:
                                        // We'll just disable if we can parse details.
                                        let details_str = ticket
                                            .details
                                            .as_ref()
                                            .map(|d| d.to_string())
                                            .unwrap_or_default();
                                        let msg_str = ticket.message.clone().unwrap_or_default();

                                        // Common expo invalid token signals
                                        let looks_invalid = details_str.contains("DeviceNotRegistered")
                                            || details_str.contains("NotRegistered")
                                            || msg_str.contains("DeviceNotRegistered")
                                            || msg_str.contains("not registered");

                                        if looks_invalid {
                                            // Best-effort: disable the corresponding device token.
                                            // We don't have device_id in the ticket, so disable all tokens with same expo token
                                            // Simplest: disable by matching expo token string.
                                            let expo_to_disable = chunk[idx]
                                                .get("to")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");

                                            // Disable any record that matches this expo token:
                                            // Since we store by device_id, we scan the token list we loaded and disable matches.
                                            for t in &tokens {
                                                if t.expo_push_token == expo_to_disable {
                                                    let _ = disable_push_token(&user_id, &t.device_id, db.clone()).await;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Expo push send failed: {}", e);
                                // You can add retry/backoff here later. For MVP, just log.
                            }
                        }
                    }
                }
                Ok(AuthWsMsg::Ok { .. }) => {}
                Ok(AuthWsMsg::Err { .. }) => {}
                Ok(other) => {
                    eprintln!("Unsupported service message: {:?}", other);
                }
                Err(e) => {
                    eprintln!("Bad JSON from service: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// --- Server accept loops ---
async fn run_user_listener(addr: &str, db: Arc<RwLock<storage::DB>>) -> Result<(), BoxError> {
    let listener = TcpListener::bind(addr).await?;
    println!("Auth USER listener on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let db = db.clone();

        tokio::spawn(async move {
            match accept_async(stream).await {
                Ok(ws) => {
                    if let Err(e) = handle_user_ws(ws, db).await {
                        eprintln!("User connection error: {}", e);
                    }
                }
                Err(e) => eprintln!("WS handshake (user) failed: {}", e),
            }
        });
    }
}

async fn run_service_listener(addr: &str, db: Arc<RwLock<storage::DB>>) -> Result<(), BoxError> {
    let listener = TcpListener::bind(addr).await?;
    println!("Auth SERVICE listener on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let db = db.clone();

        tokio::spawn(async move {
            match accept_async(stream).await {
                Ok(ws) => {
                    if let Err(e) = handle_service_ws(ws, db).await {
                        eprintln!("Service connection error: {}", e);
                    }
                }
                Err(e) => eprintln!("WS handshake (service) failed: {}", e),
            }
        });
    }
}
