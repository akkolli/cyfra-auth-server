use warp::Filter;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use shared::{storage, encryption};
use std::time::{SystemTime, UNIX_EPOCH};

const SERVER_DB_PATH: &str = "./auth_db";
const MAX_TIMESTAMP_AGE_SECS: u64 = 300; // 5 minutes

fn current_timestamp_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn is_timestamp_fresh(timestamp: u64) -> bool {
    let now = current_timestamp_secs();
    // Handle both seconds and milliseconds (JS Date.now() uses millis)
    let ts_secs = if timestamp > 1_000_000_000_000 { timestamp / 1000 } else { timestamp };
    now.abs_diff(ts_secs) <= MAX_TIMESTAMP_AGE_SECS
}

fn contains_pipe(s: &str) -> bool {
    s.contains('|')
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RegisterDeviceRequest {
    username: String,
    client_type: String, // "apple" or "android"
    push_token: String,
    public_key: String, // hex
    signature: String, // hex
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PushTriggerRequest {
    recipient_pub_key: String, // hex
    sender_pub_key: String, // hex
    timestamp: u64,
    signed_timestamp: String, // hex encoded signature
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PushTokenRecord {
    pub expo_push_token: String,
    pub platform: String,
    pub enabled: bool,
    pub updated_at: u64,
}

#[tokio::main]
async fn main() {
    let db = storage::get_db(SERVER_DB_PATH).unwrap();
    let db = Arc::new(RwLock::new(db));
    let client = reqwest::Client::new();

    // POST /register_device
    let register_db = db.clone();
    let register_route = warp::post()
        .and(warp::path("register_device"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and_then(move |req: RegisterDeviceRequest| {
            let db = register_db.clone();
            handle_register_device(req, db)
        });

    // POST /push_trigger
    let push_db = db.clone();
    let push_client = client.clone();
    let push_route = warp::post()
        .and(warp::path("push_trigger"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and_then(move |req: PushTriggerRequest| {
            let db = push_db.clone();
            let client = push_client.clone();
            handle_push_trigger(req, db, client)
        });

    let routes = register_route.or(push_route);

    println!("Auth Server listening on 0.0.0.0:3000");
    warp::serve(routes).run(([0, 0, 0, 0], 3000)).await;
}

async fn handle_register_device(req: RegisterDeviceRequest, db: Arc<RwLock<storage::DB>>) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Received register device request for user: {}", req.username);

    // Reject pipe characters to prevent signed-data delimiter confusion
    if contains_pipe(&req.username) || contains_pipe(&req.client_type) || contains_pipe(&req.push_token) {
        return Ok(warp::reply::with_status("Fields must not contain '|'", warp::http::StatusCode::BAD_REQUEST));
    }

    // Reject stale or future timestamps to prevent replay attacks
    if !is_timestamp_fresh(req.timestamp) {
        return Ok(warp::reply::with_status("Timestamp too old or too far in the future", warp::http::StatusCode::BAD_REQUEST));
    }

    // 1. Verify Signature
    let pub_key_bytes = match hex::decode(&req.public_key) {
        Ok(b) => b,
        Err(_) => return Ok(warp::reply::with_status("Invalid hex for public key", warp::http::StatusCode::BAD_REQUEST)),
    };

    let signature_bytes = match hex::decode(&req.signature) {
        Ok(b) => b,
        Err(_) => return Ok(warp::reply::with_status("Invalid hex for signature", warp::http::StatusCode::BAD_REQUEST)),
    };

    // Construct signed data: register_device|username|client_type|push_token|timestamp
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(b"register_device|");
    signed_data.extend_from_slice(req.username.as_bytes());
    signed_data.extend_from_slice(b"|");
    signed_data.extend_from_slice(req.client_type.as_bytes());
    signed_data.extend_from_slice(b"|");
    signed_data.extend_from_slice(req.push_token.as_bytes());
    signed_data.extend_from_slice(b"|");
    let timestamp_str = req.timestamp.to_string();
    signed_data.extend_from_slice(timestamp_str.as_bytes());

    if encryption::verify(&signed_data, &pub_key_bytes, &signature_bytes).is_err() {
        println!("Signature verification failed");
        return Ok(warp::reply::with_status("Invalid signature", warp::http::StatusCode::UNAUTHORIZED));
    }

    println!("Signature verified successfully");

    // 2. Store Token
    let record = PushTokenRecord {
        expo_push_token: req.push_token.clone(),
        platform: req.client_type.clone(),
        enabled: true,
        updated_at: current_timestamp_secs(),
    };

    let key = [pub_key_bytes, b"push_token".to_vec()].concat();
    let val = serde_json::to_vec(&record).unwrap();

    let _ = storage::async_set_value_in_db(&key, &val, db).await;

    println!("Device registered successfully");
    Ok(warp::reply::with_status("Registered", warp::http::StatusCode::OK))
}

async fn handle_push_trigger(req: PushTriggerRequest, db: Arc<RwLock<storage::DB>>, client: reqwest::Client) -> Result<impl warp::Reply, warp::Rejection> {
    // Reject stale or future timestamps to prevent replay attacks
    if !is_timestamp_fresh(req.timestamp) {
        return Ok(warp::reply::with_status("Timestamp too old or too far in the future", warp::http::StatusCode::BAD_REQUEST));
    }

    let sender_pub_key_bytes = match hex::decode(&req.sender_pub_key) {
        Ok(b) => b,
        Err(_) => return Ok(warp::reply::with_status("Invalid hex for sender_pub_key", warp::http::StatusCode::BAD_REQUEST)),
    };

    let signed_ts_bytes = match hex::decode(&req.signed_timestamp) {
        Ok(b) => b,
        Err(_) => return Ok(warp::reply::with_status("Invalid hex for signed_timestamp", warp::http::StatusCode::BAD_REQUEST)),
    };

    let recipient_pub_key_bytes = match hex::decode(&req.recipient_pub_key) {
        Ok(b) => b,
        Err(_) => return Ok(warp::reply::with_status("Invalid hex for recipient_pub_key", warp::http::StatusCode::BAD_REQUEST)),
    };

    // Verify signature over: timestamp_u64_le_bytes + recipient_pub_key_bytes
    let mut verification_buffer = Vec::new();
    verification_buffer.extend_from_slice(&req.timestamp.to_le_bytes());
    verification_buffer.extend_from_slice(&recipient_pub_key_bytes);

    if encryption::verify(&verification_buffer, &sender_pub_key_bytes, &signed_ts_bytes).is_err() {
        return Ok(warp::reply::with_status("Invalid signed_timestamp", warp::http::StatusCode::UNAUTHORIZED));
    }

    // Lookup Recipient Token
    let key = [recipient_pub_key_bytes, b"push_token".to_vec()].concat();

    if let Ok(Some(val)) = storage::async_get_value_from_db(&key, db).await {
        if let Ok(record) = serde_json::from_slice::<PushTokenRecord>(&val) {
            if record.enabled {
                tokio::spawn(async move {
                    if let Err(e) = send_expo_push(&client, &record.expo_push_token, "New Message", "You have a new encrypted message").await {
                        eprintln!("Failed to send push notification: {}", e);
                    }
                });
                return Ok(warp::reply::with_status("Triggered", warp::http::StatusCode::OK));
            }
        }
    }

    Ok(warp::reply::with_status("Recipient not found or disabled", warp::http::StatusCode::NOT_FOUND))
}

async fn send_expo_push(client: &reqwest::Client, token: &str, title: &str, body: &str) -> Result<(), reqwest::Error> {
    let payload = serde_json::json!({
        "to": token,
        "title": title,
        "body": body,
        "sound": "default"
    });

    let resp = client.post("https://exp.host/--/api/v2/push/send")
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        eprintln!("Expo push API returned status: {}", resp.status());
    }

    Ok(())
}
