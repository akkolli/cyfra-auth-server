use warp::Filter;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use shared::{storage, encryption};
use std::time::{SystemTime, UNIX_EPOCH};

const SERVER_DB_PATH: &str = "./auth_db";

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
    // Initialize DB
    let db = storage::get_db(SERVER_DB_PATH).unwrap();
    let db = Arc::new(RwLock::new(db));
    
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
    let push_route = warp::post()
        .and(warp::path("push_trigger"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and_then(move |req: PushTriggerRequest| {
            let db = push_db.clone();
            handle_push_trigger(req, db)
        });

    let routes = register_route.or(push_route);

    println!("Auth Server listening on 127.0.0.1:3000");
    warp::serve(routes).run(([0, 0, 0, 0], 3000)).await;
}

async fn handle_register_device(req: RegisterDeviceRequest, db: Arc<RwLock<storage::DB>>) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Recieved register device request for user: {}", req.username);
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
    // NOTE: Client uses pipe separators!
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(b"register_device|");
    signed_data.extend_from_slice(req.username.as_bytes());
    signed_data.extend_from_slice(b"|");
    signed_data.extend_from_slice(req.client_type.as_bytes());
    signed_data.extend_from_slice(b"|");
    signed_data.extend_from_slice(req.push_token.as_bytes());
    signed_data.extend_from_slice(b"|");
    
    // Client signs Date.now() which is milliseconds (u64).
    // In TS: `const signPayload = ... + timestamp` converts number to string!
    // Wait, let's double check mobile code.
    // Mobile: `const signPayload = ...` (template literal) -> timestamp is stringified.
    // Server currently does: `req.timestamp.to_le_bytes()`. This is WRONG if mobile signs the string representation.
    // Mobile: `const signPayload = ... ${timestamp}`. Yes, it's string.
    
    let timestamp_str = req.timestamp.to_string();
    signed_data.extend_from_slice(timestamp_str.as_bytes());

    if let Err(_) = encryption::verify(&signed_data, &pub_key_bytes, &signature_bytes) {
         println!("Signature verification failed");
         return Ok(warp::reply::with_status("Invalid signature", warp::http::StatusCode::UNAUTHORIZED));
    }
    
    println!("Signature verified successfully");

    // 2. Store Token
    let record = PushTokenRecord {
        expo_push_token: req.push_token.clone(),
        platform: req.client_type.clone(),
        enabled: true,
        updated_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };
    
    // Key: [pub_key_bytes] + "push_token"
    let key = [pub_key_bytes, "push_token".as_bytes().to_vec()].concat();
    let val = serde_json::to_vec(&record).unwrap();
    
    let _ = storage::async_set_value_in_db(&key, &val, db).await;

    println!("Device registered successfully");
    Ok(warp::reply::with_status("Registered", warp::http::StatusCode::OK))
}

async fn handle_push_trigger(req: PushTriggerRequest, db: Arc<RwLock<storage::DB>>) -> Result<impl warp::Reply, warp::Rejection> {
    // 1. Verify Signed Timestamp (Optional better security: actually verify it locally)
    // For now, we trust Pluto sent it, or we could verify the signature if we had the sender's key stored.
    // The payload has sender_pub_key and signed_timestamp.
    
    let sender_pub_key_bytes = hex::decode(&req.sender_pub_key).unwrap_or_default();
    let signed_ts_bytes = hex::decode(&req.signed_timestamp).unwrap_or_default();
    
    // Check if we can verify: Sign(timestamp_u64_le + recipient_pub_key)
    let recipient_pub_key_bytes = hex::decode(&req.recipient_pub_key).unwrap_or_default();
    
    let mut verification_buffer = Vec::new();
    verification_buffer.extend_from_slice(&req.timestamp.to_le_bytes());
    verification_buffer.extend_from_slice(&recipient_pub_key_bytes);
    
    if let Err(_) = encryption::verify(&verification_buffer, &sender_pub_key_bytes, &signed_ts_bytes) {
         return Ok(warp::reply::with_status("Invalid signed_timestamp", warp::http::StatusCode::UNAUTHORIZED));
    }

    // 2. Lookup Recipient Token
    // Key: [recipient_pub_key] + "push_token"
    let key = [recipient_pub_key_bytes, "push_token".as_bytes().to_vec()].concat();
    
    if let Ok(Some(val)) = storage::async_get_value_from_db(&key, db).await {
         if let Ok(record) = serde_json::from_slice::<PushTokenRecord>(&val) {
             if record.enabled {
                 // 3. Send to Expo
                 // Used "fire and forget" spawning
                 tokio::spawn(async move {
                    send_expo_push(&record.expo_push_token, "New Message", "You have a new encrypted message").await;
                 });
                 return Ok(warp::reply::with_status("Triggered", warp::http::StatusCode::OK));
             }
         }
    }
    
    Ok(warp::reply::with_status("Recipient not found or disabled", warp::http::StatusCode::NOT_FOUND))
}

async fn send_expo_push(token: &str, title: &str, body: &str) {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "to": token,
        "title": title,
        "body": body,
        "sound": "default"
    });
    
    let _ = client.post("https://exp.host/--/api/v2/push/send")
        .json(&payload)
        .send()
        .await;
}
