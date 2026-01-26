//! Discord channel plugin (interactions-only)
//!
//! Handles Discord Interaction webhooks, verifies signatures, and forwards
//! slash command payloads into tark channel messages.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DISCORD_GATEWAY_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";
const DISCORD_INTENTS_DM_ONLY: u64 = 1 | 4096 | 32768; // GUILDS + DIRECT_MESSAGES + MESSAGE_CONTENT

// =============================================================================
// Host Function Imports (provided by tark)
// =============================================================================

#[link(wasm_import_module = "tark:storage")]
extern "C" {
    #[link_name = "get"]
    fn storage_get_raw(key_ptr: i32, key_len: i32, ret_ptr: i32) -> i32;

    #[link_name = "set"]
    fn storage_set_raw(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32;

    #[link_name = "delete"]
    fn storage_delete_raw(key_ptr: i32, key_len: i32) -> i32;
}

#[link(wasm_import_module = "tark:http")]
extern "C" {
    #[link_name = "post"]
    fn http_post_raw(
        url_ptr: i32,
        url_len: i32,
        body_ptr: i32,
        body_len: i32,
        headers_ptr: i32,
        headers_len: i32,
        ret_ptr: i32,
    ) -> i32;
}

#[link(wasm_import_module = "tark:ws")]
extern "C" {
    #[link_name = "connect"]
    fn ws_connect_raw(
        url_ptr: i32,
        url_len: i32,
        headers_ptr: i32,
        headers_len: i32,
        ret_ptr: i32,
    ) -> i32;

    #[link_name = "send"]
    fn ws_send_raw(handle: i64, data_ptr: i32, data_len: i32, ret_ptr: i32) -> i32;

    #[link_name = "recv"]
    fn ws_recv_raw(
        handle: i64,
        timeout_ms: i64,
        max_bytes: i64,
        ret_ptr: i32,
    ) -> i32;

    #[link_name = "close"]
    fn ws_close_raw(handle: i64, ret_ptr: i32) -> i32;
}

#[link(wasm_import_module = "tark:log")]
extern "C" {
    #[link_name = "info"]
    fn log_info_raw(msg_ptr: i32, msg_len: i32);
    #[link_name = "error"]
    fn log_error_raw(msg_ptr: i32, msg_len: i32);
}

#[link(wasm_import_module = "tark:env")]
extern "C" {
    #[link_name = "get"]
    fn env_get_raw(name_ptr: i32, name_len: i32, ret_ptr: i32) -> i32;
}

// =============================================================================
// Memory Management
// =============================================================================

static mut RETURN_BUFFER: [u8; 262144] = [0u8; 262144];
static mut ENV_BUFFER: [u8; 512] = [0u8; 512];

fn return_buffer_ptr() -> i32 {
    std::ptr::addr_of_mut!(RETURN_BUFFER).cast::<u8>() as i32
}

fn env_buffer_ptr() -> i32 {
    std::ptr::addr_of_mut!(ENV_BUFFER).cast::<u8>() as i32
}

unsafe fn return_buffer_bytes(len: i32) -> &'static [u8] {
    std::slice::from_raw_parts(std::ptr::addr_of!(RETURN_BUFFER).cast::<u8>(), len as usize)
}

unsafe fn env_buffer_bytes(len: i32) -> &'static [u8] {
    std::slice::from_raw_parts(std::ptr::addr_of!(ENV_BUFFER).cast::<u8>(), len as usize)
}

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    let layout = std::alloc::Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { std::alloc::alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, len: i32) {
    let layout = std::alloc::Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout) }
}

// =============================================================================
// Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct WebhookRequest {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}

#[derive(Debug, Serialize)]
struct WebhookResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    messages: Vec<InboundMessage>,
}

#[derive(Debug, Serialize)]
struct InboundMessage {
    conversation_id: String,
    user_id: String,
    text: String,
    metadata_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InteractionToken {
    token: String,
    created_at: u64,
}

#[derive(Debug, Deserialize)]
struct OAuthTokens {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_at: Option<u64>,
}

#[derive(Debug, Clone)]
struct DiscordConfig {
    application_id: String,
    public_key: String,
    bot_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateMode {
    DmOnly,
}

static CONFIG_CACHE: std::sync::Mutex<Option<DiscordConfig>> = std::sync::Mutex::new(None);
static TOKEN_CACHE: std::sync::Mutex<Option<OAuthTokens>> = std::sync::Mutex::new(None);
static STATS: std::sync::LazyLock<std::sync::Mutex<DiscordStats>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(DiscordStats::default()));
static GATEWAY_STATE: std::sync::LazyLock<std::sync::Mutex<GatewayState>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(GatewayState::default()));

#[derive(Default, Clone)]
struct DiscordStats {
    sent: u64,
    received: u64,
    gateway_connected: bool,
}

#[derive(Default, Clone)]
struct GatewayState {
    handle: Option<u64>,
    heartbeat_interval_ms: Option<u64>,
    last_heartbeat: Option<Instant>,
    last_heartbeat_ack: bool,
    seq: Option<i64>,
    connected: bool,
}

#[derive(Deserialize)]
struct WsResponse {
    ok: bool,
    #[serde(default)]
    handle: Option<u64>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    closed: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

// =============================================================================
// Helpers
// =============================================================================

fn log_info(msg: &str) {
    unsafe {
        log_info_raw(msg.as_ptr() as i32, msg.len() as i32);
    }
}

fn log_error(msg: &str) {
    unsafe {
        log_error_raw(msg.as_ptr() as i32, msg.len() as i32);
    }
}

fn storage_get(key: &str) -> Option<String> {
    unsafe {
        let ret = storage_get_raw(key.as_ptr() as i32, key.len() as i32, return_buffer_ptr());
        if ret > 0 {
            String::from_utf8(return_buffer_bytes(ret).to_vec()).ok()
        } else {
            None
        }
    }
}

fn storage_set(key: &str, value: &str) -> bool {
    unsafe {
        storage_set_raw(
            key.as_ptr() as i32,
            key.len() as i32,
            value.as_ptr() as i32,
            value.len() as i32,
        ) == 0
    }
}

fn storage_delete(key: &str) -> bool {
    unsafe { storage_delete_raw(key.as_ptr() as i32, key.len() as i32) == 0 }
}

fn env_get(name: &str) -> Option<String> {
    unsafe {
        let len = env_get_raw(name.as_ptr() as i32, name.len() as i32, env_buffer_ptr());
        if len <= 0 {
            return None;
        }
        let value = std::str::from_utf8(env_buffer_bytes(len)).ok()?;
        if value.is_empty() {
            return None;
        }
        Some(value.to_string())
    }
}

fn http_post(url: &str, body: &str, headers: &[(String, String)]) -> Option<HttpResponse> {
    let headers_json = serde_json::to_string(headers).unwrap_or_default();
    unsafe {
        let ret = http_post_raw(
            url.as_ptr() as i32,
            url.len() as i32,
            body.as_ptr() as i32,
            body.len() as i32,
            headers_json.as_ptr() as i32,
            headers_json.len() as i32,
            return_buffer_ptr(),
        );
        if ret <= 0 {
            return None;
        }
        let payload = String::from_utf8(return_buffer_bytes(ret).to_vec()).ok()?;
        let value: Value = serde_json::from_str(&payload).ok()?;
        if let Some(err) = value.get("error").and_then(Value::as_str) {
            log_error(&format!("http error: {}", err));
            return None;
        }
        serde_json::from_value(value).ok()
    }
}

fn ws_connect(url: &str, headers: &[(String, String)]) -> Result<u64, String> {
    let headers_json = serde_json::to_string(headers).unwrap_or_else(|_| "[]".to_string());
    unsafe {
        let ret = ws_connect_raw(
            url.as_ptr() as i32,
            url.len() as i32,
            headers_json.as_ptr() as i32,
            headers_json.len() as i32,
            return_buffer_ptr(),
        );
        if ret <= 0 {
            return Err("ws_connect failed".to_string());
        }
        let payload = String::from_utf8(return_buffer_bytes(ret).to_vec()).map_err(|_| "bad ws response".to_string())?;
        let resp: WsResponse = serde_json::from_str(&payload).map_err(|_| "bad ws json".to_string())?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "ws_connect error".to_string()));
        }
        resp.handle.ok_or_else(|| "missing ws handle".to_string())
    }
}

fn ws_send(handle: u64, data: &str) -> Result<(), String> {
    unsafe {
        let ret = ws_send_raw(
            handle as i64,
            data.as_ptr() as i32,
            data.len() as i32,
            return_buffer_ptr(),
        );
        if ret <= 0 {
            return Err("ws_send failed".to_string());
        }
        let payload = String::from_utf8(return_buffer_bytes(ret).to_vec()).map_err(|_| "bad ws response".to_string())?;
        let resp: WsResponse = serde_json::from_str(&payload).map_err(|_| "bad ws json".to_string())?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "ws_send error".to_string()));
        }
        Ok(())
    }
}

fn ws_recv(handle: u64, timeout_ms: u64, max_bytes: u64) -> Result<WsResponse, String> {
    unsafe {
        let ret = ws_recv_raw(
            handle as i64,
            timeout_ms as i64,
            max_bytes as i64,
            return_buffer_ptr(),
        );
        if ret <= 0 {
            return Err("ws_recv failed".to_string());
        }
        let payload = String::from_utf8(return_buffer_bytes(ret).to_vec()).map_err(|_| "bad ws response".to_string())?;
        let resp: WsResponse = serde_json::from_str(&payload).map_err(|_| "bad ws json".to_string())?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "ws_recv error".to_string()));
        }
        Ok(resp)
    }
}

fn ws_close(handle: u64) {
    unsafe {
        let _ = ws_close_raw(handle as i64, return_buffer_ptr());
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn get_application_id() -> Option<String> {
    if let Ok(guard) = CONFIG_CACHE.lock() {
        if let Some(cfg) = guard.as_ref() {
            return Some(cfg.application_id.clone());
        }
    }
    if let Some(app) = storage_get("discord_application_id") {
        return Some(app);
    }
    env_get("DISCORD_APPLICATION_ID").or_else(|| env_get("DISCORD_CLIENT_ID"))
}

fn get_public_key() -> Option<String> {
    if let Ok(guard) = CONFIG_CACHE.lock() {
        if let Some(cfg) = guard.as_ref() {
            return Some(cfg.public_key.clone());
        }
    }
    if let Some(key) = storage_get("discord_public_key") {
        return Some(key);
    }
    env_get("DISCORD_PUBLIC_KEY")
}

fn get_bot_token() -> Option<String> {
    if let Ok(guard) = CONFIG_CACHE.lock() {
        if let Some(cfg) = guard.as_ref() {
            if let Some(token) = cfg.bot_token.as_ref() {
                return Some(token.clone());
            }
        }
    }
    if let Some(token) = storage_get("discord_bot_token") {
        return Some(token);
    }
    env_get("DISCORD_BOT_TOKEN")
}

fn private_mode() -> PrivateMode {
    PrivateMode::DmOnly
}

fn load_oauth_token() -> Option<(String, String, bool)> {
    if let Ok(guard) = TOKEN_CACHE.lock() {
        if let Some(tokens) = guard.as_ref() {
            let token_type = tokens.token_type.clone().unwrap_or_else(|| "Bearer".to_string());
            let expired = tokens
                .expires_at
                .map(|ts| now_ts() >= ts)
                .unwrap_or(false);
            return Some((tokens.access_token.clone(), token_type, expired));
        }
    }
    let payload = storage_get("discord_oauth_tokens")?;
    let tokens: OAuthTokens = serde_json::from_str(&payload).ok()?;
    let token_type = tokens.token_type.unwrap_or_else(|| "Bearer".to_string());
    let expired = tokens
        .expires_at
        .map(|ts| now_ts() >= ts)
        .unwrap_or(false);
    Some((tokens.access_token, token_type, expired))
}

fn store_interaction_token(channel_id: &str, token: &str) {
    let record = InteractionToken {
        token: token.to_string(),
        created_at: now_ts(),
    };
    if let Ok(payload) = serde_json::to_string(&record) {
        let key = format!("discord_interaction_token:{}", channel_id);
        storage_set(&key, &payload);
    }
}

fn load_interaction_token(channel_id: &str) -> Option<String> {
    let key = format!("discord_interaction_token:{}", channel_id);
    let payload = storage_get(&key)?;
    let record: InteractionToken = serde_json::from_str(&payload).ok()?;
    if now_ts().saturating_sub(record.created_at) > 15 * 60 {
        let _ = storage_delete(&key);
        return None;
    }
    Some(record.token)
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn verify_signature(headers: &[(String, String)], body: &str) -> bool {
    let public_key = match get_public_key() {
        Some(key) => key,
        None => return false,
    };
    let signature_hex = match header_value(headers, "x-signature-ed25519") {
        Some(sig) => sig,
        None => return false,
    };
    let timestamp = match header_value(headers, "x-signature-timestamp") {
        Some(ts) => ts,
        None => return false,
    };

    let public_key_bytes = match hex::decode(public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
        return false;
    }

    let Ok(public_key_bytes) = public_key_bytes.try_into() else {
        return false;
    };
    let Ok(signature_bytes) = signature_bytes.try_into() else {
        return false;
    };

    let Ok(key) = VerifyingKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);

    let mut data = timestamp.into_bytes();
    data.extend_from_slice(body.as_bytes());
    key.verify_strict(&data, &signature).is_ok()
}

fn respond_json(response: &WebhookResponse, ret_ptr: i32) -> i32 {
    match serde_json::to_string(response) {
        Ok(json) => write_string(ret_ptr, &json),
        Err(_) => -1,
    }
}

fn record_received() {
    if let Ok(mut stats) = STATS.lock() {
        stats.received = stats.received.saturating_add(1);
    }
}

fn record_sent() {
    if let Ok(mut stats) = STATS.lock() {
        stats.sent = stats.sent.saturating_add(1);
    }
}

fn set_gateway_connected(connected: bool) {
    if let Ok(mut stats) = STATS.lock() {
        stats.gateway_connected = connected;
    }
}

fn write_string(ptr: i32, value: &str) -> i32 {
    unsafe {
        let bytes = value.as_bytes();
        let dest = std::slice::from_raw_parts_mut(ptr as *mut u8, bytes.len());
        dest.copy_from_slice(bytes);
        bytes.len() as i32
    }
}

fn read_string(ptr: i32, len: i32) -> String {
    unsafe {
        let slice = std::slice::from_raw_parts(ptr as *const u8, len as usize);
        String::from_utf8_lossy(slice).to_string()
    }
}

// =============================================================================
// Exported Plugin Functions
// =============================================================================

#[no_mangle]
pub extern "C" fn channel_info(ret_ptr: i32) -> i32 {
    let info = serde_json::json!({
        "id": "discord",
        "display_name": "Discord",
        "description": "Discord interactions channel",
        "supports_streaming": false,
        "supports_edits": false
    });
    let json = info.to_string();
    write_string(ret_ptr, &json)
}

#[no_mangle]
pub extern "C" fn channel_start() -> i32 {
    log_info("discord channel plugin started");
    0
}

#[no_mangle]
pub extern "C" fn channel_stop() -> i32 {
    log_info("discord channel plugin stopped");
    0
}

#[no_mangle]
pub extern "C" fn channel_auth_status() -> i32 {
    if get_public_key().is_none() {
        return 2;
    }

    if get_bot_token().is_some() {
        return 1;
    }

    if let Some((_, _, expired)) = load_oauth_token() {
        if expired {
            return 3;
        }
        return 1;
    }

    2
}

#[no_mangle]
pub extern "C" fn channel_auth_init(ptr: i32, len: i32) -> i32 {
    let payload = read_string(ptr, len);
    if let Ok(value) = serde_json::from_str::<Value>(&payload) {
        let mut config_set = false;
        if let Some(cfg) = value.get("config").and_then(Value::as_object) {
            let app_id = cfg.get("application_id").and_then(Value::as_str);
            let public_key = cfg.get("public_key").and_then(Value::as_str);
            let bot_token = cfg.get("bot_token").and_then(Value::as_str);
            if let (Some(app_id), Some(public_key)) = (app_id, public_key) {
                if let Ok(mut guard) = CONFIG_CACHE.lock() {
                    *guard = Some(DiscordConfig {
                        application_id: app_id.to_string(),
                        public_key: public_key.to_string(),
                        bot_token: bot_token.map(str::to_string),
                    });
                    config_set = true;
                }
            }
        }

        if let Some(tokens) = value.get("tokens") {
            if let Ok(tokens_value) = serde_json::from_value::<OAuthTokens>(tokens.clone()) {
                if let Ok(mut guard) = TOKEN_CACHE.lock() {
                    *guard = Some(tokens_value);
                }
            }
            return 0;
        }

        if value.get("access_token").is_some() {
            if let Ok(tokens_value) = serde_json::from_value::<OAuthTokens>(value.clone()) {
                if let Ok(mut guard) = TOKEN_CACHE.lock() {
                    *guard = Some(tokens_value);
                }
            }
            return 0;
        }

        if config_set {
            return 0;
        }
    }

    -1
}

#[no_mangle]
pub extern "C" fn channel_auth_logout() -> i32 {
    let _ = storage_delete("discord_oauth_tokens");
    0
}

#[no_mangle]
pub extern "C" fn channel_handle_gateway_event(ptr: i32, len: i32, ret_ptr: i32) -> i32 {
    let payload = read_string(ptr, len);
    let messages = match serde_json::from_str::<Value>(&payload) {
        Ok(value) => parse_gateway_event(&value),
        Err(_) => Vec::new(),
    };
    match serde_json::to_string(&messages) {
        Ok(json) => write_string(ret_ptr, &json),
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn channel_poll(ret_ptr: i32) -> i32 {
    let messages = gateway_poll();
    match serde_json::to_string(&messages) {
        Ok(json) => write_string(ret_ptr, &json),
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn channel_widget_state(ret_ptr: i32) -> i32 {
    let stats = match STATS.lock() {
        Ok(s) => s.clone(),
        Err(_) => DiscordStats::default(),
    };
    let status = if stats.gateway_connected {
        "connected"
    } else {
        "disconnected"
    };
    let payload = serde_json::json!({
        "status": status,
        "messages": {
            "sent": stats.sent,
            "received": stats.received
        }
    });
    write_string(ret_ptr, &payload.to_string())
}

#[no_mangle]
pub extern "C" fn channel_handle_webhook(
    req_ptr: i32,
    req_len: i32,
    ret_ptr: i32,
) -> i32 {
    let payload = read_string(req_ptr, req_len);
    let request: WebhookRequest = match serde_json::from_str(&payload) {
        Ok(req) => req,
        Err(_) => {
            let response = WebhookResponse {
                status: 400,
                headers: vec![],
                body: "invalid request".to_string(),
                messages: vec![],
            };
            return respond_json(&response, ret_ptr);
        }
    };

    if request.method.to_uppercase() != "POST" {
        let response = WebhookResponse {
            status: 405,
            headers: vec![("Allow".to_string(), "POST".to_string())],
            body: "method not allowed".to_string(),
            messages: vec![],
        };
        return respond_json(&response, ret_ptr);
    }

    if request.body.len() > 512 * 1024 {
        let response = WebhookResponse {
            status: 413,
            headers: vec![],
            body: "payload too large".to_string(),
            messages: vec![],
        };
        return respond_json(&response, ret_ptr);
    }

    if !verify_signature(&request.headers, &request.body) {
        let response = WebhookResponse {
            status: 401,
            headers: vec![],
            body: "invalid signature".to_string(),
            messages: vec![],
        };
        return respond_json(&response, ret_ptr);
    }

    let payload: Value = match serde_json::from_str(&request.body) {
        Ok(v) => v,
        Err(_) => {
            let response = WebhookResponse {
                status: 400,
                headers: vec![],
                body: "invalid json".to_string(),
                messages: vec![],
            };
            return respond_json(&response, ret_ptr);
        }
    };

    let interaction_type = payload.get("type").and_then(Value::as_i64).unwrap_or(0);
    if interaction_type == 1 {
        let response = WebhookResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: "{\"type\":1}".to_string(),
            messages: vec![],
        };
        return respond_json(&response, ret_ptr);
    }

    if interaction_type != 2 {
        let response = WebhookResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: "{\"type\":4,\"data\":{\"content\":\"Unsupported interaction\"}}".to_string(),
            messages: vec![],
        };
        return respond_json(&response, ret_ptr);
    }

    let channel_id = payload
        .get("channel_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let interaction_token = payload
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if let Some(app_id) = payload.get("application_id").and_then(Value::as_str) {
        storage_set("discord_application_id", app_id);
    }

    let (user_id, roles) = extract_user_and_roles(&payload);
    let guild_id = payload
        .get("guild_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mode = private_mode();
    let is_guild = guild_id.is_some();
    if is_guild && mode == PrivateMode::DmOnly {
        let response = WebhookResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: "{\"type\":4,\"data\":{\"content\":\"Please DM the bot to use Tark privately.\",\"flags\":64}}".to_string(),
            messages: vec![],
        };
        return respond_json(&response, ret_ptr);
    }

    let (text, command) = extract_command(&payload);
    let conversation_id = if is_guild {
        format!("{}:{}", channel_id, user_id)
    } else {
        channel_id.clone()
    };
    if !interaction_token.is_empty() {
        store_interaction_token(&conversation_id, &interaction_token);
    }
    let ephemeral = false;
    let metadata = serde_json::json!({
        "discord": {
            "user_id": user_id.clone(),
            "channel_id": channel_id.clone(),
            "guild_id": guild_id.clone(),
            "roles": roles,
            "interaction_token": interaction_token,
            "ephemeral": ephemeral
        },
        "tark_command": command
    });

    let inbound = InboundMessage {
        conversation_id: conversation_id.clone(),
        user_id,
        text,
        metadata_json: metadata.to_string(),
    };

    let response_body = if ephemeral {
        "{\"type\":5,\"data\":{\"flags\":64}}".to_string()
    } else {
        "{\"type\":5}".to_string()
    };
    let response = WebhookResponse {
        status: 200,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: response_body,
        messages: vec![inbound],
    };
    respond_json(&response, ret_ptr)
}

#[no_mangle]
pub extern "C" fn channel_send(req_ptr: i32, req_len: i32, ret_ptr: i32) -> i32 {
    let payload = read_string(req_ptr, req_len);
    let request: Value = match serde_json::from_str(&payload) {
        Ok(v) => v,
        Err(_) => return write_string(ret_ptr, "{\"success\":false,\"error\":\"bad request\"}"),
    };

    let conversation_id = request
        .get("conversation_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let text = request
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let message_id = request
        .get("message_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let metadata_json = request
        .get("metadata_json")
        .and_then(Value::as_str)
        .unwrap_or("");
    let (channel_id_override, ephemeral) = parse_send_metadata(metadata_json);

    let app_id = match get_application_id() {
        Some(id) => id,
        None => {
            return write_string(
                ret_ptr,
                "{\"success\":false,\"error\":\"missing application id\"}",
            )
        }
    };

    if let Some(token) = load_interaction_token(&conversation_id) {
        let url = if let Some(ref msg_id) = message_id {
            format!(
                "https://discord.com/api/v10/webhooks/{}/{}/messages/{}",
                app_id, token, msg_id
            )
        } else {
            format!(
                "https://discord.com/api/v10/webhooks/{}/{}?wait=true",
                app_id, token
            )
        };
        let mut payload = serde_json::json!({ "content": text });
        if ephemeral {
            if let Value::Object(map) = &mut payload {
                map.insert("flags".to_string(), Value::Number(64.into()));
            }
        }
        let body = payload.to_string();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if let Some(resp) = http_post(&url, &body, &headers) {
            let success = resp.status >= 200 && resp.status < 300;
            if success {
                record_sent();
            }
            let msg_id = extract_message_id(&resp.body);
            let response = serde_json::json!({
                "success": success,
                "message_id": msg_id,
                "error": if success { Value::Null } else { Value::String(resp.body) }
            });
            return write_string(ret_ptr, &response.to_string());
        }
    }

    if ephemeral {
        return write_string(
            ret_ptr,
            "{\"success\":false,\"error\":\"ephemeral response requires interaction token\"}",
        );
    }

    if let Some(bot_token) = get_bot_token() {
        let channel_id = channel_id_override
            .clone()
            .unwrap_or_else(|| conversation_id.clone());
        let url = if let Some(ref msg_id) = message_id {
            format!(
                "https://discord.com/api/v10/channels/{}/messages/{}",
                channel_id, msg_id
            )
        } else {
            format!(
                "https://discord.com/api/v10/channels/{}/messages",
                channel_id
            )
        };
        let body = serde_json::json!({ "content": text }).to_string();
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), format!("Bot {}", bot_token)),
        ];
        if let Some(resp) = http_post(&url, &body, &headers) {
            let success = resp.status >= 200 && resp.status < 300;
            if success {
                record_sent();
            }
            let msg_id = extract_message_id(&resp.body);
            let response = serde_json::json!({
                "success": success,
                "message_id": msg_id,
                "error": if success { Value::Null } else { Value::String(resp.body) }
            });
            return write_string(ret_ptr, &response.to_string());
        }
    }

    if let Some((access_token, token_type, expired)) = load_oauth_token() {
        if expired {
            return write_string(
                ret_ptr,
                "{\"success\":false,\"error\":\"oauth token expired\"}",
            );
        }
        let channel_id = channel_id_override
            .clone()
            .unwrap_or_else(|| conversation_id.clone());
        let url = if let Some(ref msg_id) = message_id {
            format!(
                "https://discord.com/api/v10/channels/{}/messages/{}",
                channel_id, msg_id
            )
        } else {
            format!(
                "https://discord.com/api/v10/channels/{}/messages",
                channel_id
            )
        };
        let body = serde_json::json!({ "content": text }).to_string();
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "Authorization".to_string(),
                format!("{} {}", token_type, access_token),
            ),
        ];
        if let Some(resp) = http_post(&url, &body, &headers) {
            let success = resp.status >= 200 && resp.status < 300;
            if success {
                record_sent();
            }
            let msg_id = extract_message_id(&resp.body);
            let response = serde_json::json!({
                "success": success,
                "message_id": msg_id,
                "error": if success { Value::Null } else { Value::String(resp.body) }
            });
            return write_string(ret_ptr, &response.to_string());
        }
    }

    write_string(
        ret_ptr,
        "{\"success\":false,\"error\":\"no valid send token\"}",
    )
}

fn parse_send_metadata(metadata_json: &str) -> (Option<String>, bool) {
    if metadata_json.trim().is_empty() {
        return (None, false);
    }
    let value: Value = match serde_json::from_str(metadata_json) {
        Ok(v) => v,
        Err(_) => return (None, false),
    };
    let discord = value
        .get("discord")
        .and_then(Value::as_object);
    let channel_id = discord
        .and_then(|d| d.get("channel_id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let ephemeral = discord
        .and_then(|d| d.get("ephemeral"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    (channel_id, ephemeral)
}

// =============================================================================
// Discord payload parsing
// =============================================================================

fn extract_user_and_roles(payload: &Value) -> (String, Vec<String>) {
    let mut roles = Vec::new();
    if let Some(member) = payload.get("member") {
        if let Some(user) = member.get("user") {
            if let Some(id) = user.get("id").and_then(Value::as_str) {
                if let Some(role_list) = member.get("roles").and_then(Value::as_array) {
                    roles = role_list
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                }
                return (id.to_string(), roles);
            }
        }
    }

    if let Some(user) = payload.get("user") {
        if let Some(id) = user.get("id").and_then(Value::as_str) {
            return (id.to_string(), roles);
        }
    }

    ("unknown".to_string(), roles)
}

fn extract_command(payload: &Value) -> (String, Value) {
    let data = payload.get("data").unwrap_or(&Value::Null);
    let name = data.get("name").and_then(Value::as_str).unwrap_or("tark");
    let mut command = Value::Null;

    let options = data.get("options").and_then(Value::as_array).cloned();
    if let Some(options) = options {
        for opt in options {
            if let Some(opt_name) = opt.get("name").and_then(Value::as_str) {
                if let Some(value) = opt.get("value").and_then(Value::as_str) {
                    if opt_name == "prompt" {
                        return (value.to_string(), Value::Null);
                    }
                    if opt_name == "command" {
                        return (format!("/tark {}", value), Value::Null);
                    }
                    command = serde_json::json!({
                        "name": opt_name,
                        "value": value
                    });
                }
            }
        }
    }

    if name == "tark" {
        ("/tark status".to_string(), command)
    } else {
        (format!("/tark {}", name), command)
    }
}

fn extract_message_id(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    value.get("id").and_then(Value::as_str).map(str::to_string)
}

fn reset_gateway(state: &mut GatewayState) {
    if let Some(handle) = state.handle.take() {
        ws_close(handle);
    }
    state.heartbeat_interval_ms = None;
    state.last_heartbeat = None;
    state.last_heartbeat_ack = true;
    state.seq = None;
    state.connected = false;
    set_gateway_connected(false);
}

fn handle_gateway_payload(state: &mut GatewayState, payload: &Value, token: &str) -> Vec<InboundMessage> {
    let op = payload.get("op").and_then(Value::as_i64).unwrap_or(0);
    if let Some(seq) = payload.get("s").and_then(Value::as_i64) {
        state.seq = Some(seq);
    }

    match op {
        10 => {
            let interval_ms = payload
                .get("d")
                .and_then(|d| d.get("heartbeat_interval"))
                .and_then(Value::as_u64)
                .unwrap_or(45000);
            state.heartbeat_interval_ms = Some(interval_ms);
            state.last_heartbeat_ack = true;
            state.last_heartbeat = Some(Instant::now());
            let identify = serde_json::json!({
                "op": 2,
                "d": {
                    "token": token,
                    "intents": DISCORD_INTENTS_DM_ONLY,
                    "properties": {
                        "$os": "linux",
                        "$browser": "tark",
                        "$device": "tark"
                    }
                }
            });
            if let Some(handle) = state.handle {
                let _ = ws_send(handle, &identify.to_string());
            }
        }
        11 => {
            state.last_heartbeat_ack = true;
        }
        7 | 9 => {
            reset_gateway(state);
        }
        0 => {
            let event_type = payload.get("t").and_then(Value::as_str).unwrap_or("");
            let data = payload.get("d").unwrap_or(&Value::Null);
            match event_type {
                "READY" => {
                    state.connected = true;
                    set_gateway_connected(true);
                }
                "MESSAGE_CREATE" => return parse_gateway_message_create(data),
                "INTERACTION_CREATE" => return parse_gateway_interaction_create(data),
                _ => {}
            }
        }
        _ => {}
    }

    Vec::new()
}

fn gateway_poll() -> Vec<InboundMessage> {
    let token = match get_bot_token() {
        Some(t) => t,
        None => return Vec::new(),
    };

    let mut state = match GATEWAY_STATE.lock() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    if state.handle.is_none() {
        match ws_connect(DISCORD_GATEWAY_URL, &[]) {
            Ok(handle) => {
                state.handle = Some(handle);
                state.connected = false;
                set_gateway_connected(false);
            }
            Err(err) => {
                log_error(&format!("gateway connect failed: {}", err));
                return Vec::new();
            }
        }
    }

    let mut messages = Vec::new();
    let mut loops = 0;
    while loops < 25 {
        loops += 1;
        let handle = match state.handle {
            Some(h) => h,
            None => break,
        };
        let resp = match ws_recv(handle, 0, 65536) {
            Ok(r) => r,
            Err(_) => {
                reset_gateway(&mut state);
                break;
            }
        };

        if resp.closed.unwrap_or(false) {
            reset_gateway(&mut state);
            break;
        }
        if let Some(msg) = resp.message {
            if let Ok(payload) = serde_json::from_str::<Value>(&msg) {
                let mut inbound = handle_gateway_payload(&mut state, &payload, &token);
                messages.append(&mut inbound);
            }
            continue;
        }
        break;
    }

    if let Some(interval_ms) = state.heartbeat_interval_ms {
        if let Some(last) = state.last_heartbeat {
            if last.elapsed() >= Duration::from_millis(interval_ms) {
                if !state.last_heartbeat_ack {
                    reset_gateway(&mut state);
                    return messages;
                }
                let heartbeat = serde_json::json!({
                    "op": 1,
                    "d": state.seq
                });
                if let Some(handle) = state.handle {
                    let _ = ws_send(handle, &heartbeat.to_string());
                    state.last_heartbeat = Some(Instant::now());
                    state.last_heartbeat_ack = false;
                }
            }
        }
    }

    messages
}

fn parse_gateway_event(payload: &Value) -> Vec<InboundMessage> {
    let event_type = payload.get("t").and_then(Value::as_str).unwrap_or("");
    let data = payload.get("d").unwrap_or(&Value::Null);
    match event_type {
        "MESSAGE_CREATE" => parse_gateway_message_create(data),
        "INTERACTION_CREATE" => parse_gateway_interaction_create(data),
        _ => Vec::new(),
    }
}

fn parse_gateway_message_create(data: &Value) -> Vec<InboundMessage> {
    if data.get("guild_id").is_some() {
        return Vec::new();
    }

    let channel_type = data.get("channel_type").and_then(Value::as_i64).unwrap_or(0);
    if channel_type != 1 {
        return Vec::new();
    }

    let author = match data.get("author") {
        Some(v) => v,
        None => return Vec::new(),
    };
    if author.get("bot").and_then(Value::as_bool).unwrap_or(false) {
        return Vec::new();
    }

    let content = data
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if content.is_empty() {
        return Vec::new();
    }

    let channel_id = data
        .get("channel_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let user_id = author
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let metadata = serde_json::json!({
        "discord": {
            "user_id": user_id.clone(),
            "channel_id": channel_id.clone(),
            "guild_id": null,
            "roles": [],
            "interaction_token": "",
            "ephemeral": false
        }
    });

    record_received();
    vec![InboundMessage {
        conversation_id: channel_id,
        user_id,
        text: content.to_string(),
        metadata_json: metadata.to_string(),
    }]
}

fn parse_gateway_interaction_create(data: &Value) -> Vec<InboundMessage> {
    if data.get("guild_id").is_some() {
        return Vec::new();
    }

    let channel_id = data
        .get("channel_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let interaction_token = data
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if let Some(app_id) = data.get("application_id").and_then(Value::as_str) {
        storage_set("discord_application_id", app_id);
    }

    let (user_id, roles) = extract_user_and_roles(data);
    let (text, command) = extract_command(data);
    let conversation_id = channel_id.clone();
    if !interaction_token.is_empty() {
        store_interaction_token(&conversation_id, &interaction_token);
    }

    let metadata = serde_json::json!({
        "discord": {
            "user_id": user_id.clone(),
            "channel_id": channel_id.clone(),
            "guild_id": null,
            "roles": roles,
            "interaction_token": interaction_token,
            "ephemeral": false
        },
        "tark_command": command
    });

    if text.trim().is_empty() {
        return Vec::new();
    }

    record_received();
    vec![InboundMessage {
        conversation_id,
        user_id,
        text,
        metadata_json: metadata.to_string(),
    }]
}
