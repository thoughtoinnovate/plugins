//! ChatGPT OAuth Auth-Only Plugin
//!
//! This plugin provides OAuth authentication for ChatGPT Pro/Plus users,
//! enabling access to Codex models (gpt-5.1-codex-max, gpt-5.1-codex-mini, etc.)
//!
//! Unlike full provider plugins, this is an "auth-only" plugin that exports
//! `provider_auth_credentials()` instead of `provider_chat()`. This allows
//! tark's native OpenAI-compatible provider to handle API calls, enabling:
//! - Native streaming support
//! - Tool/function calling
//! - All future provider improvements
//!
//! The plugin handles:
//! - Reading OAuth credentials from ~/.config/tark/chatgpt_oauth.json
//! - Token refresh when expired
//! - Account ID extraction from JWT tokens
//!
//! OAuth flow (PKCE) must be performed externally (CLI or browser extension)
//! since WASM cannot run HTTP servers for callbacks.

use serde::{Deserialize, Serialize};

/// OpenAI OAuth Client ID (from opencode project)
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// OpenAI OAuth token endpoint
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
/// ChatGPT Codex API endpoint
const CODEX_API_ENDPOINT: &str = "https://chatgpt.com/backend-api/codex/responses";

// =============================================================================
// Host Function Imports (provided by tark)
// =============================================================================

#[link(wasm_import_module = "tark:storage")]
extern "C" {
    #[link_name = "get"]
    fn storage_get_raw(key_ptr: i32, key_len: i32, ret_ptr: i32) -> i32;

    #[link_name = "set"]
    fn storage_set_raw(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32;
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

#[link(wasm_import_module = "tark:log")]
extern "C" {
    #[link_name = "info"]
    fn log_info_raw(msg_ptr: i32, msg_len: i32);
    #[link_name = "error"]
    fn log_error_raw(msg_ptr: i32, msg_len: i32);
    #[link_name = "debug"]
    fn log_debug_raw(msg_ptr: i32, msg_len: i32);
}

#[link(wasm_import_module = "tark:env")]
extern "C" {
    #[link_name = "get"]
    fn env_get_raw(name_ptr: i32, name_len: i32, ret_ptr: i32) -> i32;
}

#[link(wasm_import_module = "tark:fs")]
extern "C" {
    #[link_name = "read"]
    fn fs_read_raw(path_ptr: i32, path_len: i32, ret_ptr: i32) -> i32;
}

// =============================================================================
// Types
// =============================================================================

/// OAuth token response from OpenAI
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Stored OAuth credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthCredentials {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    /// Unix timestamp (seconds) when token expires
    #[serde(default)]
    expires_at: Option<u64>,
    /// ChatGPT account ID (extracted from JWT)
    #[serde(default)]
    account_id: Option<String>,
}

/// Plugin state stored in tark storage
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PluginState {
    credentials: Option<OAuthCredentials>,
}

// =============================================================================
// Memory Management
// =============================================================================

static mut RETURN_BUFFER: [u8; 131072] = [0u8; 131072]; // 128KB for responses
static mut ENV_BUFFER: [u8; 256] = [0u8; 256];

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
// Helper Functions
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

fn log_debug(msg: &str) {
    unsafe {
        log_debug_raw(msg.as_ptr() as i32, msg.len() as i32);
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

fn http_post(url: &str, body: &str, headers: &[(String, String)]) -> Option<String> {
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
        if ret > 0 {
            String::from_utf8(return_buffer_bytes(ret).to_vec()).ok()
        } else {
            None
        }
    }
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

/// Read a file from the filesystem (if allowed by capabilities)
fn fs_read(path: &str) -> Option<String> {
    unsafe {
        let ret = fs_read_raw(path.as_ptr() as i32, path.len() as i32, return_buffer_ptr());
        if ret > 0 {
            String::from_utf8(return_buffer_bytes(ret).to_vec()).ok()
        } else {
            log_debug(&format!("fs_read({}) failed with code {}", path, ret));
            None
        }
    }
}

// =============================================================================
// State Management
// =============================================================================

fn load_state() -> PluginState {
    match storage_get("state") {
        Some(s) => serde_json::from_str(&s).unwrap_or_default(),
        None => PluginState::default(),
    }
}

fn save_state(state: &PluginState) {
    if let Ok(json) = serde_json::to_string(state) {
        storage_set("state", &json);
    }
}

// =============================================================================
// Credentials File Loading
// =============================================================================

fn credentials_path() -> String {
    // Check environment override first
    if let Some(path) = env_get("CHATGPT_OAUTH_CREDENTIALS_PATH") {
        if !path.is_empty() {
            return path;
        }
    }
    
    // Default path
    if let Some(home) = env_get("HOME") {
        format!("{}/.config/tark/chatgpt_oauth.json", home)
    } else {
        "~/.config/tark/chatgpt_oauth.json".to_string()
    }
}

fn load_credentials_from_file() -> Option<OAuthCredentials> {
    let path = credentials_path();
    log_debug(&format!("Loading credentials from: {}", path));
    
    let content = fs_read(&path)?;
    let creds: OAuthCredentials = serde_json::from_str(&content).ok()?;
    
    log_info(&format!(
        "Loaded credentials: token_len={}, has_refresh={}, has_account_id={}",
        creds.access_token.len(),
        creds.refresh_token.is_some(),
        creds.account_id.is_some()
    ));
    
    Some(creds)
}

// =============================================================================
// JWT Parsing (for Account ID extraction)
// =============================================================================

/// Parse JWT claims from a token
fn parse_jwt_claims(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    
    // Decode base64url payload (second part)
    let payload = base64url_decode(parts[1])?;
    let payload_str = String::from_utf8(payload).ok()?;
    serde_json::from_str(&payload_str).ok()
}

/// Base64url decode (no padding)
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    
    // Convert base64url to standard base64
    let standard: String = padded
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    
    // Simple base64 decode
    base64_decode(&standard)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut output = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_collected = 0;
    
    for c in input.chars() {
        if c == '=' {
            break;
        }
        
        let value = ALPHABET.iter().position(|&x| x == c as u8)? as u32;
        buffer = (buffer << 6) | value;
        bits_collected += 6;
        
        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }
    
    Some(output)
}

/// Extract account ID from JWT tokens
/// Extract account_id from a single JWT token string
fn extract_account_id_from_token(token: &str) -> Option<String> {
    let claims = parse_jwt_claims(token)?;
    
    // Check various claim locations
    if let Some(id) = claims.get("chatgpt_account_id").and_then(|v| v.as_str()) {
        return Some(id.to_string());
    }
    if let Some(auth) = claims.get("https://api.openai.com/auth") {
        if let Some(id) = auth.get("chatgpt_account_id").and_then(|v| v.as_str()) {
            return Some(id.to_string());
        }
    }
    if let Some(orgs) = claims.get("organizations").and_then(|v| v.as_array()) {
        if let Some(first) = orgs.first() {
            if let Some(id) = first.get("id").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn extract_account_id(creds: &OAuthCredentials) -> Option<String> {
    // Try id_token first
    if let Some(ref id_token) = creds.id_token {
        if let Some(claims) = parse_jwt_claims(id_token) {
            // Check various claim locations
            if let Some(id) = claims.get("chatgpt_account_id").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
            if let Some(auth) = claims.get("https://api.openai.com/auth") {
                if let Some(id) = auth.get("chatgpt_account_id").and_then(|v| v.as_str()) {
                    return Some(id.to_string());
                }
            }
            if let Some(orgs) = claims.get("organizations").and_then(|v| v.as_array()) {
                if let Some(first) = orgs.first() {
                    if let Some(id) = first.get("id").and_then(|v| v.as_str()) {
                        return Some(id.to_string());
                    }
                }
            }
        }
    }
    
    // Try access_token
    if let Some(claims) = parse_jwt_claims(&creds.access_token) {
        if let Some(id) = claims.get("chatgpt_account_id").and_then(|v| v.as_str()) {
            return Some(id.to_string());
        }
        if let Some(auth) = claims.get("https://api.openai.com/auth") {
            if let Some(id) = auth.get("chatgpt_account_id").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
        }
    }
    
    // Use stored account_id
    creds.account_id.clone()
}

// =============================================================================
// OAuth Token Management
// =============================================================================

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_expired(creds: &OAuthCredentials) -> bool {
    creds.expires_at
        .map(|exp| now_secs() >= exp.saturating_sub(300)) // 5 minute buffer
        .unwrap_or(false)
}

fn refresh_access_token(refresh_token: &str) -> Option<OAuthCredentials> {
    log_debug("Refreshing ChatGPT OAuth token...");
    
    let body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        urlencoding_encode(refresh_token),
        CLIENT_ID
    );
    
    let headers = vec![(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    )];
    
    let response = http_post(TOKEN_URL, &body, &headers)?;
    let parsed: serde_json::Value = serde_json::from_str(&response).ok()?;
    
    // Handle HTTP wrapper from host
    let body_str = if let Some(body) = parsed.get("body").and_then(|b| b.as_str()) {
        let status = parsed.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
        if status != 200 {
            log_error(&format!("Token refresh failed: HTTP {}", status));
            return None;
        }
        body.to_string()
    } else {
        response
    };
    
    let token_data: TokenResponse = serde_json::from_str(&body_str).ok()?;
    
    let expires_at = token_data.expires_in.map(|s| now_secs() + s);
    
    let mut new_creds = OAuthCredentials {
        access_token: token_data.access_token,
        refresh_token: token_data.refresh_token.or_else(|| Some(refresh_token.to_string())),
        id_token: token_data.id_token,
        expires_at,
        account_id: None,
    };
    
    // Extract account ID from new tokens
    new_creds.account_id = extract_account_id(&new_creds);
    
    log_info("ChatGPT token refreshed successfully");
    Some(new_creds)
}

/// Simple URL encoding for form data
fn urlencoding_encode(input: &str) -> String {
    let mut result = String::new();
    for c in input.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

fn get_valid_token() -> Result<(String, Option<String>), String> {
    let mut state = load_state();
    
    // First, try to load from file if no credentials in state
    if state.credentials.is_none() {
        if let Some(creds) = load_credentials_from_file() {
            state.credentials = Some(creds);
            save_state(&state);
        }
    }
    
    let creds = state.credentials.as_ref().ok_or_else(|| {
        "No credentials stored. Run 'tark auth chatgpt' or manually create ~/.config/tark/chatgpt_oauth.json".to_string()
    })?;
    
    // Extract account ID if not present
    let account_id = creds.account_id.clone().or_else(|| extract_account_id(creds));
    
    // If token is still valid, use it
    if !creds.access_token.is_empty() && !is_expired(creds) {
        return Ok((creds.access_token.clone(), account_id));
    }
    
    // Token expired - try to refresh
    if let Some(refresh) = &creds.refresh_token {
        if let Some(new_creds) = refresh_access_token(refresh) {
            let token = new_creds.access_token.clone();
            let new_account_id = new_creds.account_id.clone().or(account_id);
            state.credentials = Some(new_creds);
            save_state(&state);
            return Ok((token, new_account_id));
        }
        // Refresh failed, try existing token anyway
        if !creds.access_token.is_empty() {
            log_error("Token refresh failed, using existing token (may be expired)");
            return Ok((creds.access_token.clone(), account_id));
        }
    }
    
    // No refresh token, try existing access token
    if !creds.access_token.is_empty() {
        return Ok((creds.access_token.clone(), account_id));
    }
    
    Err("No valid token available. Run 'tark auth chatgpt' to authenticate.".to_string())
}

// =============================================================================
// Provider Plugin Interface - Auth Only
// =============================================================================

/// Get provider info (JSON)
#[no_mangle]
pub extern "C" fn provider_info(ret_ptr: i32) -> i32 {
    let info = serde_json::json!({
        "id": "chatgpt-oauth",
        "display_name": "ChatGPT (OAuth)",
        "description": "ChatGPT Pro/Plus via Codex API (auth-only plugin)",
        "requires_auth": true,
        "provider": "openai"
    });
    
    let json = info.to_string();
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
    }
    json.len() as i32
}

/// Get available models (JSON array)
/// Returns empty array - tark loads models from models.dev using "provider": "openai"
#[no_mangle]
pub extern "C" fn provider_models(ret_ptr: i32) -> i32 {
    let models = serde_json::json!([]);
    
    let json = models.to_string();
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
    }
    json.len() as i32
}

/// Process OAuth tokens after authentication
/// Extracts account_id from JWT and adds it to credentials
/// Called by tark after OAuth flow completes
#[no_mangle]
pub extern "C" fn auth_process_tokens(
    tokens_ptr: i32,
    tokens_len: i32,
    ret_ptr: i32,
) -> i32 {
    // Read tokens JSON from WASM memory
    let tokens_json = unsafe {
        let slice = std::slice::from_raw_parts(tokens_ptr as *const u8, tokens_len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => {
                log_error("Failed to read tokens JSON");
                return -1;
            }
        }
    };

    // Parse tokens
    let mut tokens: serde_json::Value = match serde_json::from_str(tokens_json) {
        Ok(t) => t,
        Err(e) => {
            log_error(&format!("Failed to parse tokens: {}", e));
            return -1;
        }
    };

    // Extract account_id from id_token or access_token JWT
    let account_id = if let Some(id_token) = tokens.get("id_token").and_then(|t| t.as_str()) {
        extract_account_id_from_token(id_token)
    } else if let Some(access_token) = tokens.get("access_token").and_then(|t| t.as_str()) {
        extract_account_id_from_token(access_token)
    } else {
        None
    };

    // Add account_id if found
    if let Some(account_id_value) = account_id {
        tokens["account_id"] = serde_json::json!(account_id_value);
        log_info(&format!("Extracted account_id: {}", account_id_value));
    }

    // Return processed JSON
    let processed_json = match serde_json::to_string_pretty(&tokens) {
        Ok(j) => j,
        Err(e) => {
            log_error(&format!("Failed to serialize processed tokens: {}", e));
            return -1;
        }
    };

    let processed_bytes = processed_json.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(processed_bytes.as_ptr(), ret_ptr as *mut u8, processed_bytes.len());
    }
    processed_bytes.len() as i32
}

/// Get auth status
/// Returns: 0 = not required, 1 = authenticated, 2 = not authenticated, 3 = expired
#[no_mangle]
pub extern "C" fn provider_auth_status() -> i32 {
    let state = load_state();
    
    // Also check file if no state
    let has_creds = state.credentials.is_some() || load_credentials_from_file().is_some();
    
    if has_creds {
        1 // Authenticated
    } else {
        2 // Not authenticated
    }
}

/// Initialize with credentials (JSON)
#[no_mangle]
pub extern "C" fn provider_auth_init(creds_ptr: i32, creds_len: i32) -> i32 {
    let creds_slice =
        unsafe { std::slice::from_raw_parts(creds_ptr as *const u8, creds_len as usize) };
    
    let creds_str = match std::str::from_utf8(creds_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let mut creds: OAuthCredentials = match serde_json::from_str(creds_str) {
        Ok(c) => c,
        Err(_) => return -2,
    };
    
    // Extract account ID if not provided
    if creds.account_id.is_none() {
        creds.account_id = extract_account_id(&creds);
    }
    
    log_info(&format!(
        "Loaded credentials: access_token_len={}, has_refresh={}, account_id={:?}",
        creds.access_token.len(),
        creds.refresh_token.is_some(),
        creds.account_id.as_ref().map(|s| &s[..s.len().min(8)])
    ));
    
    let mut state = load_state();
    state.credentials = Some(creds);
    save_state(&state);
    
    log_info("Provider initialized with ChatGPT OAuth credentials");
    0
}

/// Logout
#[no_mangle]
pub extern "C" fn provider_auth_logout() -> i32 {
    let state = PluginState::default();
    save_state(&state);
    log_info("Logged out from ChatGPT");
    0
}

/// Get auth credentials for tark's native provider
///
/// This is the key function for auth-only plugins. Instead of implementing
/// provider_chat(), we return credentials that tark uses to create a native
/// OpenAI-compatible provider with the Codex endpoint.
///
/// Returns JSON: { "access_token", "api_mode", "endpoint", "account_id" }
#[no_mangle]
pub extern "C" fn provider_auth_credentials(ret_ptr: i32) -> i32 {
    // Get valid token (refresh if needed)
    let (access_token, account_id) = match get_valid_token() {
        Ok(result) => result,
        Err(e) => {
            log_error(&format!("Failed to get valid token: {}", e));
            let error = serde_json::json!({
                "error": e
            });
            let json = error.to_string();
            unsafe {
                std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
            }
            return -(json.len() as i32); // Negative = error
        }
    };
    
    log_debug(&format!(
        "Returning auth credentials: token_len={}, account_id={:?}",
        access_token.len(),
        account_id.as_ref().map(|s| &s[..s.len().min(8)])
    ));
    
    // Return credentials for tark's OpenAI-compatible provider
    let mut custom_headers = serde_json::Map::new();
    custom_headers.insert("originator".to_string(), serde_json::json!("opencode"));
    if let Some(account_id_value) = &account_id {
        custom_headers.insert("ChatGPT-Account-Id".to_string(), serde_json::json!(account_id_value));
    }
    
    let creds = serde_json::json!({
        "access_token": access_token,
        "api_mode": "openai_compat",
        "endpoint": CODEX_API_ENDPOINT,
        "custom_headers": custom_headers
    });
    
    let json = creds.to_string();
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
    }
    json.len() as i32
}

// =============================================================================
// Legacy Interface (backwards compatibility)
// =============================================================================

#[no_mangle]
pub extern "C" fn display_name(ret_ptr: i32) -> i32 {
    let name = "ChatGPT (OAuth)";
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), ret_ptr as *mut u8, name.len());
    }
    name.len() as i32
}

#[no_mangle]
pub extern "C" fn status() -> i32 {
    let state = load_state();
    match state.credentials {
        None => 0,
        Some(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn get_token(ret_ptr: i32) -> i32 {
    match get_valid_token() {
        Ok((token, _)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(token.as_ptr(), ret_ptr as *mut u8, token.len());
            }
            token.len() as i32
        }
        Err(e) => {
            log_error(&e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn logout() -> i32 {
    provider_auth_logout()
}

#[no_mangle]
pub extern "C" fn init_with_credentials(creds_ptr: i32, creds_len: i32) -> i32 {
    provider_auth_init(creds_ptr, creds_len)
}

#[no_mangle]
pub extern "C" fn get_endpoint(ret_ptr: i32) -> i32 {
    let endpoint = CODEX_API_ENDPOINT;
    unsafe {
        std::ptr::copy_nonoverlapping(endpoint.as_ptr(), ret_ptr as *mut u8, endpoint.len());
    }
    endpoint.len() as i32
}
