//! Gemini OAuth Auth-Only Plugin
//!
//! This plugin provides OAuth authentication for Gemini using credentials
//! from Gemini CLI (~/.gemini/oauth_creds.json).
//!
//! Unlike full provider plugins, this is an "auth-only" plugin that exports
//! `provider_auth_credentials()` instead of `provider_chat()`. This allows
//! tark's native GeminiProvider to handle API calls, enabling:
//! - Native streaming support
//! - Tool/function calling
//! - All future GeminiProvider improvements
//!
//! The plugin handles:
//! - Reading OAuth credentials from ~/.gemini/oauth_creds.json
//! - Token refresh when expired
//! - Project ID discovery via loadCodeAssist API

use serde::{Deserialize, Serialize};

/// Safely truncate a string to at most `max_bytes` bytes without splitting UTF-8 characters.
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthCredentials {
    access_token: String,
    refresh_token: Option<String>,
    expiry_date: Option<u64>,
    token_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PluginState {
    credentials: Option<OAuthCredentials>,
    project_id: Option<String>,
}

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const CODE_ASSIST_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal";

#[derive(Debug, Clone)]
struct OAuthClient {
    client_id: String,
    client_secret: String,
}

// =============================================================================
// Memory Management
// =============================================================================

static mut RETURN_BUFFER: [u8; 131072] = [0u8; 131072]; // 128KB for responses
static mut ENV_BUFFER: [u8; 256] = [0u8; 256];

fn return_buffer_ptr() -> i32 {
    // Avoid creating references to `static mut` (Rust 2024 compatibility lint).
    std::ptr::addr_of_mut!(RETURN_BUFFER).cast::<u8>() as i32
}

fn env_buffer_ptr() -> i32 {
    // Avoid creating references to `static mut` (Rust 2024 compatibility lint).
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
            // Error codes: -1 = invalid path, -2 = permission denied, -3 = read error
            log_debug(&format!("fs_read({}) failed with code {}", path, ret));
            None
        }
    }
}

// =============================================================================
// Gemini CLI Credential Extraction
// =============================================================================

/// Known paths where Gemini CLI oauth2.js might be located
const GEMINI_CLI_OAUTH2_PATHS: &[&str] = &[
    "/usr/local/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/oauth2.js",
    "/usr/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/oauth2.js",
];

/// Extract OAuth client credentials from Gemini CLI installation
/// Returns (client_id, client_secret) if found
fn extract_gemini_cli_credentials() -> Option<(String, String)> {
    for path in GEMINI_CLI_OAUTH2_PATHS {
        if let Some(content) = fs_read(path) {
            log_debug(&format!("Found Gemini CLI oauth2.js at {}", path));

            // Extract OAUTH_CLIENT_ID
            let client_id = extract_js_const(&content, "OAUTH_CLIENT_ID")?;

            // Extract OAUTH_CLIENT_SECRET
            let client_secret = extract_js_const(&content, "OAUTH_CLIENT_SECRET")?;

            log_info(&format!(
                "Extracted OAuth credentials from Gemini CLI: {}",
                path
            ));
            return Some((client_id, client_secret));
        }
    }

    log_debug("Could not find Gemini CLI installation");
    None
}

/// Extract a const value from JavaScript source
/// Looks for patterns like: const NAME = 'value'; or const NAME = "value";
fn extract_js_const(content: &str, name: &str) -> Option<String> {
    // Look for: OAUTH_CLIENT_ID = 'value' or OAUTH_CLIENT_ID = "value"
    let patterns = [format!(r#"{} = '"#, name), format!(r#"{} = ""#, name)];

    for pattern in &patterns {
        if let Some(start) = content.find(pattern) {
            let value_start = start + pattern.len();
            let quote_char = if pattern.ends_with('"') { '"' } else { '\'' };

            // Find the closing quote
            if let Some(end_offset) = content[value_start..].find(quote_char) {
                let value = &content[value_start..value_start + end_offset];
                return Some(value.to_string());
            }
        }
    }

    None
}

// =============================================================================
// State Management
// =============================================================================

fn load_state() -> PluginState {
    match storage_get("state") {
        Some(s) => serde_json::from_str(&s).unwrap_or(PluginState {
            credentials: None,
            project_id: None,
        }),
        None => PluginState {
            credentials: None,
            project_id: None,
        },
    }
}

fn save_state(state: &PluginState) {
    if let Ok(json) = serde_json::to_string(state) {
        storage_set("state", &json);
    }
}

// =============================================================================
// OAuth Token Management
// =============================================================================

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn is_expired(creds: &OAuthCredentials) -> bool {
    let now = now_ms();
    creds.expiry_date.map(|exp| now >= exp).unwrap_or(false)
}

fn load_oauth_client(creds: &OAuthCredentials) -> Option<OAuthClient> {
    // 1. Try environment variables
    let env_id = env_get("GEMINI_OAUTH_CLIENT_ID");
    let env_secret = env_get("GEMINI_OAUTH_CLIENT_SECRET");
    if let (Some(client_id), Some(client_secret)) = (env_id, env_secret) {
        if !client_id.is_empty() && !client_secret.is_empty() {
            log_debug("Using OAuth client from environment variables");
            return Some(OAuthClient {
                client_id,
                client_secret,
            });
        }
    }

    // 2. Try credentials file (from ~/.gemini/oauth_creds.json)
    if let (Some(client_id), Some(client_secret)) =
        (creds.client_id.clone(), creds.client_secret.clone())
    {
        if !client_id.is_empty() && !client_secret.is_empty() {
            log_debug("Using OAuth client from credentials file");
            return Some(OAuthClient {
                client_id,
                client_secret,
            });
        }
    }

    // 3. Try extracting from Gemini CLI installation (dynamic discovery)
    if let Some((client_id, client_secret)) = extract_gemini_cli_credentials() {
        log_debug("Using OAuth client from Gemini CLI installation");
        return Some(OAuthClient {
            client_id,
            client_secret,
        });
    }

    // No client credentials available.
    //
    // NOTE: We intentionally do NOT embed any client_secret values in this repository.
    // If extraction fails, users must provide credentials via env vars or ensure Gemini CLI
    // is installed and accessible at one of the whitelisted paths in the plugin manifest.
    None
}

fn refresh_token(refresh_token: &str, oauth_client: &OAuthClient) -> Option<OAuthCredentials> {
    log_debug("Refreshing OAuth token...");

    let body = format!(
        "client_id={}&client_secret={}&refresh_token={}&grant_type=refresh_token",
        oauth_client.client_id, oauth_client.client_secret, refresh_token
    );

    let headers = vec![(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    )];

    let response = http_post(TOKEN_URL, &body, &headers)?;

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        expires_in: Option<u64>,
    }

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

    log_info("Token refreshed successfully");
    Some(OAuthCredentials {
        access_token: token_data.access_token,
        refresh_token: Some(refresh_token.to_string()),
        expiry_date: token_data.expires_in.map(|s| now_ms() + s * 1000),
        token_type: Some("Bearer".to_string()),
        client_id: None,
        client_secret: None,
    })
}

fn get_valid_token() -> Result<String, String> {
    let mut state = load_state();

    let creds = state.credentials.as_ref().ok_or_else(|| {
        "No credentials stored. Ensure ~/.gemini/oauth_creds.json exists.".to_string()
    })?;

    // If token is still valid, use it
    if !creds.access_token.is_empty() && !is_expired(creds) {
        return Ok(creds.access_token.clone());
    }

    // Token expired - try to refresh
    if let Some(refresh) = &creds.refresh_token {
        match load_oauth_client(creds) {
            Some(oauth_client) => {
                if let Some(new_creds) = refresh_token(refresh, &oauth_client) {
                    state.credentials = Some(new_creds.clone());
                    save_state(&state);
                    return Ok(new_creds.access_token);
                }
            }
            None => {
                // Cannot refresh without client credentials - fail with clear message
                return Err(
                    "Token expired but cannot refresh: GEMINI_OAUTH_CLIENT_ID and \
                     GEMINI_OAUTH_CLIENT_SECRET environment variables are required. \
                     Set them or run 'gemini auth login' to get a new token."
                        .to_string(),
                );
            }
        }
        // Refresh failed, try existing token anyway (might still work)
        if !creds.access_token.is_empty() {
            log_error("Token refresh failed, using existing token (may be expired)");
            return Ok(creds.access_token.clone());
        }
    }

    // No refresh token, try existing access token
    if !creds.access_token.is_empty() {
        return Ok(creds.access_token.clone());
    }

    Err("No valid token available. Run 'gemini auth login'.".to_string())
}

// =============================================================================
// Project ID Discovery
// =============================================================================

fn get_project_id() -> Option<String> {
    // Try state first (cached)
    let state = load_state();
    if let Some(pid) = state.project_id {
        return Some(pid);
    }

    // Try environment variables
    env_get("GOOGLE_CLOUD_PROJECT")
        .or_else(|| env_get("GCLOUD_PROJECT"))
        .or_else(|| env_get("GCP_PROJECT"))
}

fn discover_project_id(access_token: &str) -> Option<String> {
    let url = format!("{}:loadCodeAssist", CODE_ASSIST_URL);

    let request_body = serde_json::json!({
        "metadata": {
            "ideType": "IDE_UNSPECIFIED",
            "platform": "PLATFORM_UNSPECIFIED",
            "pluginType": "GEMINI"
        }
    });

    let headers = vec![
        (
            "Authorization".to_string(),
            format!("Bearer {}", access_token),
        ),
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "User-Agent".to_string(),
            "google-api-nodejs-client/9.15.1".to_string(),
        ),
        (
            "X-Goog-Api-Client".to_string(),
            "gl-node/22.17.0".to_string(),
        ),
    ];

    log_debug("Discovering project via loadCodeAssist...");

    let response = http_post(&url, &request_body.to_string(), &headers)?;
    let parsed: serde_json::Value = serde_json::from_str(&response).ok()?;

    let status = parsed.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
    if status != 200 {
        log_error(&format!("loadCodeAssist failed: HTTP {}", status));
        return None;
    }

    let body_str = parsed.get("body").and_then(|b| b.as_str())?;
    let body: serde_json::Value = serde_json::from_str(body_str).ok()?;

    let project_id = body
        .get("cloudaicompanionProject")
        .and_then(|p| p.as_str())
        .map(|s| s.to_string());

    if let Some(ref pid) = project_id {
        log_info(&format!("Discovered project ID: {}", pid));
        // Cache it
        let mut state = load_state();
        state.project_id = Some(pid.clone());
        save_state(&state);
    }

    project_id
}

// =============================================================================
// Provider Plugin Interface - Auth Only
// =============================================================================

/// Get provider info (JSON)
#[no_mangle]
pub extern "C" fn provider_info(ret_ptr: i32) -> i32 {
    let info = serde_json::json!({
        "id": "gemini-oauth",
        "display_name": "Gemini (OAuth)",
        "description": "Gemini via Cloud Code Assist API using OAuth (auth-only plugin)",
        "requires_auth": true,
        "provider": "google"
    });

    let json = info.to_string();
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
    }
    json.len() as i32
}

/// Get available models (JSON array)
/// Returns empty array - tark loads models from models.dev using "provider": "google"
#[no_mangle]
pub extern "C" fn provider_models(ret_ptr: i32) -> i32 {
    let models = serde_json::json!([]);

    let json = models.to_string();
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
    }
    json.len() as i32
}

/// Get auth status
/// Returns: 0 = not required, 1 = authenticated, 2 = not authenticated, 3 = expired
#[no_mangle]
pub extern "C" fn provider_auth_status() -> i32 {
    let state = load_state();
    match state.credentials {
        None => 2,    // Not authenticated
        Some(_) => 1, // Authenticated
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

    let creds: OAuthCredentials = match serde_json::from_str(creds_str) {
        Ok(c) => c,
        Err(_) => return -2,
    };

    log_info(&format!(
        "Loaded credentials: access_token_len={}, has_refresh={}",
        creds.access_token.len(),
        creds.refresh_token.is_some()
    ));

    let mut state = load_state();
    state.credentials = Some(creds);
    save_state(&state);

    log_info("Provider initialized with OAuth credentials");
    0
}

/// Logout
#[no_mangle]
pub extern "C" fn provider_auth_logout() -> i32 {
    let state = PluginState {
        credentials: None,
        project_id: None,
    };
    save_state(&state);
    log_info("Logged out");
    0
}

/// Get auth credentials for tark's native provider
///
/// This is the key function for auth-only plugins. Instead of implementing
/// provider_chat(), we return credentials that tark uses to create a native
/// GeminiProvider with Cloud Code Assist mode.
///
/// Returns JSON: { "access_token", "project_id", "api_mode" }
#[no_mangle]
pub extern "C" fn provider_auth_credentials(ret_ptr: i32) -> i32 {
    // Get valid token (refresh if needed)
    let access_token = match get_valid_token() {
        Ok(t) => t,
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

    // Get or discover project ID
    let project_id = get_project_id().or_else(|| discover_project_id(&access_token));

    if project_id.is_none() {
        log_error("Could not determine project ID");
        let error = serde_json::json!({
            "error": "Could not determine Google Cloud project ID. Set GOOGLE_CLOUD_PROJECT env var."
        });
        let json = error.to_string();
        unsafe {
            std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
        }
        return -(json.len() as i32);
    }

    log_debug(&format!(
        "Returning auth credentials: token_len={}, project_id={:?}",
        access_token.len(),
        project_id.as_ref().map(|s| truncate_str(s, 20))
    ));

    // Return credentials for tark's GeminiProvider
    let creds = serde_json::json!({
        "access_token": access_token,
        "project_id": project_id,
        "api_mode": "cloud_code_assist"
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
    let name = "Gemini (OAuth)";
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
        Ok(token) => {
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
    let endpoint = "https://cloudcode-pa.googleapis.com";
    unsafe {
        std::ptr::copy_nonoverlapping(endpoint.as_ptr(), ret_ptr as *mut u8, endpoint.len());
    }
    endpoint.len() as i32
}
