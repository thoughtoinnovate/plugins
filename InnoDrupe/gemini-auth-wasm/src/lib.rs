//! Gemini OAuth Provider Plugin
//!
//! This plugin provides a full LLM provider for Gemini using OAuth credentials
//! from Gemini CLI (~/.gemini/oauth_creds.json) and the Cloud Code Assist API.
//!
//! Exports the provider-plugin interface for tark.

use serde::{Deserialize, Serialize};

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
// Cloud Code Assist API (internal endpoint used by Gemini CLI)
const CODE_ASSIST_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal";

#[derive(Debug, Clone)]
struct OAuthClient {
    client_id: String,
    client_secret: String,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn is_expired(creds: &OAuthCredentials) -> bool {
    creds.expiry_date.map(|exp| now_ms() >= exp).unwrap_or(false)
}

fn load_oauth_client(creds: &OAuthCredentials) -> Option<OAuthClient> {
    let env_id = env_get("GEMINI_OAUTH_CLIENT_ID");
    let env_secret = env_get("GEMINI_OAUTH_CLIENT_SECRET");
    if let (Some(client_id), Some(client_secret)) = (env_id, env_secret) {
        if !client_id.is_empty() && !client_secret.is_empty() {
            return Some(OAuthClient {
                client_id,
                client_secret,
            });
        }
    }

    if let (Some(client_id), Some(client_secret)) = (creds.client_id.clone(), creds.client_secret.clone()) {
        if !client_id.is_empty() && !client_secret.is_empty() {
            return Some(OAuthClient { client_id, client_secret });
        }
    }

    None
}

// Static buffer for env reads
static mut ENV_BUFFER: [u8; 256] = [0u8; 256];

fn env_get(name: &str) -> Option<String> {
    unsafe {
        let len = env_get_raw(
            name.as_ptr() as i32,
            name.len() as i32,
            ENV_BUFFER.as_mut_ptr() as i32,
        );
        if len <= 0 {
            return None;
        }
        let value = std::str::from_utf8(&ENV_BUFFER[..len as usize]).ok()?;
        if value.is_empty() {
            return None;
        }
        Some(value.to_string())
    }
}

fn get_gemini_api_key() -> Option<String> {
    env_get("GEMINI_API_KEY")
}

fn get_project_id() -> Option<String> {
    // Try state first (cached from previous loadCodeAssist call)
    let state = load_state();
    if let Some(pid) = state.project_id {
        return Some(pid);
    }
    
    // Try environment variables
    env_get("GOOGLE_CLOUD_PROJECT")
        .or_else(|| env_get("GCLOUD_PROJECT"))
        .or_else(|| env_get("GCP_PROJECT"))
}

/// Discover the user's managed project ID by calling loadCodeAssist API
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
        ("Authorization".to_string(), format!("Bearer {}", access_token)),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), "google-api-nodejs-client/9.15.1".to_string()),
        ("X-Goog-Api-Client".to_string(), "gl-node/22.17.0".to_string()),
        ("Client-Metadata".to_string(), "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI".to_string()),
    ];
    
    log_debug(&format!("Discovering project via loadCodeAssist: {}", url));
    
    let response = http_post(&url, &request_body.to_string(), &headers)?;
    
    let parsed: serde_json::Value = serde_json::from_str(&response).ok()?;
    
    // Check HTTP status
    let status = parsed.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
    let body_str = parsed.get("body").and_then(|b| b.as_str()).unwrap_or("");
    
    log_debug(&format!("loadCodeAssist response: status={}, body={}", status, &body_str[..body_str.len().min(500)]));
    
    if status != 200 {
        log_error(&format!("loadCodeAssist failed with status {}: {}", status, &body_str[..body_str.len().min(200)]));
        return None;
    }
    
    // Parse body
    let body: serde_json::Value = match serde_json::from_str(body_str) {
        Ok(v) => v,
        Err(e) => {
            log_error(&format!("Failed to parse loadCodeAssist body: {}", e));
            return None;
        }
    };
    
    log_debug(&format!("loadCodeAssist parsed: {}", body));
    
    // Extract project ID
    let project_id = body.get("cloudaicompanionProject")
        .and_then(|p| p.as_str())
        .map(|s| s.to_string());
    
    if let Some(ref pid) = project_id {
        log_info(&format!("Discovered project ID: {}", pid));
        // Cache it in state
        let mut state = load_state();
        state.project_id = Some(pid.clone());
        save_state(&state);
    } else {
        log_error(&format!("No cloudaicompanionProject in response: {}", body));
    }
    
    project_id
}

// =============================================================================
// Memory Management
// =============================================================================

static mut RETURN_BUFFER: [u8; 131072] = [0u8; 131072]; // 128KB for responses

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
    unsafe { log_info_raw(msg.as_ptr() as i32, msg.len() as i32); }
}

fn log_error(msg: &str) {
    unsafe { log_error_raw(msg.as_ptr() as i32, msg.len() as i32); }
}

fn log_debug(msg: &str) {
    unsafe { log_debug_raw(msg.as_ptr() as i32, msg.len() as i32); }
}

fn storage_get(key: &str) -> Option<String> {
    unsafe {
        let ret = storage_get_raw(
            key.as_ptr() as i32,
            key.len() as i32,
            RETURN_BUFFER.as_mut_ptr() as i32,
        );
        if ret > 0 {
            String::from_utf8(RETURN_BUFFER[..ret as usize].to_vec()).ok()
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
            RETURN_BUFFER.as_mut_ptr() as i32,
        );
        if ret > 0 {
            String::from_utf8(RETURN_BUFFER[..ret as usize].to_vec()).ok()
        } else {
            None
        }
    }
}

// =============================================================================
// State Management
// =============================================================================

fn load_state() -> PluginState {
    storage_get("state")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(PluginState {
            credentials: None,
            project_id: None,
        })
}

fn save_state(state: &PluginState) {
    if let Ok(json) = serde_json::to_string(state) {
        storage_set("state", &json);
    }
}

fn refresh_token(refresh_token: &str, oauth_client: &OAuthClient) -> Option<OAuthCredentials> {
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
    let token_data = if let Some(body) = parsed.get("body") {
        serde_json::from_str::<TokenResponse>(body.as_str()?).ok()?
    } else {
        serde_json::from_value::<TokenResponse>(parsed).ok()?
    };

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

    let creds = state.credentials.as_ref().ok_or("No credentials")?;

    // If token is still valid, just use it
    if !creds.access_token.is_empty() && !is_expired(creds) {
        return Ok(creds.access_token.clone());
    }

    // Refresh if expired and we have enough info
    if let Some(refresh) = &creds.refresh_token {
        let oauth_client = load_oauth_client(creds).ok_or_else(|| {
            "Token expired and cannot refresh (missing GEMINI_OAUTH_CLIENT_ID/GEMINI_OAUTH_CLIENT_SECRET). Run Gemini CLI login again or set those env vars.".to_string()
        })?;
        log_info("Access token expired, refreshing...");
        if let Some(new_creds) = refresh_token(refresh, &oauth_client) {
            state.credentials = Some(new_creds.clone());
            save_state(&state);
            log_info("Token refreshed successfully");
            return Ok(new_creds.access_token);
        }
        return Err("Token refresh failed. Run 'gemini auth login' or set GEMINI_API_KEY.".to_string());
    }

    Err("Token expired and no refresh token is available. Run 'gemini auth login' or set GEMINI_API_KEY.".to_string())
}

// =============================================================================
// Provider Plugin Interface
// =============================================================================

/// Get provider info (JSON)
#[no_mangle]
pub extern "C" fn provider_info(ret_ptr: i32) -> i32 {
    let info = serde_json::json!({
        "id": "gemini-oauth",
        "display_name": "Gemini (OAuth)",
        "description": "Gemini via Generative Language API using OAuth",
        "requires_auth": true
    });
    
    let json = info.to_string();
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
    }
    json.len() as i32
}

/// Get available models (JSON array)
/// These models are supported by the Cloud Code Assist API
#[no_mangle]
pub extern "C" fn provider_models(ret_ptr: i32) -> i32 {
    let models = serde_json::json!([
        {
            "id": "gemini-2.5-pro-preview-05-06",
            "display_name": "Gemini 2.5 Pro Preview",
            "context_window": 1048576,
            "supports_streaming": true,
            "supports_tools": true
        },
        {
            "id": "gemini-2.5-flash-preview-04-17",
            "display_name": "Gemini 2.5 Flash Preview",
            "context_window": 1048576,
            "supports_streaming": true,
            "supports_tools": true
        },
        {
            "id": "gemini-2.0-flash",
            "display_name": "Gemini 2.0 Flash",
            "context_window": 1048576,
            "supports_streaming": true,
            "supports_tools": true
        },
        {
            "id": "gemini-2.0-flash-exp",
            "display_name": "Gemini 2.0 Flash (Experimental)",
            "context_window": 1000000,
            "supports_streaming": true,
            "supports_tools": true
        },
        {
            "id": "gemini-1.5-pro",
            "display_name": "Gemini 1.5 Pro",
            "context_window": 2000000,
            "supports_streaming": true,
            "supports_tools": true
        },
        {
            "id": "gemini-1.5-flash",
            "display_name": "Gemini 1.5 Flash",
            "context_window": 1000000,
            "supports_streaming": true,
            "supports_tools": true
        }
    ]);
    
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
    // Check for API key first
    if get_gemini_api_key().is_some() {
        return 1; // Authenticated via API key
    }
    
    // Fall back to OAuth credentials
    let state = load_state();
    match state.credentials {
        None => 2, // Not authenticated
        Some(_) => 1, // Authenticated (we have credentials)
    }
}

/// Initialize with credentials (JSON)
#[no_mangle]
pub extern "C" fn provider_auth_init(creds_ptr: i32, creds_len: i32) -> i32 {
    let creds_slice = unsafe { 
        std::slice::from_raw_parts(creds_ptr as *const u8, creds_len as usize) 
    };
    
    let creds_str = match std::str::from_utf8(creds_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let creds: OAuthCredentials = match serde_json::from_str(creds_str) {
        Ok(c) => c,
        Err(_) => return -2,
    };

    let mut state = load_state();
    state.credentials = Some(creds);
    save_state(&state);

    log_info("Provider initialized with credentials");
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

/// Chat completion
/// Args: msgs_ptr, msgs_len, model_ptr, model_len, ret_ptr
/// Returns: bytes written to ret_ptr, or negative on error
#[no_mangle]
pub extern "C" fn provider_chat(
    msgs_ptr: i32,
    msgs_len: i32,
    model_ptr: i32,
    model_len: i32,
    ret_ptr: i32,
) -> i32 {
    // Read messages JSON
    let msgs_slice = unsafe { 
        std::slice::from_raw_parts(msgs_ptr as *const u8, msgs_len as usize) 
    };
    let msgs_str = match std::str::from_utf8(msgs_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Read model
    let model_slice = unsafe { 
        std::slice::from_raw_parts(model_ptr as *const u8, model_len as usize) 
    };
    let model = match std::str::from_utf8(model_slice) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // Parse messages
    #[derive(Deserialize)]
    struct Message {
        role: String,
        content: String,
    }
    
    let messages: Vec<Message> = match serde_json::from_str(msgs_str) {
        Ok(m) => m,
        Err(e) => {
            log_error(&format!("Failed to parse messages: {}", e));
            return -3;
        }
    };

    // Get authentication - prefer API key, fallback to OAuth
    let (use_api_key, auth_value) = if let Some(api_key) = get_gemini_api_key() {
        log_info("Using GEMINI_API_KEY for authentication");
        (true, api_key)
    } else {
        log_info("No API key found, trying OAuth...");
        match get_valid_token() {
            Ok(t) => (false, t),
            Err(e) => {
                log_error(&format!("Failed to get token: {}. Set GEMINI_API_KEY or run 'gemini auth login'", e));
                return -4;
            }
        }
    };

    // Build Gemini API request
    let mut contents = Vec::new();
    let mut system_instruction: Option<String> = None;

    for msg in &messages {
        match msg.role.as_str() {
            "system" => {
                system_instruction = Some(msg.content.clone());
            }
            "user" => {
                contents.push(serde_json::json!({
                    "role": "user",
                    "parts": [{"text": msg.content}]
                }));
            }
            "assistant" => {
                contents.push(serde_json::json!({
                    "role": "model",
                    "parts": [{"text": msg.content}]
                }));
            }
            _ => {}
        }
    }

    let mut request = serde_json::json!({
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": 8192,
            "temperature": 0.7
        }
    });

    if let Some(sys) = system_instruction {
        request["systemInstruction"] = serde_json::json!({
            "parts": [{"text": sys}]
        });
    }

    // Get project ID (required for Cloud Code Assist API)
    // Try cached project ID first, then discover via loadCodeAssist
    let project_id = get_project_id().or_else(|| {
        if !use_api_key {
            discover_project_id(&auth_value)
        } else {
            None
        }
    });
    
    // Build URL and body based on auth type
    let (url, body, headers) = if use_api_key {
        // API key auth - use standard Generative Language API
        let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", model, auth_value);
        let body = request.to_string();
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        (url, body, headers)
    } else {
        // OAuth auth - use Cloud Code Assist API with wrapped request format
        let url = format!("{}:generateContent", CODE_ASSIST_URL);
        
        // Need a project ID for Cloud Code Assist
        let pid = match &project_id {
            Some(p) => p.clone(),
            None => {
                log_error("No project ID available. Set GOOGLE_CLOUD_PROJECT or ensure Gemini CLI is properly configured.");
                let error_response = serde_json::json!({
                    "text": "No Google Cloud project ID available. Please set GOOGLE_CLOUD_PROJECT environment variable or ensure your Gemini CLI is properly configured.",
                    "usage": null
                });
                let json = error_response.to_string();
                unsafe {
                    std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
                }
                return json.len() as i32;
            }
        };
        
        log_info(&format!("Using project ID: {} for model: {}", pid, model));
        
        // Wrap the request in Cloud Code Assist format
        let wrapped_request = serde_json::json!({
            "project": pid,
            "model": model,
            "request": request
        });
        let body = wrapped_request.to_string();
        
        log_debug(&format!("Request body: {}", &body[..body.len().min(500)]));
        
        // Required headers for Cloud Code Assist API
        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", auth_value)),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "google-api-nodejs-client/9.15.1".to_string()),
            ("X-Goog-Api-Client".to_string(), "gl-node/22.17.0".to_string()),
            ("Client-Metadata".to_string(), "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI".to_string()),
        ];
        (url, body, headers)
    };
    
    log_debug(&format!("Calling API: {}", url.split('?').next().unwrap_or(&url)));

    let response = match http_post(&url, &body, &headers) {
        Some(r) => r,
        None => {
            log_error("HTTP request failed");
            return -5;
        }
    };

    log_debug(&format!("Got response: {} bytes", response.len()));

    // Parse response (host returns {status, headers, body} wrapper)
    let parsed: serde_json::Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            log_error(&format!("Failed to parse response: {}", e));
            return -6;
        }
    };

    // Check for HTTP-level errors first
    if let Some(http_error) = parsed.get("error").and_then(|e| e.as_str()) {
        log_error(&format!("HTTP error: {}", http_error));
        let error_response = serde_json::json!({
            "text": format!("HTTP error: {}", http_error),
            "usage": null
        });
        let json = error_response.to_string();
        unsafe {
            std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
        }
        return json.len() as i32;
    }

    // Check HTTP status code
    let status = parsed.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
    if status != 200 {
        let body = parsed.get("body").and_then(|b| b.as_str()).unwrap_or("");
        log_error(&format!("HTTP {} - Body: {}", status, &body[..body.len().min(500)]));
        
        // Try to extract error message from body
        let error_msg = if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(body) {
            body_json.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("HTTP {}", status))
        } else {
            format!("HTTP {} - {}", status, &body[..body.len().min(200)])
        };
        
        let error_response = serde_json::json!({
            "text": format!("API Error: {}", error_msg),
            "usage": null
        });
        let json = error_response.to_string();
        unsafe {
            std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
        }
        return json.len() as i32;
    }

    // Parse the API response body
    let api_response = if let Some(body_str) = parsed.get("body").and_then(|b| b.as_str()) {
        match serde_json::from_str::<serde_json::Value>(body_str) {
            Ok(v) => v,
            Err(e) => {
                log_error(&format!("Failed to parse API body: {}", e));
                let error_response = serde_json::json!({
                    "text": format!("Failed to parse API response: {}", e),
                    "usage": null
                });
                let json = error_response.to_string();
                unsafe {
                    std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
                }
                return json.len() as i32;
            }
        }
    } else {
        log_error("No body in HTTP response");
        let error_response = serde_json::json!({
            "text": "No response body from API",
            "usage": null
        });
        let json = error_response.to_string();
        unsafe {
            std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
        }
        return json.len() as i32;
    };

    // Check for API-level error in response body
    if let Some(error) = api_response.get("error") {
        let error_msg = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        log_error(&format!("API error: {}", error_msg));
        
        let error_response = serde_json::json!({
            "text": format!("Cloud Code Assist API error: {}", error_msg),
            "usage": null
        });
        let json = error_response.to_string();
        unsafe {
            std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
        }
        return json.len() as i32;
    }

    // Cloud Code Assist API wraps the actual response in a "response" field
    // Try to unwrap it, or use the response as-is for standard API
    let inner_response = api_response.get("response").unwrap_or(&api_response);

    // Extract text from response
    let text = inner_response
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.get(0))
        .and_then(|p| p.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    // Extract usage (can be in inner response or top level)
    let usage_meta = inner_response.get("usageMetadata")
        .or_else(|| api_response.get("usageMetadata"));
    let usage = usage_meta.map(|u| {
        serde_json::json!({
            "input_tokens": u.get("promptTokenCount").and_then(|v| v.as_u64()).unwrap_or(0),
            "output_tokens": u.get("candidatesTokenCount").and_then(|v| v.as_u64()).unwrap_or(0)
        })
    });

    // Build response
    let chat_response = serde_json::json!({
        "text": text,
        "usage": usage
    });

    let json = chat_response.to_string();
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ret_ptr as *mut u8, json.len());
    }
    json.len() as i32
}

// =============================================================================
// Legacy Auth Plugin Interface (for backwards compatibility)
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
