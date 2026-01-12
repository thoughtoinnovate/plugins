//! Gemini Auth Proxy Server
//!
//! Local HTTP proxy that transforms standard Gemini API requests
//! to Cloud Code Assist API format using Gemini CLI OAuth credentials.
//!
//! Usage:
//!   gemini-auth-proxy [--port 9876]
//!
//! Tark connects to: http://localhost:9876/v1beta/models/{model}:generateContent

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use tark_plugin_gemini_auth::{
    credentials_path, is_expired, load_credentials, load_oauth_client, GeminiCliCredentials,
    OAuthClient, TOKEN_URL,
};

/// Cloud Code Assist API endpoint
const CODE_ASSIST_ENDPOINT: &str = "https://cloudcode-pa.googleapis.com";

/// Headers required by Code Assist API
const CODE_ASSIST_USER_AGENT: &str = "google-api-nodejs-client/9.15.1";
const CODE_ASSIST_CLIENT: &str = "gl-node/22.17.0";

/// Proxy server state
struct ProxyState {
    client: reqwest::Client,
    credentials: RwLock<Option<GeminiCliCredentials>>,
    project_id: RwLock<Option<String>>,
}

impl ProxyState {
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            credentials: RwLock::new(None),
            project_id: RwLock::new(None),
        }
    }

    /// Get valid access token, refreshing if needed
    async fn get_access_token(&self) -> Result<String> {
        let mut creds = self.credentials.write().await;

        // Load credentials if not cached
        if creds.is_none() {
            *creds = Some(load_credentials().map_err(|e| anyhow::anyhow!(e))?);
        }

        let credentials = creds.as_ref().unwrap();

        // Refresh if expired
        if is_expired(credentials) {
            info!("Access token expired, refreshing...");
            if let Some(refresh_token) = &credentials.refresh_token {
                let oauth_client = load_oauth_client(Some(credentials))
                    .map_err(|e| anyhow::anyhow!(e))
                    .context("Cannot refresh token (missing OAuth client info)")?;
                let new_creds =
                    refresh_access_token(&self.client, refresh_token, &oauth_client).await?;
                *creds = Some(new_creds.clone());
                return Ok(new_creds.access_token);
            } else {
                anyhow::bail!("Token expired and no refresh token available");
            }
        }

        Ok(credentials.access_token.clone())
    }

    /// Get or auto-provision project ID
    async fn get_project_id(&self, access_token: &str) -> Result<String> {
        // Check cache first
        {
            let project = self.project_id.read().await;
            if let Some(ref p) = *project {
                return Ok(p.clone());
            }
        }

        // Try environment variable
        if let Ok(project) = std::env::var("GOOGLE_CLOUD_PROJECT")
            .or_else(|_| std::env::var("GCLOUD_PROJECT"))
            .or_else(|_| std::env::var("GCP_PROJECT"))
        {
            let mut project_id = self.project_id.write().await;
            *project_id = Some(project.clone());
            return Ok(project);
        }

        // Auto-provision via Code Assist API
        info!("No project ID found, attempting auto-provision...");
        let project = auto_provision_project(&self.client, access_token).await?;

        let mut project_id = self.project_id.write().await;
        *project_id = Some(project.clone());
        Ok(project)
    }
}

/// Refresh access token using refresh token
async fn refresh_access_token(
    client: &reqwest::Client,
    refresh_token: &str,
    oauth_client: &OAuthClient,
) -> Result<GeminiCliCredentials> {
    let response = client
        .post(TOKEN_URL)
        .form(&[
            ("client_id", oauth_client.client_id.as_str()),
            ("client_secret", oauth_client.client_secret.as_str()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .context("Failed to refresh token")?;

    if !response.status().is_success() {
        let error = response.text().await.unwrap_or_default();
        anyhow::bail!("Token refresh failed: {}", error);
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        expires_in: Option<u64>,
    }

    let token_response: TokenResponse = response.json().await?;
    let expiry_date = token_response.expires_in.map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64 + secs * 1000)
            .unwrap_or(0)
    });

    // Update credentials file
    let new_creds = GeminiCliCredentials {
        access_token: token_response.access_token.clone(),
        refresh_token: Some(refresh_token.to_string()),
        expiry_date,
        token_type: Some("Bearer".to_string()),
        client_id: None,
        client_secret: None,
    };

    if let Some(path) = credentials_path() {
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&new_creds)?);
    }

    Ok(new_creds)
}

/// Auto-provision a managed project via Code Assist API
async fn auto_provision_project(client: &reqwest::Client, access_token: &str) -> Result<String> {
    // First try to load existing project
    let load_response = client
        .post(format!("{}/v1internal:loadCodeAssist", CODE_ASSIST_ENDPOINT))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", CODE_ASSIST_USER_AGENT)
        .header("X-Goog-Api-Client", CODE_ASSIST_CLIENT)
        .json(&serde_json::json!({
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI"
            }
        }))
        .send()
        .await?;

    if load_response.status().is_success() {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct LoadResponse {
            cloudaicompanion_project: Option<String>,
        }

        if let Ok(data) = load_response.json::<LoadResponse>().await {
            if let Some(project) = data.cloudaicompanion_project {
                info!("Found existing managed project: {}", project);
                return Ok(project);
            }
        }
    }

    // Onboard for free tier
    info!("Onboarding for free tier project...");
    for attempt in 0..5 {
        let response = client
            .post(format!("{}/v1internal:onboardUser", CODE_ASSIST_ENDPOINT))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", CODE_ASSIST_USER_AGENT)
            .header("X-Goog-Api-Client", CODE_ASSIST_CLIENT)
            .json(&serde_json::json!({
                "tierId": "FREE",
                "metadata": {
                    "ideType": "IDE_UNSPECIFIED",
                    "platform": "PLATFORM_UNSPECIFIED",
                    "pluginType": "GEMINI"
                }
            }))
            .send()
            .await?;

        if response.status().is_success() {
            #[derive(Deserialize)]
            struct OnboardResponse {
                done: Option<bool>,
                response: Option<OnboardResponseInner>,
            }
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct OnboardResponseInner {
                cloudaicompanion_project: Option<ProjectInfo>,
            }
            #[derive(Deserialize)]
            struct ProjectInfo {
                id: Option<String>,
            }

            if let Ok(data) = response.json::<OnboardResponse>().await {
                if data.done.unwrap_or(false) {
                    if let Some(project) = data
                        .response
                        .and_then(|r| r.cloudaicompanion_project)
                        .and_then(|p| p.id)
                    {
                        info!("Auto-provisioned project: {}", project);
                        return Ok(project);
                    }
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        info!("Waiting for project provisioning... (attempt {})", attempt + 1);
    }

    anyhow::bail!(
        "Failed to auto-provision project. Please set GOOGLE_CLOUD_PROJECT or run:\n\
         gcloud config set project YOUR_PROJECT_ID"
    )
}

/// Health check endpoint
async fn health() -> &'static str {
    "ok"
}

/// Status endpoint - shows auth state
async fn status(State(state): State<Arc<ProxyState>>) -> Json<serde_json::Value> {
    let has_creds = credentials_path().map(|p| p.exists()).unwrap_or(false);
    let project = state.project_id.read().await.clone();

    Json(serde_json::json!({
        "status": if has_creds { "authenticated" } else { "not_authenticated" },
        "credentials_path": credentials_path().map(|p| p.to_string_lossy().to_string()),
        "project_id": project,
    }))
}

/// Proxy generateContent requests
async fn proxy_generate_content(
    State(state): State<Arc<ProxyState>>,
    Path(model): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    proxy_request(state, &model, "generateContent", false, headers, body).await
}

/// Proxy streamGenerateContent requests
async fn proxy_stream_generate_content(
    State(state): State<Arc<ProxyState>>,
    Path(model): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    proxy_request(state, &model, "streamGenerateContent", true, headers, body).await
}

/// Core proxy logic
async fn proxy_request(
    state: Arc<ProxyState>,
    model: &str,
    action: &str,
    streaming: bool,
    _headers: HeaderMap,
    body: String,
) -> Response {
    // Get access token
    let access_token = match state.get_access_token().await {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to get access token: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {
                        "code": 401,
                        "message": format!("Authentication failed: {}", e),
                        "status": "UNAUTHENTICATED"
                    }
                })),
            )
                .into_response();
        }
    };

    // Get project ID
    let project_id = match state.get_project_id(&access_token).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to get project ID: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": {
                        "code": 500,
                        "message": format!("Project setup failed: {}", e),
                        "status": "INTERNAL"
                    }
                })),
            )
                .into_response();
        }
    };

    // Parse and wrap the request body
    let request_body: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "code": 400,
                        "message": format!("Invalid JSON: {}", e),
                        "status": "INVALID_ARGUMENT"
                    }
                })),
            )
                .into_response();
        }
    };

    // Wrap in Code Assist format
    let wrapped_body = serde_json::json!({
        "project": project_id,
        "model": model,
        "request": request_body
    });

    // Build Code Assist URL
    let url = format!(
        "{}/v1internal:{}{}",
        CODE_ASSIST_ENDPOINT,
        action,
        if streaming { "?alt=sse" } else { "" }
    );

    // Make request to Code Assist API
    let mut req = state
        .client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", CODE_ASSIST_USER_AGENT)
        .header("X-Goog-Api-Client", CODE_ASSIST_CLIENT)
        .header(
            "Client-Metadata",
            "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI",
        );

    if streaming {
        req = req.header("Accept", "text/event-stream");
    }

    let response = match req.json(&wrapped_body).send().await {
        Ok(r) => r,
        Err(e) => {
            error!("Request to Code Assist API failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": {
                        "code": 502,
                        "message": format!("Upstream error: {}", e),
                        "status": "UNAVAILABLE"
                    }
                })),
            )
                .into_response();
        }
    };

    let status = response.status();

    if streaming {
        // Stream the response, unwrapping the "response" field from each SSE line
        let stream = response.bytes_stream();
        let transformed = transform_sse_stream(stream);

        Response::builder()
            .status(status)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .body(Body::from_stream(transformed))
            .unwrap()
    } else {
        // Non-streaming: unwrap the "response" field
        match response.json::<serde_json::Value>().await {
            Ok(mut data) => {
                // Unwrap if wrapped
                if let Some(inner) = data.get("response").cloned() {
                    data = inner;
                }
                (StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK), Json(data))
                    .into_response()
            }
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": {
                        "code": 502,
                        "message": format!("Failed to parse response: {}", e),
                        "status": "INTERNAL"
                    }
                })),
            )
                .into_response(),
        }
    }
}

/// Transform SSE stream to unwrap "response" field from each data line
fn transform_sse_stream(
    stream: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + 'static,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static {
    use futures::StreamExt;

    futures::stream::unfold(
        (Box::pin(stream), String::new()),
        |(mut stream, mut buffer)| async move {
            loop {
                // Check if we have a complete line in buffer
                if let Some(newline_pos) = buffer.find('\n') {
                    let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
                    buffer = buffer[newline_pos + 1..].to_string();

                    if line.is_empty() {
                        return Some((Ok(bytes::Bytes::from("\n")), (stream, buffer)));
                    }

                    if let Some(json_str) = line.strip_prefix("data: ") {
                        if let Ok(mut data) = serde_json::from_str::<serde_json::Value>(json_str) {
                            // Unwrap response field if present
                            if let Some(inner) = data.get("response").cloned() {
                                data = inner;
                            }
                            let transformed = format!(
                                "data: {}\n",
                                serde_json::to_string(&data).unwrap_or_default()
                            );
                            return Some((Ok(bytes::Bytes::from(transformed)), (stream, buffer)));
                        }
                    }

                    // Pass through unchanged
                    let output = format!("{}\n", line);
                    return Some((Ok(bytes::Bytes::from(output)), (stream, buffer)));
                }

                // Need more data
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        buffer.push_str(&String::from_utf8_lossy(&chunk));
                    }
                    Some(Err(e)) => {
                        return Some((
                            Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                            (stream, buffer),
                        ));
                    }
                    None => {
                        // Stream ended
                        if !buffer.is_empty() {
                            let remaining = std::mem::take(&mut buffer);
                            return Some((Ok(bytes::Bytes::from(remaining)), (stream, buffer)));
                        }
                        return None;
                    }
                }
            }
        },
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("gemini_auth_proxy=info".parse().unwrap()),
        )
        .init();

    // Parse port from args
    let port: u16 = std::env::args()
        .skip_while(|a| a != "--port")
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(9876);

    // Check for credentials
    if !credentials_path().map(|p| p.exists()).unwrap_or(false) {
        warn!("No Gemini CLI credentials found at ~/.gemini/oauth_creds.json");
        warn!("Run: npm install -g @google/gemini-cli && gemini");
    }

    let state = Arc::new(ProxyState::new());

    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        // Standard Gemini API paths
        .route(
            "/v1beta/models/:model::generateContent",
            post(proxy_generate_content),
        )
        .route(
            "/v1beta/models/:model::streamGenerateContent",
            post(proxy_stream_generate_content),
        )
        // Also support without version prefix
        .route(
            "/models/:model::generateContent",
            post(proxy_generate_content),
        )
        .route(
            "/models/:model::streamGenerateContent",
            post(proxy_stream_generate_content),
        )
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    info!("Gemini Auth Proxy starting on http://{}", addr);
    info!("Configure tark with: GEMINI_API_BASE=http://localhost:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
