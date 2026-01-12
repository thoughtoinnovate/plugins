//! Gemini OAuth Plugin for Tark
//! Reads OAuth tokens from Gemini CLI (~/.gemini/oauth_creds.json)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiCliCredentials {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expiry_date: Option<u64>,
    pub token_type: Option<String>,
    /// Optional: some credential sources may include the OAuth client id/secret.
    /// If present, we can refresh tokens without any hardcoded secrets.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
}

fn oauth_client_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".gemini").join("oauth_client.json"))
}

pub fn credentials_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GEMINI_OAUTH_CREDENTIALS_PATH") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    dirs::home_dir().map(|h| h.join(".gemini").join("oauth_creds.json"))
}

pub fn has_credentials() -> bool {
    credentials_path().map(|p| p.exists()).unwrap_or(false)
}

pub fn load_credentials() -> Result<GeminiCliCredentials, String> {
    let path = credentials_path().ok_or("No home directory")?;
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

pub fn load_oauth_client(creds: Option<&GeminiCliCredentials>) -> Result<OAuthClient, String> {
    // 1) Environment variables (best for localhost/dev)
    let env_id = std::env::var("GEMINI_OAUTH_CLIENT_ID").ok().filter(|s| !s.is_empty());
    let env_secret = std::env::var("GEMINI_OAUTH_CLIENT_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    if let (Some(client_id), Some(client_secret)) = (env_id, env_secret) {
        return Ok(OAuthClient {
            client_id,
            client_secret,
        });
    }

    // 2) Embedded in credentials payload (some setups include it)
    if let Some(c) = creds {
        if let (Some(client_id), Some(client_secret)) =
            (c.client_id.clone(), c.client_secret.clone())
        {
            if !client_id.is_empty() && !client_secret.is_empty() {
                return Ok(OAuthClient {
                    client_id,
                    client_secret,
                });
            }
        }
    }

    // 3) Local Gemini CLI config file (optional)
    #[derive(Deserialize)]
    struct OAuthClientFile {
        client_id: String,
        client_secret: String,
    }
    if let Some(path) = oauth_client_path() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(parsed) = serde_json::from_str::<OAuthClientFile>(&content) {
                if !parsed.client_id.is_empty() && !parsed.client_secret.is_empty() {
                    return Ok(OAuthClient {
                        client_id: parsed.client_id,
                        client_secret: parsed.client_secret,
                    });
                }
            }
        }
    }

    Err("Missing OAuth client info for token refresh. Set GEMINI_OAUTH_CLIENT_ID and GEMINI_OAUTH_CLIENT_SECRET (or create ~/.gemini/oauth_client.json).".to_string())
}

pub fn is_expired(creds: &GeminiCliCredentials) -> bool {
    creds.expiry_date.map(|exp| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now >= exp
    }).unwrap_or(false)
}
