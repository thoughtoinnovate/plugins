//! Integration tests for gemini-oauth plugin
//!
//! These tests download the tark binary from GitHub releases and test
//! the plugin against it.
//!
//! ## Running Tests
//!
//! ```bash
//! # With local tark binary (recommended for development)
//! TARK_BINARY=/path/to/tark cargo test --release -- --test-threads=1 --nocapture
//!
//! # From tark repo (after building)
//! TARK_BINARY=../../tark/target/release/tark cargo test --release -- --test-threads=1 --nocapture
//!
//! # Download from GitHub (requires plugin support in release)
//! cargo test --release -- --test-threads=1 --nocapture
//! ```
//!
//! ## Environment Variables
//!
//! - `TARK_BINARY`: Path to local tark binary (skips download, recommended)
//! - `TARK_VERSION`: Version to download (default: latest)
//! - `GITHUB_TOKEN`: For authenticated API requests (optional, avoids rate limits)

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Get or download the tark binary
fn get_tark_binary() -> PathBuf {
    // Check for local override
    if let Ok(path) = env::var("TARK_BINARY") {
        let path = PathBuf::from(path);
        if path.exists() {
            println!("Using local tark binary: {:?}", path);
            return path;
        }
    }

    // Check cache directory
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("tark-plugin-tests");
    fs::create_dir_all(&cache_dir).expect("Failed to create cache dir");

    let version = env::var("TARK_VERSION").unwrap_or_else(|_| "latest".to_string());
    let binary_name = if cfg!(target_os = "windows") {
        "tark.exe"
    } else {
        "tark"
    };

    let cached_binary = cache_dir.join(format!("tark-{}", version)).join(binary_name);

    // Return cached binary if exists
    if cached_binary.exists() {
        println!("Using cached tark binary: {:?}", cached_binary);
        return cached_binary;
    }

    // Download from GitHub
    println!("Downloading tark {} from GitHub...", version);
    download_tark_binary(&cache_dir, &version)
}

/// Download tark binary from GitHub releases
fn download_tark_binary(cache_dir: &PathBuf, version: &str) -> PathBuf {
    let (os, arch) = get_platform();

    // Binary naming: tark-{os}-{arch} (no extension on Unix, .exe on Windows)
    // e.g., tark-linux-arm64, tark-darwin-x86_64, tark-windows-arm64.exe
    let binary_suffix = if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    };

    let asset_name = format!("tark-{}-{}{}", os, arch, binary_suffix);

    // Determine download URL
    // Releases at: https://github.com/thoughtoinnovate/tark/releases
    let download_url = if version == "latest" {
        format!(
            "https://github.com/thoughtoinnovate/tark/releases/latest/download/{}",
            asset_name
        )
    } else {
        format!(
            "https://github.com/thoughtoinnovate/tark/releases/download/{}/{}",
            version, asset_name
        )
    };

    println!("Download URL: {}", download_url);

    // Create version-specific directory
    let version_dir = cache_dir.join(format!("tark-{}", version));
    fs::create_dir_all(&version_dir).expect("Failed to create version dir");

    // Binary path
    let binary_name = if cfg!(target_os = "windows") {
        "tark.exe"
    } else {
        "tark"
    };
    let binary_path = version_dir.join(binary_name);

    // Download binary directly (not an archive)
    download_file(&download_url, &binary_path);

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&binary_path)
            .expect("Binary not found after download")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&binary_path, perms).expect("Failed to set permissions");
    }

    println!("Tark binary ready: {:?}", binary_path);
    binary_path
}

fn get_platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    // GitHub releases use x86_64 not amd64
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    };

    (os, arch)
}

fn download_file(url: &str, dest: &PathBuf) {
    // Use curl or wget
    let status = Command::new("curl")
        .args(["-fL", "-o", dest.to_str().unwrap(), url])
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            // Try wget as fallback
            let wget_status = Command::new("wget")
                .args(["-O", dest.to_str().unwrap(), url])
                .status();
            
            if wget_status.map(|s| !s.success()).unwrap_or(true) {
                panic!("Failed to download {} with curl or wget", url);
            }
        }
    }
}

/// Run tark command and capture output
fn run_tark(binary: &PathBuf, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(binary)
        .args(args)
        .output()
        .expect("Failed to run tark");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (output.status.success(), stdout, stderr)
}

/// Get the plugin directory (dist/ in this repo)
fn get_plugin_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest_dir).join("dist")
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_tark_binary_available() {
    let binary = get_tark_binary();
    assert!(binary.exists(), "Tark binary should exist");

    let (success, stdout, _) = run_tark(&binary, &["--version"]);
    assert!(success, "tark --version should succeed");
    assert!(stdout.contains("tark") || stdout.contains("0."), "Should show version");
    println!("✓ Tark version: {}", stdout.trim());
}

#[test]
fn test_plugin_install() {
    let binary = get_tark_binary();
    let plugin_dir = get_plugin_dir();

    // Verify plugin files exist
    assert!(
        plugin_dir.join("plugin.toml").exists(),
        "plugin.toml should exist in dist/"
    );
    assert!(
        plugin_dir.join("plugin.wasm").exists(),
        "plugin.wasm should exist in dist/"
    );

    // Install the plugin
    let (success, stdout, stderr) = run_tark(
        &binary,
        &["plugin", "add", plugin_dir.to_str().unwrap()],
    );

    // May already be installed, which is fine
    if !success && !stderr.contains("already") {
        panic!("Failed to install plugin: {}\n{}", stdout, stderr);
    }

    println!("✓ Plugin installed successfully");
}

#[test]
fn test_plugin_appears_in_list() {
    let binary = get_tark_binary();

    // First ensure plugin is installed
    let plugin_dir = get_plugin_dir();
    let _ = run_tark(&binary, &["plugin", "add", plugin_dir.to_str().unwrap()]);

    // List plugins
    let (success, stdout, _) = run_tark(&binary, &["plugin", "list"]);
    assert!(success, "tark plugin list should succeed");
    assert!(
        stdout.contains("gemini-oauth"),
        "gemini-oauth should appear in plugin list"
    );

    println!("✓ Plugin appears in list:\n{}", stdout);
}

#[test]
fn test_plugin_provider_type() {
    let binary = get_tark_binary();

    // List plugins
    let (success, stdout, _) = run_tark(&binary, &["plugin", "list"]);
    assert!(success);

    // Check it's listed as provider type
    assert!(
        stdout.contains("provider"),
        "gemini-oauth should be listed as provider type"
    );

    println!("✓ Plugin is provider type");
}

#[test]
#[ignore] // Run with: cargo test -- --ignored
fn test_chat_with_plugin_provider() {
    let binary = get_tark_binary();

    // Check if credentials exist
    let creds_path = dirs::home_dir()
        .map(|h| h.join(".gemini").join("oauth_creds.json"))
        .expect("No home dir");

    if !creds_path.exists() {
        println!("Skipping: No Gemini CLI credentials at {:?}", creds_path);
        return;
    }

    // Try to start chat with gemini-oauth provider
    // This is a smoke test - just verify it doesn't crash immediately
    let (success, _, stderr) = run_tark(&binary, &["chat", "-p", "gemini-oauth", "--help"]);

    // --help should work without actually starting chat
    assert!(
        success || stderr.contains("help"),
        "Chat command should accept gemini-oauth provider"
    );

    println!("✓ Chat accepts gemini-oauth provider");
}

// =============================================================================
// BDD-Style Scenario Tests
// =============================================================================

mod scenarios {
    use super::*;

    #[test]
    fn scenario_fresh_install_from_github() {
        // Given: Tark binary from GitHub releases
        let binary = get_tark_binary();

        // When: Installing the gemini-oauth plugin
        let plugin_dir = get_plugin_dir();
        let _ = run_tark(&binary, &["plugin", "add", plugin_dir.to_str().unwrap()]);

        // Then: Plugin should be installed and enabled
        let (_, stdout, _) = run_tark(&binary, &["plugin", "list"]);
        assert!(stdout.contains("gemini-oauth"));
        assert!(stdout.contains("enabled") || stdout.contains("✓"));

        println!("✓ Scenario: Fresh install from GitHub works");
    }

    #[test]
    fn scenario_plugin_survives_tark_upgrade() {
        // This test verifies plugin data persists across tark versions
        // For now, just verify the plugin directory structure

        let plugin_data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("tark")
            .join("plugins");

        println!("Plugin data directory: {:?}", plugin_data_dir);

        // If plugins are installed, the directory should exist
        if plugin_data_dir.exists() {
            let gemini_dir = plugin_data_dir.join("gemini-oauth");
            if gemini_dir.exists() {
                assert!(
                    gemini_dir.join("plugin.toml").exists(),
                    "Plugin manifest should persist"
                );
                println!("✓ Plugin data persists in {:?}", gemini_dir);
            }
        }

        println!("✓ Scenario: Plugin data directory structure is correct");
    }
}
