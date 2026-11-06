use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_tunnels_dir")]
    pub tunnels_dir: PathBuf,
    #[serde(default = "default_claude_binary")]
    pub claude_binary: PathBuf,
    #[serde(default = "default_browser_binary")]
    pub browser_binary: PathBuf,
    #[serde(default = "default_browser_profile_dir")]
    pub browser_profile_dir: PathBuf,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
}

fn default_tunnels_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join("claude-tunnel/tunnels")
}

fn default_claude_binary() -> PathBuf {
    PathBuf::from("claude")
}

fn default_browser_binary() -> PathBuf {
    PathBuf::from("chromium")
}

fn default_browser_profile_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("claude-tunnel/chromium-profile")
}

const fn default_poll_interval_secs() -> u64 {
    3
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            tunnels_dir: default_tunnels_dir(),
            claude_binary: default_claude_binary(),
            browser_binary: default_browser_binary(),
            browser_profile_dir: default_browser_profile_dir(),
            poll_interval_secs: default_poll_interval_secs(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, String> {
        let Some(base) = dirs::config_dir() else {
            return Ok(Self::default());
        };
        Self::load_from(&base.join("claude-tunnel/config.toml"))
    }

    pub fn load_from(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents)
                .map_err(|error| format!("invalid config {}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_uses_safe_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = AppConfig::load_from(&dir.path().join("missing.toml")).unwrap();

        assert_eq!(config.claude_binary, PathBuf::from("claude"));
        assert_eq!(config.browser_binary, PathBuf::from("chromium"));
        assert!(config
            .browser_profile_dir
            .ends_with("claude-tunnel/chromium-profile"));
        assert_eq!(config.poll_interval_secs, 3);
        assert!(config.tunnels_dir.ends_with("claude-tunnel/tunnels"));
    }

    #[test]
    fn malformed_file_is_an_error_instead_of_silently_weakening_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "poll_interval_secs = nope").unwrap();

        let error = AppConfig::load_from(&path).unwrap_err();

        assert!(error.contains("invalid config"));
    }
}
