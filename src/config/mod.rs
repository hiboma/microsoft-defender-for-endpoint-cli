use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::AppError;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub api: ApiConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ApiConfig {
    pub mde_base_url: Option<String>,
    pub graph_base_url: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self, AppError> {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path).map_err(|e| {
                AppError::Config(format!(
                    "failed to read config file {}: {}",
                    path.display(),
                    e
                ))
            })?;
            let config: Config = toml::from_str(&content)
                .map_err(|e| AppError::Config(format!("failed to parse config file: {}", e)))?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    fn config_path() -> PathBuf {
        dirs_config_path().join("config.toml")
    }
}

fn dirs_config_path() -> PathBuf {
    if let Some(config_dir) = dirs_home().map(|h| h.join(".config").join("mde")) {
        config_dir
    } else {
        PathBuf::from(".config/mde")
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Resolve a value from CLI option, environment variable, or config file (in priority order).
pub fn resolve_value(
    cli_value: Option<&str>,
    env_var: &str,
    config_value: Option<&str>,
) -> Option<String> {
    cli_value
        .map(String::from)
        .or_else(|| std::env::var(env_var).ok())
        .or_else(|| config_value.map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.auth.tenant_id.is_none());
        assert!(config.auth.client_id.is_none());
        assert!(config.auth.client_secret.is_none());
    }

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[auth]
tenant_id = "t-123"
client_id = "c-456"
client_secret = "s-789"

[api]
mde_base_url = "https://api.security.microsoft.com"
graph_base_url = "https://graph.microsoft.com"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.auth.tenant_id.as_deref(), Some("t-123"));
        assert_eq!(
            config.api.mde_base_url.as_deref(),
            Some("https://api.security.microsoft.com")
        );
    }

    #[test]
    fn test_resolve_value_priority() {
        let result = resolve_value(Some("cli"), "NONEXISTENT_VAR", Some("config"));
        assert_eq!(result.as_deref(), Some("cli"));

        let result = resolve_value(None, "NONEXISTENT_VAR_12345", Some("config"));
        assert_eq!(result.as_deref(), Some("config"));

        let result = resolve_value(None, "NONEXISTENT_VAR_12345", None);
        assert!(result.is_none());
    }
}
