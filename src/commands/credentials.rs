use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::credentials::{CredentialField, CredentialsCommand};
use crate::config::credential_store::{ACCOUNT_CLIENT_SECRET, CredentialStore, default_store};
use crate::error::AppError;

pub fn handle(cmd: &CredentialsCommand) -> Result<(), AppError> {
    let store = default_store().ok_or_else(|| {
        AppError::Config(
            "no credential store backend available on this platform (macOS Keychain required)"
                .to_string(),
        )
    })?;

    match cmd {
        CredentialsCommand::Set { field, stdin } => set_value(store.as_ref(), *field, *stdin),
        CredentialsCommand::Delete { field } => delete_value(store.as_ref(), *field),
        CredentialsCommand::Status => print_status(store.as_ref()),
        CredentialsCommand::Migrate { dry_run } => migrate(store.as_ref(), *dry_run),
    }
}

fn set_value(
    store: &dyn CredentialStore,
    field: CredentialField,
    from_stdin: bool,
) -> Result<(), AppError> {
    let value = if from_stdin {
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| AppError::Config(format!("failed to read stdin: {}", e)))?;
        let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("empty value from stdin".to_string()));
        }
        trimmed
    } else {
        let prompt = format!("Enter {} (input hidden): ", field.account());
        rpassword::prompt_password(prompt)
            .map_err(|e| AppError::Config(format!("failed to read password: {}", e)))?
    };

    if value.is_empty() {
        return Err(AppError::InvalidInput("empty value".to_string()));
    }

    store
        .set(field.account(), &value)
        .map_err(|e| AppError::Config(e.to_string()))?;
    println!("✅ Stored {} in credential store", field.account());
    Ok(())
}

fn delete_value(store: &dyn CredentialStore, field: CredentialField) -> Result<(), AppError> {
    store
        .delete(field.account())
        .map_err(|e| AppError::Config(e.to_string()))?;
    println!("✅ Deleted {} from credential store", field.account());
    Ok(())
}

fn print_status(store: &dyn CredentialStore) -> Result<(), AppError> {
    // Probe each known field; report presence only, never the value.
    let fields = [(CredentialField::ClientSecret, ACCOUNT_CLIENT_SECRET)];
    println!("Credential store: macOS Keychain (service=dev.mde-cli)");
    for (_, account) in fields {
        match store.get(account) {
            Ok(Some(_)) => println!("  {} : stored", account),
            Ok(None) => println!("  {} : not stored", account),
            Err(e) => println!("  {} : error ({})", account, e),
        }
    }
    Ok(())
}

fn migrate(store: &dyn CredentialStore, dry_run: bool) -> Result<(), AppError> {
    let path = find_credentials_toml()
        .ok_or_else(|| AppError::Config("no credentials.toml found to migrate from".to_string()))?;
    println!("Found credentials.toml: {}", path.display());

    let original = fs::read_to_string(&path)
        .map_err(|e| AppError::Config(format!("failed to read {}: {}", path.display(), e)))?;

    let secret = extract_client_secret(&original);
    let secret = match secret {
        Some(s) if !s.is_empty() => s,
        _ => {
            println!("  client_secret: not present (nothing to migrate)");
            return Ok(());
        }
    };
    println!("  client_secret: present (will move to credential store)");

    if dry_run {
        println!("(dry-run) no changes made");
        return Ok(());
    }

    // Confirm before mutating.
    print!("Migrate client_secret to the credential store? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|e| AppError::Config(format!("flush stdout: {}", e)))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|e| AppError::Config(format!("read stdin: {}", e)))?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        println!("Aborted.");
        return Ok(());
    }

    // Backup before mutating the file.
    let backup = backup_path(&path);
    fs::copy(&path, &backup)
        .map_err(|e| AppError::Config(format!("failed to write backup: {}", e)))?;
    println!("Backup written: {}", backup.display());

    store
        .set(ACCOUNT_CLIENT_SECRET, &secret)
        .map_err(|e| AppError::Config(format!("credential store: {}", e)))?;
    println!("✅ Stored client_secret in credential store");

    let updated = blank_client_secret(&original);
    fs::write(&path, updated)
        .map_err(|e| AppError::Config(format!("failed to update {}: {}", path.display(), e)))?;
    println!("✅ Cleared client_secret in {}", path.display());

    println!();
    println!(
        "⚠ The backup at {} still contains the plaintext secret.",
        backup.display()
    );
    println!("  After verifying with `mde-cli credentials status`, delete it:");
    println!("    rm {}", backup.display());

    Ok(())
}

fn find_credentials_toml() -> Option<PathBuf> {
    let candidates = credentials_search_paths();
    candidates.into_iter().find(|p| p.is_file())
}

fn credentials_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(".mde-credentials.toml")];
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        paths.push(
            PathBuf::from(config_home)
                .join("mde")
                .join("credentials.toml"),
        );
    } else if let Ok(home) = std::env::var("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".config")
                .join("mde")
                .join("credentials.toml"),
        );
    }
    paths
}

fn backup_path(p: &Path) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".bak.{}", ts));
    p.with_file_name(name)
}

/// Extract the value of `client_secret = "..."` from a credentials.toml.
/// Uses a minimal text scan rather than full TOML re-serialization so that
/// formatting and comments in the user's file are preserved on rewrite.
fn extract_client_secret(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("client_secret") {
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('=')?.trim_start();
            // Accept "..." form only; reject multi-line basic strings for safety.
            let rest = rest.strip_prefix('"')?;
            let end = rest.find('"')?;
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Replace `client_secret = "..."` with `client_secret = ""` while preserving
/// the rest of the file (comments, ordering, other fields).
fn blank_client_secret(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("client_secret") {
            let indent_len = line.len() - trimmed.len();
            out.push_str(&line[..indent_len]);
            out.push_str("client_secret = \"\"");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_quoted_value() {
        let s = r#"
[credentials]
tenant_id = "t"
client_secret = "abc123"
client_id = "c"
"#;
        assert_eq!(extract_client_secret(s).as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_returns_none_when_missing() {
        let s = r#"
[credentials]
client_id = "c"
"#;
        assert!(extract_client_secret(s).is_none());
    }

    #[test]
    fn blank_replaces_only_client_secret_line() {
        let s = r#"# comment
[credentials]
tenant_id = "t"
client_secret = "abc123"
client_id = "c"
"#;
        let out = blank_client_secret(s);
        assert!(out.contains("client_secret = \"\""));
        assert!(!out.contains("abc123"));
        assert!(out.contains("# comment"));
        assert!(out.contains("tenant_id = \"t\""));
        assert!(out.contains("client_id = \"c\""));
    }

    #[test]
    fn blank_preserves_indentation() {
        let s = "  client_secret = \"x\"\n";
        let out = blank_client_secret(s);
        assert_eq!(out, "  client_secret = \"\"\n");
    }
}
