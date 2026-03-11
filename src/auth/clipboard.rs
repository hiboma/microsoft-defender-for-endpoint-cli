use crate::error::AppError;

/// Copy token to clipboard and prompt user to verify by pasting.
pub fn copy_and_verify(token: &str, expires_in: u64) -> Result<(), AppError> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| AppError::Auth(format!("failed to access clipboard: {}", e)))?;

    clipboard
        .set_text(token)
        .map_err(|e| AppError::Auth(format!("failed to copy to clipboard: {}", e)))?;

    eprintln!("Token copied to clipboard. (expires in {}s)", expires_in);
    eprint!("Paste it to verify: ");

    let pasted = rpassword::read_password()
        .map_err(|e| AppError::Auth(format!("failed to read input: {}", e)))?;

    let suffix_len = 5;
    if pasted.trim() == token {
        let masked = mask_token(token, suffix_len);
        eprintln!("{}  OK", masked);
    } else if pasted.trim().is_empty() {
        eprintln!("(skipped)");
    } else {
        let masked = mask_token(&pasted, suffix_len);
        eprintln!("{}  MISMATCH", masked);
    }

    Ok(())
}

/// Print token to stdout (for piped usage).
pub fn print_token(token: &str) {
    println!("{}", token);
}

fn mask_token(token: &str, suffix_len: usize) -> String {
    if token.len() <= suffix_len {
        return "****".to_string();
    }
    let suffix = &token[token.len() - suffix_len..];
    format!("****...{}", suffix)
}

/// Detect if stdout is a TTY.
pub fn is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_token_long() {
        let result = mask_token("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1u", 5);
        assert_eq!(result, "****...6Ik1u");
        assert!(!result.contains("eyJ0"));
    }

    #[test]
    fn test_mask_token_short() {
        let result = mask_token("abc", 5);
        assert_eq!(result, "****");
    }

    #[test]
    fn test_mask_token_exact() {
        let result = mask_token("12345", 5);
        assert_eq!(result, "****");
    }
}
