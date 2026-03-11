use chrono::{DateTime, Utc};

pub fn format_timestamp(iso: Option<&str>) -> String {
    match iso {
        Some(s) => match s.parse::<DateTime<Utc>>() {
            Ok(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            Err(_) => s.to_string(),
        },
        None => "-".to_string(),
    }
}

pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp_iso() {
        let result = format_timestamp(Some("2024-01-15T10:30:00Z"));
        assert_eq!(result, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_format_timestamp_none() {
        assert_eq!(format_timestamp(None), "-");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world!", 8), "hello...");
    }

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate("ab", 2), "ab");
    }
}
