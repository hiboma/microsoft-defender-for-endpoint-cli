use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentStatus {
    Active,
    Resolved,
    Redirected,
}

impl IncidentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Resolved => "resolved",
            Self::Redirected => "redirected",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" => Some(Self::Active),
            "resolved" => Some(Self::Resolved),
            "redirected" => Some(Self::Redirected),
            _ => None,
        }
    }
}

impl fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_status_from_str() {
        assert_eq!(
            IncidentStatus::from_str_loose("active"),
            Some(IncidentStatus::Active)
        );
        assert_eq!(
            IncidentStatus::from_str_loose("RESOLVED"),
            Some(IncidentStatus::Resolved)
        );
        assert_eq!(IncidentStatus::from_str_loose("unknown"), None);
    }
}
