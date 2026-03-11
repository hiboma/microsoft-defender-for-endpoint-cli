use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertStatus {
    New,
    InProgress,
    Resolved,
}

impl AlertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "New",
            Self::InProgress => "InProgress",
            Self::Resolved => "Resolved",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "new" => Some(Self::New),
            "inprogress" | "in-progress" | "in_progress" => Some(Self::InProgress),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "Informational",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "informational" => Some(Self::Informational),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    TruePositive,
    FalsePositive,
    InformationalExpectedActivity,
}

impl Classification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TruePositive => "TruePositive",
            Self::FalsePositive => "FalsePositive",
            Self::InformationalExpectedActivity => "InformationalExpectedActivity",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "truepositive" => Some(Self::TruePositive),
            "falsepositive" => Some(Self::FalsePositive),
            "informationalexpectedactivity" => Some(Self::InformationalExpectedActivity),
            _ => None,
        }
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Determination {
    MultiStagedAttack,
    MaliciousUserActivity,
    CompromisedUser,
    Malware,
    Phishing,
    UnwantedSoftware,
    SecurityTesting,
    LineOfBusinessApplication,
    ConfirmedUserActivity,
    NotMalicious,
    InsufficientData,
    Other,
}

impl Determination {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MultiStagedAttack => "MultiStagedAttack",
            Self::MaliciousUserActivity => "MaliciousUserActivity",
            Self::CompromisedUser => "CompromisedUser",
            Self::Malware => "Malware",
            Self::Phishing => "Phishing",
            Self::UnwantedSoftware => "UnwantedSoftware",
            Self::SecurityTesting => "SecurityTesting",
            Self::LineOfBusinessApplication => "LineOfBusinessApplication",
            Self::ConfirmedUserActivity => "ConfirmedUserActivity",
            Self::NotMalicious => "NotMalicious",
            Self::InsufficientData => "InsufficientData",
            Self::Other => "Other",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "multistagedattack" => Some(Self::MultiStagedAttack),
            "malicioususeractivity" => Some(Self::MaliciousUserActivity),
            "compromiseduser" => Some(Self::CompromisedUser),
            "malware" => Some(Self::Malware),
            "phishing" => Some(Self::Phishing),
            "unwantedsoftware" => Some(Self::UnwantedSoftware),
            "securitytesting" => Some(Self::SecurityTesting),
            "lineofbusinessapplication" => Some(Self::LineOfBusinessApplication),
            "confirmeduseractivity" => Some(Self::ConfirmedUserActivity),
            "notmalicious" | "clean" => Some(Self::NotMalicious),
            "insufficientdata" | "notenoughdatatovalidate" => Some(Self::InsufficientData),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

impl fmt::Display for Determination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_status_from_str() {
        assert_eq!(
            AlertStatus::from_str_loose("InProgress"),
            Some(AlertStatus::InProgress)
        );
        assert_eq!(
            AlertStatus::from_str_loose("in-progress"),
            Some(AlertStatus::InProgress)
        );
        assert_eq!(AlertStatus::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str_loose("high"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_classification_from_str() {
        assert_eq!(
            Classification::from_str_loose("true-positive"),
            Some(Classification::TruePositive)
        );
        assert_eq!(
            Classification::from_str_loose("FalsePositive"),
            Some(Classification::FalsePositive)
        );
    }

    #[test]
    fn test_determination_from_str() {
        assert_eq!(
            Determination::from_str_loose("malware"),
            Some(Determination::Malware)
        );
        assert_eq!(
            Determination::from_str_loose("multi-staged-attack"),
            Some(Determination::MultiStagedAttack)
        );
        assert_eq!(
            Determination::from_str_loose("not-malicious"),
            Some(Determination::NotMalicious)
        );
    }
}
