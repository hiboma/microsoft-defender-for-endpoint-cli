use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum AlertsCommand {
    /// List alerts
    List(ListArgs),
    /// Get a single alert by ID
    Get(GetArgs),
    /// Update an alert
    Update(UpdateArgs),
    /// List files related to an alert
    Files(EntityArgs),
    /// List IPs related to an alert
    Ips(EntityArgs),
    /// List domains related to an alert
    Domains(EntityArgs),
}

#[derive(Args)]
pub struct EntityArgs {
    /// Alert ID
    pub id: String,
}

#[derive(Args)]
pub struct ListArgs {
    /// Maximum number of results
    #[arg(long, default_value = "50")]
    pub top: u32,

    /// Filter by status: New, InProgress, Resolved
    #[arg(long)]
    pub status: Option<String>,

    /// Filter by severity: Informational, Low, Medium, High
    #[arg(long)]
    pub severity: Option<String>,

    /// Raw OData $filter expression
    #[arg(long)]
    pub filter: Option<String>,

    /// Expand evidence in response
    #[arg(long)]
    pub expand_evidence: bool,
}

#[derive(Args)]
pub struct GetArgs {
    /// Alert ID
    pub id: String,

    /// Expand evidence in response
    #[arg(long)]
    pub expand_evidence: bool,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Alert ID
    pub id: String,

    /// Status: New, InProgress, Resolved
    #[arg(long)]
    pub status: Option<String>,

    /// Classification: TruePositive, FalsePositive, InformationalExpectedActivity
    #[arg(long)]
    pub classification: Option<String>,

    /// Determination: Malware, Phishing, UnwantedSoftware, etc.
    #[arg(long)]
    pub determination: Option<String>,

    /// Assign to user (email)
    #[arg(long)]
    pub assigned_to: Option<String>,

    /// Comment
    #[arg(long)]
    pub comment: Option<String>,
}
