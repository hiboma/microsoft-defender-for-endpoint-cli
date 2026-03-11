use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum IncidentsCommand {
    /// List incidents
    List(ListArgs),
    /// Get a single incident by ID
    Get(GetArgs),
    /// Update an incident
    Update(UpdateArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Maximum number of results
    #[arg(long, default_value = "50")]
    pub top: u32,

    /// Filter by status: active, resolved, redirected
    #[arg(long)]
    pub status: Option<String>,

    /// Filter by severity: informational, low, medium, high
    #[arg(long)]
    pub severity: Option<String>,

    /// Raw OData $filter expression
    #[arg(long)]
    pub filter: Option<String>,

    /// Expand alerts in response
    #[arg(long)]
    pub expand_alerts: bool,
}

#[derive(Args)]
pub struct GetArgs {
    /// Incident ID
    pub id: String,

    /// Expand alerts in response
    #[arg(long)]
    pub expand_alerts: bool,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Incident ID
    pub id: String,

    /// Status: active, resolved
    #[arg(long)]
    pub status: Option<String>,

    /// Classification: truePositive, falsePositive, informationalExpectedActivity
    #[arg(long)]
    pub classification: Option<String>,

    /// Determination: malware, phishing, multiStagedAttack, etc.
    #[arg(long)]
    pub determination: Option<String>,

    /// Assign to user
    #[arg(long)]
    pub assigned_to: Option<String>,

    /// Custom tags
    #[arg(long)]
    pub tag: Vec<String>,

    /// Resolving comment
    #[arg(long)]
    pub comment: Option<String>,
}
