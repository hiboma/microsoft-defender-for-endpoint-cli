use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum HuntingCommand {
    /// Run an advanced hunting KQL query
    Run(RunArgs),
}

#[derive(Args)]
pub struct RunArgs {
    /// KQL query string
    #[arg(long)]
    pub query: String,
}
