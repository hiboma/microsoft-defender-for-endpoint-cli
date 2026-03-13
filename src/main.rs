use clap::{CommandFactory, Parser};
use std::process;

use mde::auth::oauth2::OAuth2Auth;
use mde::auth::AuthProvider;
use mde::cli::{Cli, Commands};
use mde::client::MdeClient;
use mde::config::Config;
use mde::error::AppError;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("Error: {}", e);
        process::exit(e.exit_code());
    }
}

async fn run(cli: Cli) -> Result<(), AppError> {
    let command = match cli.command {
        Some(command) => command,
        None => {
            Cli::command().print_help().ok();
            return Ok(());
        }
    };

    let config = Config::load().unwrap_or_default();

    let tenant_id = cli
        .tenant_id
        .as_deref()
        .map(String::from)
        .or_else(|| std::env::var("MDE_TENANT_ID").ok())
        .or_else(|| config.auth.tenant_id.clone());

    let client_id = cli
        .client_id
        .as_deref()
        .map(String::from)
        .or_else(|| std::env::var("MDE_CLIENT_ID").ok())
        .or_else(|| config.auth.client_id.clone());

    let client_secret = std::env::var("MDE_CLIENT_SECRET")
        .ok()
        .or_else(|| config.auth.client_secret.clone());

    let access_token = std::env::var("MDE_ACCESS_TOKEN").ok();

    // Auth commands only need tenant_id and client_id
    if let Commands::Auth {
        command: Some(ref auth_cmd),
    } = command
    {
        let tid = tenant_id.as_deref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
        })?;
        let cid = client_id.as_deref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
        })?;
        return mde::commands::auth::handle(auth_cmd, tid, cid, client_secret.as_deref()).await;
    }

    // For API commands, build client with appropriate auth
    let build_mde_client = |base_url: &str, scope: &str| -> Result<MdeClient, AppError> {
        // If access_token is provided via MDE_ACCESS_TOKEN env var, use it
        if let Some(ref token) = access_token {
            let auth = StaticTokenAuth(token.clone());
            return MdeClient::new(base_url.to_string(), Box::new(auth));
        }

        let tid = tenant_id.as_ref().ok_or_else(|| {
            AppError::Config("tenant_id not set. Use --tenant-id or MDE_TENANT_ID.".to_string())
        })?;
        let cid = client_id.as_ref().ok_or_else(|| {
            AppError::Config("client_id not set. Use --client-id or MDE_CLIENT_ID.".to_string())
        })?;
        let cs = client_secret.as_ref().ok_or_else(|| {
            AppError::Config(
                "client_secret not set. Set MDE_CLIENT_SECRET env var or config.toml [auth].client_secret."
                    .to_string(),
            )
        })?;

        let auth = OAuth2Auth::new(tid.clone(), cid.clone(), cs.clone(), scope.to_string())?;
        MdeClient::new(base_url.to_string(), Box::new(auth))
    };

    match &command {
        Commands::Alerts {
            command: Some(cmd),
        } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            mde::commands::alerts::handle(&client, cmd, cli.output, cli.raw).await
        }
        Commands::Incidents {
            command: Some(cmd),
        } => {
            let client = build_mde_client(
                "https://graph.microsoft.com",
                "https://graph.microsoft.com/.default",
            )?;
            mde::commands::incidents::handle(&client, cmd, cli.output, cli.raw).await
        }
        Commands::Hunting {
            command: Some(cmd),
        } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            mde::commands::hunting::handle(&client, cmd, cli.output).await
        }
        Commands::Machines {
            command: Some(cmd),
        } => {
            let client = build_mde_client(
                "https://api.security.microsoft.com",
                "https://api.securitycenter.microsoft.com/.default",
            )?;
            mde::commands::machines::handle(&client, cmd, cli.output, cli.raw).await
        }
        _ => {
            Cli::command()
                .find_subcommand(command.name())
                .expect("subcommand must exist")
                .clone()
                .print_help()
                .ok();
            Ok(())
        }
    }
}

/// Simple static token auth for MDE_ACCESS_TOKEN env var usage.
struct StaticTokenAuth(String);

impl AuthProvider for StaticTokenAuth {
    fn token(&self) -> Result<String, AppError> {
        Ok(self.0.clone())
    }
}
