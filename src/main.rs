use clap::{CommandFactory, Parser};
use std::process;

use mde::auth::oauth2::OAuth2Auth;
use mde::auth::AuthProvider;
use mde::cli::{Cli, Commands};
use mde::client::MdeClient;
use mde::config::{Config, resolve_value};
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

    let tenant_id = resolve_value(
        cli.tenant_id.as_deref(),
        "MDE_TENANT_ID",
        config.auth.tenant_id.as_deref(),
    );

    let client_id = resolve_value(
        cli.client_id.as_deref(),
        "MDE_CLIENT_ID",
        config.auth.client_id.as_deref(),
    );

    let client_secret = resolve_value(
        cli.client_secret.as_deref(),
        "MDE_CLIENT_SECRET",
        config.auth.client_secret.as_deref(),
    );

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
        // If access_token is provided directly, use it
        if let Some(ref token) = cli.access_token {
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
                "client_secret not set. Use --client-secret, MDE_CLIENT_SECRET, or --access-token."
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

/// Simple static token auth for --access-token usage.
struct StaticTokenAuth(String);

impl AuthProvider for StaticTokenAuth {
    fn token(&self) -> Result<String, AppError> {
        Ok(self.0.clone())
    }
}
