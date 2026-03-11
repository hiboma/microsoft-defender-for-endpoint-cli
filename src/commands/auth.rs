use crate::auth::browser;
use crate::auth::clipboard;
use crate::cli::auth::AuthCommand;
use crate::error::AppError;

const MDE_SCOPE: &str = "https://api.securitycenter.microsoft.com/.default offline_access";

pub async fn handle(
    command: &AuthCommand,
    tenant_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<(), AppError> {
    match command {
        AuthCommand::Login => login(tenant_id, client_id).await,
        AuthCommand::Token => token(tenant_id, client_id, client_secret).await,
    }
}

async fn login(tenant_id: &str, client_id: &str) -> Result<(), AppError> {
    let (token, expires_in) = browser::browser_login(tenant_id, client_id, MDE_SCOPE).await?;

    if clipboard::is_tty() {
        clipboard::copy_and_verify(&token, expires_in)?;
    } else {
        clipboard::print_token(&token);
    }

    Ok(())
}

async fn token(
    tenant_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<(), AppError> {
    let secret = client_secret.ok_or_else(|| {
        AppError::Auth(
            "client_secret is required for token command. Set MDE_CLIENT_SECRET.".to_string(),
        )
    })?;

    let auth = crate::auth::oauth2::OAuth2Auth::new(
        tenant_id.to_string(),
        client_id.to_string(),
        secret.to_string(),
        "https://api.securitycenter.microsoft.com/.default".to_string(),
    )?;

    let token = auth.fetch_token().await?;

    if clipboard::is_tty() {
        eprintln!("Token acquired via client_credentials flow.");
        clipboard::print_token(&token);
    } else {
        clipboard::print_token(&token);
    }

    Ok(())
}
