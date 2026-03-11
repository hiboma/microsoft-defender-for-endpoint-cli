use clap::Subcommand;

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Login via browser (Authorization Code Flow with PKCE)
    Login,
    /// Show token for the client_credentials flow (CI use)
    Token,
}
