pub mod browser;
pub mod clipboard;
pub mod oauth2;

use crate::error::AppError;

pub trait AuthProvider: Send + Sync {
    fn token(&self) -> Result<String, AppError>;
}
