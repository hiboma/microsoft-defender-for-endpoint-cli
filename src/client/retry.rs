use std::future::Future;
use std::time::Duration;

use crate::error::AppError;

const MAX_RETRIES: u32 = 3;
const BASE_BACKOFF_MS: u64 = 2000;

/// Execute an async closure with retry on transient errors.
pub async fn with_retry<F, Fut>(f: F) -> Result<reqwest::Response, AppError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut last_error = None;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let backoff = Duration::from_millis(BASE_BACKOFF_MS * 2_u64.pow(attempt - 1));
            tokio::time::sleep(backoff).await;
        }

        match f().await {
            Ok(response) => {
                let status = response.status().as_u16();
                if (status == 429 || (500..=599).contains(&status)) && attempt < MAX_RETRIES {
                    last_error = Some(AppError::Api {
                        status,
                        message: format!("retrying after status {}", status),
                    });
                    continue;
                }
                return Ok(response);
            }
            Err(e) => {
                if attempt < MAX_RETRIES {
                    last_error = Some(AppError::Network(e.to_string()));
                    continue;
                }
                return Err(AppError::Http(e));
            }
        }
    }

    Err(last_error.unwrap_or(AppError::Network("max retries exceeded".to_string())))
}
