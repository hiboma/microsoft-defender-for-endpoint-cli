use reqwest::Response;

use crate::error::AppError;

/// Check the HTTP response status and convert errors.
pub async fn check_response(response: Response) -> Result<Response, AppError> {
    let status = response.status();

    if status.is_success() {
        return Ok(response);
    }

    let status_code = status.as_u16();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "failed to read response body".to_string());

    match status_code {
        401 => Err(AppError::Auth(
            "authentication failed. Verify your credentials.".to_string(),
        )),
        429 => Err(AppError::RateLimited),
        400..=499 => Err(AppError::Api {
            status: status_code,
            message: body,
        }),
        500..=599 => Err(AppError::Api {
            status: status_code,
            message: body,
        }),
        _ => Err(AppError::Api {
            status: status_code,
            message: body,
        }),
    }
}
