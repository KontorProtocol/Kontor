use axum::{Json, http::StatusCode, response::IntoResponse};
use thiserror::Error as ThisError;
use tracing::{Span, error};

use super::response::ErrorResponse;

#[derive(ThisError, Debug)]
pub enum HttpError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Not found: {0}")]
    BadRequest(String),
}

impl HttpError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            HttpError::NotFound(_) => StatusCode::NOT_FOUND,
            HttpError::BadRequest(_) => StatusCode::BAD_REQUEST,
        }
    }
}

pub struct Error(anyhow::Error);

impl<E> From<E> for Error
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = if self.0.is::<HttpError>() {
            let http_error = self.0.downcast_ref::<HttpError>().unwrap();
            (http_error.status_code(), http_error.to_string())
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string())
        };
        Span::current().record("error", message.clone());
        let error_response = Json(ErrorResponse { error: message });
        (status, error_response).into_response()
    }
}
