//! Error handling for the identity service

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Registry error: {0}")]
    Registry(String),
}

/// Helper methods for creating `IdentityError` variants
impl IdentityError {
    pub fn invalid_request(e: impl ToString) -> Self {
        Self::InvalidRequest(e.to_string())
    }

    pub fn unauthorized(e: impl ToString) -> Self {
        Self::Unauthorized(e.to_string())
    }

    pub fn internal(e: impl ToString) -> Self {
        Self::Internal(e.to_string())
    }

    pub fn registry(e: impl ToString) -> Self {
        Self::Registry(e.to_string())
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Mapping from `IdentityError` to HTTP response
impl IntoResponse for IdentityError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::Registry(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

pub type Result<T> = std::result::Result<T, IdentityError>;
