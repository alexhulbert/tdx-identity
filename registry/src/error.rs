//! Error handling utilities for the registry service

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(#[from] sled::Error),
}

/// Helper methods for creating `RegistryError` variants
impl RegistryError {
    pub fn invalid_request(e: impl ToString) -> Self {
        Self::InvalidRequest(e.to_string())
    }

    pub fn unauthorized(e: impl ToString) -> Self {
        Self::Unauthorized(e.to_string())
    }

    pub fn forbidden(e: impl ToString) -> Self {
        Self::Forbidden(e.to_string())
    }

    pub fn internal(e: impl ToString) -> Self {
        Self::Internal(e.to_string())
    }
}

/// Response body for error responses
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Implements conversion from RegistryError to Axum's response type
impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::Database(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

// Type alias for common Result type
pub type Result<T> = std::result::Result<T, RegistryError>;
