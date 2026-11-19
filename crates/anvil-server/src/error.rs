//! Uniform JSON error responses and typed API JSON extractor.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::db::DbError;

/// Response extension marker indicating the middleware should populate `error.request_id`.
#[derive(Debug, Clone, Copy)]
pub struct ApiErrorMarker;

/// Standard error body returned by all failing endpoints.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_item: Option<serde_json::Value>,
}

/// Machine-readable error details included inside `ErrorEnvelope`.
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: &'static str,
    pub message: String,
    pub request_id: String,
}

/// Application error type mapped cleanly to HTTP status codes without leaking internal details.
#[derive(Debug)]
pub enum ApiError {
    BadRequest {
        code: &'static str,
        message: String,
    },
    Unauthorized {
        code: &'static str,
        message: String,
    },
    Forbidden {
        code: &'static str,
        message: String,
    },
    NotFound {
        code: &'static str,
        message: String,
    },
    Conflict {
        code: &'static str,
        message: String,
    },
    SyncConflict {
        message: String,
        sync: serde_json::Value,
    },
    ItemConflict {
        message: String,
        current_item: serde_json::Value,
    },
    PayloadTooLarge {
        code: &'static str,
        message: String,
    },
    BadGateway {
        code: &'static str,
        message: String,
    },
    ServiceUnavailable {
        code: &'static str,
        message: String,
    },
    Internal(anyhow::Error),
}

impl ApiError {
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            message: message.into(),
        }
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::Unauthorized {
            code,
            message: message.into(),
        }
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::Forbidden {
            code,
            message: message.into(),
        }
    }

    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::NotFound {
            code,
            message: message.into(),
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            message: message.into(),
        }
    }

    pub fn payload_too_large(code: &'static str, message: impl Into<String>) -> Self {
        Self::PayloadTooLarge {
            code,
            message: message.into(),
        }
    }

    pub fn bad_gateway(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadGateway {
            code,
            message: message.into(),
        }
    }

    pub fn service_unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            code,
            message: message.into(),
        }
    }

    /// Wraps an unexpected internal failure cleanly without exposing internals to HTTP clients.
    pub fn internal(err: impl Into<anyhow::Error>) -> Self {
        Self::Internal(err.into())
    }
}

impl From<DbError> for ApiError {
    fn from(err: DbError) -> Self {
        Self::Internal(err.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, envelope) = match self {
            Self::BadRequest { code, message } => (
                StatusCode::BAD_REQUEST,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::Unauthorized { code, message } => (
                StatusCode::UNAUTHORIZED,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::Forbidden { code, message } => (
                StatusCode::FORBIDDEN,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::NotFound { code, message } => (
                StatusCode::NOT_FOUND,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::Conflict { code, message } => (
                StatusCode::CONFLICT,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::SyncConflict { message, sync } => (
                StatusCode::CONFLICT,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code: "SYNC_REVISION_CONFLICT",
                        message,
                        request_id: String::new(),
                    },
                    sync: Some(sync),
                    current_item: None,
                },
            ),
            Self::ItemConflict {
                message,
                current_item,
            } => (
                StatusCode::CONFLICT,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code: "ITEM_REVISION_CONFLICT",
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: Some(current_item),
                },
            ),
            Self::PayloadTooLarge { code, message } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::BadGateway { code, message } => (
                StatusCode::BAD_GATEWAY,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::ServiceUnavailable { code, message } => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorEnvelope {
                    error: ErrorDetail {
                        code,
                        message,
                        request_id: String::new(),
                    },
                    sync: None,
                    current_item: None,
                },
            ),
            Self::Internal(err) => {
                tracing::error!(error = ?err, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorEnvelope {
                        error: ErrorDetail {
                            code: "INTERNAL_ERROR",
                            message: "Internal server error".to_owned(),
                            request_id: String::new(),
                        },
                        sync: None,
                        current_item: None,
                    },
                )
            }
        };

        let mut response = (status, Json(envelope)).into_response();
        response.extensions_mut().insert(ApiErrorMarker);
        response
    }
}

/// JSON body extractor mapping deserialization failures to the uniform `ApiError` envelope.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(JsonRejection::BytesRejection(_)) => Err(ApiError::bad_request(
                "INVALID_REQUEST_BODY",
                "Unable to read JSON request body",
            )),
            Err(err) => Err(ApiError::bad_request("INVALID_JSON", err.body_text())),
        }
    }
}
