use core::fmt;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// Standard JSON structure returned for API errors.
///
/// This ensures a consistent error format across the entire API.
///
/// Example JSON response:
/// {
///     "status": "fail",
///     "message": "Email or password is wrong"
/// }
///
/// `status` is intentionally a string instead of HTTP status code
/// to follow common REST API response patterns.
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

/// Allows ErrorResponse to be printed as JSON string.
/// Useful for logging purposes.
impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

/// Enum representing domain-level error cases.
///
/// These errors are independent of HTTP.
/// They represent logical/business failures inside the application.
#[derive(Debug, PartialEq)]
pub enum ErrorMessage {
    EmptyPassword,
    ExceededMaxPasswordLength(usize),
    InvalidHashFormat,
    HashingError,
    InvalidToken,
    WrongCredentials,
    EmailExist,
    UserNoLongerExist,
    TokenNotProvided,
}

/// Converts domain error into user-facing message string.
impl ToString for ErrorMessage {
    fn to_string(&self) -> String {
        self.to_str().to_owned()
    }
}

impl ErrorMessage {
    /// Maps each error variant to a human-readable message.
    /// This prevents hardcoding messages throughout the codebase.
    fn to_str(&self) -> String {
        match self {
            ErrorMessage::WrongCredentials => "Email or password is wrong".to_string(),

            ErrorMessage::EmailExist => "A user with this email already exists".to_string(),

            ErrorMessage::UserNoLongerExist => {
                "User belonging to this token no longer exists".to_string()
            }

            ErrorMessage::EmptyPassword => "Password cannot be empty".to_string(),

            ErrorMessage::HashingError => "Error while hashing password".to_string(),

            ErrorMessage::InvalidHashFormat => "Invalid password hash format".to_string(),

            ErrorMessage::ExceededMaxPasswordLength(max_length) => {
                format!("Password must not be more than {} characters", max_length)
            }

            ErrorMessage::InvalidToken => "Authentication token is invalid or expired".to_string(),

            ErrorMessage::TokenNotProvided => {
                "You are not logged in, please provide a token".to_string()
            }
        }
    }
}

/// HTTP-specific error wrapper.
///
/// This struct bridges:
/// - Domain errors
/// - HTTP status codes
///
/// It is what gets returned from Axum handlers.
#[derive(Debug, Clone)]
pub struct HttpError {
    pub message: String,
    pub status: StatusCode,
}

impl HttpError {
    /// Generic constructor for custom status.
    pub fn _new(message: impl Into<String>, status: StatusCode) -> Self {
        HttpError {
            message: message.into(),
            status,
        }
    }

    /// 500 Internal Server Error.
    /// Used for unexpected failures.
    pub fn server_error(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 400 Bad Request.
    /// Used for validation failures.
    pub fn bad_request(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    /// 409 Conflict.
    /// Typically used for unique constraint violations
    /// (e.g., email already exists).
    pub fn unique_constraint_violation(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::CONFLICT,
        }
    }

    /// 401 Unauthorized.
    /// Used for authentication failures.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    /// Converts HttpError into Axum Response.
    /// This ensures all error responses follow the same JSON format.
    pub fn into_http_response(self) -> Response {
        let json_response = Json(ErrorResponse {
            status: "fail".to_string(),
            message: self.message.clone(),
        });

        (self.status, json_response).into_response()
    }
}

/// Display implementation for logging purposes.
impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HttpError: message: {}, status: {}",
            self.message, self.status
        )
    }
}

/// Allows HttpError to behave like a standard Rust error.
impl std::error::Error for HttpError {}

/// This is the key integration with Axum.
///
/// By implementing IntoResponse,
/// we can directly return `Result<T, HttpError>` from handlers.
///
/// Example:
/// async fn handler() -> Result<Json<User>, HttpError>
///
/// Axum will automatically convert HttpError into a proper HTTP response.
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        self.into_http_response()
    }
}
