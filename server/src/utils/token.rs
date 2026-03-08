use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::error::{ErrorMessage, HttpError};

/// JWT Claims structure.
///
/// This represents the payload stored inside the JWT.
///
/// Fields:
/// - sub → Subject (user identifier)
/// - iat → Issued At (timestamp when token was created)
/// - exp → Expiration timestamp
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

/// Create a signed JWT token.
///
/// Parameters:
/// - user_id → Identifier to embed inside token (usually UUID string)
/// - secret → HMAC secret key (must be kept private)
/// - expires_in_seconds → Token lifetime
///
/// Returns:
/// - Ok(String) → Signed JWT
/// - Err(...) → JWT encoding error
pub fn create_token(
    user_id: &str,
    secret: &[u8],
    expires_in_seconds: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    if user_id.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidSubject.into());
    }

    let now = Utc::now();

    let iat = now.timestamp() as usize;

    let exp = (now + Duration::minutes(expires_in_seconds)).timestamp() as usize;

    let claims = TokenClaims {
        sub: user_id.to_string(),
        iat,
        exp,
    };

    encode(
        &Header::default(), // Default header (HS256)
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Decode and validate JWT token.
///
/// Returns:
/// - Ok(user_id) → Token valid
/// - Err(HttpError::unauthorized) → Invalid or expired token
pub fn decode_token<T: Into<String>>(token: T, secret: &[u8]) -> Result<String, HttpError> {
    let decode = decode::<TokenClaims>(
        &token.into(),
        &DecodingKey::from_secret(secret),
        &Validation::new(jsonwebtoken::Algorithm::HS256),
    );

    match decode {
        // Token is valid
        Ok(token) => Ok(token.claims.sub),

        // Any error (expired, invalid signature, malformed)
        // is mapped to a generic Unauthorized error.
        Err(_err) => Err(HttpError::unauthorized(
            ErrorMessage::InvalidToken.to_string(),
        )),
    }
}
