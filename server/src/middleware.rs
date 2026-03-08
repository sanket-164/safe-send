use std::sync::Arc;

use axum::{Extension, extract::Request, http::header, middleware::Next, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    db::UserExt,
    error::{ErrorMessage, HttpError},
    models::User,
    utils::token,
};

/// This struct will be inserted into request extensions
/// after successful authentication.
///
/// Any handler downstream can extract this from the request
/// to get the currently authenticated user.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddleware {
    pub user: User,
}

/// Authentication middleware.
///
/// Responsibilities:
/// 1. Extract JWT from either:
///    - Cookie ("token")
///    - Authorization header ("Bearer <token>")
/// 2. Validate and decode the JWT.
/// 3. Fetch the user from database using `sub` (user_id).
/// 4. Attach the authenticated user to request extensions.
/// 5. Forward the request to the next middleware/handler.
///
/// If any step fails, it returns `401 Unauthorized`.
pub async fn auth(
    cookie_jar: CookieJar,
    Extension(app_state): Extension<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, HttpError> {
    // Try to get token from cookie first
    let cookies = cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            // If cookie not found, try Authorization header
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    // Expect format: "Bearer <token>"
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned()) // strip "Bearer "
                    } else {
                        None
                    }
                })
        });

    // If no token found in either location → return 401
    let token = cookies
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::TokenNotProvided.to_string()))?;

    // Decode token using secret stored in environment config.
    // If token is invalid, expired, or tampered → return 401.
    let token_details = match token::decode_token(token, app_state.env.jwt_secret.as_bytes()) {
        Ok(token_details) => token_details,
        Err(_) => {
            return Err(HttpError::unauthorized(
                ErrorMessage::InvalidToken.to_string(),
            ));
        }
    };

    // The `sub` field in JWT contains the user_id.
    // Convert it to UUID.
    let user_id = uuid::Uuid::parse_str(&token_details)
        .map_err(|_| HttpError::unauthorized(ErrorMessage::InvalidToken.to_string()))?;

    let user = app_state
        .db_client
        .get_user(Some(user_id), None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // If user does not exist anymore (e.g., deleted account),
    // authentication must fail.
    let user =
        user.ok_or_else(|| HttpError::unauthorized(ErrorMessage::UserNoLongerExist.to_string()))?;

    // Insert user into request extensions so downstream handlers
    // can access it using:
    // `Extension<JWTAuthMiddleware>`
    req.extensions_mut()
        .insert(JWTAuthMiddleware { user: user.clone() });

    // Pass request to next middleware or route handler.
    Ok(next.run(req).await)
}
