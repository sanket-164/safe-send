use crate::{
    AppState,
    db::UserExt,
    dtos::{LoginUserDto, RegisterUserDto, Response, UserLoginResponseDto},
    error::{ErrorMessage, HttpError},
    utils::{keys::generate_key, password, token},
};
use axum::{
    Extension, Json, Router,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use axum_extra::extract::cookie::Cookie;
use std::sync::Arc;
use validator::Validate;

pub fn auth_handler() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
}

/// ------------------------------------------------------------
/// REGISTER USER
/// ------------------------------------------------------------
/// Flow:
/// 1. Validate incoming DTO
/// 2. Hash password securely (Argon2)
/// 3. Save user in database
/// 4. Generate RSA key pair for user
/// 5. Return success response
pub async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    // Prevents invalid email formats, empty fields, etc.
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    // This prevents storing plaintext passwords in DB.
    let hash_password =
        password::hash(&body.password).map_err(|e| HttpError::server_error(e.to_string()))?;

    // save_user() should return inserted user row.
    let result = app_state
        .db_client
        .save_user(&body.name, &body.email, &hash_password)
        .await;

    match result {
        Ok(user) => {
            // - Public key stored in DB
            // - Private key stored securely in server assets directory
            //
            // This enables encrypted file sharing feature.
            let _key_result = generate_key(app_state, user).await?;

            Ok((
                StatusCode::CREATED,
                Json(Response {
                    message: "Registrations successful!".to_string(),
                    status: "success",
                }),
            ))
        }

        // Handle database unique constraint violation (duplicate email)
        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                Err(HttpError::unique_constraint_violation(
                    ErrorMessage::EmailExist.to_string(),
                ))
            } else {
                Err(HttpError::server_error(db_err.to_string()))
            }
        }

        // Any other unexpected DB error
        Err(e) => Err(HttpError::server_error(e.to_string())),
    }
}

/// ------------------------------------------------------------
/// LOGIN USER
/// ------------------------------------------------------------
/// Flow:
/// 1. Validate login DTO
/// 2. Fetch user by email
/// 3. Compare hashed password
/// 4. Generate JWT token
/// 5. Set HTTP-only cookie
/// 6. Return token in response body
pub async fn login(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<LoginUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    // Validate login input
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    // Fetch user by email
    let result = app_state
        .db_client
        .get_user(None, None, Some(&body.email))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // If user not found → return generic wrong credentials error
    // (Avoid revealing whether email exists)
    let user = result.ok_or(HttpError::bad_request(
        ErrorMessage::WrongCredentials.to_string(),
    ))?;

    // Compare provided password with stored hash
    let password_matched = password::compare(&body.password, &user.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if password_matched {
        // Generate JWT token
        let token = token::create_token(
            &user.id.to_string(),
            &app_state.env.jwt_secret.as_bytes(),
            app_state.env.jwt_maxage,
        )
        .map_err(|e| HttpError::server_error(e.to_string()))?;

        // Build secure HTTP-only cookie
        // http_only(true) prevents JavaScript access (XSS mitigation)
        // max_age controls expiration
        let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);

        let cookie = Cookie::build(("token", token.clone()))
            .path("/")
            .max_age(cookie_duration)
            .http_only(true)
            .build();

        // Return token in response body as well
        let response = Json(UserLoginResponseDto {
            status: "success".to_string(),
            token,
        });

        let mut headers = HeaderMap::new();

        headers.append(header::SET_COOKIE, cookie.to_string().parse().unwrap());

        let mut response = response.into_response();
        response.headers_mut().extend(headers);

        Ok(response)
    } else {
        // Password mismatch
        Err(HttpError::bad_request(
            ErrorMessage::WrongCredentials.to_string(),
        ))
    }
}
