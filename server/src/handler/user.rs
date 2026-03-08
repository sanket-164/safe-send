use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, put},
};
use validator::Validate;

use crate::{
    AppState,
    db::UserExt,
    dtos::{
        EmailListResponseDto, FilterEmailDto, FilterUserDto, NameUpdateDto, Response,
        SearchQueryByEmailDTO, UserData, UserPasswordUpdateDto, UserResponseDto,
    },
    error::{ErrorMessage, HttpError},
    middleware::JWTAuthMiddleware,
    utils::password,
};

pub fn user_handler() -> Router {
    Router::new()
        .route("/me", get(get_me))
        .route("/name", put(update_user_name))
        .route("/password", put(update_user_password))
        .route("/search-emails", get(search_by_email))
}

pub async fn get_me(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    let filtered_user = FilterUserDto::filter_user(&user.user);

    let response = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(Json(response))
}

pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<NameUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;
    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .update_user_name(user_id.clone(), &body.name)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(Json(response))
}

pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<UserPasswordUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let password_match = password::compare(&body.old_password, &user.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if !password_match {
        return Err(HttpError::server_error(
            ErrorMessage::WrongCredentials.to_string(),
        ));
    }

    let hashed_password =
        password::hash(&body.new_password).map_err(|e| HttpError::server_error(e.to_string()))?;

    let _result = app_state
        .db_client
        .update_user_password(user_id, hashed_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "Password updated successfully".to_string(),
        status: "success",
    };

    Ok(Json(response))
}

pub async fn search_by_email(
    Query(params): Query<SearchQueryByEmailDTO>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    params
        .validate()
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let query_pattern = format!("%{}%", params.query);
    let user_id = uuid::Uuid::parse_str(&user.user.id.to_string()).unwrap();

    let users = app_state
        .db_client
        .search_by_email(user_id.clone(), query_pattern.clone())
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_email = FilterEmailDto::filter_emails(&users);

    let response_data = EmailListResponseDto {
        status: "success".to_string(),
        emails: filtered_email,
    };

    Ok(Json(response_data))
}
