pub mod auth;
pub mod file;
pub mod file_query;
pub mod user;

use axum::response::IntoResponse;

pub async fn health_check() -> impl IntoResponse {
    "Server is running 🚀"
}
