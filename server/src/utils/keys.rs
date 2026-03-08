use std::{
    fs::{self, File},
    io::Write,
    sync::Arc,
};

use axum::{http::StatusCode, response::IntoResponse};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
};

use crate::{AppState, db::UserExt, error::HttpError, models::User};

/// Generate RSA key pair for a user.
///
/// Flow:
/// 1️⃣ Generate 2048-bit RSA private key
/// 2️⃣ Derive public key
/// 3️⃣ Convert both to PEM format
/// 4️⃣ Store PUBLIC key in database
/// 5️⃣ Store PRIVATE key securely on server filesystem
///
/// Returns:
/// - HTTP 200 if successful
/// - HttpError if any step fails
pub async fn generate_key(
    app_state: Arc<AppState>,
    user: User,
) -> Result<impl IntoResponse, HttpError> {
    let mut rng = OsRng;

    // 2048 bits is currently considered secure for most applications.
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| HttpError::server_error(e.to_string()))?;

    let public_key = RsaPublicKey::from(&private_key);

    // Convert keys to PEM format
    let private_key_pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let public_key_pem = public_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let public_key_b64 = STANDARD.encode(public_key_pem.as_bytes());

    let user_id = user.id;

    app_state
        .db_client
        .save_user_key(user_id, public_key_b64.clone())
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Directory where private keys are stored.
    // ⚠️ In production:
    // - Use restricted permissions (chmod 600)
    // - Consider using encrypted storage
    // - Consider HSM / KMS instead of filesystem
    let private_keys_dir = "assets/private_keys";

    fs::create_dir_all(&private_keys_dir).map_err(|e| HttpError::server_error(e.to_string()))?;

    let pem_file_path = format!("{}/{}.pem", private_keys_dir, user_id);

    let mut file =
        File::create(&pem_file_path).map_err(|e| HttpError::server_error(e.to_string()))?;

    file.write_all(private_key_pem.as_bytes())
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok((StatusCode::OK, "true"))
}
