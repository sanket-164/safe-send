use aes::Aes256;
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::error::HttpError;

/// Decrypts a file encrypted using Hybrid Encryption (RSA + AES).
///
/// Parameters:
/// - encrypted_aes_key: AES key encrypted with RSA public key
/// - encrypted_file_data: File encrypted with AES-256-CBC
/// - iv: Initialization Vector used during AES encryption
/// - user_private_key: RSA private key corresponding to public key used during encryption
///
/// Returns:
/// - Original decrypted file bytes on success
pub async fn decrypt_file(
    encrypted_aes_key: Vec<u8>,
    encrypted_file_data: Vec<u8>,
    iv: Vec<u8>,
    user_private_key: &RsaPrivateKey,
) -> Result<Vec<u8>, HttpError> {
    // If this fails, the encrypted AES key was:
    // - corrupted
    // - encrypted with a different public key
    // - tampered
    let aes_key = user_private_key
        .decrypt(Pkcs1v15Encrypt, &encrypted_aes_key)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // AES-256 requires:
    // - 32-byte key
    // - 16-byte IV
    //
    // new_from_slices() validates key + IV length.
    // If incorrect size → error returned.
    let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(&aes_key, &iv)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Decrypt the file data
    let mut buffer = encrypted_file_data.clone();

    let decrypted_data = cipher
        .decrypt_vec(&mut buffer)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(decrypted_data)
}
