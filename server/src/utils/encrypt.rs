use crate::error::HttpError;
use aes::Aes256;
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};
use rand::Rng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

/// Encrypts a file using Hybrid Encryption:
///
/// Why Hybrid?
/// - RSA is slow and cannot encrypt large data.
/// - AES is fast and suitable for large file encryption.
///
/// Flow:
/// 1. Generate random AES-256 key.
/// 2. Generate random IV (Initialization Vector).
/// 3. Encrypt file using AES-256-CBC.
/// 4. Encrypt AES key using user's RSA public key.
/// 5. Return:
///     - Encrypted AES key (RSA encrypted)
///     - Encrypted file data (AES encrypted)
///     - IV (needed for decryption)
///
/// The private RSA key will later be used to:
///     - Decrypt AES key
///     - Use decrypted AES key + IV to decrypt file
pub async fn encrypt_file(
    file_data: Vec<u8>,
    user_public_key: &RsaPublicKey,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), HttpError> {
    // AES-256 requires a 256-bit (32-byte) key.
    let mut aes_key = [0u8; 32];

    // CBC mode requires a 16-byte IV.
    // IV does NOT need to be secret but must be unpredictable.
    let mut iv = [0u8; 16];

    // Fill AES key and IV with cryptographically secure randomness
    rand::thread_rng().fill(&mut aes_key);
    rand::thread_rng().fill(&mut iv);

    // PKCS7 padding ensures data length becomes multiple of 16 bytes.
    let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(&aes_key, &iv)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Clone file_data because encrypt_vec consumes mutable buffer.
    let mut buffer = file_data.clone();

    // Perform AES encryption
    let encrypted_data = cipher.encrypt_vec(&mut buffer);

    // This ensures only the holder of the RSA private key
    // can decrypt the AES key and therefore the file.
    let encrypted_aes_key = user_public_key
        .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &aes_key)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Return everything needed for decryption
    Ok((encrypted_aes_key, encrypted_data, iv.to_vec()))
}
