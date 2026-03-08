use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::error::ErrorMessage;

const MAX_PASSWORD_LENGTH: usize = 64;

/// Hash a plain-text password using Argon2.
///
/// Security model:
/// - Argon2 is a memory-hard password hashing algorithm.
/// - A unique random salt is generated for every password.
/// - The output string contains:
///     - algorithm
///     - parameters
///     - salt
///     - hash
///
/// Returns:
/// - Ok(String) → Encoded Argon2 hash (ready for DB storage)
/// - Err(ErrorMessage) → Validation or hashing failure
pub fn hash(password: impl Into<String>) -> Result<String, ErrorMessage> {
    let password = password.into();

    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    // OsRng uses the operating system’s secure random source.
    let salt = SaltString::generate(&mut OsRng);

    let hash_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ErrorMessage::HashingError)?
        .to_string();

    Ok(hash_password)
}

/// Compare a plain-text password against a stored Argon2 hash.
///
/// Returns:
/// - Ok(true)  → Password matches
/// - Ok(false) → Password does not match
/// - Err(ErrorMessage) → Validation or parsing failure
///
/// Flow:
/// 1. Validate input password
/// 2. Parse stored hash string
/// 3. Verify password using Argon2
pub fn compare(password: &str, hashed_password: &str) -> Result<bool, ErrorMessage> {
    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    // This extracts:
    // - algorithm
    // - parameters
    // - salt
    // - hash value
    let parsed_hash =
        PasswordHash::new(hashed_password).map_err(|_| ErrorMessage::InvalidHashFormat)?;

    let password_matched = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    Ok(password_matched)
}
