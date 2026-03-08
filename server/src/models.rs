use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a registered user in the system.
///
/// This struct maps directly to the `users` table in the database.
/// It stores authentication data and cryptographic identity information.
///
/// Derives:
/// - Deserialize / Serialize → Used for API request/response handling.
/// - sqlx::FromRow → Allows mapping DB rows directly into this struct.
/// - sqlx::Type → Enables usage in SQLx queries where needed.
#[derive(Debug, Clone, Deserialize, Serialize, sqlx::FromRow, sqlx::Type)]
pub struct User {
    pub id: uuid::Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub public_key: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Represents an encrypted file stored in the system.
///
/// This struct maps to the `files` table.
/// Files are stored in encrypted form using hybrid encryption:
/// - File content → Encrypted using AES
/// - AES key → Encrypted using recipient's public key
#[derive(Debug, Clone, Deserialize, Serialize, sqlx::FromRow, sqlx::Type)]
pub struct File {
    pub id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub file_name: String,
    pub file_size: i64,
    pub encrypted_aes_key: Vec<u8>,
    pub encrypted_file: Vec<u8>,
    pub iv: Vec<u8>, // Initialization Vector used in AES encryption.
    pub created_at: Option<DateTime<Utc>>,
}

/// Represents a file sharing link.
///
/// This struct maps to the `share_links` table.
/// It allows one user to share an encrypted file with another user,
/// optionally protected by password and expiration.
#[derive(Debug, Clone, Deserialize, Serialize, sqlx::FromRow, sqlx::Type)]
pub struct SharedLink {
    pub id: uuid::Uuid,
    pub file_id: Option<uuid::Uuid>,
    pub recipient_user_id: Option<uuid::Uuid>,
    pub password: String,
    pub expiration_date: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

/// Represents a view model for files SENT by a user.
///
/// This struct is used for JOIN queries.
/// It does not map to a direct table.
/// Instead, it combines file and recipient data.
#[derive(sqlx::FromRow)]
pub struct SentFileDetails {
    pub file_id: uuid::Uuid,
    pub file_name: String,
    pub recipient_email: String,
    pub expiration_date: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

/// Represents a view model for files RECEIVED by a user.
///
/// Used for JOIN queries between:
/// - files
/// - share_links
/// - users (sender)
///
/// This is not a direct table mapping.
#[derive(sqlx::FromRow)]
pub struct ReceiveFileDetails {
    pub file_id: uuid::Uuid,
    pub file_name: String,
    pub sender_email: String,
    pub expiration_date: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}
