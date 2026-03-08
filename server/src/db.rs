use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::{File, ReceiveFileDetails, SentFileDetails, SharedLink, User};

/// Database client wrapper.
///
/// This struct encapsulates the PostgreSQL connection pool.
/// It acts as the entry point for all database operations.
///
/// By wrapping `Pool<Postgres>`:
/// - We centralize DB access
/// - We allow trait-based abstraction
/// - We make testing/mocking easier later
#[derive(Debug, Clone)]
pub struct DBClient {
    /// SQLx PostgreSQL connection pool.
    pool: Pool<Postgres>,
}

impl DBClient {
    /// Creates a new DBClient instance.
    /// Should be called once during application startup
    /// and injected into application state.
    pub fn new(pool: Pool<Postgres>) -> Self {
        DBClient { pool }
    }
}

/// Database abstraction layer.
///
/// This trait defines all persistence-related operations
/// for users, files, and sharing logic.
///
/// Why use a trait?
/// - Enables dependency injection
/// - Allows mocking in tests
/// - Decouples application logic from SQLx
#[async_trait]
pub trait UserExt {
    /// Fetch a single user based on optional filters.
    ///
    /// Only one parameter is expected to be Some(...) at a time.
    /// Returns:
    /// - Ok(Some(User)) → user found
    /// - Ok(None) → user not found
    /// - Err(sqlx::Error) → database error
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error>;

    /// Create a new user.
    /// Password must already be hashed before calling this.
    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
    ) -> Result<User, sqlx::Error>;

    /// Update user's display name.
    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        name: T,
    ) -> Result<User, sqlx::Error>;

    /// Update user's hashed password.
    /// Password must be hashed before calling this.
    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error>;

    /// Save or update user's public key.
    /// Used for asymmetric encryption when sharing files.
    async fn save_user_key(&self, user_id: Uuid, public_key: String) -> Result<(), sqlx::Error>;

    /// Search users by email substring.
    /// Used for file sharing recipient search.
    /// `user_id` is typically used to exclude current user.
    async fn search_by_email(&self, user_id: Uuid, query: String)
    -> Result<Vec<User>, sqlx::Error>;

    /// Save encrypted file and create share link.
    ///
    /// Encryption model:
    /// - File encrypted with AES
    /// - AES key encrypted using recipient's public key
    ///
    /// This method likely:
    /// 1. Inserts into `files`
    /// 2. Inserts into `share_links`
    ///
    /// Consider wrapping in transaction to ensure atomicity.
    async fn save_encrypted_file(
        &self,
        user_id: Uuid, // sender
        file_name: String,
        file_size: i64,
        recipient_user_id: Uuid,
        password: String, // should be hashed before storing
        expiration_date: DateTime<Utc>,
        encrypted_aes_key: Vec<u8>,
        encrypted_file: Vec<u8>,
        iv: Vec<u8>,
    ) -> Result<(), sqlx::Error>;

    /// Retrieve share link details.
    ///
    /// Used when recipient attempts to access a shared file.
    /// `userid` ensures proper access control.
    async fn get_shared(
        &self,
        shared_id: Uuid,
        userid: Uuid,
    ) -> Result<Option<SharedLink>, sqlx::Error>;

    /// Retrieve encrypted file metadata + content.
    ///
    /// Returns None if file does not exist.
    async fn get_file(&self, file_id: Uuid) -> Result<Option<File>, sqlx::Error>;

    /// Retrieve files sent by user (Paginated).
    ///
    /// Returns:
    /// - Vector of file details
    /// - Total count (for pagination UI)
    ///
    /// `page` starts from 1 (recommended convention).
    async fn get_sent_files(
        &self,
        user_id: Uuid,
        page: u32,
        limit: usize,
    ) -> Result<(Vec<SentFileDetails>, i64), sqlx::Error>;

    /// Retrieve files received by user (Paginated).
    ///
    /// Same pagination contract as get_sent_files.
    async fn get_receive_files(
        &self,
        user_id: Uuid,
        page: u32,
        limit: usize,
    ) -> Result<(Vec<ReceiveFileDetails>, i64), sqlx::Error>;

    /// Delete expired files and/or share links.
    ///
    /// Should be triggered:
    /// - Periodically via background task
    /// - Or via database cron job
    ///
    /// Important: ensure proper cascading delete rules.
    async fn delete_expired_files(&self) -> Result<(), sqlx::Error>;
}

#[async_trait]
impl UserExt for DBClient {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let mut user: Option<User> = None;

        if let Some(user_id) = user_id {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, public_key, created_at, updated_at FROM users WHERE id = $1"#,
                user_id
            ).fetch_optional(&self.pool).await?;
        } else if let Some(name) = name {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, public_key, created_at, updated_at FROM users WHERE name = $1"#,
                name
            ).fetch_optional(&self.pool).await?;
        } else if let Some(email) = email {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, name, email, password, public_key, created_at, updated_at FROM users WHERE email = $1"#,
                email
            ).fetch_optional(&self.pool).await?;
        }

        Ok(user)
    }

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password) 
            VALUES ($1, $2, $3) 
            RETURNING id, name, email, password, public_key, created_at, updated_at
            "#,
            name.into(),
            email.into(),
            password.into()
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        new_name: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET name = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, public_key, created_at, updated_at
            "#,
            new_name.into(),
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user_password(
        &self,
        user_id: Uuid,
        new_password: String,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET password = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, public_key, created_at, updated_at
            "#,
            new_password,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn save_user_key(&self, user_id: Uuid, public_key: String) -> Result<(), sqlx::Error> {
        sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET public_key = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, public_key, created_at, updated_at
            "#,
            public_key,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(())
    }

    async fn search_by_email(
        &self,
        user_id: Uuid,
        query: String,
    ) -> Result<Vec<User>, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, name, email, password, public_key, created_at, updated_at
            FROM users
            WHERE email LIKE $1
            AND public_key IS NOT NULL
            AND id != $2
            "#,
            query,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(user)
    }

    async fn save_encrypted_file(
        &self,
        user_id: Uuid,
        file_name: String,
        file_size: i64,
        recipient_user_ud: Uuid,
        password: String,
        expiration_date: DateTime<Utc>,
        encrypted_aes_key: Vec<u8>,
        encrypted_file: Vec<u8>,
        iv: Vec<u8>,
    ) -> Result<(), sqlx::Error> {
        // Insert into the files table and get the file_id
        let file_id: Uuid = sqlx::query_scalar!(
            r#"
            INSERT INTO files (user_id, file_name, file_size, encrypted_aes_key, encrypted_file, iv, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            RETURNING id
            "#,
            user_id,
            file_name,
            file_size,
            encrypted_aes_key,
            encrypted_file,
            iv
        )
        .fetch_one(&self.pool)
        .await?;

        // Insert into the shared_links table using the returned file_id
        sqlx::query!(
            r#"
            INSERT INTO shared_links (file_id, recipient_user_id, password, expiration_date, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            "#,
            file_id,
            recipient_user_ud,
            password,
            expiration_date
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_shared(
        &self,
        shared_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SharedLink>, sqlx::Error> {
        let share_link = sqlx::query_as!(
            SharedLink,
            r#"
            SELECT id, file_id, recipient_user_id, password, expiration_date, created_at
            FROM shared_links
            WHERE id = $1
            AND recipient_user_id = $2
            AND expiration_date > NOW()
            "#,
            shared_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(share_link)
    }

    async fn get_file(&self, file_id: Uuid) -> Result<Option<File>, sqlx::Error> {
        let file = sqlx::query_as!(
            File,
            r#"
            SELECT id, user_id, file_name, file_size, encrypted_aes_key, encrypted_file, iv, created_at
            FROM files
            WHERE id = $1
            "#,
            file_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(file)
    }

    async fn get_sent_files(
        &self,
        user_id: Uuid,
        page: u32,
        limit: usize,
    ) -> Result<(Vec<SentFileDetails>, i64), sqlx::Error> {
        let offset = (page - 1) * limit as u32;

        let files = sqlx::query_as!(
            SentFileDetails,
            r#"
                SELECT
                    f.id AS file_id,
                    f.file_name,
                    u.email AS recipient_email,
                    sl.expiration_date,
                    sl.created_at
                FROM 
                    shared_links sl
                JOIN 
                    files f ON sl.file_id = f.id
                JOIN 
                    users u ON sl.recipient_user_id = u.id
                WHERE 
                    f.user_id = $1
                ORDER BY 
                    sl.created_at DESC 
                LIMIT $2 
                OFFSET $3
            "#,
            user_id,
            limit as i64,
            offset as i64,
        )
        .fetch_all(&self.pool)
        .await?;

        let count_row = sqlx::query_scalar!(
            r#"
                SELECT COUNT(*)
                FROM shared_links sl
                JOIN files f ON sl.file_id = f.id
                WHERE f.user_id = $1
            "#,
            user_id,
        )
        .fetch_one(&self.pool)
        .await?;

        let total_count = count_row.unwrap_or(0);

        Ok((files, total_count))
    }

    async fn get_receive_files(
        &self,
        user_id: Uuid,
        page: u32,
        limit: usize,
    ) -> Result<(Vec<ReceiveFileDetails>, i64), sqlx::Error> {
        let offset = (page - 1) * limit as u32;

        let files = sqlx::query_as!(
            ReceiveFileDetails,
            r#"
                SELECT
                    sl.id AS file_id,
                    f.file_name,
                    u.email AS sender_email,
                    sl.expiration_date,
                    sl.created_at
                FROM 
                    shared_links sl
                JOIN 
                    files f ON sl.file_id = f.id
                JOIN 
                    users u ON f.user_id = u.id
                WHERE 
                    sl.recipient_user_id = $1
                ORDER BY 
                    sl.created_at DESC 
                LIMIT $2 
                OFFSET $3
            "#,
            user_id,
            limit as i64,
            offset as i64,
        )
        .fetch_all(&self.pool)
        .await?;

        let count_row = sqlx::query_scalar!(
            r#"
                SELECT COUNT(*)
                FROM shared_links sl
                JOIN files f ON sl.file_id = f.id
                WHERE sl.recipient_user_id = $1
            "#,
            user_id,
        )
        .fetch_one(&self.pool)
        .await?;

        let total_count = count_row.unwrap_or(0);

        Ok((files, total_count))
    }

    async fn delete_expired_files(&self) -> Result<(), sqlx::Error> {
        let expired_shared_links: Vec<Uuid> = sqlx::query_scalar!(
            r#"
            SELECT sl.id
            FROM shared_links sl
            WHERE sl.expiration_date < NOW()
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        if expired_shared_links.is_empty() {
            println!("No expired files or shared links to delete.");
            return Ok(());
        }

        let expired_file_ids: Vec<Uuid> = sqlx::query_scalar!(
            r#"
            SELECT f.id
            FROM files f
            WHERE f.id IN (
                SELECT sl.file_id
                FROM shared_links sl
                WHERE sl.expiration_date < NOW()
            )
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        sqlx::query!(
            r#"
            DELETE FROM shared_links
            WHERE id = ANY($1)
            "#,
            &expired_shared_links[..] // Pass the list of expired shared link IDs
        )
        .execute(&self.pool)
        .await?;

        // Delete the expired files
        sqlx::query!(
            r#"
            DELETE FROM files
            WHERE id = ANY($1)
            "#,
            &expired_file_ids[..] // Pass the list of expired file IDs
        )
        .execute(&self.pool)
        .await?;

        println!("Successfully deleted expired files and their shared links.");

        Ok(())
    }
}
