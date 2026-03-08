/// Application configuration structure.
///
/// This struct holds all environment-based configuration
/// required to start and run the backend service.
///
/// Values are loaded from environment variables (.env file)
/// during application startup.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_maxage: i64,
    pub environment: String,
    pub port: u16,
}

impl Config {
    /// Initializes the Config struct by reading required
    /// environment variables.
    ///
    /// This function should be called once during application startup.
    ///
    /// It will panic if any required environment variable is missing.
    /// This is intentional because the application cannot safely
    /// start without these critical values.
    pub fn init() -> Config {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file");

        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env file");

        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE must be set in .env file");

        let environment =
            std::env::var("ENVIRONMENT").expect("ENVIRONMENT must be set in .env file");

        Config {
            database_url,
            jwt_secret,

            // Convert JWT_MAXAGE string into i64.
            // `unwrap()` will panic if parsing fails.
            // This ensures misconfigured environments fail fast.
            jwt_maxage: jwt_maxage.parse::<i64>().unwrap(),

            environment,

            // Currently hardcode, Consider moving this to environment variable
            port: 8000,
        }
    }
}
