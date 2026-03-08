use std::sync::Arc;

use crate::{
    config::Config,
    db::{DBClient, UserExt},
    router::create_router,
};

use axum::http::{
    HeaderValue, Method,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
};

use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tokio_cron_scheduler::{Job, JobScheduler};
use tower_http::cors::CorsLayer;
use tracing_subscriber::filter::LevelFilter;

mod config;
mod db;
mod dtos;
mod error;
mod handler;
mod middleware;
mod models;
mod router;
mod utils;

/// Shared application state.
///
/// This struct is injected into Axum routes using `with_state`.
/// It contains:
/// - Environment configuration
/// - Database client
///
/// Must be `Clone` because Axum clones state internally.
#[derive(Debug, Clone)]
pub struct AppState {
    pub env: Config,
    pub db_client: DBClient,
}

#[tokio::main]
async fn main() {
    // Allows frontend (localhost:3000) to communicate with backend.
    // Important for browser security policy.
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT]);

    dotenv().ok();

    // Read environment configuration
    let config = Config::init();

    let filter_level = match config.environment.as_str() {
        "production" => LevelFilter::INFO,
        _ => LevelFilter::DEBUG,
    };

    tracing_subscriber::fmt()
        .with_max_level(filter_level)
        .init();

    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("Connected to database");
            pool
        }
        Err(_err) => {
            println!("Failed to connect to database");
            // Fail fast: Application cannot run without DB
            std::process::exit(1);
        }
    };

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    // Wrap SQLx pool inside DBClient abstraction
    let db_client = DBClient::new(pool);

    let app_state = AppState {
        env: config.clone(),
        db_client: db_client.clone(),
    };

    // Used for periodic maintenance tasks.
    // Here: deleting expired shared files.
    let scheduler = JobScheduler::new().await.unwrap();

    // Cron pattern: "0 0 * * * *"
    // Runs every hour at minute 0 (depends on scheduler format).
    let job = Job::new_async("0 0 * * * *", {
        move |_, _| {
            let db_client = db_client.clone();

            Box::pin(async move {
                println!("Running scheduled task to delete expired files...");

                if let Err(err) = db_client.delete_expired_files().await {
                    eprintln!("Error deleting expired files: {:?}", err);
                } else {
                    println!("Successfully deleted expired files.");
                }
            })
        }
    })
    .unwrap();

    scheduler.add(job).await.unwrap();

    // Run scheduler in background without blocking main thread
    tokio::spawn(async move {
        scheduler.start().await.unwrap();
    });

    // Axum application router
    let app = create_router(Arc::new(app_state.clone())).layer(cors.clone());

    println!("Server is running on http://localhost:{}", config.port);

    // Bind to 0.0.0.0 to allow external connections (e.g., Docker).
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &config.port))
        .await
        .unwrap();

    // Start serving requests
    axum::serve(listener, app).await.unwrap();
}
