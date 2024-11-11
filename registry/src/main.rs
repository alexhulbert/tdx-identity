use axum::{
    routing::{get, post},
    Router,
};
use state::AppState;
use std::sync::Arc;
use tokio::net::TcpListener;

mod error;
mod handlers;
mod state;
mod tdx;
mod validation;

#[tokio::main]
async fn main() {
    let state = AppState::new().expect("Failed to initialize state");

    let app = Router::new()
        .route("/register", post(handlers::register))
        .route("/instance/:pubkey", get(handlers::get_instance))
        .with_state(Arc::new(state));

    println!("Starting server on 0.0.0.0:3000");
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
