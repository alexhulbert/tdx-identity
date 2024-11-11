use crate::{handlers::create_router, state::AppState};
use std::sync::Arc;
use tokio::net::TcpListener;

mod encryption;
mod error;
mod handlers;
mod ssh;
mod state;
mod storage;
mod tdx;
mod validation;
mod workload;

#[tokio::main]
async fn main() {
    let state = AppState::new().await.expect("Failed to initialize state");
    let app = create_router(Arc::new(state));
    println!("Starting server on 0.0.0.0:3001");
    let listener = TcpListener::bind("0.0.0.0:3001").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
