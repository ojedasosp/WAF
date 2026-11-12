mod jev;
mod normalization;
mod proxy;
mod rate_limiter;

#[cfg(test)]
mod tests;

use axum::Router;
use std::net::SocketAddr;

use crate::rate_limiter::Limiter;

const UPSTREAM: &str = "http://127.0.0.1:9000";

#[tokio::main]
async fn main() {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let limiter = Limiter::new();
    let app =
        Router::new()
            .fallback(proxy::handler)
            .with_state((client, UPSTREAM.to_string(), limiter));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
