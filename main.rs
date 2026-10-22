mod jev;
mod normalization;
mod proxy;

#[cfg(test)]
mod tests;

use axum::Router;

const UPSTREAM: &str = "http://127.0.0.1:9000";

#[tokio::main]
async fn main() {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let app = Router::new()
        .fallback(proxy::handler)
        .with_state((client, UPSTREAM.to_string()));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
