mod detector;
mod fast_path;
mod jev;
mod normalization;
mod proxy;
mod rate_limiter;

#[cfg(test)]
mod tests;

use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;

use crate::rate_limiter::Limiter;

#[derive(Deserialize)]
struct WafConfig {
    config: Config,
}

#[derive(Clone, Deserialize)]
pub struct Config {
    pub upstream: String,
    pub port: u16,
    pub jev_url: String,
    pub model: String,
    pub questions: String,
    pub quota: u32,
    pub max_body: u64, // MiB
    pub block_threshold: u8,
}

fn get_conf() -> Config {
    let raw = std::fs::read_to_string("waf.toml").expect("read waf.toml");
    toml::from_str::<WafConfig>(&raw)
        .expect("parse waf.toml")
        .config
}

#[tokio::main]
async fn main() {
    let cfg = get_conf();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let port = cfg.port;
    let limiter = Limiter::new(cfg.quota);
    let app = Router::new()
        .fallback(proxy::handler)
        .with_state((client, limiter, cfg));
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
