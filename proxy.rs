use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    response::Response,
};
use reqwest::StatusCode;
use std::net::SocketAddr;

use crate::{jev, normalization::normalize, rate_limiter::Limiter};

const MAX_BODY: usize = 1 << 20; // 1 MiB

pub async fn handler(
    State((client, upstream, limiter)): State<(reqwest::Client, String, Limiter)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    rq: Request,
) -> Result<Response, StatusCode> {
    let path = rq.uri().path().to_string();
    let query = rq.uri().query().unwrap_or("").to_string();

    if !limiter.check(addr.ip()) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let (parts, body) = rq.into_parts();

    let body = to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    // detect-only: veredicto de Jev si hay JEV_API_KEY
    if let Some(key) = std::env::var("JEV_API_KEY").ok() {
        let body_str = String::from_utf8_lossy(&body);
        let path_normalized = normalize(&path);
        let st = jev::state(
            parts.method.as_str(),
            &path_normalized,
            &query,
            &parts.headers,
            Some(&body_str),
        );
        match jev::ask(&client, &key, &st).await {
            Ok(j) => eprintln!("[jev] {}", jev::verdict(&j)),
            Err(e) => eprintln!("[jev] error: {e}"),
        }
    }

    let res = client
        .request(parts.method, format!("{upstream}{path}{query}"))
        .headers(parts.headers)
        .body(body)
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let status = res.status();
    let headers = res.headers().clone();
    let mut response = Response::new(Body::from_stream(res.bytes_stream()));

    *response.status_mut() = status;
    *response.headers_mut() = headers;

    Ok(response)
}
