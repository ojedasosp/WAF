use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    response::Response,
};
use reqwest::StatusCode;
use std::net::SocketAddr;

use crate::{
    detector::{self, Detector},
    fast_path, jev,
    normalization::normalize,
    rate_limiter::Limiter,
};

const MAX_BODY: usize = 1 << 20; // 1 MiB
const BLOCK_THRESHOLD: u32 = 2; // threat_level >= 2 → block (tune with the phase-8 corpus)

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

    if let Some(key) = std::env::var("JEV_API_KEY").ok() {
        let body_str = String::from_utf8_lossy(&body);
        let path_normalized = normalize(&path);
        let haystack = format!("{path_normalized} {query} {body_str}");
        if let Some(rule) = fast_path::check(&haystack) {
            let st = jev::state(
                parts.method.as_str(),
                &path_normalized,
                &query,
                &parts.headers,
                Some(&body_str),
            );
            match jev::ask(&client, &key, &st).await {
                Ok(j) => match detector::JevDetector.detect(&j, &st) {
                    Some(m) if m.score >= BLOCK_THRESHOLD => {
                        eprintln!(
                            "[audit] block ip={} rule={} location={} score={}",
                            addr.ip(),
                            m.rule_id,
                            m.location,
                            m.score
                        );
                        return Err(StatusCode::FORBIDDEN);
                    }
                    Some(m) => {
                        eprintln!("[jev] {rule} {} location={}", jev::verdict(&j), m.location)
                    }
                    None => eprintln!("[jev] {rule} benign, regex false positive"),
                },
                Err(e) => eprintln!("[jev] error: {e}"),
            }
        } else {
            eprintln!("[fast-path] benign, skipping Jev");
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
