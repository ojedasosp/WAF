use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    response::Response,
};
use reqwest::StatusCode;
use std::net::{IpAddr, SocketAddr};

use crate::{
    detector::{self, Detector, Match},
    fast_path, jev,
    normalization::normalize,
    rate_limiter::Limiter,
    Config,
};

pub async fn handler(
    State((client, limiter, cfg)): State<(reqwest::Client, Limiter, Config)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    rq: Request,
) -> Result<Response, StatusCode> {
    let path = rq.uri().path().to_string();
    let query = rq.uri().query().unwrap_or("").to_string();

    if !limiter.check(addr.ip()) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let (parts, body) = rq.into_parts();

    let max_body = cfg.max_body as usize * (1 << 20); // config value is MiB
    let body = to_bytes(body, max_body)
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
            match jev::ask(&client, &key, &st, &cfg.jev_url, &cfg.model, &cfg.questions).await {
                Ok(j) => match detector::JevDetector.detect(&j, &st) {
                    Some(m) if m.score >= cfg.block_threshold as u32 => {
                        return Ok(blocked(addr.ip(), &m));
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
        .request(parts.method, format!("{}{path}{query}", cfg.upstream))
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

/// Single place for all blocks: one audit line + 403 with a simple page.
fn blocked(ip: IpAddr, m: &Match) -> Response {
    eprintln!(
        "[audit] block ip={} rule={} location={} score={}",
        ip, m.rule_id, m.location, m.score
    );
    let body = format!(
        "<!doctype html><html><body><h1>403 Forbidden</h1><p>Request blocked by the WAF (rule {}).</p></body></html>",
        m.rule_id
    );
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = StatusCode::FORBIDDEN;
    res.headers_mut().insert(
        reqwest::header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocked_gives_403_with_page() {
        let m = Match { rule_id: 1, score: 2, location: "query".into() };
        let res = blocked("127.0.0.1".parse().unwrap(), &m);
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("403") && s.contains("rule 1"));
    }
}
