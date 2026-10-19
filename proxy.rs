use std::time::Duration;

use axum::{
    body::Body,
    extract::{Request, State},
    response::Response,
};
use reqwest::StatusCode;

pub async fn handler(
    State((client, upstream)): State<(reqwest::Client, String)>,
    rq: Request,
) -> Result<Response, StatusCode> {
    let path = rq
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());

    let (parts, body) = rq.into_parts();

    let res = client
        .request(parts.method, format!("{upstream}{path}"))
        .headers(parts.headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
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
