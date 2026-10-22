use std::time::Duration;

use axum::{
    body::Body,
    extract::{Request, State},
    response::Response,
};
use reqwest::StatusCode;

use crate::jev;

pub async fn handler(
    State((client, upstream)): State<(reqwest::Client, String)>,
    rq: Request,
) -> Result<Response, StatusCode> {
    let path = rq.uri().path().to_string();
    let query = rq.uri().query().unwrap_or("").to_string();

    let (parts, body) = rq.into_parts();

    // detect-only: veredicto de Jev si hay JEV_API_KEY
    // shortcut: body no se envía a Jev (el stream se consume para el upstream); bufferizarlo cuando llegue detección por body
    if let Some(key) = std::env::var("JEV_API_KEY").ok() {
        let st = jev::state(parts.method.as_str(), &path, &query, &parts.headers, None);
        match jev::ask(&client, &key, &st).await {
            Ok(j) => eprintln!("[jev] {}", jev::verdict(&j)),
            Err(e) => eprintln!("[jev] error: {e}"),
        }
    }

    let res = client
        .request(parts.method, format!("{upstream}{path}{query}"))
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
