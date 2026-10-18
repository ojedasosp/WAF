use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    response::Response,
};
use reqwest::StatusCode;

const UPSTREAM: &str = "http://127.0.0.1:9000";

#[tokio::main]
async fn main() {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let app = Router::new().fallback(handler).with_state(client);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handler(
    State(client): State<reqwest::Client>,
    rq: Request,
) -> Result<Response, StatusCode> {
    let path = rq
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());

    let (parts, body) = rq.into_parts();

    let upstream = client
        .request(parts.method, format!("{UPSTREAM}{path}"))
        .headers(parts.headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let status = upstream.status();
    let headers = upstream.headers().clone();
    let mut response = Response::new(Body::from_stream(upstream.bytes_stream()));

    *response.status_mut() = status;
    *response.headers_mut() = headers;

    Ok(response)
}
