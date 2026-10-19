use super::proxy::handler;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    routing::{get, post},
};
use reqwest::StatusCode;

// Stub upstream: one route with a fixed body + header, one that echoes the body.
async fn hello() -> impl axum::response::IntoResponse {
    ([("x-upstream", "stub")], "hello from upstream")
}

async fn echo(body: Body) -> axum::body::Bytes {
    to_bytes(body, 1024).await.unwrap()
}

// Serves the stub on 127.0.0.1 with a random free port.
async fn start_stub_upstream() -> String {
    let app = Router::new()
        .route("/hello", get(hello))
        .route("/echo", post(echo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn request(method: axum::http::Method, uri: &str, body: Vec<u8>) -> Request {
    let mut rq = Request::new(Body::from(body));
    *rq.method_mut() = method;
    *rq.uri_mut() = uri.parse().unwrap();
    rq
}

#[tokio::test]
async fn forwards_get_status_headers_and_body() {
    let upstream = start_stub_upstream().await;
    let client = reqwest::Client::new();
    let res = handler(
        State((client, upstream)),
        request(axum::http::Method::GET, "/hello", vec![]),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("x-upstream"),
        Some(&axum::http::HeaderValue::from_static("stub"))
    );
    let body = to_bytes(res.into_body(), 1024).await.unwrap();
    assert_eq!(body.as_ref(), b"hello from upstream");
}

#[tokio::test]
async fn forwards_post_body() {
    let upstream = start_stub_upstream().await;
    let client = reqwest::Client::new();
    let res = handler(
        State((client, upstream)),
        request(axum::http::Method::POST, "/echo", b"hello world".to_vec()),
    )
    .await
    .unwrap();
    let body = to_bytes(res.into_body(), 1024).await.unwrap();
    assert_eq!(body.as_ref(), b"hello world");
}

#[tokio::test]
async fn upstream_down_gives_502() {
    let client = reqwest::Client::new();
    let res = handler(
        State((client, "http://127.0.0.1:1".to_string())),
        request(axum::http::Method::GET, "/hello", vec![]),
    )
    .await;
    assert!(matches!(res, Err(StatusCode::BAD_GATEWAY)));
}
