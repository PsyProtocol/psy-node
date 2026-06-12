use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{Method, Request, Response, StatusCode};
use tower::{Layer, Service};

/// Simple health check middleware that intercepts GET /health requests
/// and returns 200 OK without processing them through the RPC server
#[derive(Clone)]
pub struct HealthLayer;

impl<S> Layer<S> for HealthLayer {
    type Service = HealthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HealthService { inner }
    }
}

#[derive(Clone)]
pub struct HealthService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for HealthService<S>
where
    S: Service<Request<B>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: From<&'static str> + Send + 'static,
{
    type Response = Response<B>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        // Check if this is a GET /health request
        if req.method() == Method::GET && req.uri().path() == "/health" {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(B::from(r#"{"status":"ok"}"#))
                .unwrap();

            return Box::pin(async move { Ok(response) });
        }

        // For all other requests, pass through to the inner service
        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}
