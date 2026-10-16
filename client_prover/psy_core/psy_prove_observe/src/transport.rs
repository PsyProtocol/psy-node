use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderValue, Request as HttpRequest, Response};
use jsonrpsee::{
    core::server::{BatchResponseBuilder, MethodResponse},
    server::middleware::rpc::{Batch, BatchEntry, Notification, Request, RpcServiceT},
};
use serde_json::json;
use tower::{Layer, Service};

use crate::{Observer, Stage};

#[derive(Clone)]
struct Correlation(String);

#[derive(Clone)]
pub struct HttpLayer(pub Observer);
impl<S> Layer<S> for HttpLayer {
    type Service = HttpObserver<S>;
    fn layer(&self, inner: S) -> Self::Service {
        HttpObserver {
            inner,
            observer: self.0.clone(),
        }
    }
}
#[derive(Clone)]
pub struct HttpObserver<S> {
    inner: S,
    observer: Observer,
}

impl<S, B, R> Service<HttpRequest<B>> for HttpObserver<S>
where
    S: Service<HttpRequest<B>, Response = Response<R>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    R: Send + 'static,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, mut req: HttpRequest<B>) -> Self::Future {
        if self.observer.0.is_none() {
            return Box::pin(self.inner.call(req));
        }
        // This ID is correlation, never authentication. No arbitrary header content is
        // logged.
        let id = self.observer.request_id(req.headers().get("x-request-id").and_then(|v| v.to_str().ok()));
        req.extensions_mut().insert(Correlation(id.clone()));
        let mut activity = self.observer.activity("http", &id, "http", Stage::Http);
        let length = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        activity.event("http_received", json!({"declared_body_bytes":length}));
        // Call the same service whose readiness was polled; do not clone away
        // back-pressure.
        let future = self.inner.call(req);
        Box::pin(async move {
            match future.await {
                Ok(mut response) => {
                    activity.finish("response_prepared");
                    activity.event("http_response_prepared", json!({"status":response.status().as_u16()}));
                    if let Ok(value) = HeaderValue::from_str(&id) {
                        response.headers_mut().insert("x-request-id", value);
                    }
                    // Body delivery/caller disconnect is observed at Nginx, not asserted here.
                    Ok(response)
                }
                Err(err) => {
                    activity.finish("transport_error");
                    Err(err)
                }
            }
        })
    }
}

#[derive(Clone)]
pub struct RpcObserver<S> {
    inner: S,
    observer: Observer,
    max_response_bytes: usize,
}
impl<S> RpcObserver<S> {
    pub fn new(inner: S, observer: Observer, max_response_bytes: usize) -> Self {
        Self {
            inner,
            observer,
            max_response_bytes,
        }
    }
}
impl<S> RpcServiceT for RpcObserver<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse, BatchResponse = MethodResponse, NotificationResponse = MethodResponse>
        + Clone
        + Send
        + Sync
        + 'static,
{
    type MethodResponse = MethodResponse;
    type BatchResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let id = req
            .extensions()
            .get::<Correlation>()
            .map(|v| v.0.clone())
            .unwrap_or_else(|| self.observer.request_id(None));
        // Do not copy/log the JSON-RPC id, params, proof, or ErrorObject data.
        let mut activity = self.observer.activity("rpc", &id, req.method_name(), Stage::Rpc);
        let context = activity.context();
        let inner = self.inner.clone();
        async move {
            context
                .scope(async move {
                    // Construct the future inside the context too: sync callbacks can run in
                    // call().
                    let response = inner.call(req).await;
                    activity.finish(if response.is_success() { "rpc_success" } else { "rpc_error" });
                    activity.event(
                        "rpc_response_prepared",
                        json!({"response_bytes":response.as_ref().len(),
                    "success":response.is_success()}),
                    );
                    response
                })
                .await
        }
    }
    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let service = self.clone();
        // Match jsonrpsee 0.26's sequential batch execution, response size cap, invalid
        // entries, and notification behavior. Forwarding inner.batch would
        // bypass per-call tracking.
        async move {
            if service.observer.0.is_none() {
                return service.inner.batch(batch).await;
            }
            let mut builder = BatchResponseBuilder::new_with_limit(service.max_response_bytes);
            let mut notification = false;
            for entry in batch {
                match entry {
                    Ok(BatchEntry::Call(req)) => {
                        if let Err(err) = builder.append(service.call(req).await) {
                            return err;
                        }
                    }
                    Ok(BatchEntry::Notification(n)) => {
                        notification = true;
                        service.notification(n).await;
                    }
                    Err(err) => {
                        let (err, id) = err.into_parts();
                        if let Err(err) = builder.append(MethodResponse::error(id, err)) {
                            return err;
                        }
                    }
                }
            }
            if builder.is_empty() && notification {
                MethodResponse::notification()
            } else {
                MethodResponse::from_batch(builder.finish())
            }
        }
    }
    fn notification<'a>(&self, n: Notification<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        // Keep framework semantics; it does not invoke registered request handlers
        // here.
        let inner = self.inner.clone();
        async move { inner.notification(n).await }
    }
}
