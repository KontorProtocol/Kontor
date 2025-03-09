use std::time::Duration;

use axum::{
    Router,
    http::{HeaderName, Request, Response},
    routing::get,
};
use tower::ServiceBuilder;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::{MakeSpan, OnFailure, OnResponse, TraceLayer},
};
use tracing::{Level, Span, error, field, info, span};

use super::{
    context::Context,
    handlers::{get_block, get_block_latest},
};

#[derive(Clone)]
struct CustomMakeSpan;
impl<B> MakeSpan<B> for CustomMakeSpan {
    fn make_span(&mut self, req: &Request<B>) -> Span {
        let id = req
            .extensions()
            .get::<RequestId>()
            .and_then(|id| id.header_value().to_str().ok())
            .unwrap_or("unknown");
        span!(
            Level::INFO,
            "request",
            id = %id,
            method = %req.method(),
            path = %req.uri().path(),
            version = ?req.version(),
            error = field::Empty
        )
    }
}

#[derive(Clone)]
struct CustomOnResponse;
impl<B> OnResponse<B> for CustomOnResponse {
    fn on_response(self, res: &Response<B>, latency: Duration, _: &Span) {
        if res.status().is_success() {
            info!("{} {}ms", res.status(), latency.as_millis());
        } else {
            error!("{} {}ms", res.status(), latency.as_millis());
        }
    }
}

#[derive(Clone)]
struct NoOpOnFailure;
impl<B> OnFailure<B> for NoOpOnFailure {
    fn on_failure(&mut self, _res: B, _latency: Duration, _span: &Span) {}
}

pub fn new(context: Context) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .nest(
            "/api",
            Router::new()
                .route("/block/{height}", get(get_block))
                .route("/block/latest", get(get_block_latest)),
        )
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::new(
                    x_request_id.clone(),
                    MakeRequestUuid,
                ))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(CustomMakeSpan)
                        .on_response(CustomOnResponse)
                        .on_failure(NoOpOnFailure),
                )
                .layer(PropagateRequestIdLayer::new(x_request_id)),
        )
        .with_state(context)
}
