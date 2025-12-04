use std::time::Duration;

use axum::{
    Json, Router,
    http::{HeaderName, Request, Response},
    response::IntoResponse,
    routing::{any, get, post},
};
use indexer_types::ErrorResponse;
use reqwest::StatusCode;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::{MakeSpan, OnFailure, OnResponse, TraceLayer},
};
use tracing::{Level, Span, error, field, info, span};

use crate::api::handlers::{
    get_blocks, get_contract, get_contracts, get_index, get_result, get_results, get_transaction,
    get_transaction_inspect, get_transactions, post_compose, post_contract,
    post_transaction_hex_inspect, stop,
};

use super::{
    Env,
    handlers::{get_block, get_block_latest, post_compose_commit, post_compose_reveal},
    ws,
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
            error = field::Empty,
        )
    }
}

#[derive(Clone)]
struct CustomOnResponse;
impl<B> OnResponse<B> for CustomOnResponse {
    fn on_response(self, res: &Response<B>, latency: Duration, _: &Span) {
        if res.status().is_success() || res.status() == StatusCode::SWITCHING_PROTOCOLS {
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

fn handle_panic(panic: Box<dyn std::any::Any + Send>) -> axum::response::Response {
    let message = panic
        .downcast_ref::<String>()
        .map(|s| s.as_str())
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("Unknown panic occurred")
        .to_string();

    let error_response = Json(ErrorResponse { error: message });
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        error_response,
    )
        .into_response()
}

pub fn new(context: Env) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .route("/ws", any(ws::handler))
        .nest(
            "/api",
            Router::new()
                .route("/", get(get_index))
                .route("/stop", get(stop))
                .nest(
                    "/blocks",
                    Router::new()
                        .route("/", get(get_blocks))
                        .route("/latest", get(get_block_latest))
                        .route("/{height|hash}", get(get_block))
                        .route("/{height}/transactions", get(get_transactions)),
                )
                .nest(
                    "/transactions",
                    Router::new()
                        .route("/", get(get_transactions))
                        .route("/{txid}", get(get_transaction))
                        .route("/{txid}/inspect", get(get_transaction_inspect))
                        .route("/inspect", post(post_transaction_hex_inspect))
                        .nest(
                            "/compose",
                            Router::new()
                                .route("/", post(post_compose))
                                .route("/commit", post(post_compose_commit))
                                .route("/reveal", post(post_compose_reveal)),
                        ),
                )
                .nest(
                    "/contracts",
                    Router::new()
                        .route("/", get(get_contracts))
                        .route("/{address}", get(get_contract).post(post_contract)),
                )
                .nest(
                    "/results",
                    Router::new()
                        .route("/", get(get_results))
                        .route("/{id}", get(get_result)),
                ),
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
                .layer(PropagateRequestIdLayer::new(x_request_id))
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
                .layer(CatchPanicLayer::custom(handle_panic))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(30),
                )),
        )
        .with_state(context)
}
