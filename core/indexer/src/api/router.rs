use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Request as AxumRequest, State},
    http::{HeaderName, Request, Response},
    middleware::{Next, from_fn_with_state},
    response::IntoResponse,
    routing::{get, post},
};
use indexer_types::ErrorResponse;
use metrics_exporter_prometheus::PrometheusHandle;
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
    get_block_transactions, get_blocks, get_contract, get_contracts, get_fees, get_index,
    get_metrics, get_result, get_results, get_signer, get_transaction, get_transaction_inspect,
    get_transactions, post_compose, post_contract, post_simulate, post_transaction_broadcast,
    post_transaction_hex_inspect,
};

use super::{
    API_REQUEST_TIMEOUT_MS, Env,
    error::HttpError,
    handlers::{get_block, get_block_latest, post_compose_commit, post_compose_reveal},
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

/// Tower middleware that 503s every chain-state-dependent endpoint while
/// the reactor isn't ready. Single source of truth for the rule that the
/// per-handler `if !available` blocks used to encode — the handlers
/// themselves now assume availability.
async fn require_available(
    State(env): State<Env>,
    req: AxumRequest,
    next: Next,
) -> std::result::Result<axum::response::Response, super::error::Error> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    Ok(next.run(req).await)
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

pub fn new(context: Env, prom_handle: PrometheusHandle) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");

    // Scrape endpoint sits in its own sub-router with PrometheusHandle as
    // state, merged AFTER `.layer()` and `.with_state()` so GMP scrapes
    // bypass the API's middleware stack (30s timeout, CORS, request-id,
    // catch-panic, trace) — `Router::layer` only applies to routes
    // already in the router at the time of the call.
    let metrics_router = Router::new()
        .route("/metrics", get(get_metrics))
        .with_state(prom_handle);

    // Chain-state-dependent endpoints — gated by the `require_available`
    // middleware below.
    let chain_routes = Router::new()
        .route("/", get(get_index))
        .route("/fees", get(get_fees))
        .nest(
            "/blocks",
            Router::new()
                .route("/", get(get_blocks))
                .route("/latest", get(get_block_latest))
                .route("/{height|hash}", get(get_block))
                .route("/{height|hash}/transactions", get(get_block_transactions)),
        )
        .nest(
            "/transactions",
            Router::new()
                .route("/", get(get_transactions))
                .route("/{txid}", get(get_transaction))
                .route("/{txid}/inspect", get(get_transaction_inspect))
                .route("/inspect", post(post_transaction_hex_inspect))
                .route("/simulate", post(post_simulate))
                .route("/broadcast", post(post_transaction_broadcast))
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
        )
        .route("/signers/{identifier}", get(get_signer))
        .layer(from_fn_with_state(context.clone(), require_available));

    Router::new()
        .nest("/api", chain_routes)
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
                    Duration::from_millis(API_REQUEST_TIMEOUT_MS),
                )),
        )
        .with_state(context)
        .merge(metrics_router)
}
