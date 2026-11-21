use crate::bitcoin_client::Client;
use crate::metrics::Telemetry;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use bitcoin::Network;
use metrics_exporter_prometheus::PrometheusHandle;

#[derive(Clone)]
pub struct MetricsState {
    pub handle: PrometheusHandle,
    pub telemetry: Telemetry,
    pub bitcoin: Client,
    pub network: Network,
}

pub async fn get_metrics(State(state): State<MetricsState>) -> impl IntoResponse {
    let mut text = state.handle.render();
    text.push_str(&state.telemetry.render(&state.bitcoin, state.network));
    (
        [
            (
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        text,
    )
}

#[cfg(test)]
mod tests {
    use crate::api::handlers::tests::new_test_env;
    use crate::api::router;
    use crate::metrics::recorder_builder;
    use anyhow::Result;
    use axum_test::TestServer;
    use futures_util::future::join_all;
    use std::future::IntoFuture;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn scrape_works_while_unready_and_writer_transaction_is_held() -> Result<()> {
        let (env, conn, _directory) = new_test_env().await?;
        env.reactor_ready.store(false, Ordering::Relaxed);
        let recorder = recorder_builder().build_recorder();
        let server = TestServer::new(router::new(env, recorder.handle()));
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let responses = timeout(
            Duration::from_secs(2),
            join_all((0..16).map(|_| server.get("/metrics").into_future())),
        )
        .await?;
        for response in responses {
            response.assert_status_ok();
            response.assert_header("content-type", "text/plain; version=0.0.4; charset=utf-8");
            let body = response.text();
            assert!(body.contains("kontor_state_observation_valid 0\n"));
            assert!(body.contains("kontor_engine_metrics_available 0\n"));
            assert!(!body.contains("# EOF"));
        }
        assert!(!conn.is_autocommit());
        conn.execute("ROLLBACK", ()).await?;
        Ok(())
    }
}
