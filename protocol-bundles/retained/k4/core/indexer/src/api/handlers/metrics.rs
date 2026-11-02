use axum::extract::State;
use metrics_exporter_prometheus::PrometheusHandle;

pub async fn get_metrics(State(handle): State<PrometheusHandle>) -> String {
    handle.render()
}
