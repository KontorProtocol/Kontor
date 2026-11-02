use axum::{Json, extract::State};
use libsql::TransactionBehavior;
use tokio::sync::oneshot;

use crate::api::{Env, error::HttpError, result::Result};
use crate::upgrade_control::{
    QueuedUpgrade, SubmissionError, SubmitUpgrade, UpgradeState, UpgradeSubmission,
    decode_submission, snapshot,
};

fn submission_error(error: SubmissionError) -> HttpError {
    match error {
        SubmissionError::Invalid(message) => HttpError::BadRequest(message),
        error => HttpError::ServiceUnavailable(error.to_string()),
    }
}

pub async fn post_upgrade(
    State(env): State<Env>,
    Json(request): Json<SubmitUpgrade>,
) -> Result<QueuedUpgrade> {
    let envelope = decode_submission(request).map_err(submission_error)?;
    let (reply, result) = oneshot::channel();
    env.upgrade_tx
        .try_send(UpgradeSubmission { envelope, reply })
        .map_err(|_| {
            HttpError::ServiceUnavailable("upgrade submission is busy or unavailable".into())
        })?;
    let queued = result
        .await
        .map_err(|_| HttpError::ServiceUnavailable("upgrade submission stopped".into()))?
        .map_err(submission_error)?;
    Ok(queued.into())
}

pub async fn get_upgrade_state(State(env): State<Env>) -> Result<UpgradeState> {
    let conn = env.reader.connection().await?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .await?;
    let state = snapshot(&transaction).await.map_err(|error| {
        if error.is::<SubmissionError>() {
            HttpError::ServiceUnavailable(error.to_string()).into()
        } else {
            error
        }
    })?;
    transaction.commit().await?;
    Ok(state.into())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use axum::{Router, extract::DefaultBodyLimit, http::StatusCode, routing::get};
    use axum_test::TestServer;
    use serde_json::{Value, json};
    use tokio::sync::{mpsc, oneshot};

    use super::{get_upgrade_state, post_upgrade};
    use crate::api::handlers::tests::new_test_env;
    use crate::database::certified_history;
    use crate::upgrade_control::{
        QueuedUpgrade, SUBMISSION_BODY_LIMIT, SubmitUpgrade, UpgradeSubmission, decode_submission,
    };

    #[tokio::test]
    async fn submission_http_bounds_backpressure_and_local_acknowledgement() -> Result<()> {
        let (mut env, conn, _directory) = new_test_env().await?;
        certified_history::initialize(&conn).await?;
        let (tx, mut rx) = mpsc::channel(1);
        env.upgrade_tx = tx.clone();
        let server = TestServer::new(
            Router::new()
                .route(
                    "/",
                    get(get_upgrade_state)
                        .post(post_upgrade)
                        .layer(DefaultBodyLimit::max(SUBMISSION_BODY_LIMIT)),
                )
                .with_state(env),
        );
        server
            .get("/")
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        server
            .post("/")
            .json(&json!({"envelope_hex":"zz"}))
            .await
            .assert_status_bad_request();
        server
            .post("/")
            .json(&json!({"envelope_hex":"0".repeat(SUBMISSION_BODY_LIMIT)}))
            .await
            .assert_status(StatusCode::PAYLOAD_TOO_LARGE);
        assert!(rx.try_recv().is_err());

        let vector: Value = serde_json::from_str(include_str!(
            "../../protocol/coordinator/control/test-vector.json"
        ))?;
        let request = json!({"envelope_hex":vector["control_hex"]});
        let envelope = decode_submission(SubmitUpgrade {
            envelope_hex: vector["control_hex"].as_str().unwrap().into(),
        })?;
        let (reply, _) = oneshot::channel();
        tx.try_send(UpgradeSubmission {
            envelope: envelope.clone(),
            reply,
        })
        .unwrap();
        server
            .post("/")
            .json(&request)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        rx.try_recv().unwrap();
        let receive = async {
            let submission = rx.recv().await.unwrap();
            assert_eq!(submission.envelope, envelope);
            submission
                .reply
                .send(Ok(QueuedUpgrade {
                    action_id: vector["action_id"].as_str().unwrap().into(),
                    control_id: vector["control_id"].as_str().unwrap().into(),
                    status: "queued".into(),
                }))
                .unwrap();
        };
        let (response, _) = tokio::join!(server.post("/").json(&request), receive);
        response.assert_status_ok();
        let body: Value = response.json();
        assert_eq!(body["result"]["status"], "queued");
        assert_eq!(body["result"]["action_id"], vector["action_id"]);
        drop(rx);
        server
            .post("/")
            .json(&request)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }
}
