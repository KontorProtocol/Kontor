use anyhow::{Result, anyhow};
use indexer_types::{
    CheckpointRow, CommitOutputs, ComposeOutputs, ContractProvenanceResponse, ContractResponse,
    ErrorResponse, FootprintResponse, Info, OpWithResult, ResultResponse, ResultRow, Reveal,
    RevealOutputs, SignerResponse, TransactionHex, TransactionRow, ViewExpr, ViewResult,
};
use reqwest::{Client as HttpClient, ClientBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use std::ops::Deref;

use crate::api::handlers::NodeStatus;
use crate::retry::retry_extended;
use crate::{config::Config, database::types::OpResultId, runtime::ContractAddress};

#[derive(Clone, Debug)]
pub struct Client {
    client: HttpClient,
    url: String,
}

impl Client {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Client {
            client,
            url: base_url.into(),
        })
    }

    pub fn new_from_config(config: &Config) -> Result<Self> {
        Self::new(format!("http://localhost:{}/api", config.api_port))
    }

    async fn handle_response<T: Serialize + for<'a> Deserialize<'a> + TS>(
        res: Response,
    ) -> Result<T> {
        if res.status().is_success() {
            let result: ResultResponse<T> = res.json().await?;
            Ok(result.result)
        } else {
            let error: ErrorResponse = res.json().await?;
            Err(anyhow!(error.error))
        }
    }

    pub async fn index(&self) -> Result<Info> {
        Self::handle_response(self.client.get(&self.url).send().await?).await
    }

    /// Node status. Unlike `index`, this is not gated by availability, so it
    /// answers during bootstrap (before quorum exists) — used to read back a
    /// node's resolved `consensus_listen_addr`.
    pub async fn status(&self) -> Result<NodeStatus> {
        Ok(self
            .client
            .get(format!("{}/status", &self.url))
            .send()
            .await?
            .json::<NodeStatus>()
            .await?)
    }

    /// Long-poll variant of `index`: the server holds the request until
    /// the indexer's `Info::signature` differs from `since`, or `wait_ms`
    /// elapse. Backs the regtest harness's `wait_for_txids`.
    pub async fn index_wait(&self, since: &str, wait_ms: u64) -> Result<Info> {
        // `since` is a sha256 hex digest — URL-safe, no escaping needed.
        let url = format!("{}?wait={}&since={}", &self.url, wait_ms, since);
        Self::handle_response(self.client.get(url).send().await?).await
    }

    /// The node's checkpoint as of `height` (latest checkpoint at or before it).
    pub async fn checkpoint_at(&self, height: u64) -> Result<CheckpointRow> {
        Self::handle_response(
            self.client
                .get(format!("{}/checkpoints/{height}", &self.url))
                .send()
                .await?,
        )
        .await
    }

    pub async fn compose(&self, reveal: Reveal) -> Result<ComposeOutputs> {
        Self::handle_response(
            self.client
                .post(format!("{}/transactions/compose", &self.url))
                .json(&reveal)
                .send()
                .await?,
        )
        .await
    }

    pub async fn compose_commit(&self, reveal: Reveal) -> Result<CommitOutputs> {
        Self::handle_response(
            self.client
                .post(format!("{}/transactions/compose/commit", &self.url))
                .json(&reveal)
                .send()
                .await?,
        )
        .await
    }

    pub async fn compose_reveal(&self, reveal: Reveal) -> Result<RevealOutputs> {
        Self::handle_response(
            self.client
                .post(format!("{}/transactions/compose/reveal", &self.url))
                .json(&reveal)
                .send()
                .await?,
        )
        .await
    }

    pub async fn transaction_hex_inspect(
        &self,
        tx_hex: TransactionHex,
    ) -> Result<Vec<OpWithResult>> {
        Self::handle_response(
            self.client
                .post(format!("{}/transactions/inspect", &self.url))
                .json(&tx_hex)
                .send()
                .await?,
        )
        .await
    }

    pub async fn transaction_simulate(&self, tx_hex: TransactionHex) -> Result<Vec<OpWithResult>> {
        Self::handle_response(
            self.client
                .post(format!("{}/transactions/simulate", &self.url))
                .json(&tx_hex)
                .send()
                .await?,
        )
        .await
    }

    pub async fn transaction_inspect(&self, txid: &bitcoin::Txid) -> Result<Vec<OpWithResult>> {
        Self::handle_response(
            self.client
                .get(format!("{}/transactions/{}/inspect", &self.url, txid))
                .send()
                .await?,
        )
        .await
    }

    pub async fn view(&self, contract_address: &ContractAddress, expr: &str) -> Result<ViewResult> {
        let view_expr = ViewExpr {
            expr: expr.to_string(),
        };
        Self::handle_response(
            self.client
                .post(format!("{}/contracts/{}", &self.url, contract_address))
                .json(&view_expr)
                .send()
                .await?,
        )
        .await
    }

    pub async fn wit(&self, contract_address: &ContractAddress) -> Result<ContractResponse> {
        Self::handle_response(
            self.client
                .get(format!("{}/contracts/{}", &self.url, contract_address))
                .send()
                .await?,
        )
        .await
    }

    pub async fn provenance(
        &self,
        contract_address: &ContractAddress,
    ) -> Result<ContractProvenanceResponse> {
        Self::handle_response(
            self.client
                .get(format!(
                    "{}/contracts/{}/provenance",
                    &self.url, contract_address
                ))
                .send()
                .await?,
        )
        .await
    }

    pub async fn result(&self, id: &OpResultId) -> Result<Option<ResultRow>> {
        Self::handle_response(
            self.client
                .get(format!("{}/results/{}", &self.url, id))
                .send()
                .await?,
        )
        .await
    }

    /// Fetch an indexed transaction by txid. `None` when the indexer has
    /// not processed it yet (the endpoint 404s).
    pub async fn transaction(&self, txid: &str) -> Result<Option<TransactionRow>> {
        let res = self
            .client
            .get(format!("{}/transactions/{}", &self.url, txid))
            .send()
            .await?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::handle_response(res).await.map(Some)
    }

    pub async fn signer(&self, identifier: &str) -> Result<SignerResponse> {
        Self::handle_response(
            self.client
                .get(format!("{}/signers/{}", &self.url, identifier))
                .send()
                .await?,
        )
        .await
    }

    /// The signer's storage-deposit footprint (`/signers/{identifier}/footprint`).
    /// `None` on 404 (signer not found), like `signer_opt`.
    pub async fn signer_footprint(&self, identifier: &str) -> Result<Option<FootprintResponse>> {
        let res = self
            .client
            .get(format!("{}/signers/{}/footprint", &self.url, identifier))
            .send()
            .await?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::handle_response(res).await.map(Some)
    }

    /// Like `signer`, but `None` on 404 (identity genuinely not registered / not yet
    /// indexed) — so a caller can distinguish "absent" from a transport/5xx failure,
    /// which still surfaces as an error rather than masquerading as "not registered".
    pub async fn signer_opt(&self, identifier: &str) -> Result<Option<SignerResponse>> {
        let res = self
            .client
            .get(format!("{}/signers/{}", &self.url, identifier))
            .send()
            .await?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::handle_response(res).await.map(Some)
    }
}

/// Test-harness wrapper around [`Client`] that retries transient transport
/// failures (connection refused/reset/timeout, transient 5xx) on the
/// steady-state reads the regtest harness makes under heavy parallel CI load.
/// Only `Err` results retry: a 404 (`Ok(None)` from `transaction`/`result`) or a
/// contract-level `ViewResult::Err` is a valid answer and passes through, so the
/// `wait_for_txids` polling loop is unaffected. Reads not listed here (e.g.
/// `signer`, where absence is under test) and all writes (`compose*`, broadcast)
/// fall through to the inner `Client` unchanged via `Deref`.
#[derive(Clone)]
pub struct RetryClient(Client);

impl RetryClient {
    pub fn new(inner: Client) -> Self {
        Self(inner)
    }

    pub async fn index(&self) -> Result<Info> {
        retry_extended(|| self.0.index()).await
    }

    pub async fn index_wait(&self, since: &str, wait_ms: u64) -> Result<Info> {
        retry_extended(|| self.0.index_wait(since, wait_ms)).await
    }

    pub async fn transaction(&self, txid: &str) -> Result<Option<TransactionRow>> {
        retry_extended(|| self.0.transaction(txid)).await
    }

    pub async fn view(&self, contract_address: &ContractAddress, expr: &str) -> Result<ViewResult> {
        retry_extended(|| self.0.view(contract_address, expr)).await
    }

    pub async fn result(&self, id: &OpResultId) -> Result<Option<ResultRow>> {
        retry_extended(|| self.0.result(id)).await
    }

    pub async fn wit(&self, contract_address: &ContractAddress) -> Result<ContractResponse> {
        retry_extended(|| self.0.wit(contract_address)).await
    }
}

impl Deref for RetryClient {
    type Target = Client;

    fn deref(&self) -> &Client {
        &self.0
    }
}
