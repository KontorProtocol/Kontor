use anyhow::{Result, anyhow};
use indexer_types::{
    CommitOutputs, ComposeOutputs, ContractResponse, ErrorResponse, Info, OpWithResult,
    ResultResponse, ResultRow, Reveal, RevealOutputs, SignerResponse, TransactionHex,
    TransactionRow, ViewExpr, ViewResult,
};
use reqwest::{Client as HttpClient, ClientBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

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

    /// Long-poll variant of `index`: the server holds the request until
    /// the indexer's `Info::signature` differs from `since`, or `wait_ms`
    /// elapse. Backs the regtest harness's `wait_for_txids`.
    pub async fn index_wait(&self, since: &str, wait_ms: u64) -> Result<Info> {
        // `since` is a sha256 hex digest — URL-safe, no escaping needed.
        let url = format!("{}?wait={}&since={}", &self.url, wait_ms, since);
        Self::handle_response(self.client.get(url).send().await?).await
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
}
