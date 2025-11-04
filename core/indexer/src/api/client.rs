use anyhow::{Result, anyhow};
use reqwest::{Client as HttpClient, ClientBuilder, Response};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        compose::{ComposeOutputs, ComposeQuery},
        error::ErrorResponse,
        handlers::{Info, OpWithResult, TransactionHex, ViewExpr, WitResponse},
        result::ResultResponse,
    },
    config::Config,
    reactor::results::ResultEvent,
    runtime::ContractAddress,
};

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
        let proto = if config.should_use_tls() {
            "https"
        } else {
            "http"
        };
        Self::new(format!("{}://localhost:{}/api", proto, config.api_port))
    }

    async fn handle_response<T: Serialize + for<'a> Deserialize<'a>>(res: Response) -> Result<T> {
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

    pub async fn stop(&self) -> Result<Info> {
        Self::handle_response(
            self.client
                .get(format!("{}/stop", &self.url))
                .send()
                .await?,
        )
        .await
    }

    pub async fn compose(&self, query: ComposeQuery) -> Result<ComposeOutputs> {
        Self::handle_response(
            self.client
                .post(format!("{}/compose", &self.url))
                .json(&query)
                .send()
                .await?,
        )
        .await
    }

    pub async fn transaction_ops(&self, tx_hex: TransactionHex) -> Result<Vec<OpWithResult>> {
        Self::handle_response(
            self.client
                .post(format!("{}/transactions/ops", &self.url))
                .json(&tx_hex)
                .send()
                .await?,
        )
        .await
    }

    fn contract_address_string(contract_address: &ContractAddress) -> String {
        format!(
            "{}_{}_{}",
            contract_address.name, contract_address.height, contract_address.tx_index
        )
    }

    pub async fn view(
        &self,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<ResultEvent> {
        let view_expr = ViewExpr {
            expr: expr.to_string(),
        };
        Self::handle_response(
            self.client
                .post(format!(
                    "{}/view/{}",
                    &self.url,
                    Self::contract_address_string(contract_address)
                ))
                .json(&view_expr)
                .send()
                .await?,
        )
        .await
    }

    pub async fn wit(&self, contract_address: &ContractAddress) -> Result<WitResponse> {
        Self::handle_response(
            self.client
                .get(format!(
                    "{}/wit/{}",
                    &self.url,
                    Self::contract_address_string(contract_address)
                ))
                .send()
                .await?,
        )
        .await
    }
}
