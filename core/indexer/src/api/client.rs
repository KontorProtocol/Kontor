use anyhow::{Result, anyhow};
use reqwest::{Client as HttpClient, ClientBuilder, Response};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        compose::{ComposeAddressQuery, ComposeOutputs, ComposeQuery},
        error::ErrorResponse,
        handlers::{Info, ViewExpr},
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
        Self::new(format!("https://localhost:{}/api", config.api_port))
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
                .get(format!("{}{}", &self.url, "/stop"))
                .send()
                .await?,
        )
        .await
    }

    pub async fn compose(&self, query: ComposeAddressQuery) -> Result<ComposeOutputs> {
        let query = ComposeQuery {
            addresses: vec![query],
            sat_per_vbyte: 2,
            envelope: None,
            chained_script_data: None,
        };
        Self::handle_response(
            self.client
                .post(format!("{}/compose", &self.url))
                .json(&query)
                .send()
                .await?,
        )
        .await
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
                    "{}/view/{}_{}_{}",
                    &self.url,
                    contract_address.name,
                    contract_address.height,
                    contract_address.tx_index
                ))
                .json(&view_expr)
                .send()
                .await?,
        )
        .await
    }
}
