use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64_engine;
use reqwest::{Client as HttpClient, ClientBuilder, Response};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        compose::{ComposeAddressQuery, ComposeOutputs},
        error::ErrorResponse,
        handlers::Info,
        result::ResultResponse,
    },
    config::Config,
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
        let json_bytes = serde_json::to_vec(&[query])?;
        let addresses_b64 = base64_engine.encode(json_bytes);
        Self::handle_response(
            self.client
                .get(format!(
                    "{}/compose?addresses={}&sat_per_vbyte=2",
                    &self.url,
                    urlencoding::encode(&addresses_b64),
                ))
                .send()
                .await?,
        )
        .await
    }
}
