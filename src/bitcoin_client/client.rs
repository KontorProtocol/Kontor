use base64::prelude::*;
use bitcoin::{Block, BlockHash, Transaction, Txid, consensus::encode};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reqwest::{Client as HttpClient, ClientBuilder, header::HeaderMap};
use serde::Deserialize;
use serde_json::Value;

use crate::config::Config;

use super::{
    error::{BitcoinRpcErrorResponse, Error},
    types::{GetBlockchainInfoResult, Request, Response},
};

#[derive(Clone, Debug)]
pub struct Client {
    client: HttpClient,
    url: String,
}

const JSONRPC: &str = "2.0";

impl Client {
    pub fn new(url: String, user: String, password: String) -> Result<Self, Error> {
        let client = ClientBuilder::new()
            .default_headers({
                let mut headers = HeaderMap::new();
                let auth_str = BASE64_STANDARD.encode(format!("{}:{}", user, password));
                headers.insert(
                    "Authorization",
                    format!("Basic {}", auth_str).parse().unwrap(),
                );
                headers.insert("Content-Type", "application/json".parse().unwrap());
                headers.insert("Accept", "application/json".parse().unwrap());
                headers
            })
            .build()?;

        Ok(Client { client, url })
    }

    pub fn new_from_config(config: Config) -> Result<Self, Error> {
        Client::new(
            config.bitcoin_rpc_url,
            config.bitcoin_rpc_user,
            config.bitcoin_rpc_password,
        )
    }

    fn handle_response<T>(response: Response) -> Result<T, Error>
    where
        T: for<'de> Deserialize<'de>,
    {
        match (response.result, response.error) {
            (Some(result), None) => Ok(serde_json::from_value(result)?),
            (None, Some(error)) => {
                let detail: BitcoinRpcErrorResponse = serde_json::from_value(error)?;
                Err(Error::BitcoinRpc {
                    code: detail.code,
                    message: detail.message,
                })
            }
            (None, None) => Err(Error::Unexpected(
                "No result or error in RPC response".to_string(),
            )),
            (Some(_), Some(_)) => Err(Error::Unexpected(
                "Both result and error present in RPC response".to_string(),
            )),
        }
    }

    pub async fn call<T>(&self, method: &str, params: Vec<Value>) -> Result<T, Error>
    where
        T: for<'de> Deserialize<'de>,
    {
        let request = Request {
            jsonrpc: JSONRPC.to_owned(),
            id: "0".to_string(),
            method: method.to_string(),
            params,
        };

        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await?
            .json::<Response>()
            .await?;

        Self::handle_response(response)
    }

    pub async fn batch_call<T>(
        &self,
        calls: Vec<(String, Vec<Value>)>,
    ) -> Result<Vec<Result<T, Error>>, Error>
    where
        T: for<'de> Deserialize<'de>,
    {
        let requests: Vec<Request> = calls
            .into_iter()
            .enumerate()
            .map(|(i, (method, params))| Request {
                jsonrpc: JSONRPC.to_owned(),
                id: format!("{}", i),
                method: method.to_owned(),
                params,
            })
            .collect();

        let responses = self
            .client
            .post(&self.url)
            .json(&requests)
            .send()
            .await?
            .json::<Vec<Response>>()
            .await?;

        Ok(responses.into_iter().map(Self::handle_response).collect())
    }

    pub async fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, Error> {
        self.call("getblockchaininfo", vec![]).await
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        self.call("getblockhash", vec![height.into()]).await
    }

    pub async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        let hex: String = self
            .call("getblock", vec![serde_json::to_value(hash)?, 0.into()])
            .await?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    pub async fn get_raw_mempool(&self) -> Result<Vec<Txid>, Error> {
        self.call("getrawmempool", vec![]).await
    }

    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, Error> {
        let hex: String = self
            .call(
                "getrawtransaction",
                vec![
                    serde_json::to_value(txid).unwrap(),
                    serde_json::to_value(false).unwrap(),
                ],
            )
            .await?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    pub async fn get_raw_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<Transaction, Error>>, Error> {
        let calls = txids
            .iter()
            .map(|txid| {
                (
                    "getrawtransaction".to_owned(),
                    vec![
                        serde_json::to_value(txid).unwrap(),
                        serde_json::to_value(false).unwrap(),
                    ],
                )
            })
            .collect();
        let results: Vec<Result<String, Error>> = self.batch_call(calls).await?;
        Ok(results
            .into_par_iter()
            .map(|result| result.and_then(|hex| Ok(encode::deserialize_hex::<Transaction>(&hex)?)))
            .collect())
    }
}
