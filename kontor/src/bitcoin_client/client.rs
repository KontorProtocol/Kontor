use base64::prelude::*;
use bitcoin::{Block, BlockHash, Transaction, Txid, consensus::encode};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reqwest::{Client as HttpClient, ClientBuilder, header::HeaderMap};
use serde::Deserialize;
use serde_json::Value;

use crate::bitcoin_client::types::TestMempoolAcceptResult;
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
                headers.insert("Authorization", format!("Basic {}", auth_str).parse()?);
                headers.insert("Content-Type", "application/json".parse()?);
                headers.insert("Accept", "application/json".parse()?);
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
                vec![serde_json::to_value(txid)?, serde_json::to_value(false)?],
            )
            .await?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    pub async fn get_raw_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<Transaction, Error>>, Error> {
        let mut calls = vec![];
        for txid in txids {
            calls.push((
                "getrawtransaction".to_owned(),
                vec![serde_json::to_value(txid)?, serde_json::to_value(false)?],
            ))
        }
        let results: Vec<Result<String, Error>> = self.batch_call(calls).await?;
        Ok(results
            .into_par_iter()
            .map(|result| result.and_then(|hex| Ok(encode::deserialize_hex::<Transaction>(&hex)?)))
            .collect())
    }

    pub async fn test_mempool_accept(
        &self,
        raw_txs: &[String],
    ) -> Result<Vec<TestMempoolAcceptResult>, Error> {
        self.call("testmempoolaccept", vec![raw_txs.into()]).await
    }
}

pub trait BitcoinRpc: Send + Sync + Clone + 'static {
    fn get_blockchain_info(&self) -> impl std::future::Future<Output = Result<GetBlockchainInfoResult, Error>> + std::marker::Send;

    fn get_block_hash(&self, height: u64) -> impl std::future::Future<Output = Result<BlockHash, Error>> + std::marker::Send;

    fn get_block(&self, hash: &BlockHash) -> impl std::future::Future<Output = Result<Block, Error>> + std::marker::Send;

    fn get_raw_transaction(&self, txid: &Txid) -> impl std::future::Future<Output = Result<Transaction, Error>> + std::marker::Send;
}

impl BitcoinRpc for Client {
    async fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, Error> {
        self.get_blockchain_info().await
    }
    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        self.get_block_hash(height).await
    }
    async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        self.get_block(hash).await
    }
    async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, Error> {
        self.get_raw_transaction(txid).await
    }
}
