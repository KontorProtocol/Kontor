use base64::prelude::*;
use bitcoin::Amount;
use bitcoin::{Block, BlockHash, Transaction, Txid, consensus::encode};
use moka::future::Cache;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reqwest::{Client as HttpClient, ClientBuilder, header::HeaderMap};
use serde::Deserialize;
use serde_json::Value;

use crate::bitcoin_client::types::{
    CreateWalletResult, GetMempoolInfoResult, GetNetworkInfoResult, GetRawMempoolResult,
    TestMempoolAcceptResult,
};
use crate::config::{Config, RegtestConfig};

use super::types::{RawTransactionInput, SignRawTransactionResult, UnspentOutput};
use super::{
    error::{BitcoinRpcErrorResponse, Error},
    types::{GetBlockchainInfoResult, Request, Response},
};

/// Shared transaction cache. Moka's Cache is internally Arc-ed, so Clone
/// gives a handle to the same underlying cache.
pub type TxCache = Cache<Txid, Transaction>;

const TX_CACHE_CAPACITY: u64 = 10_000;

pub fn new_tx_cache() -> TxCache {
    Cache::builder().max_capacity(TX_CACHE_CAPACITY).build()
}

#[derive(Clone, Debug)]
pub struct Client {
    client: HttpClient,
    url: String,
    tx_cache: TxCache,
}

const JSONRPC: &str = "2.0";

pub trait BitcoinRpcConfig {
    fn bitcoin_rpc_url(&self) -> &str;
    fn bitcoin_rpc_user(&self) -> &str;
    fn bitcoin_rpc_password(&self) -> &str;
}

impl BitcoinRpcConfig for Config {
    fn bitcoin_rpc_url(&self) -> &str {
        &self.bitcoin_rpc_url
    }
    fn bitcoin_rpc_user(&self) -> &str {
        &self.bitcoin_rpc_user
    }
    fn bitcoin_rpc_password(&self) -> &str {
        &self.bitcoin_rpc_password
    }
}

impl BitcoinRpcConfig for RegtestConfig {
    fn bitcoin_rpc_url(&self) -> &str {
        &self.bitcoin_rpc_url
    }
    fn bitcoin_rpc_user(&self) -> &str {
        &self.bitcoin_rpc_user
    }
    fn bitcoin_rpc_password(&self) -> &str {
        &self.bitcoin_rpc_password
    }
}

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

        Ok(Client {
            client,
            url,
            tx_cache: new_tx_cache(),
        })
    }

    pub fn new_from_config<C: BitcoinRpcConfig>(config: &C) -> Result<Self, Error> {
        Client::new(
            config.bitcoin_rpc_url().to_owned(),
            config.bitcoin_rpc_user().to_owned(),
            config.bitcoin_rpc_password().to_owned(),
        )
    }

    pub fn tx_cache(&self) -> &TxCache {
        &self.tx_cache
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
        let block: Block = encode::deserialize_hex(&hex)?;
        for tx in &block.txdata {
            self.tx_cache.insert(tx.compute_txid(), tx.clone()).await;
        }
        Ok(block)
    }

    pub async fn get_raw_mempool(&self) -> Result<Vec<Txid>, Error> {
        self.call("getrawmempool", vec![]).await
    }

    pub async fn get_raw_mempool_sequence(&self) -> Result<GetRawMempoolResult, Error> {
        self.call("getrawmempool", vec![false.into(), true.into()])
            .await
    }

    pub async fn get_mempool_info(&self) -> Result<GetMempoolInfoResult, Error> {
        self.call("getmempoolinfo", vec![]).await
    }

    pub async fn get_network_info(&self) -> Result<GetNetworkInfoResult, Error> {
        self.call("getnetworkinfo", vec![]).await
    }

    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, Error> {
        if let Some(tx) = self.tx_cache.get(txid).await {
            return Ok(tx);
        }
        let hex: String = self
            .call(
                "getrawtransaction",
                vec![serde_json::to_value(txid)?, serde_json::to_value(false)?],
            )
            .await?;
        let tx: Transaction = encode::deserialize_hex(&hex)?;
        self.tx_cache.insert(*txid, tx.clone()).await;
        Ok(tx)
    }

    pub async fn get_raw_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<Transaction, Error>>, Error> {
        // Check cache first, collect misses
        let mut results: Vec<Option<Result<Transaction, Error>>> = Vec::with_capacity(txids.len());
        let mut miss_indices = Vec::new();
        for (i, txid) in txids.iter().enumerate() {
            if let Some(tx) = self.tx_cache.get(txid).await {
                results.push(Some(Ok(tx)));
            } else {
                results.push(None);
                miss_indices.push(i);
            }
        }

        if !miss_indices.is_empty() {
            let mut calls = Vec::with_capacity(miss_indices.len());
            for &i in &miss_indices {
                calls.push((
                    "getrawtransaction".to_owned(),
                    vec![
                        serde_json::to_value(txids[i])?,
                        serde_json::to_value(false)?,
                    ],
                ));
            }
            let rpc_results: Vec<Result<String, Error>> = self.batch_call(calls).await?;
            let parsed: Vec<Result<Transaction, Error>> = rpc_results
                .into_par_iter()
                .map(|r| r.and_then(|hex| Ok(encode::deserialize_hex::<Transaction>(&hex)?)))
                .collect();

            for (parsed_result, &orig_idx) in parsed.into_iter().zip(miss_indices.iter()) {
                if let Ok(ref tx) = parsed_result {
                    self.tx_cache.insert(txids[orig_idx], tx.clone()).await;
                }
                results[orig_idx] = Some(parsed_result);
            }
        }

        Ok(results.into_iter().map(|r| r.unwrap()).collect())
    }

    pub async fn test_mempool_accept(
        &self,
        raw_txs: &[String],
    ) -> Result<Vec<TestMempoolAcceptResult>, Error> {
        self.call("testmempoolaccept", vec![raw_txs.into()]).await
    }

    pub async fn stop(&self) -> Result<String, Error> {
        self.call("stop", vec![]).await
    }
}

pub trait BitcoinRpc: Send + Sync + Clone + 'static {
    fn get_blockchain_info(
        &self,
    ) -> impl Future<Output = Result<GetBlockchainInfoResult, Error>> + Send;

    fn get_block_hash(&self, height: u64) -> impl Future<Output = Result<BlockHash, Error>> + Send;

    fn get_block(&self, hash: &BlockHash) -> impl Future<Output = Result<Block, Error>> + Send;

    fn get_raw_mempool(&self) -> impl Future<Output = Result<Vec<Txid>, Error>> + Send;

    fn get_raw_mempool_sequence(
        &self,
    ) -> impl Future<Output = Result<GetRawMempoolResult, Error>> + Send;

    fn get_raw_transaction(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Transaction, Error>> + Send;

    fn get_raw_transactions(
        &self,
        txids: &[Txid],
    ) -> impl Future<Output = Result<Vec<Result<Transaction, Error>>, Error>> + Send;
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
    async fn get_raw_mempool(&self) -> Result<Vec<Txid>, Error> {
        self.get_raw_mempool().await
    }
    async fn get_raw_mempool_sequence(&self) -> Result<GetRawMempoolResult, Error> {
        self.get_raw_mempool_sequence().await
    }
    async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, Error> {
        self.get_raw_transaction(txid).await
    }
    async fn get_raw_transactions(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Result<Transaction, Error>>, Error> {
        self.get_raw_transactions(txids).await
    }
}

pub trait RegtestRpc: Send + Sync + Clone + 'static {
    fn create_wallet(&self, name: &str) -> impl Future<Output = Result<CreateWalletResult, Error>>;

    fn load_wallet(&self, name: &str) -> impl Future<Output = Result<(), Error>>;

    fn get_new_address(&self) -> impl Future<Output = Result<String, Error>>;

    fn generate_to_address(
        &self,
        blocks: u64,
        address: &str,
    ) -> impl Future<Output = Result<Vec<String>, Error>>;

    fn get_balance(&self) -> impl Future<Output = Result<f64, Error>>;

    fn send_to_address(
        &self,
        address: &str,
        amount: Amount,
    ) -> impl Future<Output = Result<String, Error>>;

    fn send_to_address_with_options(
        &self,
        address: &str,
        amount: Amount,
    ) -> impl Future<Output = Result<String, Error>>;

    fn list_unspent(
        &self,
        min_conf: u32,
        addresses: &[String],
    ) -> impl Future<Output = Result<Vec<UnspentOutput>, Error>>;

    fn list_wallets(&self) -> impl Future<Output = Result<Vec<String>, Error>>;

    fn get_immature_balance(&self) -> impl Future<Output = Result<f64, Error>>;

    fn get_unconfirmed_balance(&self) -> impl Future<Output = Result<f64, Error>>;

    fn create_raw_transaction(
        &self,
        inputs: &[RawTransactionInput],
        outputs: &std::collections::HashMap<String, f64>,
        locktime: Option<u32>,
        replaceable: Option<bool>,
    ) -> impl Future<Output = Result<String, Error>>;

    fn sign_raw_transaction_with_wallet(
        &self,
        raw_tx: &str,
    ) -> impl Future<Output = Result<SignRawTransactionResult, Error>>;

    fn send_raw_transaction(&self, raw_tx: &str) -> impl Future<Output = Result<String, Error>>;
}

impl RegtestRpc for Client {
    async fn create_wallet(&self, name: &str) -> Result<CreateWalletResult, Error> {
        let params = vec![name.into()];
        let result: CreateWalletResult = self.call("createwallet", params).await?;
        Ok(result)
    }

    async fn load_wallet(&self, name: &str) -> Result<(), Error> {
        let params = vec![name.into()];
        self.call::<()>("loadwallet", params).await?;
        Ok(())
    }

    async fn get_new_address(&self) -> Result<String, Error> {
        self.call("getnewaddress", vec![]).await
    }

    async fn generate_to_address(&self, blocks: u64, address: &str) -> Result<Vec<String>, Error> {
        let params = vec![blocks.into(), address.into()];
        self.call("generatetoaddress", params).await
    }

    async fn get_balance(&self) -> Result<f64, Error> {
        let balance: f64 = self.call("getbalance", vec![]).await?;
        Ok(balance)
    }

    async fn send_to_address(&self, address: &str, amount: Amount) -> Result<String, Error> {
        let params = vec![address.into(), amount.to_sat().into()];
        self.call("sendtoaddress", params).await
    }

    async fn send_to_address_with_options(
        &self,
        address: &str,
        amount: Amount,
    ) -> Result<String, Error> {
        let params = vec![address.into(), amount.to_sat().into()];
        self.call("sendtoaddress", params).await
    }

    async fn list_unspent(
        &self,
        min_conf: u32,
        addresses: &[String],
    ) -> Result<Vec<UnspentOutput>, Error> {
        let params = vec![min_conf.into(), 9999999.into(), addresses.into()];
        self.call("listunspent", params).await
    }

    async fn list_wallets(&self) -> Result<Vec<String>, Error> {
        self.call("listwallets", vec![]).await
    }

    async fn get_immature_balance(&self) -> Result<f64, Error> {
        self.call("getimmaturebalance", vec![]).await
    }

    async fn get_unconfirmed_balance(&self) -> Result<f64, Error> {
        self.call("getunconfirmedbalance", vec![]).await
    }

    async fn create_raw_transaction(
        &self,
        inputs: &[RawTransactionInput],
        outputs: &std::collections::HashMap<String, f64>,
        locktime: Option<u32>,
        replaceable: Option<bool>,
    ) -> Result<String, Error> {
        let params = vec![
            serde_json::to_value(inputs)?,
            serde_json::to_value(outputs)?,
            locktime.into(),
            replaceable.into(),
        ];
        self.call("createrawtransaction", params).await
    }

    async fn sign_raw_transaction_with_wallet(
        &self,
        raw_tx: &str,
    ) -> Result<SignRawTransactionResult, Error> {
        let params = vec![raw_tx.into()];
        self.call("signrawtransactionwithwallet", params).await
    }

    async fn send_raw_transaction(&self, raw_tx: &str) -> Result<String, Error> {
        let params = vec![raw_tx.into()];
        self.call("sendrawtransaction", params).await
    }
}
