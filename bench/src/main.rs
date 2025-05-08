
#![feature(test)]

extern crate test;

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use anyhow::Result;
use httpmock::prelude::*;
use rand::prelude::*;

use bitcoin::{ Txid };
use bitcoin::hashes::{ Hash };
use tokio::runtime::Runtime;

use kontor::{
    bitcoin_client::Client,
    bitcoin_client::types::{Response},
};

fn rand_txid() -> Result<Txid> {
    let mut data = [0u8; 32];
    rand::rng().fill_bytes(&mut data);

    Ok(Txid::from_slice(&data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[tokio::test]
    async fn poorman_benchmark_getrawmempool() -> Result<()> {
        let server = MockServer::start();

        let mut txs = HashMap::new();
        for _ in 0..200000 { // 200k
            txs.insert(rand_txid().unwrap(), "");
        }
        let size = txs.len();

        let hello_mock = server.mock(|_, then| {
            let resp = Response {
                result: Some(serde_json::to_value::<Vec<Txid>>(
                                txs.into_keys().collect()).unwrap()),
                error: None,
                id: "".to_string(),
            };

            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&resp);
        });


        let start_time = SystemTime::now();

        let client = Client::new(server.url(""), "".to_string(), "".to_string())?;
        let txs = client.get_raw_mempool().await?;

        let duration = SystemTime::now()
            .duration_since(start_time)
            .unwrap_or(Duration::from_secs(0));

        assert_eq!(size, txs.len());
        println!("fetched {} txids in {:?}s", txs.len(), duration.as_secs_f64());
        hello_mock.assert();

        Ok(())
    }


    // this works but isn't a great fit for a slow query; b.iter() insists on running
    // many samples (on the order of 100) which makes the benchmark very slow.
    #[bench]
    fn benchmark_getrawmempool(b: &mut Bencher) {
        let server = MockServer::start();

        let mut txs = HashMap::new();
        for _ in 0..20000 { // 20k
            txs.insert(rand_txid().unwrap(), "");
        }
        let size = txs.len();

        server.mock(|_, then| {
            let resp = Response {
                result: Some(serde_json::to_value::<Vec<Txid>>(
                                txs.into_keys().collect()).unwrap()),
                error: None,
                id: "".to_string(),
            };

            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&resp);
        });


        let client = Client::new(server.url(""), "".to_string(), "".to_string()).unwrap();

        b.iter(|| {
            let indexes = Runtime::new().unwrap().block_on(client.get_raw_mempool()).unwrap();
            assert_eq!(size, indexes.len());
        });

    }
}

fn main() { // placeholder
}

