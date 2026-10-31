use std::io;

use anyhow::{Result, ensure};
use bitcoin::Network;
use reqwest::Url;
use tokio::process::Child;

use crate::bitcoin_client::Client;
use crate::config::RegtestConfig;

pub(crate) enum WorkloadBitcoin {
    Owned(Child),
    External,
}

impl WorkloadBitcoin {
    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        match self {
            Self::Owned(child) => child.start_kill(),
            Self::External => Ok(()),
        }
    }

    pub(crate) async fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Owned(child) => child.kill().await,
            Self::External => Ok(()),
        }
    }

    pub(crate) async fn wait(&mut self) -> io::Result<()> {
        if let Self::Owned(child) = self {
            child.wait().await?;
        }
        Ok(())
    }
}

impl Drop for WorkloadBitcoin {
    fn drop(&mut self) {
        // Only the supervisor owns an external daemon. Test failure must not
        // orphan an owned child or terminate a separately supervised service.
        let _ = self.start_kill();
    }
}

fn endpoint(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some_and(|port| port > 0)
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "external workload Bitcoin must be an explicit loopback RPC endpoint"
    );
    Ok(url)
}

pub(super) async fn connect(value: &str) -> Result<(WorkloadBitcoin, Client)> {
    let url = endpoint(value)?;
    let client = Client::new_from_config(&RegtestConfig {
        bitcoin_rpc_url: url.to_string(),
        ..RegtestConfig::default()
    })?;
    let info = client.get_blockchain_info().await?;
    ensure!(
        info.chain == Network::Regtest && info.blocks == 0,
        "external workload Bitcoin must be a fresh regtest chain"
    );
    eprintln!("workload_external_bitcoin=true");
    Ok((WorkloadBitcoin::External, client))
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, ensure};
    use bitcoin::{Address, Network, ScriptBuf};
    use tempfile::TempDir;

    use super::{WorkloadBitcoin, connect, endpoint};
    use crate::bitcoin_client::client::RegtestRpc;
    use crate::reg_tester::run_bitcoin;

    #[test]
    fn workload_external_bitcoin_requires_loopback_endpoint() -> Result<()> {
        endpoint("http://127.0.0.1:18443")?;
        for value in [
            "http://example.com:18443",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://rpc:rpc@127.0.0.1:18443",
            "http://127.0.0.1:18443/wallet/a",
            "http://127.0.0.1:18443?x=1",
            "http://127.0.0.1:18443#x",
        ] {
            ensure!(endpoint(value).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires local bitcoind; external service ownership"]
    async fn workload_external_bitcoin_does_not_terminate_supervisor_owned_process() -> Result<()> {
        let directory = TempDir::new()?;
        let (child, client, url, _) = run_bitcoin(directory.path()).await?;
        let mut owned = WorkloadBitcoin::Owned(child);
        let (mut external, _) = connect(&url).await?;
        external.start_kill()?;
        external.kill().await?;
        external.wait().await?;
        drop(external);
        ensure!(client.get_blockchain_info().await?.blocks == 0);
        let address = Address::p2wsh(&ScriptBuf::from_bytes(vec![0x51]), Network::Regtest);
        client.generate_to_address(1, &address.to_string()).await?;
        ensure!(
            connect(&url).await.is_err(),
            "reused Bitcoin chain was accepted"
        );
        owned.kill().await?;
        Ok(())
    }
}
