use std::sync::Arc;

use anyhow::{Result, anyhow};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async, connect_async_tls_with_config,
    tungstenite::Message,
};
use tracing::info;
use uuid::Uuid;

use crate::{
    api::ws::{Request, Response},
    config::Config,
    database::types::OpResultId,
    reactor::results::ResultEventFilter,
};

pub struct WebSocketClient {
    pub stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

fn to_message<T>(value: &T) -> Result<Message>
where
    T: ?Sized + Serialize,
{
    let s = serde_json::to_string(value)?;
    Ok(Message::Text(s.into()))
}

pub fn from_message(m: Message) -> Result<Response> {
    let text = m.to_text()?;
    info!("Received message: {}", text);
    Ok(serde_json::from_str(text)?)
}

impl WebSocketClient {
    pub async fn new() -> Result<Self> {
        let config = Config::try_parse()?;
        let url = format!("localhost:{}/ws", config.api_port);
        let stream = if config.should_use_tls() {
            let url = format!("wss://{}", url);
            let mut root_store = RootCertStore::empty();
            #[cfg(not(windows))]
            {
                let certs = rustls_native_certs::load_native_certs().unwrap();
                for cert in certs {
                    root_store.add(cert)?;
                }
            }
            #[cfg(windows)]
            {
                use std::env;
                use std::fs;
                use std::io::BufReader;

                let cert_file_path =
                    env::var("ROOT_CA_FILE").expect("ROOT_CA_FILE env var not set on Windows");
                let cert_file = fs::File::open(cert_file_path)?;
                let mut reader = BufReader::new(cert_file);
                let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
                root_store.add_parsable_certificates(certs);
            }

            let connector = Connector::Rustls(Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            ));
            let (stream, _) =
                connect_async_tls_with_config(url, None, false, Some(connector)).await?;
            stream
        } else {
            let url = format!("ws://{}", url);
            let (stream, _) = connect_async(url).await?;
            stream
        };

        Ok(WebSocketClient { stream })
    }

    pub async fn ping(&mut self) -> Result<()> {
        let data = "echo";
        self.stream.send(Message::Ping(data.into())).await?;
        if let Message::Pong(bs) = self.stream.next().await.unwrap()?
            && data == str::from_utf8(&bs)?
        {
            Ok(())
        } else {
            Err(anyhow!("Unexpected pong"))
        }
    }

    pub async fn subscribe(&mut self, id: &OpResultId) -> Result<Uuid> {
        self.stream
            .send(to_message(&Request::Subscribe {
                filter: ResultEventFilter::OpResultId(id.clone()),
            })?)
            .await?;
        if let Response::SubscribeResponse {
            id: subscription_id,
        } = from_message(self.stream.next().await.unwrap()?)?
        {
            info!("Subscribed to op result id {} @ {}", id, subscription_id);
            Ok(subscription_id)
        } else {
            Err(anyhow!("Unexpected subscribe response from server"))
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        self.stream.send(Message::Close(None)).await?;
        if self.stream.next().await.unwrap()?.is_close() {
            Ok(())
        } else {
            Err(anyhow!("Unexpected close response from server"))
        }
    }

    pub async fn next(&mut self) -> Result<Response> {
        from_message(self.stream.next().await.unwrap()?)
    }
}
