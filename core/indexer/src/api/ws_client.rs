use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use indexer_types::WsResponse;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

pub struct WebSocketClient {
    pub stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

pub fn from_message(m: Message) -> Result<WsResponse> {
    let text = m.to_text()?;
    Ok(serde_json::from_str(text)?)
}

impl WebSocketClient {
    pub async fn new(port: u16) -> Result<Self> {
        let url = format!("ws://localhost:{}/ws", port);
        let (stream, _) = connect_async(url).await?;
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

    pub async fn close(&mut self) -> Result<()> {
        self.stream.send(Message::Close(None)).await?;
        if self.stream.next().await.unwrap()?.is_close() {
            Ok(())
        } else {
            Err(anyhow!("Unexpected close response from server"))
        }
    }

    pub async fn next(&mut self) -> Result<WsResponse> {
        loop {
            let msg = self.stream.next().await.unwrap()?;
            if !msg.is_ping() {
                return from_message(msg);
            }
        }
    }
}
