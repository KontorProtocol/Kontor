use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use tracing::info;
use uuid::Uuid;

use crate::{
    api::ws::{Request, Response},
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
