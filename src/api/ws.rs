use std::net::SocketAddr;

use axum::{
    Extension,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{self, WebSocket},
    },
    response::IntoResponse,
};
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use tokio::select;
use tower_http::request_id::RequestId;
use tracing::{Instrument, info, info_span, warn};

use crate::utils::ControlFlow;

use super::Env;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    Test { message: String },
    Error { error: String },
}

pub fn handle_message(ws_msg: Message) -> Option<Message> {
    match ws_msg {
        Message::Test { message } => {
            info!("Received test message: {}", message);
            Some(Message::Test { message })
        }
        Message::Error { .. } => None,
    }
}

pub async fn handle_socket_message(socket: &mut WebSocket, message: ws::Message) -> ControlFlow {
    match message {
        ws::Message::Text(text) => match serde_json::from_str::<Message>(&text) {
            Ok(msg) => {
                if let Some(response) = handle_message(msg) {
                    let response_json = serde_json::to_string(&response)
                        .expect("Failed to serialize response despite being created internally");
                    if socket
                        .send(ws::Message::Text(response_json.into()))
                        .await
                        .is_err()
                    {
                        warn!("Failed to send message: connection closed");
                        return ControlFlow::Break;
                    }
                }
            }
            Err(e) => {
                warn!("Invalid message: {}", e);
                let error = Message::Error {
                    error: format!("Invalid message: {}", e),
                };
                let error_json = serde_json::to_string(&error)
                    .expect("Failed to serialize error despite being created internally");
                if socket
                    .send(ws::Message::Text(error_json.into()))
                    .await
                    .is_err()
                {
                    warn!("Failed to send error: connection closed");
                    return ControlFlow::Break;
                }
            }
        },
        ws::Message::Ping(data) => {
            info!("Received ping message");
            if socket.send(ws::Message::Pong(data)).await.is_err() {
                warn!("Failed to send pong: connection closed");
                return ControlFlow::Break;
            }
        }
        ws::Message::Close(_close) => {
            info!("Received close message");
            return ControlFlow::Break;
        }
        other => {
            info!("Received unsupported message type: {:?}", other);
            let error = Message::Error {
                error: "Only text messages supported".to_string(),
            };
            let error_json = serde_json::to_string(&error).unwrap();
            if socket
                .send(ws::Message::Text(error_json.into()))
                .await
                .is_err()
            {
                warn!("Failed to send error: connection closed");
                return ControlFlow::Break;
            }
        }
    }

    ControlFlow::Continue
}

pub async fn handle_socket(mut socket: WebSocket, env: Env, addr: SocketAddr, request_id: String) {
    let span = info_span!("socket", id = %request_id, client_addr = %addr.to_string());
    async move {
        info!("New WebSocket connection");
        loop {
            select! {
                _ = env.cancel_token.cancelled() => {
                    info!("WebSocket connection cancelled");
                    break;
                }
                option_result_message = socket.recv() => match option_result_message {
                    Some(result_message) => {
                        match result_message {
                            Ok(message) => {
                                if let ControlFlow::Break = handle_socket_message(&mut socket, message).await {
                                    break;
                                }
                            }
                            Err(err) => {
                                info!("Error receiving message: {}", err);
                                break;
                            }
                        }
                    }
                    None => {
                        warn!("Received empty message");
                        break;
                    }
                }
            };
        }
        let _ = socket.close().await;
        info!("WebSocket connection closed");
    }
    .instrument(span)
    .await;
}

pub async fn handler(
    ws: WebSocketUpgrade,
    State(env): State<Env>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(request_id): Extension<RequestId>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            env,
            addr,
            request_id.into_header_value().to_str().unwrap().into(),
        )
    })
}
