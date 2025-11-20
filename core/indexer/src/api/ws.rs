use std::{net::SocketAddr, time::Duration};

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
use tokio::{select, sync::broadcast::Receiver, time::timeout};
use tower_http::request_id::RequestId;
use tracing::{Instrument, info, info_span, warn};

use crate::event::Event;

use super::Env;

const MAX_SEND_MILLIS: u64 = 1000;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Request {
    Subscribe,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Response {
    Event { event: Event },
    Error { error: String },
}

pub struct SocketState {
    pub receiver: Receiver<Event>,
}

pub async fn handle_socket(mut socket: WebSocket, env: Env, addr: SocketAddr, request_id: String) {
    let span = info_span!("socket", id = %request_id, client_addr = %addr.to_string());
    let cancel_token = env.cancel_token.clone();
    let mut state = SocketState {
        receiver: env.event_subscriber.subscribe(),
    };

    async move {
        info!("New WebSocket connection");
        loop {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("WebSocket connection cancelled");
                    break;
                },
                result = state.receiver.recv() => match result {
                    Ok(event) => {
                        info!("Received event");
                        if timeout(
                            Duration::from_millis(MAX_SEND_MILLIS),
                            socket.send(ws::Message::Text(
                                serde_json::to_string(&Response::Event { event })
                                    .expect("Failed to serialize response")
                                    .into(),
                            )),
                        )
                        .await
                        .is_err()
                        {
                            warn!("Failed to send error: connection closed");
                            break;
                        }
                    }
                    Err(err) => {
                        warn!("Error receiving event: {}", err);
                        break;
                    }
                },
                option_result_message = socket.recv() => match option_result_message {
                    Some(Ok(ws::Message::Ping(data))) => {
                        if timeout(
                            Duration::from_millis(MAX_SEND_MILLIS),
                            socket.send(ws::Message::Pong(data)),
                        )
                        .await
                        .is_err()
                        {
                            warn!("Failed to send pong: connection closed");
                            break;
                        }
                    }
                    Some(Ok(ws::Message::Close(_))) => {
                        info!("Received close message");
                        break;
                    }
                    Some(Ok(_)) => {
                        info!("Received unsupported message type");
                        let error = Response::Error {
                            error: "Requests are not supported".to_string(),
                        };
                        let error_json = serde_json::to_string(&error)
                            .expect("Should not fail to serialize error defined above");
                        if timeout(
                            Duration::from_millis(MAX_SEND_MILLIS),
                            socket.send(ws::Message::Text(error_json.into())),
                        )
                        .await
                        .is_err()
                        {
                            warn!("Failed to send error: connection closed");
                            break;
                        }
                    }
                    Some(Err(err)) => {
                        info!("Error receiving message: {}", err);
                        break;
                    }
                    None => {
                        warn!("Received empty message");
                        break;
                    }
                }
            }
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
            request_id
                .into_header_value()
                .to_str()
                .expect("Should not fail to convert application defined request ID to string")
                .into(),
        )
    })
}
