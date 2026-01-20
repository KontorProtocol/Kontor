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
use indexer_types::{Event, WsResponse};
use tokio::{select, sync::broadcast::Receiver, time::timeout};
use tower_http::request_id::RequestId;
use tracing::{Instrument, info, info_span, warn};

use super::Env;

const MAX_SEND_MILLIS: u64 = 1000;
const PING_INTERVAL_SECS: u64 = 20;

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
        let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
        ping_interval.reset(); // Don't ping immediately on connect
        loop {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("WebSocket connection cancelled");
                    break;
                },
                _ = ping_interval.tick() => {
                    if timeout(
                        Duration::from_millis(MAX_SEND_MILLIS),
                        socket.send(ws::Message::Ping(vec![].into())),
                    )
                    .await
                    .is_err()
                    {
                        warn!("Failed to send ping: connection closed");
                        break;
                    }
                },
                result = state.receiver.recv() => match result {
                    Ok(event) => {
                        info!("Received event");
                        if timeout(
                            Duration::from_millis(MAX_SEND_MILLIS),
                            socket.send(ws::Message::Text(
                                serde_json::to_string(&WsResponse::Event { event })
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
                    Some(Ok(ws::Message::Close(_))) => {
                        info!("Received close message");
                        break;
                    }
                    // Ping/Pong are handled automatically by tungstenite at the protocol level
                    Some(Ok(ws::Message::Ping(_) | ws::Message::Pong(_))) => {}
                    Some(Ok(_)) => {
                        info!("Received unsupported message type");
                        let error = WsResponse::Error {
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
