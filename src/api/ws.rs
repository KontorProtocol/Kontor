use std::{collections::HashSet, net::SocketAddr, pin::Pin, time::Duration};

use axum::{
    Extension,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{self, WebSocket},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use tokio::{select, sync::broadcast, time::timeout};
use tower_http::request_id::RequestId;
use tracing::{Instrument, info, info_span, warn};

use crate::{
    reactor::events::{Event, EventFilter},
    utils::ControlFlow,
};

use super::Env;

const MAX_SEND_MILLIS: u64 = 1000;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Request {
    Subscribe { filter: EventFilter },
    Unsubscribe { id: usize },
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Response {
    SubscribeResponse { id: usize },
    UnsubscribeResponse { id: usize },
    Event { id: usize, event: Event },
    Error { error: String },
}

type Futures = FuturesUnordered<
    Pin<
        Box<
            dyn std::future::Future<
                    Output = (
                        usize,
                        Result<Event, broadcast::error::RecvError>,
                        broadcast::Receiver<Event>,
                    ),
                > + Send,
        >,
    >,
>;

#[derive(Default)]
pub struct SocketState {
    pub subscription_ids: HashSet<usize>,
    pub futures: Futures,
}

pub async fn handle_message(
    env: &mut Env,
    state: &mut SocketState,
    request: Request,
) -> Option<Response> {
    match request {
        Request::Subscribe { filter } => {
            info!("Received subscribe request");
            let (id, mut rx) = env.event_subscriber.subscribe(filter.clone()).await;
            state.futures.push(Box::pin(async move {
                let result = rx.recv().await;
                (id, result, rx)
            }));
            state.subscription_ids.insert(id);
            info!("Subscribed with ID: {}", id);
            Some(Response::SubscribeResponse { id })
        }
        Request::Unsubscribe { id } => {
            info!("Received unsubscribe request for ID: {}", id);
            if state.subscription_ids.remove(&id) {
                let _ = env.event_subscriber.unsubscribe(id).await;
                info!("Unsubscribed ID: {}", id);
                Some(Response::UnsubscribeResponse { id })
            } else {
                warn!("Unsubscribe failed: ID {} not found", id);
                Some(Response::Error {
                    error: format!("Subscription ID {} not found", id),
                })
            }
        }
    }
}

pub async fn handle_socket_message(
    socket: &mut WebSocket,
    env: &mut Env,
    state: &mut SocketState,
    message: ws::Message,
) -> ControlFlow {
    match message {
        ws::Message::Text(text) => match serde_json::from_str::<Request>(&text) {
            Ok(request) => {
                if let Some(response) = handle_message(env, state, request).await {
                    let response_json = serde_json::to_string(&response)
                        .expect("Failed to serialize response despite being created internally");
                    if timeout(
                        Duration::from_millis(MAX_SEND_MILLIS),
                        socket.send(ws::Message::Text(response_json.into())),
                    )
                    .await
                    .is_err()
                    {
                        warn!("Failed to send response: connection closed");
                        return ControlFlow::Break;
                    }
                }
            }
            Err(e) => {
                warn!("Invalid request: {}", e);
                let error = Response::Error {
                    error: format!("Invalid request: {}", e),
                };
                let error_json = serde_json::to_string(&error)
                    .expect("Failed to serialize error despite being created internally");
                if timeout(
                    Duration::from_millis(MAX_SEND_MILLIS),
                    socket.send(ws::Message::Text(error_json.into())),
                )
                .await
                .is_err()
                {
                    warn!("Failed to send error: connection closed");
                    return ControlFlow::Break;
                }
            }
        },
        ws::Message::Ping(data) => {
            if timeout(
                Duration::from_millis(MAX_SEND_MILLIS),
                socket.send(ws::Message::Pong(data)),
            )
            .await
            .is_err()
            {
                warn!("Failed to send pong: connection closed");
                return ControlFlow::Break;
            }
        }
        ws::Message::Close(_close) => {
            info!("Received close message");
            return ControlFlow::Break;
        }
        _ => {
            info!("Received unsupported message type");
            let error = Response::Error {
                error: "Only text messages supported".to_string(),
            };
            let error_json = serde_json::to_string(&error).unwrap();
            if timeout(
                Duration::from_millis(MAX_SEND_MILLIS),
                socket.send(ws::Message::Text(error_json.into())),
            )
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

pub async fn handle_socket(
    mut socket: WebSocket,
    mut env: Env,
    addr: SocketAddr,
    request_id: String,
) {
    let span = info_span!("socket", id = %request_id, client_addr = %addr.to_string());
    let cancel_token = env.cancel_token.clone();
    let mut state = SocketState::default();

    async move {
        info!("New WebSocket connection");
        loop {
            select! {
                _ = cancel_token.cancelled() => {
                    info!("WebSocket connection cancelled");
                    break;
                }
                Some((id, result, mut rx)) = state.futures.next(), if !state.futures.is_empty() => {
                    match result {
                        Ok(event) => {
                            if state.subscription_ids.contains(&id) {
                                state.futures.push(Box::pin(async move {
                                    (id, rx.recv().await, rx)
                                }));
                            }

                            let msg = Response::Event { id, event };
                            let json = serde_json::to_string(&msg).expect("Failed to serialize event");
                            if timeout(
                                Duration::from_millis(MAX_SEND_MILLIS),
                                socket.send(ws::Message::Text(json.into())),
                            )
                            .await
                            .is_err()
                            {
                                warn!("Failed to send event: connection closed");
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            state.subscription_ids.remove(&id);
                            warn!("Subscription channel {} closed", id);
                        }
                        Err(e) => warn!("Error receiving event: {}", e),
                    }
                }
                option_result_message = socket.recv() => match option_result_message {
                    Some(result_message) => {
                        match result_message {
                            Ok(message) => {
                                if let ControlFlow::Break = handle_socket_message(&mut socket, &mut env, &mut state, message).await {
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
            }
        }

        for id in state.subscription_ids.drain() {
            let _ = env.event_subscriber.unsubscribe(id).await;
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
