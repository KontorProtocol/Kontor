use std::{collections::HashMap, net::SocketAddr, pin::Pin, time::Duration};

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
use tokio::{
    select,
    sync::broadcast::{self, Receiver},
    time::timeout,
};
use tower_http::request_id::RequestId;
use tracing::{Instrument, error, info, info_span, warn};
use uuid::Uuid;

use crate::reactor::results::{ResultEvent, ResultEventFilter};

use super::Env;

const MAX_SEND_MILLIS: u64 = 1000;

pub enum ControlFlow {
    Continue,
    Break,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Request {
    Subscribe { filter: ResultEventFilter },
    Unsubscribe { id: Uuid },
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Response {
    SubscribeResponse { id: Uuid },
    UnsubscribeResponse { id: Uuid },
    Result { id: Uuid, result: ResultEvent },
    Error { error: String },
}

type Futures = FuturesUnordered<
    Pin<
        Box<
            dyn std::future::Future<
                    Output = (
                        Uuid,
                        Result<ResultEvent, broadcast::error::RecvError>,
                        Receiver<ResultEvent>,
                    ),
                > + Send,
        >,
    >,
>;

#[derive(PartialEq, Eq)]
pub enum SubscriptionType {
    Recurring,
    OneShot,
}

impl From<ResultEventFilter> for SubscriptionType {
    fn from(filter: ResultEventFilter) -> Self {
        match filter {
            ResultEventFilter::All => SubscriptionType::Recurring,
            ResultEventFilter::Contract { .. } => SubscriptionType::Recurring,
            ResultEventFilter::OpResultId(_) => SubscriptionType::OneShot,
        }
    }
}

#[derive(Default)]
pub struct SocketState {
    pub subscriptions: HashMap<Uuid, SubscriptionType>,
    pub futures: Futures,
}

impl SocketState {
    fn push_future(&mut self, id: Uuid, mut rx: Receiver<ResultEvent>) {
        self.futures.push(Box::pin(async move {
            let result = rx.recv().await;
            (id, result, rx)
        }));
    }
}

pub async fn handle_message(
    env: &mut Env,
    state: &mut SocketState,
    request: Request,
) -> Option<Response> {
    let conn = env.reader.connection().await;
    if conn.is_err() {
        warn!("Failed to connect to database");
        return Some(Response::Error {
            error: "Failed to connect to database".to_string(),
        });
    }
    let conn = conn.unwrap();
    match request {
        Request::Subscribe { filter } => {
            info!("Received subscribe request");
            let result = env.result_subscriber.subscribe(&conn, filter.clone()).await;
            if result.is_err() {
                warn!("Failed to subscribe to result");
                return Some(Response::Error {
                    error: "Failed to subscribe to result".to_string(),
                });
            }
            let (id, rx) = result.unwrap();
            state.push_future(id, rx);
            state.subscriptions.insert(id, filter.into());
            info!("Subscribed with ID: {}", id);
            Some(Response::SubscribeResponse { id })
        }
        Request::Unsubscribe { id } => {
            info!("Received unsubscribe request for ID: {}", id);
            match state.subscriptions.remove(&id) {
                Some(_) => {
                    let _ = env.result_subscriber.unsubscribe(&conn, id).await;
                    info!("Unsubscribed ID: {}", id);
                    Some(Response::UnsubscribeResponse { id })
                }
                None => {
                    warn!("Unsubscribe failed: ID {} not found", id);
                    Some(Response::Error {
                        error: format!("Subscription ID {} not found", id),
                    })
                }
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
                Some((id, result, rx)) = state.futures.next(), if !state.futures.is_empty() => {
                    match result {
                        Ok(result) => {
                            if let Some(subscription_type) = state.subscriptions.get(&id) {

                                let msg = Response::Result { id,  result };
                                let json = serde_json::to_string(&msg).expect("Failed to serialize event");
                                info!("Sending event: {:#?}", json.clone());
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

                                match *subscription_type {
                                    SubscriptionType::Recurring => {
                                        state.push_future(id, rx);
                                    },
                                    SubscriptionType::OneShot => {
                                        state.subscriptions.remove(&id);
                                    },
                                };
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            state.subscriptions.remove(&id);
                            warn!("Subscription channel {} closed", id);
                        }
                        Err(e) => error!("Error receiving event: {}", e),
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

        if let Ok(conn) = env.reader.connection().await {
            for (id, ..) in state.subscriptions.drain() {
                let _ = env.result_subscriber.unsubscribe(&conn, id).await;
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
