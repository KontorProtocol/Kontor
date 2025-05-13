use axum::{Json, response::IntoResponse};
use serde::Serialize;

use super::error::Error;

#[derive(Debug, Serialize)]
pub struct ResultResponse<T: Serialize> {
    pub result: T,
}

#[derive(Debug)]
pub struct Response<T: Serialize>(pub Json<ResultResponse<T>>);

impl<T: Serialize> IntoResponse for Response<T> {
    fn into_response(self) -> axum::response::Response {
        self.0.into_response()
    }
}

impl<T: Serialize> From<T> for Response<T> {
    fn from(value: T) -> Self {
        Response(Json(ResultResponse { result: value }))
    }
}

pub type Result<T> = std::result::Result<Response<T>, Error>;
