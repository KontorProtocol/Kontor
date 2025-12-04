use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::error::Error;

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../kontor-ts/bindings.d.ts")]
pub struct ResultResponse<T: TS> {
    pub result: T,
}

#[derive(Debug)]
pub struct Response<T: Serialize + TS>(pub Json<ResultResponse<T>>);

impl<T: Serialize + TS> IntoResponse for Response<T> {
    fn into_response(self) -> axum::response::Response {
        self.0.into_response()
    }
}

impl<T: Serialize + TS> From<T> for Response<T> {
    fn from(value: T) -> Self {
        Response(Json(ResultResponse { result: value }))
    }
}

pub type Result<T> = std::result::Result<Response<T>, Error>;
