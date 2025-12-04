use axum::{Json, response::IntoResponse};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct ResultResponse<T: Serialize + JsonSchema> {
    pub result: T,
}

#[derive(Debug)]
pub struct Response<T: Serialize + JsonSchema>(pub Json<ResultResponse<T>>);

impl<T: Serialize + JsonSchema> IntoResponse for Response<T> {
    fn into_response(self) -> axum::response::Response {
        self.0.into_response()
    }
}

impl<T: Serialize + JsonSchema> From<T> for Response<T> {
    fn from(value: T) -> Self {
        Response(Json(ResultResponse { result: value }))
    }
}

pub type Result<T> = std::result::Result<Response<T>, Error>;
