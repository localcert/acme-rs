use thiserror::Error;

use super::wire::problem::AcmeProblem;

pub type AcmeResult<T> = Result<T, AcmeError>;

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("{0}")]
    AcmeProblem(AcmeProblem),

    #[error(transparent)]
    CryptoError(anyhow::Error),

    #[error("http: [{}] {0}", .0.status())]
    HttpError(http_client::Error),

    #[error("json: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("missing expected field {0}")]
    MissingExpectedField(&'static str),

    #[error("missing expected header {0}")]
    MissingExpectedHeader(&'static str),

    #[error("account key missing key id")]
    NoKeyId,

    #[error("{0}")]
    InvalidState(String),
}

impl From<http_client::Error> for AcmeError {
    fn from(err: http_client::Error) -> Self {
        AcmeError::HttpError(err)
    }
}