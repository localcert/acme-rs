use async_trait::async_trait;
use http_client::Response;
use serde::de::DeserializeOwned;

use crate::error::{AcmeError, AcmeResult};

// Serde skip_serialization_if helper
pub(crate) fn is_false(value: &bool) -> bool {
    !value
}

pub trait ResourceStatus: std::fmt::Debug + Copy + Sized {
    fn is_failure(&self) -> bool;

    fn error(&self) -> Option<AcmeError> {
        if self.is_failure() {
            Some(AcmeError::InvalidState(
                format!("{:?}", self).to_ascii_lowercase(),
            ))
        } else {
            None
        }
    }

    fn as_result(&self) -> AcmeResult<Self> {
        match self.error() {
            Some(err) => Err(err),
            None => Ok(*self),
        }
    }
}

#[async_trait]
pub(crate) trait LocationResource: DeserializeOwned + Send {
    fn location_mut(&mut self) -> &mut Option<String>;

    fn take_location(&mut self) -> AcmeResult<String> {
        self.location_mut()
            .take()
            .ok_or(AcmeError::MissingExpectedHeader("Location"))
    }

    async fn from_response(mut resp: Response) -> AcmeResult<Self> {
        let mut resource: Self = resp.body_json().await?;
        if let Some(values) = resp.header("Location") {
            *resource.location_mut() = Some(values.last().as_str().to_owned());
        }
        Ok(resource)
    }
}
