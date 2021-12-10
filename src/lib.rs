pub mod api;
pub mod crypto;
pub mod error;
pub mod wire;

#[cfg(feature = "x509")]
mod x509;

pub(crate) mod base64url;

use std::sync::Arc;

pub use api::client::Client;
pub use error::{AcmeError, AcmeResult};

pub static LETS_ENCRYPT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub async fn lets_encrypt_client(
    http: impl Into<Arc<dyn http_client::HttpClient>>,
) -> AcmeResult<Client> {
    Client::for_directory_url(http, LETS_ENCRYPT_DIRECTORY_URL).await
}

pub static LETS_ENCRYPT_STAGING_DIRECTORY_URL: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
pub async fn lets_encrypt_staging_client(
    http: impl Into<Arc<dyn http_client::HttpClient>>,
) -> AcmeResult<Client> {
    Client::for_directory_url(http, LETS_ENCRYPT_STAGING_DIRECTORY_URL).await
}
