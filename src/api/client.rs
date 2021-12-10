use std::sync::Arc;

use http_client::HttpClient;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::crypto::account_key::AccountKey;
use crate::crypto::generate_account_key;
use crate::error::AcmeError;
use crate::error::AcmeResult;
use crate::wire::account::NewAccountResource;
use crate::wire::client::AcmeClient;
use crate::wire::directory::DirectoryMetadata;
use crate::wire::directory::DirectoryResource;

use super::account::Account;
use super::account::Contact;

pub struct Client {
    http: Arc<dyn HttpClient>,
    directory: DirectoryResource,
}

impl Client {
    pub fn new(http: impl Into<Arc<dyn HttpClient>>, directory: DirectoryResource) -> Self {
        Self {
            http: http.into(),
            directory,
        }
    }

    pub async fn for_directory_url(
        http: impl Into<Arc<dyn HttpClient + 'static>>,
        directory_url: impl AsRef<str>,
    ) -> AcmeResult<Self> {
        let http_arc = http.into();
        let directory = AcmeClient::get_directory(http_arc.as_ref(), directory_url).await?;
        Ok(Self::new(http_arc, directory))
    }

    pub fn metadata(&self) -> &DirectoryMetadata {
        &self.directory.meta
    }

    pub fn terms_of_service_uri(&self) -> Option<&str> {
        self.directory.meta.terms_of_service.as_deref()
    }

    pub async fn register_account(
        &self,
        contact_email: String,
        terms_of_service_agreed: bool,
    ) -> AcmeResult<Account> {
        self.register_account_config(RegisterAccountConfig {
            contacts: Vec::from([Contact::Email(contact_email)]),
            terms_of_service_agreed,
            ..Default::default()
        })
        .await
    }

    pub async fn register_account_config(
        &self,
        config: RegisterAccountConfig,
    ) -> AcmeResult<Account> {
        let req = &NewAccountResource {
            contact: config.contacts.into_iter().map(Contact::uri).collect(),
            terms_of_service_agreed: config.terms_of_service_agreed,
            external_account_binding: config.external_account_binding,
            ..Default::default()
        };
        let account_key = config
            .account_key
            .unwrap_or_else(|| Box::new(generate_account_key()));
        self.get_account(account_key, req).await
    }

    pub async fn find_account(
        &self,
        account_key: impl AccountKey + 'static,
    ) -> AcmeResult<Account> {
        let req = &NewAccountResource {
            only_return_existing: true,
            ..Default::default()
        };
        self.get_account(account_key, req).await
    }

    async fn get_account(
        &self,
        account_key: impl AccountKey + 'static,
        req: &NewAccountResource,
    ) -> AcmeResult<Account> {
        let public_jwk = account_key.public_jwk().map_err(AcmeError::CryptoError)?;
        let public_jwk_json = RawValue::from_string(public_jwk)?;
        let client = AcmeClient::new(self.http.clone(), self.directory.clone());
        let resource = client
            .new_account(&account_key, &public_jwk_json, req)
            .await?;
        Account::from_resource(client, account_key, resource)
    }
}

#[derive(Default)]
pub struct RegisterAccountConfig {
    pub account_key: Option<Box<dyn AccountKey>>,
    pub contacts: Vec<Contact>,
    pub terms_of_service_agreed: bool,
    pub external_account_binding: Option<Value>,
}
