use std::sync::Arc;

use crate::{
    crypto::account_key::AccountKey,
    error::AcmeResult,
    wire::{
        account::{AccountResource, AccountStatus},
        client::AcmeClient,
        common::LocationResource,
        identifier::AcmeIdentifier,
        order::NewOrderResource,
    },
};

use super::{account_context::AccountContext, order::Order};

pub struct Account {
    context: Arc<AccountContext>,
    resource: AccountResource,
}

impl Account {
    pub(crate) fn from_resource(
        client: AcmeClient,
        account_key: impl AccountKey + 'static,
        mut resource: AccountResource,
    ) -> AcmeResult<Self> {
        let context = AccountContext {
            client,
            account_key: Box::new(account_key),
            account_url: resource.take_location()?,
        };
        Ok(Self {
            context: Arc::new(context),
            resource,
        })
    }

    pub fn client(&self) -> &AcmeClient {
        &self.context.client
    }

    pub fn key(&self) -> &impl AccountKey {
        &self.context.account_key
    }

    pub fn resource(&self) -> &AccountResource {
        &self.resource
    }

    pub fn url(&self) -> &str {
        &self.context.account_url
    }

    pub fn status(&self) -> AccountStatus {
        self.resource.status
    }

    pub async fn new_order(&self, new_order: &NewOrderResource) -> AcmeResult<Order> {
        let order = context_client_request!(self.context, new_order, new_order).await?;
        Order::from_resource(self.context.clone(), order)
    }

    pub async fn new_dns_order(&self, dns_name: impl Into<String>) -> AcmeResult<Order> {
        let new_order = &NewOrderResource {
            identifiers: vec![AcmeIdentifier::dns(dns_name)],
            ..Default::default()
        };
        self.new_order(new_order).await
    }

    pub async fn get_order(&self, order_url: impl AsRef<str>) -> AcmeResult<Order> {
        let order = context_client_request!(self.context, get_resource, order_url.as_ref()).await?;
        Order::from_resource(self.context.clone(), order)
    }

    pub async fn deactivate(&mut self) -> AcmeResult<()> {
        self.resource = context_client_request!(self.context, account_deactivate).await?;
        Ok(())
    }
}

pub enum Contact {
    Email(String),
    Uri(String),
}

impl Contact {
    pub(crate) fn uri(self) -> String {
        match self {
            Self::Email(email) if !email.starts_with("mailto:") => format!("mailto:{}", email),
            Self::Email(email) => email,
            Self::Uri(uri) => uri,
        }
    }
}
