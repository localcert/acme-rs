use std::{future::Future, sync::Arc};

use crate::{
    base64url,
    error::{AcmeError, AcmeResult},
    wire::order::{OrderResource, OrderStatus},
    wire::{
        common::{LocationResource, ResourceStatus},
        order::FinalizeOrder,
    },
};

use super::{
    account_context::AccountContext, authorization::Authorization, dns_identifier::DnsIdentifier,
};

pub struct Order {
    context: Arc<AccountContext>,
    resource: OrderResource,
    url: String,
}

impl Order {
    pub(crate) fn from_resource(
        context: Arc<AccountContext>,
        mut resource: OrderResource,
    ) -> AcmeResult<Self> {
        let url = resource.take_location()?;
        Ok(Self {
            context,
            resource,
            url,
        })
    }

    pub fn resource(&self) -> &OrderResource {
        &self.resource
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn status(&self) -> OrderStatus {
        self.resource.status
    }

    pub fn status_result(&self) -> AcmeResult<OrderStatus> {
        if let Some(ref problem) = self.resource.error {
            Err(AcmeError::AcmeProblem(problem.clone()))
        } else {
            self.status().as_result()
        }
    }

    pub fn state(&mut self) -> OrderState<'_> {
        use OrderStatus::*;
        match self.resource.status {
            Pending => OrderState::Pending(OrderStatePending(self)),
            Ready => OrderState::Ready(OrderStateReady(self)),
            Processing => OrderState::Processing,
            Valid => OrderState::Valid(OrderStateValid(self)),
            Invalid => OrderState::Invalid,
        }
    }

    pub fn state_result(&mut self) -> AcmeResult<OrderState<'_>> {
        self.status_result()?;
        Ok(self.state())
    }

    pub fn dns_name(&self) -> Option<DnsIdentifier> {
        DnsIdentifier::find_acme_identifier(&self.resource.identifiers, false)
    }

    pub async fn refresh(&mut self) -> AcmeResult<OrderStatus> {
        self.resource = context_client_request!(self.context, get_resource, self.url()).await?;
        Ok(self.status())
    }

    pub async fn status_changed<AsyncSleep, SleepFuture>(
        &mut self,
        mut polling_sleep: AsyncSleep,
    ) -> AcmeResult<OrderStatus>
    where
        AsyncSleep: FnMut() -> SleepFuture + Send,
        SleepFuture: Future<Output = ()> + Send,
    {
        let status = self.status();
        while self.refresh().await? == status {
            polling_sleep().await;
        }
        Ok(self.status())
    }
}

pub enum OrderState<'a> {
    Pending(OrderStatePending<'a>),
    Ready(OrderStateReady<'a>),
    Processing,
    Valid(OrderStateValid<'a>),
    Invalid,
}

pub struct OrderStatePending<'a>(&'a Order);

impl<'a> OrderStatePending<'a> {
    pub fn authorization_urls(&self) -> std::slice::Iter<'a, String> {
        self.0.resource.authorizations.iter()
    }

    pub fn only_authorization_url(&self) -> AcmeResult<&'a str> {
        let authzs = &self.0.resource.authorizations;
        if authzs.len() == 1 {
            Ok(&authzs[0])
        } else {
            Err(AcmeError::InvalidState(format!(
                "expected 1 item in authorizations list; got {}",
                authzs.len()
            )))
        }
    }

    pub fn get_authorizations(&self) -> impl Iterator + 'a {
        self.authorization_urls()
            .map(|authorization_url| Authorization::get(self.0.context.clone(), authorization_url))
    }

    pub async fn get_only_authorization(&self) -> AcmeResult<Authorization> {
        let authorization_url = self.only_authorization_url()?;
        Authorization::get(self.0.context.clone(), authorization_url).await
    }
}

pub struct OrderStateReady<'a>(&'a mut Order);

impl<'a> OrderStateReady<'a> {
    pub async fn finalize(&mut self, csr_der: impl AsRef<[u8]>) -> AcmeResult<OrderState<'_>> {
        let finalize_order = &FinalizeOrder {
            csr: base64url::encode(csr_der),
        };
        let finalize_url = self
            .0
            .resource
            .finalize
            .as_deref()
            .ok_or(AcmeError::MissingExpectedField("finalize"))?;
        self.0.resource =
            context_client_request!(self.0.context, finalize_order, finalize_url, finalize_order)
                .await?;
        Ok(self.0.state())
    }

    #[cfg(feature = "x509")]
    // Returns PEM-encoded private key
    pub async fn finalize_with_generated_key(&mut self) -> AcmeResult<String> {
        let dns_ident = self
            .0
            .dns_name()
            .ok_or(AcmeError::InvalidState("not a DNS order".to_string()))?;

        let (key_pem, csr_der) = crate::x509::generate_key_and_csr(dns_ident.as_ref())?;

        self.finalize(csr_der).await?;

        Ok(key_pem)
    }
}

pub struct OrderStateValid<'a>(&'a Order);

impl<'a> OrderStateValid<'a> {
    pub async fn get_certificate_chain(&self) -> AcmeResult<String> {
        let certificate_url = self
            .0
            .resource
            .certificate
            .as_deref()
            .ok_or(AcmeError::MissingExpectedField("certificate"))?;
        context_client_request!(self.0.context, get_certificate_chain, &certificate_url).await
    }
}
