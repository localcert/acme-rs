use std::sync::Arc;

use crate::{
    error::AcmeResult,
    wire::challenge::ChallengeResource,
    wire::{
        authorization::{AuthorizationResource, AuthorizationStatus},
        common::ResourceStatus,
        identifier::AcmeIdentifier,
    },
};

use super::{account_context::AccountContext, challenge::Challenge, dns_identifier::DnsIdentifier};

pub struct Authorization {
    context: Arc<AccountContext>,
    resource: AuthorizationResource,
    url: String,
    dns_identifier: Option<DnsIdentifier>,
    challenges: Vec<Arc<ChallengeResource>>,
}

impl Authorization {
    pub(crate) async fn get(context: Arc<AccountContext>, url: &str) -> AcmeResult<Self> {
        let mut resource = context_client_request!(context, get_authorization, url).await?;
        let dns_identifier =
            DnsIdentifier::from_acme_identifier(&resource.identifier, resource.wildcard);
        let challenges = (&mut resource.challenges).drain(..).map(Arc::new).collect();
        Ok(Self {
            context,
            resource,
            url: url.to_string(),
            dns_identifier,
            challenges,
        })
    }

    pub fn resource(&self) -> &AuthorizationResource {
        &self.resource
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn status(&self) -> AuthorizationStatus {
        self.resource.status
    }

    pub fn status_result(&self) -> AcmeResult<AuthorizationStatus> {
        self.status().as_result()
    }

    pub fn identifier(&self) -> &AcmeIdentifier {
        &self.resource.identifier
    }

    pub fn dns_identifier(&self) -> Option<&DnsIdentifier> {
        self.dns_identifier.as_ref()
    }

    pub fn challenges(&self) -> impl Iterator + '_ {
        self.challenges
            .iter()
            .map(|resource| Challenge::new(self.context.clone(), resource.clone()))
    }

    pub fn find_challenge_type(&self, challenge_type: &str) -> Option<Challenge> {
        self.challenges.iter().find_map(|resource| {
            if resource.type_ == challenge_type {
                Some(Challenge::new(self.context.clone(), resource.clone()))
            } else {
                None
            }
        })
    }
}
