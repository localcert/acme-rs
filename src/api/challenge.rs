use std::sync::Arc;

use chrono::{DateTime, FixedOffset};

use crate::{
    error::{AcmeError, AcmeResult},
    wire::{
        challenge::{ChallengeResource, ChallengeStatus},
        common::ResourceStatus,
        problem::AcmeProblem,
    },
};

use super::account_context::AccountContext;

pub struct Challenge {
    context: Arc<AccountContext>,
    resource: Arc<ChallengeResource>,
}

impl Challenge {
    pub(crate) fn new(context: Arc<AccountContext>, resource: Arc<ChallengeResource>) -> Self {
        Self { context, resource }
    }

    pub fn resource(&self) -> &ChallengeResource {
        self.resource.as_ref()
    }

    pub fn url(&self) -> &str {
        &self.resource.url
    }

    pub fn status(&self) -> ChallengeStatus {
        self.resource.status
    }

    pub fn status_result(&self) -> AcmeResult<ChallengeStatus> {
        self.status().as_result()
    }

    pub fn challenge_type(&self) -> &str {
        &self.resource.type_
    }

    pub fn token(&self) -> Option<&str> {
        self.resource.token.as_deref()
    }

    pub fn state(&mut self) -> ChallengeState<'_> {
        use ChallengeStatus::*;
        match self.status() {
            Pending => ChallengeState::Pending(ChallengeStatePending(self)),
            Processing => ChallengeState::Processing,
            Valid => ChallengeState::Valid(ChallengeStateValid(self)),
            Invalid => ChallengeState::Invalid(ChallengeStateInvalid(self)),
        }
    }

    pub fn state_result(&mut self) -> AcmeResult<ChallengeState<'_>> {
        self.status_result()?;
        Ok(self.state())
    }
}

pub enum ChallengeState<'a> {
    Pending(ChallengeStatePending<'a>),
    Processing,
    Valid(ChallengeStateValid<'a>),
    Invalid(ChallengeStateInvalid<'a>),
}

pub struct ChallengeStatePending<'a>(&'a mut Challenge);

impl<'a> ChallengeStatePending<'a> {
    pub async fn respond(&'a mut self) -> AcmeResult<ChallengeState<'a>> {
        let resource =
            context_client_request!(self.0.context, respond_challenge, self.0.url(), None).await?;
        self.0.resource = Arc::new(resource);
        Ok(self.0.state())
    }
}

pub struct ChallengeStateValid<'a>(&'a Challenge);

impl<'a> ChallengeStateValid<'a> {
    pub fn validated(&self) -> AcmeResult<DateTime<FixedOffset>> {
        self.0
            .resource
            .validated
            .ok_or(AcmeError::MissingExpectedField("validated"))
    }
}

pub struct ChallengeStateInvalid<'a>(&'a Challenge);

impl<'a> ChallengeStateInvalid<'a> {
    pub fn error(&self) -> Option<&AcmeProblem> {
        self.0.resource.error.as_ref()
    }
}
