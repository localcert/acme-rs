use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use http_client::{Body, HttpClient, Request, Response};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Value};

use super::{
    account::{AccountResource, AccountStatus, NewAccountResource},
    authorization::AuthorizationResource,
    challenge::ChallengeResource,
    common::LocationResource,
    directory::DirectoryResource,
    order::{FinalizeOrder, NewOrderResource, OrderResource},
    problem::{AcmeProblem, AcmeProblemType},
};
use crate::{
    crypto::jws::{self, jws_flattened, Jws, JwsHeader, JwsSigner},
    error::{AcmeError, AcmeResult},
};

pub struct AcmeClient {
    http: Arc<dyn HttpClient>,
    directory: DirectoryResource,
    nonces: Mutex<VecDeque<String>>,
}

pub static NO_PAYLOAD: Option<()> = None;

impl AcmeClient {
    pub fn new(http: impl Into<Arc<dyn HttpClient>>, directory: DirectoryResource) -> Self {
        Self {
            http: http.into(),
            directory,
            nonces: Default::default(),
        }
    }

    pub async fn for_directory_url(
        http: impl Into<Arc<dyn HttpClient>>,
        directory_url: &str,
    ) -> AcmeResult<AcmeClient> {
        let http_arc = http.into();
        let directory: DirectoryResource =
            Self::get_directory(http_arc.as_ref(), directory_url).await?;
        Ok(Self::new(http_arc, directory))
    }

    pub async fn get_directory(
        http: &(impl HttpClient + ?Sized),
        directory_url: impl AsRef<str>,
    ) -> AcmeResult<DirectoryResource> {
        let mut resp = http.send(Request::get(directory_url.as_ref())).await?;
        http_error_result(&mut resp).await?;
        Ok(resp.body_json().await?)
    }

    pub fn directory(&self) -> &DirectoryResource {
        &self.directory
    }

    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
    pub async fn new_account(
        &self,
        signer: &impl JwsSigner,
        public_jwk: &impl Serialize,
        new_account: &'_ NewAccountResource,
    ) -> AcmeResult<AccountResource> {
        self.request_resource(
            signer,
            &self.directory.new_account,
            Auth::Jwk(public_jwk),
            Some(new_account),
        )
        .await
    }

    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.2
    pub async fn update_account(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
        account: &AccountResource,
    ) -> AcmeResult<AccountResource> {
        self.request_resource(signer, account_url, Auth::kid(account_url), Some(account))
            .await
    }

    // TODO: account key rollover: https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.5

    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.6
    pub async fn account_deactivate(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
    ) -> AcmeResult<AccountResource> {
        let deactivate = AccountResource {
            status: AccountStatus::Deactivated,
            ..Default::default()
        };
        self.request_resource(
            signer,
            account_url,
            Auth::<'_, ()>::Kid(account_url),
            Some(deactivate),
        )
        .await
    }

    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
    pub async fn new_order(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
        new_order: &NewOrderResource,
    ) -> AcmeResult<OrderResource> {
        self.request_resource(
            signer,
            &self.directory.new_order,
            Auth::kid(account_url),
            Some(new_order),
        )
        .await
    }

    pub async fn finalize_order(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
        finalize_url: &str,
        finalize_order: &FinalizeOrder,
    ) -> AcmeResult<OrderResource> {
        self.request_resource(
            signer,
            finalize_url,
            Auth::kid(account_url),
            Some(finalize_order),
        )
        .await
    }

    pub async fn get_certificate_chain(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
        certificate_url: &str,
    ) -> AcmeResult<String> {
        let mut resp = self
            .request(signer, certificate_url, Auth::kid(account_url), NO_PAYLOAD)
            .await?;
        Ok(resp.body_string().await?)
    }

    pub async fn get_authorization(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
        authorization_url: &str,
    ) -> AcmeResult<AuthorizationResource> {
        self.request_resource(
            signer,
            authorization_url,
            Auth::kid(account_url),
            NO_PAYLOAD,
        )
        .await
    }

    pub async fn respond_challenge(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
        challenge_url: &str,
        response: Option<Map<String, Value>>,
    ) -> AcmeResult<ChallengeResource> {
        let payload = response.unwrap_or_default();
        let mut resp = self
            .request(signer, challenge_url, Auth::kid(account_url), Some(payload))
            .await?;
        Ok(resp.body_json().await?)
    }

    pub async fn get_resource<R: DeserializeOwned>(
        &self,
        signer: &impl JwsSigner,
        account_url: &str,
        resource_url: &str,
    ) -> AcmeResult<R> {
        let mut resp = self
            .request(signer, resource_url, Auth::kid(account_url), NO_PAYLOAD)
            .await?;
        Ok(resp.body_json().await?)
    }

    async fn request_resource<R: LocationResource>(
        &self,
        signer: &impl JwsSigner,
        url: &str,
        auth: Auth<'_, impl Serialize>,
        payload: Option<impl Serialize>,
    ) -> AcmeResult<R> {
        R::from_response(self.request(signer, url, auth, payload).await?).await
    }

    async fn request(
        &self,
        signer: &impl JwsSigner,
        url: &str,
        auth: Auth<'_, impl Serialize>,
        payload: Option<impl Serialize>,
    ) -> AcmeResult<Response> {
        let mut res = self.request_once(signer, url, &auth, &payload).await;
        if let Err(AcmeError::AcmeProblem(ref problem)) = res {
            // Like certbot, retry exactly once on badNonce error
            if problem.has_type(AcmeProblemType::BadNonce) {
                res = self.request_once(signer, url, &auth, &payload).await
            }
        }
        res
    }

    async fn request_once(
        &self,
        signer: &impl JwsSigner,
        url: &str,
        auth: &Auth<'_, impl Serialize>,
        payload: &Option<impl Serialize>,
    ) -> AcmeResult<Response> {
        let jws = self.build_request_body(signer, url, auth, payload).await?;

        let mut req = Request::post(url);
        req.set_body(&jws);

        let mut resp = self.http.send(req).await?;
        self.handle_response_headers(&mut resp).await?;
        Ok(resp)
    }

    pub async fn build_request_body(
        &self,
        signer: &impl JwsSigner,
        url: &str,
        auth: &Auth<'_, impl Serialize>,
        payload: &Option<impl Serialize>,
    ) -> AcmeResult<Jws> {
        let (kid, jwk) = match auth {
            &Auth::Kid(url) => (Some(url), None),
            Auth::Jwk(jwk) => (None, Some(jwk)),
        };
        let jws_header = JwsHeader {
            alg: signer.jws_alg(),
            url,
            nonce: &self.get_nonce().await?,
            kid,
            jwk,
        };

        let payload_bytes = if let Some(p) = payload {
            serde_json::to_vec(&p)?
        } else {
            Vec::new()
        };

        jws_flattened(signer, &jws_header, &payload_bytes).map_err(AcmeError::CryptoError)
    }

    async fn get_nonce(&self) -> AcmeResult<String> {
        {
            let mut nonces = self.nonces.lock().unwrap();
            if let Some(nonce) = nonces.pop_front() {
                return Ok(nonce);
            }
        }
        let req = Request::head(self.directory.new_nonce.as_str());
        let mut resp = self.http.send(req).await?;
        http_error_result(&mut resp).await?;
        get_replay_nonce(&resp).ok_or(AcmeError::MissingExpectedHeader("Replay-Nonce"))
    }

    async fn handle_response_headers(&self, resp: &mut Response) -> Result<(), AcmeError> {
        if let Some(nonce) = get_replay_nonce(resp) {
            let mut nonces = self.nonces.lock().unwrap();
            nonces.push_back(nonce);
        }
        http_error_result(resp).await?;
        Ok(())
    }
}

pub enum Auth<'a, Jwk: Serialize> {
    Jwk(Jwk),
    Kid(&'a str),
}

impl<'a> Auth<'a, ()> {
    pub fn kid(account_url: &'a str) -> Self {
        Auth::Kid(account_url)
    }
}

fn get_replay_nonce(resp: &Response) -> Option<String> {
    Some(resp.header("Replay-Nonce")?.last().as_str().to_owned())
}

async fn http_error_result(resp: &mut Response) -> AcmeResult<()> {
    let status = resp.status();
    if status.is_success() || status.is_informational() {
        return Ok(());
    }

    if resp
        .content_type()
        .map(|ct| ct.essence() == AcmeProblem::CONTENT_TYPE)
        .unwrap_or(false)
    {
        if let Ok(problem) = resp.body_json().await {
            return Err(AcmeError::AcmeProblem(problem));
        }
    }

    Err(AcmeError::from(http_client::Error::from_str(status, "")))
}

impl From<&Jws> for Body {
    fn from(jws: &Jws) -> Self {
        let mut body = Body::from_json(jws).unwrap();
        body.set_mime(jws::CONTENT_TYPE);
        body
    }
}
