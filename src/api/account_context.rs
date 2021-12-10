use crate::{crypto::account_key::AccountKey, wire::client::AcmeClient};

pub(crate) struct AccountContext {
    pub client: AcmeClient,
    pub account_key: Box<dyn AccountKey>,
    pub account_url: String,
}
