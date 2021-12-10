macro_rules! context_client_request {
    ($ctx:expr, $method:ident, $($arg:expr),+) => ($ctx.client.$method(&$ctx.account_key, &$ctx.account_url, $($arg),+));
    ($ctx:expr, $method:ident) => ($ctx.client.$method(&$ctx.account_key, &$ctx.account_url))
}

pub mod account;
pub mod account_context;
pub mod client;
pub mod authorization;
pub mod challenge;
pub mod dns_identifier;
pub mod order;
