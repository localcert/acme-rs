use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::common::{is_false, LocationResource, ResourceStatus};

/// ACME Account resource
/// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccountResource {
    /// The status of this account.
    pub status: AccountStatus,

    /// An array of URLs that the server can use to contact the client for
    /// issues related to this account.  For example, the server may wish to
    /// notify the client about server-initiated revocation or certificate
    /// expiration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,

    /// Including this field in a newAccount request, with a value of true,
    /// indicates the client's agreement with the terms of service.  This field
    /// cannot be updated by the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    /// Including this field in a newAccount request indicates approval by the
    /// holder of an existing non-ACME account to bind that account to this ACME
    /// account. This field is not updateable by the client
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<Value>,

    /// A URL from which a list of orders submitted by this account can be fetched
    ///
    /// NOTE: Technically required by RFC 8555, but Let's Encrypt's Boulder server
    /// doesn't implement it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orders: Option<String>,

    /// The URL of this resource, as returned in the Location header.
    #[serde(skip)]
    pub location: Option<String>,
}

impl LocationResource for AccountResource {
    fn location_mut(&mut self) -> &mut Option<String> {
        &mut self.location
    }
}

/// ACME newAccount resource
/// https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountResource {
    /// An array of URLs that the server can use to contact the client for
    /// issues related to this account.  For example, the server may wish to
    /// notify the client about server-initiated revocation or certificate
    /// expiration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,

    /// Including this field in a newAccount request, with a value of true,
    /// indicates the client's agreement with the terms of service.  This field
    /// cannot be updated by the client.
    #[serde(default, skip_serializing_if = "is_false")]
    pub terms_of_service_agreed: bool,

    /// If this field is present with the value "true", then the server MUST NOT
    /// create a new account if one does not already exist.  This allows a
    /// client to look up an account URL based on an account key
    #[serde(default, skip_serializing_if = "is_false")]
    pub only_return_existing: bool,

    /// Including this field in a newAccount request indicates approval by the
    /// holder of an existing non-ACME account to bind that account to this ACME
    /// account. This field is not updateable by the client
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account objects are created in the "valid" state
    Valid,

    /// "deactivated" should be used to indicate client-initiated deactivation
    Deactivated,

    /// "revoked" should be used to indicate server-initiated deactivation
    Revoked,
}

impl Default for AccountStatus {
    fn default() -> Self {
        Self::Valid
    }
}

impl ResourceStatus for AccountStatus {
    fn is_failure(&self) -> bool {
        !matches!(self, Self::Valid)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rfc8555_account_example() {
        let account = AccountResource::deserialize(json!({
            "status": "valid",
            "contact": [
                "mailto:cert-admin@example.org",
                "mailto:admin@example.org"
            ],
            "termsOfServiceAgreed": true,
            "orders": "https://example.com/acme/orders/rzGoeA"
        }))
        .unwrap();

        assert_eq!(account.status, AccountStatus::Valid);
        assert_eq!(
            account.contact,
            ["mailto:cert-admin@example.org", "mailto:admin@example.org"]
        );
        assert_eq!(account.terms_of_service_agreed.unwrap(), true);
        assert_eq!(
            account.orders.unwrap(),
            "https://example.com/acme/orders/rzGoeA"
        );
    }

    #[test]
    fn rfc8555_new_account_example() {
        let new_account = NewAccountResource {
            terms_of_service_agreed: true,
            contact: vec![
                "mailto:cert-admin@example.org".to_string(),
                "mailto:admin@example.org".to_string(),
            ],
            only_return_existing: false,
            external_account_binding: None,
        };
        assert_eq!(
            serde_json::to_value(new_account).unwrap(),
            json!({
                "termsOfServiceAgreed": true,
                "contact": [
                    "mailto:cert-admin@example.org",
                    "mailto:admin@example.org"
                ]
            })
        );
    }
}
