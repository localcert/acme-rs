use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use super::{
    common::{LocationResource, ResourceStatus},
    identifier::AcmeIdentifier,
    problem::AcmeProblem,
};

/// ACME Order resource
/// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OrderResource {
    /// The status of this order.
    pub status: OrderStatus,

    /// The timestamp after which the server will consider this order invalid,
    /// encoded in the format specified in [RFC3339].  This field is REQUIRED
    /// for objects with "pending" or "valid" in the status field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<FixedOffset>>,

    /// An array of identifier objects that the order pertains to.
    pub identifiers: Vec<AcmeIdentifier>,

    /// The requested value of the notBefore field in the certificate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<FixedOffset>>,

    /// The requested value of the notAfter field in the certificate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<FixedOffset>>,

    /// The error that occurred while processing the order, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AcmeProblem>,

    /// For pending orders, the authorizations that the client needs to complete
    /// before the requested certificate can be issued, including unexpired
    /// authorizations that the client has completed in the past for identifiers
    /// specified in the order.  The authorizations required are dictated by
    /// server policy; there may not be a 1:1 relationship between the order
    /// identifiers and the authorizations required.  For final orders (in the
    /// "valid" or "invalid" state), the authorizations that were completed.
    /// Each entry is a URL from which an authorization can be fetched
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorizations: Vec<String>,

    /// A URL that a CSR must be POSTed to once all of the order's
    /// authorizations are satisfied to finalize the order.  The result of a
    /// successful finalization will be the population of the certificate URL
    /// for the order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalize: Option<String>,

    /// A URL for the certificate that has been issued in response to this order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,

    /// The URL of this resource, as returned in the Location header.
    #[serde(skip)]
    pub location: Option<String>,
}

impl LocationResource for OrderResource {
    fn location_mut(&mut self) -> &mut Option<String> {
        &mut self.location
    }
}

/// ACME newOrder resource
/// https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct NewOrderResource {
    /// An array of identifier objects that the order pertains to.
    pub identifiers: Vec<AcmeIdentifier>,

    /// The requested value of the notBefore field in the certificate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<FixedOffset>>,

    /// The requested value of the notAfter field in the certificate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<FixedOffset>>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    /// Order objects are created in the "pending" state.
    Pending,

    /// Once all of the authorizations listed in the order object are in the
    /// "valid" state, the order transitions to the "ready" state.
    Ready,

    /// The order moves to the "processing" state after the client submits a
    /// request to the order's "finalize" URL and the CA begins the issuance
    /// process for the certificate.
    Processing,

    /// Once the certificate is issued, the order enters the "valid" state.
    Valid,

    /// If an error occurs at any of these stages, the order moves to the
    /// "invalid" state. The order also moves to the "invalid" state if it
    /// expires or one of its authorizations enters a final state other than
    /// "valid" ("expired", "revoked", or "deactivated").
    Invalid,
}

impl ResourceStatus for OrderStatus {
    fn is_failure(&self) -> bool {
        matches!(self, Self::Invalid)
    }
}

/// Finalize order request
/// https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub struct FinalizeOrder {
    /// A CSR encoding the parameters for the certificate being requested
    /// [RFC2986]. The CSR is sent in the base64url-encoded version of the DER
    /// format. (Note: Because this field uses base64url, and does not include
    /// headers, it is different from PEM.)
    pub csr: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rfc8555_order_example() {
        let order = OrderResource::deserialize(json!({
            "status": "valid",
            "expires": "2016-01-20T14:09:07.99Z",
            "identifiers": [
                { "type": "dns", "value": "www.example.org" },
                { "type": "dns", "value": "example.org" }
            ],
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2016-01-08T00:00:00Z",
            "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis",
                "https://example.com/acme/authz/r4HqLzrSrpI"
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
            "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
        }))
        .unwrap();

        assert_eq!(order.status, OrderStatus::Valid);
        assert_eq!(
            order.expires.unwrap(),
            DateTime::parse_from_rfc3339("2016-01-20T14:09:07.99Z").unwrap()
        );
        assert_eq!(
            order.identifiers,
            [
                AcmeIdentifier::dns("www.example.org"),
                AcmeIdentifier::dns("example.org"),
            ]
        );
        assert_eq!(
            order.not_before.unwrap(),
            DateTime::parse_from_rfc3339("2016-01-01T00:00:00Z").unwrap()
        );
        assert_eq!(
            order.not_after.unwrap(),
            DateTime::parse_from_rfc3339("2016-01-08T00:00:00Z").unwrap()
        );
        assert_eq!(
            order.authorizations,
            [
                "https://example.com/acme/authz/PAniVnsZcis",
                "https://example.com/acme/authz/r4HqLzrSrpI"
            ]
        );
        assert_eq!(
            order.finalize.unwrap(),
            "https://example.com/acme/order/TOlocE8rfgo/finalize"
        );
        assert_eq!(
            order.certificate.unwrap(),
            "https://example.com/acme/cert/mAt3xBGaobw"
        );
    }

    #[test]
    fn rfc8555_new_order_example() {
        let new_order = NewOrderResource {
            identifiers: vec![
                AcmeIdentifier::dns("www.example.org"),
                AcmeIdentifier::dns("example.org"),
            ],
            not_before: Some(DateTime::parse_from_rfc3339("2016-01-01T00:04:00+04:00").unwrap()),
            not_after: Some(DateTime::parse_from_rfc3339("2016-01-08T00:04:00+04:00").unwrap()),
        };
        assert_eq!(
            serde_json::to_value(new_order).unwrap(),
            json!({
                "identifiers": [
                    { "type": "dns", "value": "www.example.org" },
                    { "type": "dns", "value": "example.org" }
                ],
                "notBefore": "2016-01-01T00:04:00+04:00",
                "notAfter": "2016-01-08T00:04:00+04:00"
            })
        );
    }
}
