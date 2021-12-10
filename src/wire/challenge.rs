use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{common::ResourceStatus, problem::AcmeProblem};

pub static CHALLENGE_TYPE_DNS_01: &str = "dns-01";
pub static CHALLENGE_TYPE_HTTP_01: &str = "http-01";

/// ACME Challenge resource
/// https://datatracker.ietf.org/doc/html/rfc8555#section-8
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResource {
    /// The type of challenge encoded in the object.
    #[serde(rename = "type")]
    pub type_: String,

    /// The URL to which a response can be posted.
    pub url: String,

    /// The status of this challenge.
    pub status: ChallengeStatus,

    /// The time at which the server validated this challenge, [...]. This field
    /// is REQUIRED if the "status" field is "valid".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated: Option<DateTime<FixedOffset>>,

    /// Error that occurred while the server was validating the challenge, if
    /// any, structured as a problem document [RFC7807].  Multiple errors can be
    /// indicated by using subproblems Section 6.7.1.  A challenge object with
    /// an error MUST have status equal to "invalid".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AcmeProblem>,

    /// A random value that uniquely identifies the challenge.
    ///
    /// NOTE: Not a generic challenge resource field, but used by most challenge
    /// types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// All additional fields are specified by the challenge type.
    ///
    /// NOTE: Since "token" is widely used it has its own field.
    #[serde(flatten)]
    pub additional_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    /// Challenge objects are created in the "pending" state.
    Pending,

    /// They transition to the "processing" state when the client responds to
    /// the challenge [...] and the server begins attempting to validate that
    /// the client has completed the challenge.
    Processing,

    /// If validation is successful, the challenge moves to the "valid" state
    Valid,

    /// If there is an error, the challenge moves to the "invalid" state.
    Invalid,
}

impl ResourceStatus for ChallengeStatus {
    fn is_failure(&self) -> bool {
        matches!(self, Self::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rfc8555_challenge_example() {
        let chal = ChallengeResource::deserialize(json!({
                "url": "https://example.com/acme/chall/prV_B7yEyA4",
                "type": "http-01",
                "status": "valid",
                "token": "DGyRejmCefe7v4NfDGDKfA",
                "validated": "2014-12-01T12:05:58.16Z"
        }))
        .unwrap();

        assert_eq!(chal.url, "https://example.com/acme/chall/prV_B7yEyA4");
        assert_eq!(chal.type_, "http-01");
        assert_eq!(chal.status, ChallengeStatus::Valid);
        assert_eq!(chal.token.unwrap(), "DGyRejmCefe7v4NfDGDKfA");
        assert_eq!(
            chal.validated.unwrap(),
            DateTime::parse_from_rfc3339("2014-12-01T12:05:58.16Z").unwrap()
        );
    }
}
