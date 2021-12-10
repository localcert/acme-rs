use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use super::{
    challenge::ChallengeResource,
    common::{is_false, LocationResource, ResourceStatus},
    identifier::AcmeIdentifier,
};

/// ACME Authorization resource
/// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationResource {
    /// The identifier that the account is authorized to represent.
    pub identifier: AcmeIdentifier,

    /// The status of this authorization.
    pub status: AuthorizationStatus,

    /// The timestamp after which the server will consider this authorization
    /// invalid [...].  This field is REQUIRED for objects with "valid" in the
    /// "status" field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<FixedOffset>>,

    /// For pending authorizations, the challenges that the client can fulfill
    /// in order to prove possession of the identifier.  For valid
    /// authorizations, the challenge that was validated.  For invalid
    /// authorizations, the challenge that was attempted and failed.  Each array
    /// entry is an object with parameters required to validate the challenge.
    /// A client should attempt to fulfill one of these challenges, and a server
    /// should consider any one of the challenges sufficient to make the
    /// authorization valid.
    pub challenges: Vec<ChallengeResource>,

    /// This field MUST be present and true for authorizations created as a
    /// result of a newOrder request containing a DNS identifier with a value
    /// that was a wildcard domain name.  For other authorizations, it MUST be
    /// absent.
    #[serde(default, skip_serializing_if = "is_false")]
    pub wildcard: bool,

    /// The URL of this resource, as returned in the Location header.
    #[serde(skip)]
    pub location: Option<String>,
}

impl LocationResource for AuthorizationResource {
    fn location_mut(&mut self) -> &mut Option<String> {
        &mut self.location
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    /// Authorization objects are created in the "pending" state.
    Pending,

    /// If one of the challenges listed in the authorization transitions to the
    /// "valid" state, then the authorization also changes to the "valid" state.
    Valid,

    /// If the client attempts to fulfill a challenge and fails, or if there is
    /// an error while the authorization is still pending, then the
    /// authorization transitions to the "invalid" state.
    Invalid,

    /// Once the authorization is in the "valid" state, it can [...] be
    /// deactivated by the client
    Deactivated,

    /// Once the authorization is in the "valid" state, it can expire
    Expired,

    /// Once the authorization is in the "valid" state, it can [...] be
    /// revoked by the server
    Revoked,
}

impl ResourceStatus for AuthorizationStatus {
    fn is_failure(&self) -> bool {
        !matches!(self, Self::Pending | Self::Valid)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rfc8555_authorization_example() {
        let authz = AuthorizationResource::deserialize(json!({
            "status": "valid",
            "expires": "2015-03-01T14:09:07.99Z",
            "identifier": {
              "type": "dns",
              "value": "www.example.org"
            },
            "challenges": [
              {
                "url": "https://example.com/acme/chall/prV_B7yEyA4",
                "type": "http-01",
                "status": "valid",
                "token": "DGyRejmCefe7v4NfDGDKfA",
                "validated": "2014-12-01T12:05:58.16Z"
              }
            ],
            "wildcard": false
        }))
        .unwrap();

        assert_eq!(authz.status, AuthorizationStatus::Valid);
        assert_eq!(
            authz.expires.unwrap(),
            DateTime::parse_from_rfc3339("2015-03-01T14:09:07.99Z").unwrap()
        );
        assert_eq!(authz.identifier, AcmeIdentifier::dns("www.example.org"),);
        assert_eq!(authz.challenges.len(), 1);
        assert_eq!(authz.wildcard, false);
    }
}
