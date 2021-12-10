use serde::{Deserialize, Serialize};
/// ACME Directory resource
/// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryResource {
    /// New nonce URL
    pub new_nonce: String,

    /// New account URL
    pub new_account: String,

    /// New order URL
    pub new_order: String,

    /// New authorization URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_authz: Option<String>,

    /// Revoke certificate URL
    pub revoke_cert: String,

    /// Key change URL
    pub key_change: String,

    pub meta: DirectoryMetadata,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMetadata {
    /// A URL identifying the current terms of service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,

    /// An HTTP or HTTPS URL locating a website providing more information about
    /// the ACME server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    /// The hostnames that the ACME server recognizes as referring to itself for
    /// the purposes of CAA record validation as defined in [RFC6844].  Each
    /// string MUST represent the same sequence of ASCII code points that the
    /// server will expect to see as the "Issuer Domain Name" in a CAA issue or
    /// issuewild property tag.  This allows clients to determine the correct
    /// issuer domain name to use when configuring CAA records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caa_identities: Vec<String>,

    /// If this field is present and set to "true", then the CA requires that
    /// all newAccount requests include an "externalAccountBinding" field
    /// associating the new account with an external account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_account_required: Option<bool>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rfc8555_directory_example() {
        let directory = DirectoryResource::deserialize(json!({
          "newNonce": "https://example.com/acme/new-nonce",
          "newAccount": "https://example.com/acme/new-account",
          "newOrder": "https://example.com/acme/new-order",
          "newAuthz": "https://example.com/acme/new-authz",
          "revokeCert": "https://example.com/acme/revoke-cert",
          "keyChange": "https://example.com/acme/key-change",
          "meta": {
            "termsOfService": "https://example.com/acme/terms/2017-5-30",
            "website": "https://www.example.com/",
            "caaIdentities": ["example.com"],
            "externalAccountRequired": false
          }
        }))
        .unwrap();

        assert_eq!(directory.new_nonce, "https://example.com/acme/new-nonce");
        assert_eq!(
            directory.new_account,
            "https://example.com/acme/new-account"
        );
        assert_eq!(directory.new_order, "https://example.com/acme/new-order");
        assert_eq!(
            directory.new_authz.unwrap(),
            "https://example.com/acme/new-authz"
        );
        assert_eq!(
            directory.revoke_cert,
            "https://example.com/acme/revoke-cert"
        );
        assert_eq!(directory.key_change, "https://example.com/acme/key-change");

        assert_eq!(
            directory.meta.terms_of_service.unwrap(),
            "https://example.com/acme/terms/2017-5-30"
        );
        assert_eq!(directory.meta.website.unwrap(), "https://www.example.com/");
        assert_eq!(directory.meta.caa_identities, ["example.com"]);
        assert_eq!(directory.meta.external_account_required.unwrap(), false);
    }
}
