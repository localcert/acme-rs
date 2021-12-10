use crate::wire::identifier::AcmeIdentifier;

#[derive(Debug)]
pub struct DnsIdentifier(String);

impl DnsIdentifier {
    pub fn from_acme_identifier(acme_ident: &AcmeIdentifier, add_wildcard: bool) -> Option<Self> {
        acme_ident.dns_name().map(|name| {
            if add_wildcard {
                Self("*.".to_string() + name)
            } else {
                Self(name.to_string())
            }
        })
    }

    pub fn find_acme_identifier<'a>(
        iter: impl IntoIterator<Item = &'a AcmeIdentifier>,
        add_wildcard: bool,
    ) -> Option<Self> {
        iter.into_iter()
            .find(|acme_ident| acme_ident.is_dns())
            .and_then(|acme_ident| DnsIdentifier::from_acme_identifier(acme_ident, add_wildcard))
    }

    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }

    pub fn without_wildcard(&self) -> &str {
        if self.is_wildcard() {
            &self.0[2..]
        } else {
            &self.0
        }
    }
}

impl AsRef<str> for DnsIdentifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<DnsIdentifier> for String {
    fn from(ident: DnsIdentifier) -> Self {
        ident.0
    }
}
