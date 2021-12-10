use serde::{Deserialize, Serialize};

pub static IDENTIFIER_TYPE_DNS: &str = "dns";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AcmeIdentifier {
    /// The type of identifier.
    #[serde(rename = "type")]
    pub type_: String,

    /// The identifier itself.
    pub value: String,
}

impl AcmeIdentifier {
    pub fn dns(name: impl Into<String>) -> Self {
        Self {
            type_: IDENTIFIER_TYPE_DNS.to_string(),
            value: name.into(),
        }
    }

    pub fn is_dns(&self) -> bool {
        self.type_ == IDENTIFIER_TYPE_DNS
    }

    pub fn dns_name(&self) -> Option<&str> {
        if self.is_dns() {
            Some(&self.value)
        } else {
            None
        }
    }
}
