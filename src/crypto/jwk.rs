use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Jwk<'a> {
    pub kty: &'a str,
    pub crv: &'a str,
    pub x: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<&'a str>,
}
