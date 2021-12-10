use serde::Serialize;

use crate::base64url;

pub static CONTENT_TYPE: &str = "application/jose+json";

pub trait JwsSigner {
    fn jws_alg(&self) -> &str;
    fn jws_sign(&self, input: &[u8]) -> Vec<u8>;
}

pub fn jws_flattened(
    signer: &impl JwsSigner,
    header: &JwsHeader<impl Serialize>,
    payload: &[u8],
) -> anyhow::Result<Jws> {
    // https://tools.ietf.org/id/draft-ietf-jose-json-web-signature-01.html#rfc.section.5
    let header_json = serde_json::to_vec(header)?;
    let header_b64 = base64url::encode(header_json);
    let payload_b64 = base64url::encode(payload);
    let input = format!("{}.{}", header_b64, payload_b64);
    let signature = signer.jws_sign(input.as_bytes());
    let signature_b64 = base64url::encode(signature);
    Ok(Jws {
        protected: header_b64,
        payload: payload_b64,
        signature: signature_b64,
    })
}

#[derive(Serialize)]
pub struct Jws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct JwsHeader<'a, JwkT: Serialize> {
    pub alg: &'a str,
    pub nonce: &'a str,
    pub url: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JwkT>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<&'a str>,
}
