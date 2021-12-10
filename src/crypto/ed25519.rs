use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, SECRET_KEY_LENGTH};
use zeroize::Zeroizing;

use crate::{base64url, crypto::jws::JwsSigner};

use super::{
    account_key::{AccountKey, GenerateAccountKey},
    jwk::Jwk,
};

#[derive(Debug)]
pub struct Ed25519AccountKey(Keypair);

pub fn from_jwk(jwk: impl AsRef<str>) -> anyhow::Result<Ed25519AccountKey> {
    if let Jwk {
        kty: "OKP",
        crv: "Ed25519",
        x,
        d: Some(d),
        ..
    } = serde_json::from_str(jwk.as_ref())?
    {
        let secret = SecretKey::from_bytes(&base64url::decode(d)?)?;
        let public = PublicKey::from_bytes(&base64url::decode(x)?)?;
        Ok(Keypair { secret, public }.into())
    } else {
        anyhow::bail!("invalid JWK for Ed25519 private key")
    }
}

impl JwsSigner for Ed25519AccountKey {
    fn jws_alg(&self) -> &str {
        "EdDSA"
    }

    fn jws_sign(&self, input: &[u8]) -> Vec<u8> {
        self.0.sign(input).as_ref().to_vec()
    }
}

impl AccountKey for Ed25519AccountKey {
    fn public_jwk(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(&Jwk {
            kty: "OKP",
            crv: "Ed25519",
            x: &base64url::encode(self.0.public.as_bytes()),
            y: None,
            d: None,
        })?)
    }

    fn private_jwk(&self) -> anyhow::Result<Zeroizing<String>> {
        let x = base64url::encode(self.0.public.as_bytes());
        let d = base64url::encode(self.0.secret.as_bytes());
        let jwk = Jwk {
            kty: "OKP",
            crv: "Ed25519",
            x: x.as_ref(),
            y: None,
            d: Some(d.as_ref()),
        };
        Ok(Zeroizing::new(serde_json::to_string(&jwk)?))
    }
}

impl GenerateAccountKey for Ed25519AccountKey {
    fn generate_rng(mut rng: impl rand::CryptoRng + rand::RngCore) -> Self {
        // Adapted from Keypair::random to avoid rand crate version problem
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut bytes[..]);
        let secret = SecretKey::from_bytes(&bytes).expect("SecretKey::from_bytes failed");
        let public: PublicKey = (&secret).into();
        Keypair { secret, public }.into()
    }
}

impl From<Keypair> for Ed25519AccountKey {
    fn from(pair: Keypair) -> Self {
        Self(pair)
    }
}

impl From<Ed25519AccountKey> for Keypair {
    fn from(key: Ed25519AccountKey) -> Self {
        key.0
    }
}

#[cfg(test)]
pub mod tests {
    use once_cell::sync::Lazy;

    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.1
    pub const JWK: &'static str = r#"{
        "kty":"OKP","crv":"Ed25519",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }"#;

    const KEY: Lazy<Ed25519AccountKey> = Lazy::new(|| from_jwk(JWK).unwrap());

    #[test]
    fn round_trip_jwk() {
        let jwk = KEY.private_jwk().unwrap();
        let expect: String = JWK.split_whitespace().collect();
        assert_eq!(*jwk, expect);
    }

    #[test]
    fn generate_smoke_test() {
        Ed25519AccountKey::generate();
    }

    #[test]
    fn sign_smoke_test() {
        KEY.jws_sign(b"test");
    }
}
