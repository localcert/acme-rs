use p256::{ecdsa::SigningKey, SecretKey};
use rand::{CryptoRng, RngCore};
use signature::Signer;
use zeroize::Zeroizing;

use super::{
    account_key::{AccountKey, GenerateAccountKey},
    jws::JwsSigner,
};

#[derive(Debug)]
pub struct Es256AccountKey(SecretKey);

pub fn from_jwk(jwk: impl AsRef<str>) -> anyhow::Result<Es256AccountKey> {
    Ok(SecretKey::from_jwk_str(jwk.as_ref())?.into())
}

impl GenerateAccountKey for Es256AccountKey {
    fn generate_rng(rng: impl CryptoRng + RngCore) -> Self {
        SecretKey::random(rng).into()
    }
}

impl JwsSigner for Es256AccountKey {
    fn jws_alg(&self) -> &str {
        "ES256"
    }

    fn jws_sign(&self, input: &[u8]) -> Vec<u8> {
        SigningKey::from(&self.0).sign(input).as_ref().to_vec()
    }
}

impl AccountKey for Es256AccountKey {
    fn private_jwk(&self) -> anyhow::Result<Zeroizing<String>> {
        Ok(self.0.to_jwk_string())
    }

    fn public_jwk(&self) -> anyhow::Result<String> {
        Ok(self.0.public_key().to_jwk_string())
    }
}

impl From<SecretKey> for Es256AccountKey {
    fn from(secret: SecretKey) -> Self {
        Self(secret)
    }
}

impl From<Es256AccountKey> for SecretKey {
    fn from(key: Es256AccountKey) -> Self {
        key.0
    }
}

#[cfg(test)]
pub mod tests {
    use once_cell::sync::Lazy;

    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    pub const JWK: &'static str = r#"{
        "kty":"EC", "crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
    }"#;

    const KEY: Lazy<Es256AccountKey> = Lazy::new(|| from_jwk(JWK).unwrap());

    #[test]
    fn round_trip_jwk() {
        let jwk = KEY.private_jwk().unwrap();
        let expect: String = JWK.split_whitespace().collect();
        assert_eq!(*jwk, expect);
    }

    #[test]
    fn generate_smoke_test() {
        Es256AccountKey::generate();
    }

    #[test]
    fn sign_smoke_test() {
        KEY.jws_sign(b"test");
    }
}
