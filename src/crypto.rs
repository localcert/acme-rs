pub mod account_key;
pub mod ed25519;
pub mod es256;
pub mod jws;

pub(crate) mod jwk;

use account_key::{AccountKey, GenerateAccountKey};
use es256::Es256AccountKey;

use crate::{AcmeError, AcmeResult};

pub fn generate_account_key() -> impl AccountKey {
    Es256AccountKey::generate()
}

pub fn account_key_from_jwk(jwk: impl AsRef<str>) -> AcmeResult<Box<dyn AccountKey>> {
    let jwk = jwk.as_ref();
    if let Ok(key) = es256::from_jwk(jwk) {
        Ok(Box::new(key))
    } else if let Ok(key) = ed25519::from_jwk(jwk) {
        Ok(Box::new(key))
    } else {
        Err(AcmeError::CryptoError(anyhow::anyhow!(
            "couldn't decode account key from JWK"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_key_from_jwk_es256() {
        let key = account_key_from_jwk(es256::tests::JWK).unwrap();
        assert_eq!(key.jws_alg(), "ES256");
    }

    #[test]
    fn account_key_from_jwk_ed25519() {
        let key = account_key_from_jwk(ed25519::tests::JWK).unwrap();
        assert_eq!(key.jws_alg(), "EdDSA");
    }

    #[test]
    fn account_key_from_jwk_invalid() {
        account_key_from_jwk("{}").unwrap_err();
    }
}
