use rand::{CryptoRng, RngCore};
use signature::rand_core::OsRng;
use zeroize::Zeroizing;

use super::jws::JwsSigner;

pub trait AccountKey: JwsSigner + Send + Sync + std::fmt::Debug {
    fn private_jwk(&self) -> anyhow::Result<Zeroizing<String>>;
    fn public_jwk(&self) -> anyhow::Result<String>;
}

pub trait GenerateAccountKey: AccountKey + Sized {
    fn generate_rng(rng: impl CryptoRng + RngCore) -> Self;

    fn generate() -> Self {
        Self::generate_rng(OsRng)
    }
}

impl JwsSigner for Box<dyn AccountKey> {
    fn jws_alg(&self) -> &str {
        self.as_ref().jws_alg()
    }

    fn jws_sign(&self, input: &[u8]) -> Vec<u8> {
        self.as_ref().jws_sign(input)
    }
}

impl AccountKey for Box<dyn AccountKey> {
    fn private_jwk(&self) -> anyhow::Result<Zeroizing<String>> {
        self.as_ref().private_jwk()
    }

    fn public_jwk(&self) -> anyhow::Result<String> {
        self.as_ref().public_jwk()
    }
}
