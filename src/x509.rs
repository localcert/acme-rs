use openssl::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509ReqBuilder},
};

use crate::{AcmeError, AcmeResult};

pub fn generate_key_and_csr(name: impl AsRef<str>) -> AcmeResult<(String, Vec<u8>)> {
    let ec_group = EcGroup::from_curve_name(Nid::SECP256K1)?;
    let key = PKey::from_ec_key(EcKey::generate(ec_group.as_ref())?)?;
    let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8()?).unwrap();

    let mut csr = X509ReqBuilder::new()?;
    csr.set_pubkey(key.as_ref())?;
    let mut extensions = Stack::new()?;
    extensions.push(
        SubjectAlternativeName::new()
            .dns(name.as_ref())
            .build(&csr.x509v3_context(None))?,
    )?;
    csr.add_extensions(extensions.as_ref())?;
    csr.sign(key.as_ref(), MessageDigest::sha256())?;
    let csr_der = csr.build().to_der()?;

    Ok((key_pem, csr_der))
}

impl From<ErrorStack> for AcmeError {
    fn from(err: ErrorStack) -> Self {
        AcmeError::CryptoError(err.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test() {
        generate_key_and_csr("example.com").unwrap();
    }
}
