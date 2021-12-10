pub fn encode(input: impl AsRef<[u8]>) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

pub fn decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD)
}
