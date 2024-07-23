use hex::{FromHex, ToHex};
use ring::digest::{Context, SHA256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    pub fn new(data: &[u8]) -> Self {
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();

        Self(
            digest
                .as_ref()
                .try_into()
                .expect("SHA256 should be 32 bytes"),
        )
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ToHex for Sha256 {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.encode_hex()
    }
    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.encode_hex_upper()
    }
}

impl FromHex for Sha256 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = Vec::from_hex(hex)?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| hex::FromHexError::InvalidStringLength)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_new() {
        let data = b"hello world";
        let sha256 = Sha256::new(data);
        assert_eq!(sha256.0.len(), 32);
    }

    #[test]
    fn test_sha256_to_hex() {
        let data = b"test data";
        let sha256 = Sha256::new(data);
        let hex: String = sha256.encode_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha256_from_hex_valid() {
        let hex = "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";
        let result = Sha256::from_hex(hex);
        assert!(result.is_ok());
        let sha256 = result.unwrap();
        assert_eq!(sha256.0.len(), 32);
    }

    #[test]
    fn test_sha256_roundtrip() {
        let original_data = b"roundtrip test";
        let sha256 = Sha256::new(original_data);
        let hex: String = sha256.encode_hex();
        let roundtrip_sha256 = Sha256::from_hex(&hex).unwrap();
        assert_eq!(sha256.0, roundtrip_sha256.0);
    }
}
