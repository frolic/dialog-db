use std::fmt::{Debug, Formatter, Result as FmtResult};

use zeroize::Zeroize;

use crate::SealError;

/// The length in bytes of a [`SealKey`].
pub const SEAL_KEY_LENGTH: usize = 32;

/// The secret a space seals its blocks with.
///
/// Every key a block is actually sealed or opened with is derived from this
/// one (see [`KeyRing`](crate::KeyRing)), so a caller only ever stores and
/// shares these 32 bytes. The bytes are wiped when the key is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct SealKey([u8; SEAL_KEY_LENGTH]);

impl SealKey {
    /// Generates a new random key from the platform's secure random source.
    pub fn generate() -> Result<Self, SealError> {
        let mut bytes = [0u8; SEAL_KEY_LENGTH];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| SealError::Randomness(error.to_string()))?;
        Ok(Self(bytes))
    }

    /// The raw key bytes, for a caller that stores or shares the key.
    pub fn as_bytes(&self) -> &[u8; SEAL_KEY_LENGTH] {
        &self.0
    }
}

impl From<[u8; SEAL_KEY_LENGTH]> for SealKey {
    fn from(bytes: [u8; SEAL_KEY_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl Drop for SealKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Never prints the key bytes.
impl Debug for SealKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("SealKey(..)")
    }
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use super::SealKey;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    #[dialog_common::test]
    fn it_generates_distinct_keys() -> anyhow::Result<()> {
        assert_ne!(SealKey::generate()?, SealKey::generate()?);
        Ok(())
    }

    #[dialog_common::test]
    fn it_does_not_print_the_key() {
        let key = SealKey::from([0xab; 32]);
        assert_eq!(format!("{key:?}"), "SealKey(..)");
    }
}
