use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};

use crate::key_ring::GenerationKeys;
use crate::{Generation, KeyRing, SEAL_KEY_LENGTH, SealError, SealKey};

/// Key derivation context for the key that encrypts a link.
const LINK_CONTEXT: &str = "dialog/e2ee/link/v1";

/// Key derivation context for the key that derives a link's nonce.
const LINK_NONCE_CONTEXT: &str = "dialog/e2ee/link-nonce/v1";

const NONCE_LENGTH: usize = 24;
const TAG_LENGTH: usize = 16;

/// The length in bytes of a [`KeyLink`].
pub const KEY_LINK_LENGTH: usize = NONCE_LENGTH + SEAL_KEY_LENGTH + TAG_LENGTH;

/// The seal key of one generation, sealed under the key of the next one.
///
/// A space publishes one link when a generation opens. A reader that holds
/// the newest key follows the links back to every older key, so one key
/// wrap gives the whole history. The newer key is not derived from the
/// older one, so a member removed before the new generation cannot compute
/// it.
///
/// The link is bound to the newer key's generation, and its nonce comes
/// from a keyed hash of the older key, so the same two keys always give
/// the same link.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyLink([u8; KEY_LINK_LENGTH]);

impl KeyLink {
    /// Seals `older` under `newer`, the key of `generation`.
    pub fn new(
        newer: &SealKey,
        generation: Generation,
        older: &SealKey,
    ) -> Result<Self, SealError> {
        let nonce_key = blake3::derive_key(LINK_NONCE_CONTEXT, newer.as_bytes());
        let hash = blake3::keyed_hash(&nonce_key, older.as_bytes());
        let mut bytes = [0u8; KEY_LINK_LENGTH];
        bytes[..NONCE_LENGTH].copy_from_slice(&hash.as_bytes()[..NONCE_LENGTH]);
        let (nonce, rest) = bytes.split_at_mut(NONCE_LENGTH);
        let (key, tag) = rest.split_at_mut(SEAL_KEY_LENGTH);
        key.copy_from_slice(older.as_bytes());
        let sealed = cipher(newer)
            .encrypt_in_place_detached(XNonce::from_slice(nonce), &generation.to_le_bytes(), key)
            .map_err(|_| SealError::Authentication)?;
        tag.copy_from_slice(&sealed);
        Ok(Self(bytes))
    }

    /// The older key, opened with `newer`, the key of `generation`.
    ///
    /// Fails when the link was sealed under another key or for another
    /// generation.
    pub fn open(&self, newer: &SealKey, generation: Generation) -> Result<SealKey, SealError> {
        let (nonce, rest) = self.0.split_at(NONCE_LENGTH);
        let (sealed, tag) = rest.split_at(SEAL_KEY_LENGTH);
        let mut key = [0u8; SEAL_KEY_LENGTH];
        key.copy_from_slice(sealed);
        cipher(newer)
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
                &generation.to_le_bytes(),
                &mut key,
                Tag::from_slice(tag),
            )
            .map_err(|_| SealError::Authentication)?;
        Ok(SealKey::from(key))
    }

    /// The link's bytes, for a caller that stores it.
    pub fn as_bytes(&self) -> &[u8; KEY_LINK_LENGTH] {
        &self.0
    }
}

impl TryFrom<&[u8]> for KeyLink {
    type Error = SealError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; KEY_LINK_LENGTH] = bytes.try_into().map_err(|_| SealError::NotSealed)?;
        Ok(Self(bytes))
    }
}

/// Prints only the length: a link is ciphertext, but it is key material.
impl Debug for KeyLink {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("KeyLink(..)")
    }
}

fn cipher(newer: &SealKey) -> XChaCha20Poly1305 {
    let key = blake3::derive_key(LINK_CONTEXT, newer.as_bytes());
    XChaCha20Poly1305::new(Key::from_slice(&key))
}

impl KeyRing {
    /// A ring holding `key` at `generation`, and every older generation
    /// that the links reach.
    ///
    /// `links` gives the link published when a generation opened. The walk
    /// stops with [`SealError::MissingLink`] at the first generation that
    /// has none, and fails when a link does not open.
    pub fn from_links(
        generation: Generation,
        key: SealKey,
        links: impl Fn(Generation) -> Option<KeyLink>,
    ) -> Result<Self, SealError> {
        let mut generations = BTreeMap::from([(generation, GenerationKeys::from(&key))]);
        let mut newer = key;
        for opened in (1..=generation).rev() {
            let link = links(opened).ok_or(SealError::MissingLink(opened))?;
            let older = link.open(&newer, opened)?;
            generations.insert(opened - 1, GenerationKeys::from(&older));
            newer = older;
        }
        Ok(Self::from_generations(generation, generations))
    }
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use dialog_common::Buffer;

    use super::KeyLink;
    use crate::{BlockCodec, KeyRing, SealError, SealKey};

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    fn key(byte: u8) -> SealKey {
        SealKey::from([byte; 32])
    }

    #[dialog_common::test]
    fn it_opens_the_older_key_with_the_newer_one() -> anyhow::Result<()> {
        let link = KeyLink::new(&key(2), 1, &key(1))?;
        assert_eq!(link.open(&key(2), 1)?, key(1));
        assert_eq!(KeyLink::new(&key(2), 1, &key(1))?, link);
        assert!(!link.as_bytes().windows(32).any(|part| part == [1; 32]));
        Ok(())
    }

    #[dialog_common::test]
    fn it_does_not_open_with_another_key_or_generation() -> anyhow::Result<()> {
        let link = KeyLink::new(&key(2), 1, &key(1))?;
        assert_eq!(link.open(&key(3), 1), Err(SealError::Authentication));
        assert_eq!(link.open(&key(2), 2), Err(SealError::Authentication));
        Ok(())
    }

    #[dialog_common::test]
    fn it_reads_every_generation_from_the_newest_key() -> anyhow::Result<()> {
        let first = BlockCodec::sealed(KeyRing::new(key(1)));
        let old = first.encode(Buffer::from(b"before".as_slice()))?;
        let links = [
            KeyLink::new(&key(2), 1, &key(1))?,
            KeyLink::new(&key(3), 2, &key(2))?,
        ];

        let ring = KeyRing::from_links(2, key(3), |generation| {
            links.get(generation as usize - 1).cloned()
        })?;
        assert_eq!(ring.current(), 2);
        let newest = BlockCodec::sealed(ring);
        assert_eq!(newest.decode(old)?.as_ref(), b"before");
        let new = newest.encode(Buffer::from(b"after".as_slice()))?;
        assert!(matches!(
            first.decode(new),
            Err(SealError::UnknownGeneration(2))
        ));
        Ok(())
    }

    #[dialog_common::test]
    fn it_stops_at_a_missing_link() {
        let result = KeyRing::from_links(2, key(3), |_| None);
        assert!(matches!(result, Err(SealError::MissingLink(2))));
    }
}
