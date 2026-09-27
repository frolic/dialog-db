use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};

use zeroize::Zeroize;

use crate::SealKey;

/// Key derivation context for the key that encrypts a block's frame.
const DATA_CONTEXT: &str = "dialog/e2ee/data/v1";

/// Key derivation context for the key that derives a block's nonce.
const NONCE_CONTEXT: &str = "dialog/e2ee/nonce/v1";

/// Key derivation context for a key's public identifier.
const KEY_ID_CONTEXT: &str = "dialog/e2ee/key-id/v1";

/// A seal key's generation: a counter that names which key sealed a block.
///
/// Every sealed block carries its generation in its header, so a reader
/// knows which key to open it with without a lookup.
pub type Generation = u32;

/// A public identifier for a [`SealKey`].
///
/// It is a one-way derivation of the key, so it can be stored beside a
/// sealed space to check that a key supplied later is the one the space was
/// sealed with, without storing the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 32]);

impl KeyId {
    /// The identifier's bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl SealKey {
    /// The public identifier of this key.
    pub fn id(&self) -> KeyId {
        KeyId(blake3::derive_key(KEY_ID_CONTEXT, self.as_bytes()))
    }
}

/// The keys one generation seals and opens with, derived from its
/// [`SealKey`] with domain-separated key derivation.
#[derive(Clone)]
pub(crate) struct GenerationKeys {
    pub(crate) data: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) id: KeyId,
}

impl From<&SealKey> for GenerationKeys {
    fn from(key: &SealKey) -> Self {
        Self {
            data: blake3::derive_key(DATA_CONTEXT, key.as_bytes()),
            nonce: blake3::derive_key(NONCE_CONTEXT, key.as_bytes()),
            id: key.id(),
        }
    }
}

impl Drop for GenerationKeys {
    fn drop(&mut self) {
        self.data.zeroize();
        self.nonce.zeroize();
    }
}

/// The seal keys a reader holds, by generation.
///
/// New blocks are sealed under the newest generation. A block is opened with
/// the generation its header names, so a ring holding older generations
/// still reads blocks written before a key rotation.
#[derive(Clone)]
pub struct KeyRing {
    current: Generation,
    generations: BTreeMap<Generation, GenerationKeys>,
}

impl KeyRing {
    /// A ring holding one key at generation 0.
    pub fn new(key: SealKey) -> Self {
        Self {
            current: 0,
            generations: BTreeMap::from([(0, GenerationKeys::from(&key))]),
        }
    }

    /// A ring over derived keys, sealing under `current`.
    pub(crate) fn from_generations(
        current: Generation,
        generations: BTreeMap<Generation, GenerationKeys>,
    ) -> Self {
        Self {
            current,
            generations,
        }
    }

    /// Adds `key` at `generation`. The newest generation in the ring is the
    /// one new blocks are sealed under.
    pub fn insert(mut self, generation: Generation, key: SealKey) -> Self {
        self.generations
            .insert(generation, GenerationKeys::from(&key));
        self.current = self.current.max(generation);
        self
    }

    /// The generation new blocks are sealed under.
    pub fn current(&self) -> Generation {
        self.current
    }

    /// The identifier of the key at `generation`, if the ring holds one.
    pub fn key_id(&self, generation: Generation) -> Option<KeyId> {
        self.generations.get(&generation).map(|keys| keys.id)
    }

    pub(crate) fn keys(&self, generation: Generation) -> Option<&GenerationKeys> {
        self.generations.get(&generation)
    }

    pub(crate) fn current_keys(&self) -> &GenerationKeys {
        self.generations
            .get(&self.current)
            .expect("the current generation is always in the ring")
    }
}

/// Never prints key material.
impl Debug for KeyRing {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter
            .debug_struct("KeyRing")
            .field("current", &self.current)
            .field("generations", &self.generations.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use super::KeyRing;
    use crate::SealKey;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    #[dialog_common::test]
    fn it_seals_under_the_newest_generation() {
        let ring = KeyRing::new(SealKey::from([1; 32])).insert(3, SealKey::from([2; 32]));
        assert_eq!(ring.current(), 3);
        assert_eq!(ring.key_id(3), Some(SealKey::from([2; 32]).id()));
        assert_eq!(ring.key_id(0), Some(SealKey::from([1; 32]).id()));
        assert_eq!(ring.key_id(1), None);
    }

    #[dialog_common::test]
    fn it_derives_separate_keys_for_each_purpose() {
        let ring = KeyRing::new(SealKey::from([9; 32]));
        let keys = ring.current_keys();
        assert_ne!(keys.data, keys.nonce);
        assert_ne!(&keys.data, keys.id.as_bytes());
        assert_ne!(&keys.data, &[9; 32]);
    }

    #[dialog_common::test]
    fn it_does_not_print_key_material() {
        let ring = KeyRing::new(SealKey::from([0xcd; 32]));
        let printed = format!("{ring:?}");
        assert!(!printed.contains("205"), "{printed}");
        assert!(!printed.to_lowercase().contains("cd"), "{printed}");
    }
}
