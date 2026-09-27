use std::sync::Arc;

use dialog_common::Buffer;

use crate::{KeyId, KeyRing, Padding, SealError, open, seal, sealed_generation};

/// How a store encodes the blocks it holds.
///
/// A plain codec stores a block's bytes as they are, byte for byte the
/// format of a store without encryption. A sealed codec stores every block
/// sealed (see [`seal`]), so a block's address is the hash of its sealed
/// bytes. The choice is made once per store, and every writer and reader of
/// the store uses the same one.
#[derive(Clone, Debug, Default)]
pub enum BlockCodec {
    /// Blocks are stored as they are.
    #[default]
    Plain,
    /// Blocks are stored sealed under a key ring.
    Sealed(Arc<SealedCodec>),
}

/// The keys and padding a sealed store encodes with.
#[derive(Debug)]
pub struct SealedCodec {
    ring: KeyRing,
    padding: Padding,
}

/// A sealed block's plaintext, remembered on the sealed block's buffer so a
/// block read once is not decrypted again. The key identifier makes sure a
/// reader with another key never receives it.
struct Opened {
    key: KeyId,
    plaintext: Buffer,
}

impl BlockCodec {
    /// A codec that seals under `ring`'s current generation with the default
    /// padding.
    pub fn sealed(ring: KeyRing) -> Self {
        Self::sealed_with(ring, Padding::default())
    }

    /// A codec that seals under `ring`'s current generation with `padding`.
    pub fn sealed_with(ring: KeyRing, padding: Padding) -> Self {
        Self::Sealed(Arc::new(SealedCodec { ring, padding }))
    }

    /// Whether blocks are stored sealed.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// The identifier of the key new blocks are sealed under, or `None` for
    /// a plain codec. A store records it to tell a matching key from
    /// another one without keeping the key.
    pub fn key_id(&self) -> Option<KeyId> {
        match self {
            Self::Plain => None,
            Self::Sealed(codec) => Some(codec.ring.current_keys().id),
        }
    }

    /// The stored form of `plaintext`.
    ///
    /// A sealed block remembers the plaintext it was sealed from, so reading
    /// back a block this process just wrote does not decrypt it.
    pub fn encode(&self, plaintext: Buffer) -> Result<Buffer, SealError> {
        let Self::Sealed(codec) = self else {
            return Ok(plaintext);
        };
        let block = Buffer::from(seal(plaintext.as_ref(), &codec.ring, codec.padding)?);
        let key = codec.ring.current_keys().id;
        block.memoize_decode(|| Ok::<_, SealError>(Opened { key, plaintext }))?;
        Ok(block)
    }

    /// The plaintext of a stored `block`.
    ///
    /// A sealed block's plaintext is remembered on the block's buffer, so a
    /// block served again from a cache is not decrypted again.
    pub fn decode(&self, block: Buffer) -> Result<Buffer, SealError> {
        let Self::Sealed(codec) = self else {
            return Ok(block);
        };
        let generation = sealed_generation(block.as_ref())?;
        let key = codec
            .ring
            .key_id(generation)
            .ok_or(SealError::UnknownGeneration(generation))?;
        if let Some(opened) = block.memoized::<Opened>() {
            if opened.key == key {
                return Ok(opened.plaintext.clone());
            }
            return codec.open(&block);
        }
        let opened = block.memoize_decode(|| {
            codec
                .open(&block)
                .map(|plaintext| Opened { key, plaintext })
        })?;
        match opened {
            Some(opened) => Ok(opened.plaintext.clone()),
            None => codec.open(&block),
        }
    }
}

/// Two codecs are equal when they write the same bytes for every block: both
/// plain, or both sealing under the same key, generation, and padding.
impl PartialEq for BlockCodec {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Plain, Self::Plain) => true,
            (Self::Sealed(left), Self::Sealed(right)) => {
                left.ring.current() == right.ring.current()
                    && left.ring.current_keys().id == right.ring.current_keys().id
                    && left.padding == right.padding
            }
            _ => false,
        }
    }
}

impl Eq for BlockCodec {}

impl SealedCodec {
    fn open(&self, block: &Buffer) -> Result<Buffer, SealError> {
        open(block.as_ref(), &self.ring).map(Buffer::from)
    }
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use dialog_common::Buffer;

    use super::BlockCodec;
    use crate::{KeyRing, SealError, SealKey};

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    fn sealed(byte: u8) -> BlockCodec {
        BlockCodec::sealed(KeyRing::new(SealKey::from([byte; 32])))
    }

    #[dialog_common::test]
    fn it_passes_plain_blocks_through_unchanged() -> anyhow::Result<()> {
        let plaintext = Buffer::from(b"plain".as_slice());
        let block = BlockCodec::Plain.encode(plaintext.clone())?;
        assert_eq!(block, plaintext);
        assert_eq!(block.blake3_hash(), plaintext.blake3_hash());
        assert_eq!(BlockCodec::Plain.decode(block)?, plaintext);
        Ok(())
    }

    #[dialog_common::test]
    fn it_addresses_a_sealed_block_by_its_sealed_bytes() -> anyhow::Result<()> {
        let plaintext = Buffer::from(b"sealed".as_slice());
        let block = sealed(1).encode(plaintext.clone())?;
        assert_ne!(block.blake3_hash(), plaintext.blake3_hash());
        assert_eq!(sealed(1).decode(block.clone())?, plaintext);
        // Another codec with the same key reads it; the address is the same
        // on every replica.
        assert_eq!(
            sealed(1).encode(plaintext)?.blake3_hash(),
            block.blake3_hash()
        );
        Ok(())
    }

    #[dialog_common::test]
    fn it_does_not_serve_a_remembered_plaintext_to_another_key() -> anyhow::Result<()> {
        let block = sealed(1).encode(Buffer::from(b"secret".as_slice()))?;
        assert_eq!(sealed(1).decode(block.clone())?.as_ref(), b"secret");
        assert_eq!(sealed(2).decode(block), Err(SealError::Authentication));
        Ok(())
    }

    #[dialog_common::test]
    fn it_refuses_plain_bytes_in_a_sealed_store() {
        assert_eq!(
            sealed(1).decode(Buffer::from(b"plain bytes".as_slice())),
            Err(SealError::NotSealed)
        );
    }

    #[dialog_common::test]
    fn it_compares_codecs_by_the_blocks_they_write() {
        assert_eq!(BlockCodec::Plain, BlockCodec::default());
        assert_eq!(sealed(1), sealed(1));
        assert_ne!(sealed(1), sealed(2));
        assert_ne!(sealed(1), BlockCodec::Plain);
        assert_eq!(BlockCodec::Plain.key_id(), None);
        assert_eq!(sealed(1).key_id(), Some(SealKey::from([1; 32]).id()));
    }

    #[dialog_common::test]
    fn it_returns_aligned_plaintext() -> anyhow::Result<()> {
        let block = sealed(1).encode(Buffer::from(vec![7u8; 1000]))?;
        let plaintext = sealed(1).decode(block)?;
        assert_eq!(plaintext.as_ref().as_ptr() as usize % 16, 0);
        Ok(())
    }
}
