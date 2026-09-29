//! How a store encodes the blocks and blobs it holds.
//!
//! A store is plain or sealed, by one choice made when it is created. A
//! plain store keeps a block's bytes as they are. A sealed store keeps every
//! block and blob in a form a [`Sealing`] makes, so the address of a block
//! is the hash of its stored bytes. dialog-db defines only this hook: the
//! cipher, the keys, and the stored format belong to the [`Sealing`] a
//! caller passes in.

use std::fmt::Debug;
use std::sync::Arc;

use dialog_common::{Buffer, ConditionalSend, ConditionalSync};
use thiserror::Error;

/// Why a [`Sealing`] could not seal or open some bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SealingError {
    /// The bytes are not in the sealed form.
    #[error("the bytes are not sealed")]
    NotSealed,

    /// The bytes are sealed, but not under a key this sealing holds, or they
    /// were changed.
    #[error("authentication failed: the sealed bytes do not open under this key")]
    Authentication,

    /// Any other failure the sealing reports.
    #[error("{0}")]
    Other(String),
}

/// A transform a sealed store applies to every block and blob it holds.
///
/// A sealing must be deterministic: the same plaintext under the same key
/// gives the same stored bytes, so every replica computes the same address.
pub trait Sealing: Debug + ConditionalSend + ConditionalSync + 'static {
    /// The identifier of the key new bytes are sealed under. A store records
    /// it to refuse another key without keeping the key.
    fn key_id(&self) -> Vec<u8>;

    /// Names the bytes this sealing writes: two sealings with the same
    /// fingerprint write the same stored bytes for every block.
    fn fingerprint(&self) -> Vec<u8>;

    /// The stored form of one block.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealingError>;

    /// The plaintext of one stored block.
    fn open(&self, stored: &[u8]) -> Result<Vec<u8>, SealingError>;

    /// Whether `stored` is in the sealed form, without opening it. A sealed
    /// store refuses a block that is not.
    fn is_sealed(&self, stored: &[u8]) -> bool;

    /// A sealer for one blob, fed its plaintext in order.
    fn blob_sealer(&self) -> Box<dyn BlobSealing>;

    /// An opener for the plaintext range `offset..offset + length` of a
    /// sealed blob. `None` for `length` reads to the end.
    fn blob_opener(&self, offset: u64, length: Option<u64>) -> Box<dyn BlobOpening>;
}

/// Seals one blob as its plaintext streams in.
pub trait BlobSealing: ConditionalSend {
    /// The stored bytes for the next piece of plaintext. It may return
    /// nothing until it holds a whole chunk.
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SealingError>;

    /// The stored bytes of what is left, once the plaintext ends.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, SealingError>;
}

/// Opens one range of a sealed blob as its stored bytes stream in.
pub trait BlobOpening: ConditionalSend {
    /// Where the stored bytes that hold the range start.
    fn sealed_offset(&self) -> u64;

    /// How many stored bytes hold the range, or `None` to read to the end.
    fn sealed_length(&self) -> Option<u64>;

    /// The plaintext for the next piece of stored bytes.
    fn open(&mut self, stored: &[u8]) -> Result<Vec<u8>, SealingError>;

    /// The plaintext of what is left, once the stored bytes end.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, SealingError>;
}

/// How a store encodes the blocks it holds: plain, or sealed by a
/// [`Sealing`]. Every writer and reader of one store uses the same codec.
#[derive(Clone, Debug, Default)]
pub enum BlockCodec {
    /// Blocks are stored as they are.
    #[default]
    Plain,
    /// Blocks are stored in the form the sealing makes.
    Sealed(Arc<dyn Sealing>),
}

/// A sealed block's plaintext, remembered on the block's buffer so a block
/// read once is not opened again. The fingerprint makes sure a reader with
/// another key never receives it.
struct Opened {
    fingerprint: Vec<u8>,
    plaintext: Buffer,
}

impl BlockCodec {
    /// A codec that seals with `sealing`.
    pub fn sealed(sealing: impl Sealing) -> Self {
        Self::Sealed(Arc::new(sealing))
    }

    /// Whether blocks are stored sealed.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// The identifier of the key new blocks are sealed under, or `None` for
    /// a plain codec.
    pub fn key_id(&self) -> Option<Vec<u8>> {
        match self {
            Self::Plain => None,
            Self::Sealed(sealing) => Some(sealing.key_id()),
        }
    }

    /// Whether a store with this codec accepts `stored` as a block: any
    /// bytes when plain, only sealed bytes when sealed.
    pub fn accepts(&self, stored: &[u8]) -> bool {
        match self {
            Self::Plain => true,
            Self::Sealed(sealing) => sealing.is_sealed(stored),
        }
    }

    /// The stored form of `plaintext`.
    ///
    /// A sealed block remembers the plaintext it was sealed from, so reading
    /// back a block this process just wrote does not open it.
    pub fn encode(&self, plaintext: Buffer) -> Result<Buffer, SealingError> {
        let Self::Sealed(sealing) = self else {
            return Ok(plaintext);
        };
        let block = Buffer::from(sealing.seal(plaintext.as_ref())?);
        let fingerprint = sealing.fingerprint();
        block.memoize_decode(|| {
            Ok::<_, SealingError>(Opened {
                fingerprint,
                plaintext,
            })
        })?;
        Ok(block)
    }

    /// The plaintext of a stored `block`.
    ///
    /// A sealed block's plaintext is remembered on the block's buffer, so a
    /// block served again from a cache is not opened again.
    pub fn decode(&self, block: Buffer) -> Result<Buffer, SealingError> {
        let Self::Sealed(sealing) = self else {
            return Ok(block);
        };
        let fingerprint = sealing.fingerprint();
        let open = || sealing.open(block.as_ref()).map(Buffer::from);
        if let Some(opened) = block.memoized::<Opened>() {
            if opened.fingerprint == fingerprint {
                return Ok(opened.plaintext.clone());
            }
            return open();
        }
        let opened = block.memoize_decode(|| {
            open().map(|plaintext| Opened {
                fingerprint: fingerprint.clone(),
                plaintext,
            })
        })?;
        match opened {
            Some(opened) => Ok(opened.plaintext.clone()),
            None => open(),
        }
    }

    /// A sealer for one blob, or `None` for a plain codec.
    pub fn blob_sealer(&self) -> Option<Box<dyn BlobSealing>> {
        match self {
            Self::Plain => None,
            Self::Sealed(sealing) => Some(sealing.blob_sealer()),
        }
    }

    /// An opener for a range of a sealed blob, or `None` for a plain codec.
    pub fn blob_opener(&self, offset: u64, length: Option<u64>) -> Option<Box<dyn BlobOpening>> {
        match self {
            Self::Plain => None,
            Self::Sealed(sealing) => Some(sealing.blob_opener(offset, length)),
        }
    }
}

/// Two codecs are equal when they write the same bytes for every block.
impl PartialEq for BlockCodec {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Plain, Self::Plain) => true,
            (Self::Sealed(left), Self::Sealed(right)) => left.fingerprint() == right.fingerprint(),
            _ => false,
        }
    }
}

impl Eq for BlockCodec {}

#[cfg(test)]
mod tests {
    use dialog_common::Buffer;

    use super::BlockCodec;
    use crate::{SealingError, TestSealing};

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    #[dialog_common::test]
    fn it_passes_plain_blocks_through_unchanged() -> anyhow::Result<()> {
        let plaintext = Buffer::from(b"plain".as_slice());
        let block = BlockCodec::Plain.encode(plaintext.clone())?;
        assert_eq!(block, plaintext);
        assert_eq!(BlockCodec::Plain.decode(block)?, plaintext);
        Ok(())
    }

    #[dialog_common::test]
    fn it_addresses_a_sealed_block_by_its_stored_bytes() -> anyhow::Result<()> {
        let codec = BlockCodec::sealed(TestSealing::new(1));
        let plaintext = Buffer::from(b"sealed".as_slice());
        let block = codec.encode(plaintext.clone())?;
        assert_ne!(block.blake3_hash(), plaintext.blake3_hash());
        assert_eq!(codec.decode(block.clone())?, plaintext);
        let again = BlockCodec::sealed(TestSealing::new(1)).encode(plaintext)?;
        assert_eq!(again.blake3_hash(), block.blake3_hash());
        Ok(())
    }

    #[dialog_common::test]
    fn it_does_not_serve_a_remembered_plaintext_to_another_key() -> anyhow::Result<()> {
        let block =
            BlockCodec::sealed(TestSealing::new(1)).encode(Buffer::from(b"x".as_slice()))?;
        assert_eq!(
            BlockCodec::sealed(TestSealing::new(2)).decode(block),
            Err(SealingError::Authentication)
        );
        Ok(())
    }

    #[dialog_common::test]
    fn it_compares_codecs_by_the_blocks_they_write() {
        assert_eq!(BlockCodec::Plain, BlockCodec::default());
        assert_eq!(
            BlockCodec::sealed(TestSealing::new(1)),
            BlockCodec::sealed(TestSealing::new(1))
        );
        assert_ne!(
            BlockCodec::sealed(TestSealing::new(1)),
            BlockCodec::sealed(TestSealing::new(2))
        );
        assert_ne!(BlockCodec::sealed(TestSealing::new(1)), BlockCodec::Plain);
        assert!(!BlockCodec::sealed(TestSealing::new(1)).accepts(b"plain"));
    }
}
