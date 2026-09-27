#![deny(missing_docs)]

//! Deterministic sealing of content-addressed blocks.
//!
//! A sealed block is the block: storage holds only the sealed bytes, and the
//! block's address is the hash of those bytes. Sealing is deterministic, so
//! two replicas holding the same key seal the same plaintext to the same
//! bytes, and content addressing keeps deduplicating, diffing, and
//! converging as it does for plain blocks.
//!
//! The construction derives the nonce from a keyed hash of the plaintext
//! frame, then encrypts the frame with XChaCha20-Poly1305:
//!
//! - `frame = u32_le(plaintext_len) || plaintext || zero padding`
//! - `nonce = blake3_keyed(K_nonce, frame)[0..24]`
//! - `header = "DLGE" || version || suite || u32_le(generation) || nonce`
//! - `block = header || XChaCha20Poly1305(K_data, nonce, aad = header, frame)`
//!
//! The same plaintext under the same key always gives the same block. Equal
//! plaintexts are therefore visible as equal blocks, which is what
//! deduplication means. A block opened with a key it was not sealed under
//! fails authentication.
//!
//! Sealing is synchronous and pure Rust on every target, because it runs
//! inside the tree's synchronous write path.
//!
//! A key rotation opens a new generation under a fresh key. A [`KeyLink`]
//! seals the previous generation's key under the new one, so a reader that
//! holds the newest key reads every older block with
//! [`KeyRing::from_links`].
//!
//! A blob can be too large to seal as one block. [`BlobSealer`] seals it as
//! a sequence of chunks stored end to end, and [`BlobOpener`] opens any byte
//! range of it. The blob's address is the hash of the stored chunks.
//!
//! ```
//! use dialog_common::Buffer;
//! use dialog_crypto::{BlockCodec, KeyRing, SealKey};
//!
//! let codec = BlockCodec::sealed(KeyRing::new(SealKey::from([7; 32])));
//! let block = codec.encode(Buffer::from(b"hello".as_slice())).unwrap();
//!
//! assert_ne!(block.as_ref(), b"hello");
//! assert_eq!(codec.decode(block).unwrap().as_ref(), b"hello");
//! ```

mod block_codec;
pub use block_codec::*;

mod error;
pub use error::*;

mod key_link;
pub use key_link::*;

mod key_ring;
pub use key_ring::*;

mod padding;
pub use padding::*;

mod seal;
pub use seal::*;

mod seal_key;
pub use seal_key::*;

mod sealed_blob;
pub use sealed_blob::*;
