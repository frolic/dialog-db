use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};

use crate::{Generation, KeyRing, Padding, SealError};

/// The bytes every sealed block starts with.
pub const SEALED_BLOCK_MAGIC: [u8; 4] = *b"DLGE";

/// The envelope version this build writes and reads.
pub const SEALED_BLOCK_VERSION: u8 = 1;

/// The one cipher suite: XChaCha20-Poly1305, with keys and nonces derived
/// through BLAKE3. The byte exists so the suite can change without breaking
/// the envelope format.
pub const XCHACHA20_POLY1305_BLAKE3: u8 = 1;

const NONCE_LENGTH: usize = 24;
const TAG_LENGTH: usize = 16;
const LENGTH_PREFIX: usize = 4;

/// The header's length: magic, version, suite, generation, and nonce.
pub const SEALED_BLOCK_HEADER_LENGTH: usize = 4 + 1 + 1 + 4 + NONCE_LENGTH;

/// Seals `plaintext` under the ring's current generation.
///
/// The frame is the plaintext behind a length prefix, padded with zeros. Its
/// nonce is a keyed hash of the frame, so the same plaintext under the same
/// key and padding always seals to the same bytes.
pub fn seal(plaintext: &[u8], ring: &KeyRing, padding: Padding) -> Result<Vec<u8>, SealError> {
    seal_frame(
        plaintext,
        ring,
        padding.padded_length(LENGTH_PREFIX + plaintext.len()),
    )
}

/// The length of the block [`seal`] makes from a frame of `frame_length`
/// bytes.
pub(crate) const fn sealed_length(frame_length: usize) -> usize {
    SEALED_BLOCK_HEADER_LENGTH + frame_length + TAG_LENGTH
}

/// The frame length that holds `plaintext_length` bytes without padding.
pub(crate) const fn frame_length(plaintext_length: usize) -> usize {
    LENGTH_PREFIX + plaintext_length
}

/// Seals `plaintext` in a frame of `frame_length` bytes, which must hold
/// the length prefix and the plaintext.
pub(crate) fn seal_frame(
    plaintext: &[u8],
    ring: &KeyRing,
    frame_length: usize,
) -> Result<Vec<u8>, SealError> {
    let length = u32::try_from(plaintext.len()).map_err(|_| SealError::TooLong(plaintext.len()))?;
    let frame_length = frame_length.max(LENGTH_PREFIX + plaintext.len());
    let generation = ring.current();
    let keys = ring.current_keys();

    let mut block = Vec::with_capacity(sealed_length(frame_length));
    block.extend_from_slice(&SEALED_BLOCK_MAGIC);
    block.push(SEALED_BLOCK_VERSION);
    block.push(XCHACHA20_POLY1305_BLAKE3);
    block.extend_from_slice(&generation.to_le_bytes());
    block.extend_from_slice(&[0; NONCE_LENGTH]);
    block.extend_from_slice(&length.to_le_bytes());
    block.extend_from_slice(plaintext);
    block.resize(SEALED_BLOCK_HEADER_LENGTH + frame_length, 0);

    let (header, frame) = block.split_at_mut(SEALED_BLOCK_HEADER_LENGTH);
    let nonce = frame_nonce(&keys.nonce, frame);
    header[SEALED_BLOCK_HEADER_LENGTH - NONCE_LENGTH..].copy_from_slice(&nonce);

    let tag = XChaCha20Poly1305::new(Key::from_slice(&keys.data))
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), header, frame)
        .map_err(|_| SealError::TooLong(plaintext.len()))?;
    block.extend_from_slice(&tag);
    Ok(block)
}

/// Opens a block sealed by [`seal`], returning its plaintext.
///
/// Fails when the block was sealed under a key the ring does not hold, when
/// its bytes were changed, and when its frame is not the one [`seal`] would
/// produce for the plaintext inside.
pub fn open(block: &[u8], ring: &KeyRing) -> Result<Vec<u8>, SealError> {
    let header = SealedHeader::parse(block)?;
    let keys = ring
        .keys(header.generation)
        .ok_or(SealError::UnknownGeneration(header.generation))?;

    let (header_bytes, rest) = block.split_at(SEALED_BLOCK_HEADER_LENGTH);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LENGTH);
    let mut frame = ciphertext.to_vec();
    XChaCha20Poly1305::new(Key::from_slice(&keys.data))
        .decrypt_in_place_detached(
            XNonce::from_slice(&header.nonce),
            header_bytes,
            &mut frame,
            Tag::from_slice(tag),
        )
        .map_err(|_| SealError::Authentication)?;

    if frame_nonce(&keys.nonce, &frame) != header.nonce {
        return Err(SealError::NonCanonical("nonce does not match frame"));
    }
    let (prefix, body) = frame.split_at(LENGTH_PREFIX);
    let length = u32::from_le_bytes(prefix.try_into().expect("prefix is four bytes")) as usize;
    if length > body.len() {
        return Err(SealError::NonCanonical("length prefix exceeds frame"));
    }
    if body[length..].iter().any(|byte| *byte != 0) {
        return Err(SealError::NonCanonical("nonzero padding"));
    }
    frame.truncate(LENGTH_PREFIX + length);
    frame.drain(..LENGTH_PREFIX);
    Ok(frame)
}

/// Reads the generation a sealed block names, without opening it.
pub fn sealed_generation(block: &[u8]) -> Result<Generation, SealError> {
    SealedHeader::parse(block).map(|header| header.generation)
}

/// The cleartext header of a sealed block.
struct SealedHeader {
    generation: Generation,
    nonce: [u8; NONCE_LENGTH],
}

impl SealedHeader {
    fn parse(block: &[u8]) -> Result<Self, SealError> {
        if block.len() < SEALED_BLOCK_HEADER_LENGTH + LENGTH_PREFIX + TAG_LENGTH
            || block[..4] != SEALED_BLOCK_MAGIC
        {
            return Err(SealError::NotSealed);
        }
        if block[4] != SEALED_BLOCK_VERSION {
            return Err(SealError::UnsupportedVersion(block[4]));
        }
        if block[5] != XCHACHA20_POLY1305_BLAKE3 {
            return Err(SealError::UnsupportedSuite(block[5]));
        }
        let generation = u32::from_le_bytes(block[6..10].try_into().expect("four bytes"));
        let nonce = block[10..SEALED_BLOCK_HEADER_LENGTH]
            .try_into()
            .expect("nonce is 24 bytes");
        Ok(Self { generation, nonce })
    }
}

fn frame_nonce(key: &[u8; 32], frame: &[u8]) -> [u8; NONCE_LENGTH] {
    let hash = blake3::keyed_hash(key, frame);
    hash.as_bytes()[..NONCE_LENGTH]
        .try_into()
        .expect("a blake3 hash is longer than a nonce")
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use super::{SEALED_BLOCK_HEADER_LENGTH, open, seal, sealed_generation};
    use crate::{KeyRing, Padding, SealError, SealKey};

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    fn ring(byte: u8) -> KeyRing {
        KeyRing::new(SealKey::from([byte; 32]))
    }

    fn sample(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 31 % 251) as u8).collect()
    }

    #[dialog_common::test]
    fn it_round_trips_plaintexts_of_every_size() -> anyhow::Result<()> {
        for padding in [Padding::None, Padding::PowerOfTwo, Padding::Padme] {
            for length in [0, 1, 2, 3, 15, 16, 17, 255, 4096, 65_537] {
                let plaintext = sample(length);
                let block = seal(&plaintext, &ring(1), padding)?;
                assert_eq!(open(&block, &ring(1))?, plaintext, "{padding:?} {length}");
            }
        }
        Ok(())
    }

    #[dialog_common::test]
    fn it_seals_deterministically() -> anyhow::Result<()> {
        let plaintext = sample(1000);
        assert_eq!(
            seal(&plaintext, &ring(1), Padding::Padme)?,
            seal(&plaintext, &ring(1), Padding::Padme)?
        );
        Ok(())
    }

    #[dialog_common::test]
    fn it_seals_differently_under_another_key_or_plaintext() -> anyhow::Result<()> {
        let plaintext = sample(1000);
        let sealed = seal(&plaintext, &ring(1), Padding::Padme)?;
        assert_ne!(sealed, seal(&plaintext, &ring(2), Padding::Padme)?);
        let mut other = plaintext.clone();
        other[500] ^= 1;
        let resealed = seal(&other, &ring(1), Padding::Padme)?;
        assert_ne!(
            sealed[..SEALED_BLOCK_HEADER_LENGTH],
            resealed[..SEALED_BLOCK_HEADER_LENGTH]
        );
        Ok(())
    }

    #[dialog_common::test]
    fn it_hides_the_plaintext() -> anyhow::Result<()> {
        let marker = b"a plaintext marker that must not survive sealing";
        let block = seal(marker, &ring(1), Padding::Padme)?;
        assert!(!block.windows(marker.len()).any(|window| window == marker));
        Ok(())
    }

    #[dialog_common::test]
    fn it_refuses_the_wrong_key() -> anyhow::Result<()> {
        let block = seal(&sample(100), &ring(1), Padding::Padme)?;
        assert_eq!(open(&block, &ring(2)), Err(SealError::Authentication));
        Ok(())
    }

    #[dialog_common::test]
    fn it_refuses_a_changed_byte_anywhere() -> anyhow::Result<()> {
        let block = seal(&sample(64), &ring(1), Padding::None)?;
        for index in 0..block.len() {
            let mut tampered = block.clone();
            tampered[index] ^= 0x01;
            assert!(open(&tampered, &ring(1)).is_err(), "byte {index}");
        }
        Ok(())
    }

    #[dialog_common::test]
    fn it_refuses_bytes_that_are_not_sealed() {
        assert_eq!(open(b"plain bytes", &ring(1)), Err(SealError::NotSealed));
        assert_eq!(open(&[0; 100], &ring(1)), Err(SealError::NotSealed));
    }

    #[dialog_common::test]
    fn it_names_the_generation_in_the_header() -> anyhow::Result<()> {
        let rotated = ring(1).insert(4, SealKey::from([2; 32]));
        let block = seal(&sample(10), &rotated, Padding::Padme)?;
        assert_eq!(sealed_generation(&block)?, 4);
        assert_eq!(open(&block, &rotated)?, sample(10));
        assert_eq!(open(&block, &ring(1)), Err(SealError::UnknownGeneration(4)));

        // A ring that holds an older generation still opens its blocks.
        let old = seal(&sample(10), &ring(1), Padding::Padme)?;
        assert_eq!(open(&old, &rotated)?, sample(10));
        Ok(())
    }

    #[dialog_common::test]
    fn it_pads_to_the_policy_length() -> anyhow::Result<()> {
        let unpadded = seal(&sample(1000), &ring(1), Padding::None)?;
        let padded = seal(&sample(1000), &ring(1), Padding::PowerOfTwo)?;
        assert_eq!(unpadded.len(), SEALED_BLOCK_HEADER_LENGTH + 4 + 1000 + 16);
        assert_eq!(padded.len(), SEALED_BLOCK_HEADER_LENGTH + 1024 + 16);
        // Nearby lengths share a padded size.
        let near = seal(&sample(990), &ring(1), Padding::PowerOfTwo)?;
        assert_eq!(padded.len(), near.len());
        Ok(())
    }
}
