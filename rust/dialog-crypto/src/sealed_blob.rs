//! Sealing of blobs, which can be too large to seal as one block.
//!
//! A sealed blob is a sequence of sealed chunks, stored end to end as one
//! blob. Chunk `i` holds plaintext bytes `i * BLOB_CHUNK_LENGTH` up to the
//! next chunk. Its frame is `u64_le(i) || data`, sealed like a block, so a
//! chunk cannot move to another position and two equal chunks at different
//! positions seal to different bytes.
//!
//! The blob's plaintext length is padded with the codec's padding. Chunks
//! after the data carry no data, and the last chunk's frame is cut to the
//! padded length. So the stored length follows from the padded length only.
//!
//! Every chunk before the last has the same sealed length. A reader can
//! therefore find the chunks that hold a byte range without reading the
//! chunks in front of it.

use std::sync::Arc;

use crate::seal::{frame_length, seal_frame, sealed_length};
use crate::{BlockCodec, SealError, SealedCodec, open};

/// The plaintext bytes one chunk of a sealed blob holds.
pub const BLOB_CHUNK_LENGTH: usize = 64 * 1024;

/// The bytes in front of a chunk's data: its position in the blob.
const CHUNK_INDEX_LENGTH: usize = 8;

/// The stored length of every chunk of a sealed blob except the last.
pub const SEALED_BLOB_CHUNK_LENGTH: usize =
    sealed_length(frame_length(CHUNK_INDEX_LENGTH + BLOB_CHUNK_LENGTH));

impl BlockCodec {
    /// A sealer for one blob, or `None` for a plain codec, which stores a
    /// blob's bytes as they are.
    pub fn blob_sealer(&self) -> Option<BlobSealer> {
        match self {
            Self::Plain => None,
            Self::Sealed(codec) => Some(BlobSealer {
                codec: codec.clone(),
                pending: Vec::with_capacity(BLOB_CHUNK_LENGTH),
                index: 0,
                length: 0,
            }),
        }
    }

    /// An opener for `length` plaintext bytes from `offset` of one sealed
    /// blob (to the end when `length` is `None`), or `None` for a plain
    /// codec.
    ///
    /// The opener names the stored byte range to read. It accepts the bytes
    /// of that range in any split, and returns only the requested plaintext.
    pub fn blob_opener(&self, offset: u64, length: Option<u64>) -> Option<BlobOpener> {
        let Self::Sealed(codec) = self else {
            return None;
        };
        let chunk = BLOB_CHUNK_LENGTH as u64;
        let first = offset / chunk;
        let sealed_length = match length {
            Some(0) => Some(0),
            Some(length) => {
                let last = (offset.saturating_add(length) - 1) / chunk;
                Some((last - first + 1).saturating_mul(SEALED_BLOB_CHUNK_LENGTH as u64))
            }
            None => None,
        };
        Some(BlobOpener {
            codec: codec.clone(),
            pending: Vec::new(),
            index: first,
            sealed_offset: first.saturating_mul(SEALED_BLOB_CHUNK_LENGTH as u64),
            sealed_length,
            skip: offset - first * chunk,
            remaining: length,
        })
    }
}

/// Seals one blob as it is written, chunk by chunk.
///
/// Write the plaintext with [`seal`](Self::seal) and store what it returns,
/// in order. Then store what [`finish`](Self::finish) returns. The stored
/// bytes are the same for the same plaintext and key, so replicas agree on
/// the blob's address.
pub struct BlobSealer {
    codec: Arc<SealedCodec>,
    pending: Vec<u8>,
    index: u64,
    length: u64,
}

impl BlobSealer {
    /// Adds `plaintext` to the blob, returning the sealed bytes of every
    /// chunk it completes.
    pub fn seal(&mut self, mut plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut sealed = Vec::new();
        self.length += plaintext.len() as u64;
        while !plaintext.is_empty() {
            let take = (BLOB_CHUNK_LENGTH - self.pending.len()).min(plaintext.len());
            self.pending.extend_from_slice(&plaintext[..take]);
            plaintext = &plaintext[take..];
            if self.pending.len() == BLOB_CHUNK_LENGTH {
                let data = std::mem::take(&mut self.pending);
                sealed.extend(self.seal_chunk(&data, BLOB_CHUNK_LENGTH)?);
                self.pending = data;
                self.pending.clear();
            }
        }
        Ok(sealed)
    }

    /// The plaintext bytes written so far.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Ends the blob, returning the sealed bytes of the chunks still open:
    /// the partial chunk, and the chunks that pad the blob.
    pub fn finish(mut self) -> Result<Vec<u8>, SealError> {
        let length = usize::try_from(self.length).map_err(|_| SealError::TooLong(usize::MAX))?;
        let padded = self.codec.padding.padded_length(length);
        let chunks = padded.div_ceil(BLOB_CHUNK_LENGTH).max(1) as u64;
        let last_capacity = padded - (chunks as usize - 1) * BLOB_CHUNK_LENGTH;
        let data = std::mem::take(&mut self.pending);
        let mut sealed = Vec::new();
        let mut data = data.as_slice();
        while self.index < chunks {
            let capacity = if self.index + 1 == chunks {
                last_capacity
            } else {
                BLOB_CHUNK_LENGTH
            };
            sealed.extend(self.seal_chunk(data, capacity)?);
            data = &[];
        }
        Ok(sealed)
    }

    fn seal_chunk(&mut self, data: &[u8], capacity: usize) -> Result<Vec<u8>, SealError> {
        let mut plaintext = Vec::with_capacity(CHUNK_INDEX_LENGTH + data.len());
        plaintext.extend_from_slice(&self.index.to_le_bytes());
        plaintext.extend_from_slice(data);
        self.index += 1;
        seal_frame(
            &plaintext,
            &self.codec.ring,
            frame_length(CHUNK_INDEX_LENGTH + capacity),
        )
    }
}

/// Opens a byte range of one sealed blob as its stored bytes arrive.
pub struct BlobOpener {
    codec: Arc<SealedCodec>,
    pending: Vec<u8>,
    index: u64,
    sealed_offset: u64,
    sealed_length: Option<u64>,
    skip: u64,
    remaining: Option<u64>,
}

impl BlobOpener {
    /// The offset of the first stored byte to read.
    pub fn sealed_offset(&self) -> u64 {
        self.sealed_offset
    }

    /// How many stored bytes to read, or `None` to read to the end. A range
    /// that runs past the end of the blob reads to the end.
    pub fn sealed_length(&self) -> Option<u64> {
        self.sealed_length
    }

    /// Takes the next stored bytes of the range, returning the plaintext of
    /// every chunk they complete.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        self.pending.extend_from_slice(sealed);
        let mut plaintext = Vec::new();
        let mut start = 0;
        while self.pending.len() - start >= SEALED_BLOB_CHUNK_LENGTH {
            let end = start + SEALED_BLOB_CHUNK_LENGTH;
            let data = open_chunk(&self.codec, self.index, &self.pending[start..end])?;
            self.index += 1;
            self.keep(&data, &mut plaintext);
            start = end;
        }
        self.pending.drain(..start);
        Ok(plaintext)
    }

    /// Ends the range, returning the plaintext of the last, shorter chunk.
    pub fn finish(mut self) -> Result<Vec<u8>, SealError> {
        let mut plaintext = Vec::new();
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            let data = open_chunk(&self.codec, self.index, &pending)?;
            self.keep(&data, &mut plaintext);
        }
        Ok(plaintext)
    }

    /// Appends the part of `data` inside the requested range to `plaintext`.
    fn keep(&mut self, data: &[u8], plaintext: &mut Vec<u8>) {
        let skip = (self.skip as usize).min(data.len());
        self.skip -= skip as u64;
        let mut data = &data[skip..];
        if let Some(remaining) = self.remaining.as_mut() {
            let take = (*remaining as usize).min(data.len());
            *remaining -= take as u64;
            data = &data[..take];
        }
        plaintext.extend_from_slice(data);
    }
}

/// Opens one stored chunk, which must be chunk `index` of its blob, and
/// returns its data.
fn open_chunk(codec: &SealedCodec, index: u64, block: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut frame = open(block, &codec.ring)?;
    if frame.len() < CHUNK_INDEX_LENGTH || frame[..CHUNK_INDEX_LENGTH] != index.to_le_bytes() {
        return Err(SealError::NonCanonical("blob chunk out of place"));
    }
    if frame.len() > CHUNK_INDEX_LENGTH + BLOB_CHUNK_LENGTH {
        return Err(SealError::NonCanonical("blob chunk too long"));
    }
    frame.drain(..CHUNK_INDEX_LENGTH);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    use super::{BLOB_CHUNK_LENGTH, SEALED_BLOB_CHUNK_LENGTH};
    use crate::{BlockCodec, KeyRing, Padding, SEALED_BLOCK_MAGIC, SealError, SealKey};

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    fn sealed(byte: u8) -> BlockCodec {
        BlockCodec::sealed(KeyRing::new(SealKey::from([byte; 32])))
    }

    fn sample(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 31 % 251) as u8).collect()
    }

    /// Seals `plaintext` written in pieces of `piece` bytes.
    fn seal_blob(codec: &BlockCodec, plaintext: &[u8], piece: usize) -> Result<Vec<u8>, SealError> {
        let mut sealer = codec.blob_sealer().expect("a sealed codec");
        let mut stored = Vec::new();
        for part in plaintext.chunks(piece.max(1)) {
            stored.extend(sealer.seal(part)?);
        }
        assert_eq!(sealer.length(), plaintext.len() as u64);
        stored.extend(sealer.finish()?);
        Ok(stored)
    }

    /// Opens `length` bytes from `offset`, reading the stored range the
    /// opener names in pieces of `piece` bytes.
    fn open_blob(
        codec: &BlockCodec,
        stored: &[u8],
        offset: u64,
        length: Option<u64>,
        piece: usize,
    ) -> Result<Vec<u8>, SealError> {
        let mut opener = codec.blob_opener(offset, length).expect("a sealed codec");
        let start = (opener.sealed_offset() as usize).min(stored.len());
        let end = match opener.sealed_length() {
            Some(length) => (start + length as usize).min(stored.len()),
            None => stored.len(),
        };
        let mut plaintext = Vec::new();
        for part in stored[start..end].chunks(piece) {
            plaintext.extend(opener.open(part)?);
        }
        plaintext.extend(opener.finish()?);
        Ok(plaintext)
    }

    #[dialog_common::test]
    fn it_leaves_blobs_plain_under_a_plain_codec() {
        assert!(BlockCodec::Plain.blob_sealer().is_none());
        assert!(BlockCodec::Plain.blob_opener(0, None).is_none());
    }

    #[dialog_common::test]
    fn it_round_trips_blobs_of_every_size() -> anyhow::Result<()> {
        let codec = sealed(1);
        for length in [
            0,
            1,
            1000,
            BLOB_CHUNK_LENGTH - 1,
            BLOB_CHUNK_LENGTH,
            BLOB_CHUNK_LENGTH + 1,
            3 * BLOB_CHUNK_LENGTH + 17,
        ] {
            let plaintext = sample(length);
            let stored = seal_blob(&codec, &plaintext, 10_000)?;
            assert!(stored.starts_with(&SEALED_BLOCK_MAGIC));
            assert_eq!(open_blob(&codec, &stored, 0, None, 7_000)?, plaintext);
        }
        Ok(())
    }

    #[dialog_common::test]
    fn it_seals_the_same_blob_to_the_same_bytes() -> anyhow::Result<()> {
        let plaintext = sample(2 * BLOB_CHUNK_LENGTH + 5);
        assert_eq!(
            seal_blob(&sealed(1), &plaintext, 1000)?,
            seal_blob(&sealed(1), &plaintext, 50_000)?
        );
        assert_ne!(
            seal_blob(&sealed(1), &plaintext, 1000)?,
            seal_blob(&sealed(2), &plaintext, 1000)?
        );
        Ok(())
    }

    #[dialog_common::test]
    fn it_hides_equal_chunks_and_the_plaintext() -> anyhow::Result<()> {
        let marker = b"a plaintext marker that must not survive sealing";
        let plaintext: Vec<u8> = marker
            .iter()
            .copied()
            .cycle()
            .take(2 * BLOB_CHUNK_LENGTH)
            .collect();
        let stored = seal_blob(&sealed(1), &plaintext, 4096)?;
        assert!(!stored.windows(marker.len()).any(|window| window == marker));
        let (first, second) = stored.split_at(SEALED_BLOB_CHUNK_LENGTH);
        assert_ne!(first, &second[..SEALED_BLOB_CHUNK_LENGTH]);
        Ok(())
    }

    #[dialog_common::test]
    fn it_opens_any_byte_range() -> anyhow::Result<()> {
        let codec = sealed(1);
        let plaintext = sample(3 * BLOB_CHUNK_LENGTH + 100);
        let stored = seal_blob(&codec, &plaintext, 65_000)?;
        let chunk = BLOB_CHUNK_LENGTH as u64;
        for (offset, length) in [
            (0, Some(0)),
            (10, Some(9)),
            (chunk - 3, Some(6)),
            (chunk, Some(chunk)),
            (2 * chunk + 50, None),
            (3 * chunk + 90, Some(1000)),
            (5 * chunk, Some(10)),
        ] {
            let start = (offset as usize).min(plaintext.len());
            let end = match length {
                Some(length) => (start + length as usize).min(plaintext.len()),
                None => plaintext.len(),
            };
            assert_eq!(
                open_blob(&codec, &stored, offset, length, 3000)?,
                plaintext[start..end],
                "{offset} {length:?}"
            );
        }
        Ok(())
    }

    #[dialog_common::test]
    fn it_pads_the_stored_length() -> anyhow::Result<()> {
        let codec =
            BlockCodec::sealed_with(KeyRing::new(SealKey::from([1; 32])), Padding::PowerOfTwo);
        let near = seal_blob(&codec, &sample(BLOB_CHUNK_LENGTH + 10), 4096)?;
        let far = seal_blob(&codec, &sample(2 * BLOB_CHUNK_LENGTH - 10), 4096)?;
        assert_eq!(near.len(), far.len());
        assert_eq!(near.len(), 2 * SEALED_BLOB_CHUNK_LENGTH);
        Ok(())
    }

    #[dialog_common::test]
    fn it_refuses_another_key() -> anyhow::Result<()> {
        let stored = seal_blob(&sealed(1), &sample(1000), 1000)?;
        assert_eq!(
            open_blob(&sealed(2), &stored, 0, None, 1000),
            Err(SealError::Authentication)
        );
        Ok(())
    }

    #[dialog_common::test]
    fn it_refuses_chunks_out_of_place() -> anyhow::Result<()> {
        let codec = sealed(1);
        let stored = seal_blob(&codec, &sample(2 * BLOB_CHUNK_LENGTH), 4096)?;
        let (first, second) = stored.split_at(SEALED_BLOB_CHUNK_LENGTH);
        let swapped = [second, first].concat();
        assert_eq!(
            open_blob(&codec, &swapped, 0, None, 4096),
            Err(SealError::NonCanonical("blob chunk out of place"))
        );
        Ok(())
    }
}
