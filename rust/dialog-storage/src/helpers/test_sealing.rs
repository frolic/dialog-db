//! A small sealing for tests of the [`Sealing`](crate::Sealing) hook.

use crate::{BlobOpening, BlobSealing, Sealing, SealingError};

/// The first bytes of a block sealed by [`TestSealing`].
pub const TEST_SEALED_MAGIC: [u8; 4] = *b"TSL1";

/// A deterministic sealing for tests: a keyed hash tags each block, and a
/// keystream from that tag hides its bytes. It is not a cipher to trust; a
/// real sealing is passed in by the caller of dialog-db.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestSealing {
    key: [u8; 32],
}

impl TestSealing {
    /// A sealing under a key made of `byte`.
    pub fn new(byte: u8) -> Self {
        Self { key: [byte; 32] }
    }

    fn tag(&self, plaintext: &[u8]) -> [u8; 16] {
        let hash = blake3::keyed_hash(&self.key, plaintext);
        let mut tag = [0; 16];
        tag.copy_from_slice(&hash.as_bytes()[..16]);
        tag
    }

    fn keystream(&self, nonce: &[u8], offset: u64, bytes: &mut [u8]) {
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(nonce);
        let mut reader = hasher.finalize_xof();
        reader.set_position(offset);
        let mut stream = vec![0; bytes.len()];
        reader.fill(&mut stream);
        for (byte, mask) in bytes.iter_mut().zip(stream) {
            *byte ^= mask;
        }
    }
}

impl Sealing for TestSealing {
    fn key_id(&self) -> Vec<u8> {
        blake3::hash(&self.key).as_bytes()[..8].to_vec()
    }

    fn fingerprint(&self) -> Vec<u8> {
        self.key_id()
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealingError> {
        let tag = self.tag(plaintext);
        let mut body = plaintext.to_vec();
        self.keystream(&tag, 0, &mut body);
        Ok([TEST_SEALED_MAGIC.as_slice(), &tag, &body].concat())
    }

    fn open(&self, stored: &[u8]) -> Result<Vec<u8>, SealingError> {
        if !self.is_sealed(stored) {
            return Err(SealingError::NotSealed);
        }
        let (tag, body) = stored[4..].split_at(16);
        let mut plaintext = body.to_vec();
        self.keystream(tag, 0, &mut plaintext);
        if self.tag(&plaintext) != tag {
            return Err(SealingError::Authentication);
        }
        Ok(plaintext)
    }

    fn is_sealed(&self, stored: &[u8]) -> bool {
        stored.len() >= 20 && stored.starts_with(&TEST_SEALED_MAGIC)
    }

    fn blob_sealer(&self) -> Box<dyn BlobSealing> {
        Box::new(TestBlobSealer {
            sealing: *self,
            position: 0,
            tag: blake3::Hasher::new_keyed(&self.key),
        })
    }

    fn blob_opener(&self, offset: u64, length: Option<u64>) -> Box<dyn BlobOpening> {
        Box::new(TestBlobOpener {
            sealing: *self,
            start: offset,
            position: offset,
            length,
            tail: Vec::new(),
            tag: blake3::Hasher::new_keyed(&self.key),
        })
    }
}

/// A blob sealed by [`TestSealing`] is the magic, then each byte hidden
/// by the keystream at its position, then a keyed hash of the plaintext.
struct TestBlobSealer {
    sealing: TestSealing,
    position: u64,
    tag: blake3::Hasher,
}

impl BlobSealing for TestBlobSealer {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SealingError> {
        let mut output = if self.position == 0 {
            TEST_SEALED_MAGIC.to_vec()
        } else {
            Vec::new()
        };
        let mut body = plaintext.to_vec();
        self.sealing.keystream(b"blob", self.position, &mut body);
        self.tag.update(plaintext);
        self.position += plaintext.len() as u64;
        output.extend(body);
        Ok(output)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, SealingError> {
        let mut output = if self.position == 0 {
            TEST_SEALED_MAGIC.to_vec()
        } else {
            Vec::new()
        };
        output.extend(&self.tag.finalize().as_bytes()[..16]);
        Ok(output)
    }
}

/// Opens a range of a blob [`TestBlobSealer`] wrote. A read to the end
/// holds back the keyed hash, and a read of the whole blob checks it.
struct TestBlobOpener {
    sealing: TestSealing,
    start: u64,
    position: u64,
    length: Option<u64>,
    tail: Vec<u8>,
    tag: blake3::Hasher,
}

impl BlobOpening for TestBlobOpener {
    fn sealed_offset(&self) -> u64 {
        self.start + TEST_SEALED_MAGIC.len() as u64
    }

    fn sealed_length(&self) -> Option<u64> {
        self.length
    }

    fn open(&mut self, stored: &[u8]) -> Result<Vec<u8>, SealingError> {
        let mut pending = std::mem::take(&mut self.tail);
        pending.extend_from_slice(stored);
        if self.length.is_none() {
            let split = pending.len().saturating_sub(16);
            self.tail = pending.split_off(split);
        }
        self.sealing.keystream(b"blob", self.position, &mut pending);
        self.position += pending.len() as u64;
        self.tag.update(&pending);
        Ok(pending)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, SealingError> {
        if self.start == 0
            && self.length.is_none()
            && self.tail != self.tag.finalize().as_bytes()[..16]
        {
            return Err(SealingError::Authentication);
        }
        Ok(Vec::new())
    }
}
