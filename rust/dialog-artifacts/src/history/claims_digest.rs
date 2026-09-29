use crate::{Datum, Key};

/// The domain tag opening every claims digest, so a digest of one kind of
/// content can never match a digest of another.
pub const CLAIMS_DIGEST_DOMAIN: &[u8] = b"dialog/claims@1\n";

/// A digest of the history records one revision wrote.
///
/// A revision's records occupy one contiguous span of the history region
/// (their keys open with the revision's version), and no later revision
/// writes into that span. So the span is the revision's own changes, and
/// its digest, signed in the [`RevisionRecord`](super::RevisionRecord),
/// lets a reader check that the records it finds under a version are the
/// ones the issuer wrote: a record added, removed, or altered in the span
/// changes the digest.
///
/// Feed the live entries in key order. Each entry adds its key bytes (the
/// entity, the attribute, and the value or the hash of a spilled value),
/// its polarity, and the versions it supersedes.
#[derive(Debug, Clone)]
pub struct ClaimsDigest {
    hasher: blake3::Hasher,
}

impl Default for ClaimsDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaimsDigest {
    /// An empty digest.
    pub fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CLAIMS_DIGEST_DOMAIN);
        Self { hasher }
    }

    /// Adds one live history entry.
    pub fn add(&mut self, key: &Key, datum: &Datum) {
        let key = key.as_ref();
        self.hasher.update(&(key.len() as u64).to_be_bytes());
        self.hasher.update(key);
        self.hasher.update(&[u8::from(datum.retraction)]);
        self.hasher
            .update(&(datum.supersedes.len() as u64).to_be_bytes());
        for version in &datum.supersedes {
            self.hasher.update(&version.key_bytes());
        }
    }

    /// The digest of every entry added.
    pub fn finish(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}
