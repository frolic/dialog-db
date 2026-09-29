use thiserror::Error;

/// Why a block could not be sealed or opened.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The bytes are too short or do not start with the sealed-block magic,
    /// so they are not a sealed block at all.
    #[error("Not a sealed block")]
    NotSealed,

    /// The block names an envelope version this build does not read.
    #[error("Unsupported sealed-block version {0}")]
    UnsupportedVersion(u8),

    /// The block names a cipher suite this build does not read.
    #[error("Unsupported sealed-block suite {0}")]
    UnsupportedSuite(u8),

    /// The block was sealed under a key generation the key ring does not hold.
    #[error("No key for sealed-block generation {0}")]
    UnknownGeneration(u32),

    /// The block failed authentication: it was sealed under another key, or
    /// its bytes were changed.
    #[error("Sealed block failed authentication")]
    Authentication,

    /// The block opened, but its frame is not the one sealing produces for
    /// its plaintext (a bad length prefix, nonzero padding, or a nonce that
    /// does not match the frame).
    #[error("Sealed block is not in canonical form: {0}")]
    NonCanonical(&'static str),

    /// The plaintext is too long for the frame's 32-bit length prefix.
    #[error("Plaintext of {0} bytes is too long to seal")]
    TooLong(usize),

    /// A key chain has no link for the generation named, so the keys
    /// before it cannot be opened.
    #[error("No key link for generation {0}")]
    MissingLink(u32),

    /// The platform could not supply randomness for a new key.
    #[error("Could not generate a seal key: {0}")]
    Randomness(String),
}
