use dialog_storage::DialogStorageError;
use dialog_storage::SealingError;
use thiserror::Error;

/// Errors that can occur when working with search trees.
#[derive(Error, Debug)]
pub enum DialogSearchTreeError {
    /// An error that occurs when accessing a node.
    #[error("Problem accessing node: {0}")]
    Node(String),

    /// An error from the storage backend.
    #[error("{0}")]
    Storage(#[source] DialogStorageError),

    /// An error that occurs during a tree operation.
    #[error("Failed to operate the tree: {0}")]
    Operation(String),

    /// An error that occurs when accessing part of the tree.
    #[error("Failed to access part of the tree: {0}")]
    Access(String),

    /// An error that occurs when interpreting bytes.
    #[error("Failed to interpret bytes: {0}")]
    Encoding(String),

    /// A block could not be sealed or opened: it was sealed under another
    /// key, its bytes were changed, or a sealed tree met a plain block.
    #[error("Failed to seal or open a block: {0}")]
    Seal(#[from] SealingError),

    /// A write would encode blocks with a codec other than its store's.
    #[error("A delta's block codec differs from its store's")]
    CodecMismatch,
}

impl From<DialogStorageError> for DialogSearchTreeError {
    fn from(value: DialogStorageError) -> Self {
        DialogSearchTreeError::Storage(value)
    }
}
