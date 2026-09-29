//! Opening the stored bytes of a sealed blob as they stream in.

use dialog_effects::blob::{BlobError, BlobReader, BlobSource};
use dialog_storage::{BlobOpening, SealingError};

/// A reader over the plaintext of a sealed blob's stored bytes.
struct OpenedBlob {
    stored: BlobReader,
    opener: Option<Box<dyn BlobOpening>>,
}

/// Wraps `stored`, the stored bytes of the range `opener` names, in a reader
/// that yields the plaintext of that range.
pub(super) fn open_blob(stored: BlobReader, opener: Box<dyn BlobOpening>) -> BlobReader {
    Box::new(OpenedBlob {
        stored,
        opener: Some(opener),
    })
}

/// A blob that does not seal or open is reported as a storage failure:
/// the bytes the store holds are not the ones this key sealed.
pub(super) fn sealing_error(error: SealingError) -> BlobError {
    BlobError::Storage(format!("sealed blob: {error}"))
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl BlobSource for OpenedBlob {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, BlobError> {
        loop {
            let Some(opener) = self.opener.as_mut() else {
                return Ok(None);
            };
            let plaintext = match self.stored.next().await? {
                Some(stored) => opener.open(&stored).map_err(sealing_error)?,
                None => {
                    let opener = self.opener.take().expect("checked above");
                    opener.finish().map_err(sealing_error)?
                }
            };
            if !plaintext.is_empty() {
                return Ok(Some(plaintext));
            }
        }
    }
}
