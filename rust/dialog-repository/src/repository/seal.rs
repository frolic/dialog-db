//! The seal a repository records at creation.
//!
//! A repository is sealed or plain by one choice made when it is created.
//! A sealed repository records the identifier of its key in its memory, so
//! a later load can refuse a missing key, a wrong key, or a key for a plain
//! repository before any tree block is read or written.

use dialog_capability::{Provider, Subject};
use dialog_common::ConditionalSync;
use dialog_effects::memory;
use dialog_effects::memory::prelude::SpaceScope;
use dialog_storage::BlockCodec;
use serde::{Deserialize, Serialize};

use crate::{Cell, RepositorySealError};

/// The memory space holding a repository's seal record.
const SEAL_SPACE: &str = "seal";

/// What a sealed repository records: the identifier of the key its tree
/// blocks are sealed under. The identifier names the key without revealing
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SealRecord {
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

fn seal_cell(subject: &Subject) -> Cell<SealRecord> {
    SpaceScope::new(subject.clone(), SEAL_SPACE)
        .cell("key")
        .into()
}

/// Records that `subject`'s repository is sealed under `codec`'s key. A
/// plain codec records nothing.
pub(crate) async fn record_seal<Env>(
    subject: &Subject,
    codec: &BlockCodec,
    env: &Env,
) -> Result<(), RepositorySealError>
where
    Env: Provider<memory::Publish> + ConditionalSync,
{
    let Some(key) = codec.key_id() else {
        return Ok(());
    };
    seal_cell(subject)
        .publish(SealRecord { key })
        .perform(env)
        .await?;
    Ok(())
}

/// Fails unless `codec` is the codec `subject`'s repository was created
/// with: plain for a plain repository, or sealed under its key.
pub(crate) async fn check_seal<Env>(
    subject: &Subject,
    codec: &BlockCodec,
    env: &Env,
) -> Result<(), RepositorySealError>
where
    Env: Provider<memory::Resolve> + ConditionalSync,
{
    let cell = seal_cell(subject);
    cell.resolve().perform(env).await?;
    match (cell.content(), codec.key_id()) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(RepositorySealError::KeyRequired),
        (None, Some(_)) => Err(RepositorySealError::NotSealed),
        (Some(record), Some(key)) if record.key == key => Ok(()),
        (Some(_), Some(_)) => Err(RepositorySealError::WrongKey),
    }
}

#[cfg(test)]
mod tests;
