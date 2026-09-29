use crate::repository::seal::check_seal;
use crate::{LoadRepositoryError, Repository};
use dialog_capability::{Capability, Provider};
use dialog_common::ConditionalSync;
use dialog_effects::memory;
use dialog_effects::space::{self, SpaceExt};
use dialog_storage::{BlockCodec, Sealing};

/// Command to load an existing repository.
///
/// Returns `Repository<Credential>` since the credential
/// may be verifier-only. A sealed repository refuses to load without its
/// key; use [`LoadRepository::sealed`].
pub struct LoadRepository(pub Capability<space::Space>);

impl LoadRepository {
    /// Execute against an operator.
    pub async fn perform<Env>(self, env: &Env) -> Result<Repository, LoadRepositoryError>
    where
        Env: Provider<space::Load> + Provider<memory::Resolve> + ConditionalSync,
    {
        let repository = Repository::from(self.0.load().perform(env).await?);
        check_seal(&repository.subject(), repository.codec(), env).await?;
        Ok(repository)
    }

    /// Load a sealed repository with its `sealing`.
    pub fn sealed(self, sealing: impl Sealing) -> LoadSealedRepository {
        LoadSealedRepository {
            space: self.0,
            codec: BlockCodec::sealed(sealing),
        }
    }
}

/// A [`LoadRepository`] command for a sealed repository.
///
/// Fails unless the repository was created sealed under the same key.
pub struct LoadSealedRepository {
    space: Capability<space::Space>,
    codec: BlockCodec,
}

impl LoadSealedRepository {
    /// Execute against an operator.
    pub async fn perform<Env>(self, env: &Env) -> Result<Repository, LoadRepositoryError>
    where
        Env: Provider<space::Load> + Provider<memory::Resolve> + ConditionalSync,
    {
        let codec = self.codec;
        let repository = Repository::from(self.space.load().perform(env).await?);
        check_seal(&repository.subject(), &codec, env).await?;
        Ok(repository.encoded_with(codec))
    }
}
