use crate::repository::seal::{check_seal, record_seal};
use crate::{OpenRepositoryError, Repository};
use dialog_capability::{Capability, Provider};
use dialog_common::ConditionalSync;
use dialog_credentials::Ed25519Signer;
use dialog_credentials::credential::{Credential, SignerCredential};
use dialog_crypto::{KeyRing, SealKey};
use dialog_effects::memory;
use dialog_effects::space::{self, SpaceExt};
use dialog_storage::BlockCodec;

/// Command to open (load-or-create) a repository.
///
/// Returns `Repository<Credential>` since the loaded credential
/// may be verifier-only. A sealed repository refuses to open without its
/// key; use [`OpenRepository::sealed`].
pub struct OpenRepository(pub Capability<space::Space>);

impl OpenRepository {
    /// Execute against an operator.
    pub async fn perform<Env>(self, env: &Env) -> Result<Repository, OpenRepositoryError>
    where
        Env: Provider<space::Load>
            + Provider<space::Create>
            + Provider<memory::Resolve>
            + ConditionalSync,
    {
        let credential = match self.0.clone().load().perform(env).await {
            Ok(credential) => credential,
            Err(_) => return Ok(Repository::from(create(self.0, env).await?)),
        };
        let repository = Repository::from(credential);
        check_seal(&repository.subject(), repository.codec(), env).await?;
        Ok(repository)
    }

    /// Open a sealed repository with its `key`, creating it sealed under
    /// that key when it does not exist.
    pub fn sealed(self, key: SealKey) -> OpenSealedRepository {
        OpenSealedRepository { space: self.0, key }
    }
}

/// An [`OpenRepository`] command for a sealed repository.
///
/// An existing repository opens only when it was created sealed under the
/// same key.
pub struct OpenSealedRepository {
    space: Capability<space::Space>,
    key: SealKey,
}

impl OpenSealedRepository {
    /// Execute against an operator.
    pub async fn perform<Env>(self, env: &Env) -> Result<Repository, OpenRepositoryError>
    where
        Env: Provider<space::Load>
            + Provider<space::Create>
            + Provider<memory::Resolve>
            + Provider<memory::Publish>
            + ConditionalSync,
    {
        let codec = BlockCodec::sealed(KeyRing::new(self.key));
        let repository = match self.space.clone().load().perform(env).await {
            Ok(credential) => {
                let repository = Repository::from(credential);
                check_seal(&repository.subject(), &codec, env).await?;
                repository
            }
            Err(_) => {
                let repository = Repository::from(create(self.space, env).await?);
                record_seal(&repository.subject(), &codec, env).await?;
                repository
            }
        };
        Ok(repository.encoded_with(codec))
    }
}

/// Creates the space with a fresh signer, returning its credential.
async fn create<Env>(
    space: Capability<space::Space>,
    env: &Env,
) -> Result<Credential, OpenRepositoryError>
where
    Env: Provider<space::Create> + ConditionalSync,
{
    let signer = Ed25519Signer::generate().await?;
    let credential = Credential::Signer(SignerCredential::from(signer));
    Ok(space.create(credential).perform(env).await?)
}
