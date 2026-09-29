use crate::repository::seal::record_seal;
use crate::{CreateRepositoryError, Repository};
use dialog_capability::{Capability, Provider};
use dialog_common::ConditionalSync;
use dialog_credentials::Ed25519Signer;
use dialog_credentials::credential::{Credential, SignerCredential};
use dialog_crypto::{KeyRing, SealKey};
use dialog_effects::memory;
use dialog_effects::space::{self, SpaceExt};
use dialog_storage::BlockCodec;

/// Command to create a new repository.
///
/// Returns `Repository<SignerCredential>` since a freshly generated
/// credential always has a private key.
pub struct CreateRepository(pub Capability<space::Space>);

impl CreateRepository {
    /// Create the repository with a freshly generated keypair.
    pub async fn perform<Env>(
        self,
        env: &Env,
    ) -> Result<Repository<SignerCredential>, CreateRepositoryError>
    where
        Env: Provider<space::Create> + ConditionalSync,
    {
        self.with_credential(Ed25519Signer::generate().await?)
            .perform(env)
            .await
    }

    /// Create the repository with a caller-supplied credential instead
    /// of generating a fresh keypair.
    ///
    /// Useful when the space name is derived from the credential's DID:
    /// generate the signer first, derive the name, then create the
    /// repository with that same signer.
    ///
    /// ```no_run
    /// # async fn example<Env>(
    /// #     profile: &dialog_operator::Profile,
    /// #     operator: &Env,
    /// # ) -> Result<(), Box<dyn std::error::Error>>
    /// # where Env: dialog_capability::Provider<dialog_effects::space::Create> + dialog_common::ConditionalSync {
    /// use dialog_credentials::Ed25519Signer;
    /// use dialog_repository::RepositoryExt;
    /// use dialog_varsig::Principal;
    ///
    /// let signer = Ed25519Signer::generate().await?;
    /// let did = signer.did().to_string();
    /// let name = &did[did.len() - 8..];
    ///
    /// let repo = profile
    ///     .repository(name)
    ///     .create()
    ///     .with_credential(signer)
    ///     .perform(operator)
    ///     .await?;
    /// # let _ = repo;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_credential(self, credential: impl Into<SignerCredential>) -> CreateRepositoryWith {
        CreateRepositoryWith {
            space: self.0,
            credential: credential.into(),
        }
    }
    /// Create a sealed repository: every tree block it stores is sealed
    /// under `key`, and it opens only with the same key.
    pub fn sealed(self, key: SealKey) -> CreateSealedRepository {
        CreateSealedRepository {
            space: self.0,
            credential: None,
            key,
        }
    }
}

/// A [`CreateRepository`] command bound to a caller-supplied credential.
///
/// Because the credential is already provided, `perform` cannot fail to
/// generate a keypair — the only failure is backend storage.
pub struct CreateRepositoryWith {
    space: Capability<space::Space>,
    credential: SignerCredential,
}

impl CreateRepositoryWith {
    /// Execute against an operator.
    pub async fn perform<Env>(
        self,
        env: &Env,
    ) -> Result<Repository<SignerCredential>, CreateRepositoryError>
    where
        Env: Provider<space::Create> + ConditionalSync,
    {
        self.space
            .create(Credential::Signer(self.credential.clone()))
            .perform(env)
            .await?;
        Ok(Repository::from(self.credential))
    }
    /// Create the repository sealed under `key`.
    pub fn sealed(self, key: SealKey) -> CreateSealedRepository {
        CreateSealedRepository {
            space: self.space,
            credential: Some(self.credential),
            key,
        }
    }
}

/// A [`CreateRepository`] command for a sealed repository.
///
/// The repository records the identifier of its key, so a later load
/// refuses a missing or different key.
pub struct CreateSealedRepository {
    space: Capability<space::Space>,
    credential: Option<SignerCredential>,
    key: SealKey,
}

impl CreateSealedRepository {
    /// Create the repository with a caller-supplied credential instead of
    /// generating a fresh keypair.
    pub fn with_credential(self, credential: impl Into<SignerCredential>) -> Self {
        Self {
            credential: Some(credential.into()),
            ..self
        }
    }

    /// Execute against an operator.
    pub async fn perform<Env>(
        self,
        env: &Env,
    ) -> Result<Repository<SignerCredential>, CreateRepositoryError>
    where
        Env: Provider<space::Create> + Provider<memory::Publish> + ConditionalSync,
    {
        let credential = match self.credential {
            Some(credential) => credential,
            None => SignerCredential::from(Ed25519Signer::generate().await?),
        };
        let repository = CreateRepositoryWith {
            space: self.space,
            credential,
        }
        .perform(env)
        .await?;
        let codec = BlockCodec::sealed(KeyRing::new(self.key));
        record_seal(&repository.subject(), &codec, env).await?;
        Ok(repository.encoded_with(codec))
    }
}
