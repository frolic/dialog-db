use std::collections::HashMap;

use dialog_artifacts::history::{Authorship, TreeHistory, Version};
use dialog_artifacts::{Artifact, DialogArtifactsError};
use dialog_capability::{Did, Fork, Provider};
use dialog_common::ConditionalSync;
use dialog_effects::archive::{Get, Put};
use dialog_effects::memory::Resolve;
use dialog_storage::{Blake3Hash, DialogStorageError, StorageBackend};
use futures_util::TryStreamExt as _;

use super::Select;
use crate::{NetworkedIndex, RemoteSite};

/// One selected fact and the profile that provably wrote it.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthoredArtifact {
    /// The fact.
    pub artifact: Artifact,
    /// The profile whose revision asserted the fact, when a reader can
    /// prove it (see [`Authorship`]). None for a fact whose revision has
    /// no endorsement or no claims digest, or whose revision's records do
    /// not match the digest it signs.
    pub author: Option<Did>,
}

/// A [`Select`] whose rows carry the profile that wrote each fact, made
/// by [`Select::authored`].
///
/// A row stands for the revisions that asserted it (its claim versions).
/// For each, the select reads the revision's record and history records
/// once, and names the first author who provably asserted the fact.
pub struct SelectAuthored<'a>(Select<'a>);

impl<'a> Select<'a> {
    /// The same select, with the author of each row.
    pub fn authored(self) -> SelectAuthored<'a> {
        SelectAuthored(self)
    }
}

impl SelectAuthored<'_> {
    /// [`Select::perform`], collecting each row with its author.
    pub async fn perform<Env>(
        self,
        env: &Env,
    ) -> Result<Vec<AuthoredArtifact>, DialogArtifactsError>
    where
        Env: Provider<Get>
            + Provider<Put>
            + Provider<Resolve>
            + Provider<crate::Hydrate>
            + Provider<Fork<RemoteSite, Resolve>>
            + ConditionalSync
            + 'static,
    {
        let remote = self.0.source.fallback(env).await;
        let store = NetworkedIndex::new(env, self.0.catalog(), remote, self.0.codec());
        self.execute(store).await
    }

    /// [`Select::execute`], collecting each row with its author.
    pub async fn execute<S>(self, store: S) -> Result<Vec<AuthoredArtifact>, DialogArtifactsError>
    where
        S: StorageBackend<Key = Blake3Hash, Value = Vec<u8>, Error = DialogStorageError>
            + Clone
            + ConditionalSync,
    {
        let history = TreeHistory::from_root_with_cache(
            &self.0.source.root(),
            store.clone(),
            self.0.source.node_cache(),
        )
        .with_record_cache(self.0.source.records());
        let views: Vec<_> = self.0.execute(store).await?.try_collect().await?;
        let mut authorships: HashMap<Version, Option<Authorship>> = HashMap::new();
        let mut rows = Vec::with_capacity(views.len());
        for view in views {
            let artifact = view.to_owned()?;
            let mut author = None;
            for version in view.versions() {
                if !authorships.contains_key(version) {
                    let authorship = history.authorship(version).await?;
                    authorships.insert(*version, authorship);
                }
                if let Some(Some(authorship)) = authorships.get(version)
                    && authorship.asserted(&artifact)
                {
                    author = authorship.author().parse::<Did>().ok();
                    break;
                }
            }
            rows.push(AuthoredArtifact { artifact, author });
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests;
