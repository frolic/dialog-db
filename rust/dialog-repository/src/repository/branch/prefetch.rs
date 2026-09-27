//! The top of a tree, named beside a published head and read in one
//! round trip.
//!
//! A reader that holds none of a tree reads it one level at a time: the
//! root names its children, and each child is one more round trip. The
//! writer holds the whole tree when it publishes, so it names the upper
//! levels in the head ([`Revision::prefetch`]), or the whole tree when it
//! is small. A reader then fetches the root and those nodes together, and
//! only the leaves a query needs below them remain.

use dialog_artifacts::{Datum, Key as ArtifactKey, State};
use dialog_capability::Provider;
use dialog_common::{Blake3Hash as NodeHash, ConditionalSync, Priority};
use dialog_effects::archive::prelude::CatalogScope;
use dialog_search_tree::{ContentAddressedStorage, DialogSearchTreeError, top_nodes};
use dialog_storage::{DialogStorageError, StorageBackend};
use futures_util::future::join_all;
use std::iter::once;

use crate::{Hydrate, HydrationRequest, RemoteRepository, Revision};

/// The most nodes a head names. A tree with at most this many nodes
/// below its root is named whole. A larger tree has its upper levels
/// named, top first. Leaves hold at most about 64 KiB of entries, so a
/// whole tree named this way is a few MiB at most.
pub const MOST_PREFETCHED: usize = 64;

/// The nodes below `root` that a head names: the top of the tree, as
/// [`top_nodes`] reads it, within [`MOST_PREFETCHED`].
pub async fn name_prefetch<Backend>(
    root: &NodeHash,
    storage: &ContentAddressedStorage<Backend>,
) -> Result<Vec<[u8; 32]>, DialogSearchTreeError>
where
    Backend: StorageBackend<Key = NodeHash, Value = Vec<u8>, Error = DialogStorageError>
        + ConditionalSync,
{
    let named =
        top_nodes::<ArtifactKey, State<Datum>, Backend>(root, storage, MOST_PREFETCHED).await?;
    Ok(named.iter().map(|hash| *hash.as_bytes()).collect())
}

/// Copies the root of `revision`'s tree and the blocks its head names
/// from `remote` into `catalog`, all at once. A block this archive holds
/// is not fetched again.
///
/// A block is kept under the digest of its own bytes, so a block that
/// does not match its name is never read in place of it. A failed fetch
/// is dropped: the read that needs the block fetches it again.
pub async fn prefetch<Env>(
    env: &Env,
    remote: &RemoteRepository,
    catalog: &CatalogScope,
    revision: &Revision,
) where
    Env: Provider<Hydrate> + ConditionalSync,
{
    let route = remote.address();
    let digests = once(*revision.tree.hash())
        .chain(revision.prefetch.iter().copied())
        .filter(|digest| digest != &dialog_artifacts::EMPTY_TREE_HASH);
    let reads = digests.map(|digest| {
        let request = HydrationRequest {
            address: route.address.clone(),
            subject: route.subject.clone(),
            catalog: catalog.clone(),
            digest: dialog_common::Blake3Hash::from(digest),
            priority: Priority::Demand,
        };
        async move {
            if let Err(error) = Provider::<Hydrate>::execute(env, request).await {
                tracing::debug!(
                    target: "dialog::sync::prefetch",
                    %error,
                    "a named block was not prefetched"
                );
            }
        }
    });
    join_all(reads).await;
}
