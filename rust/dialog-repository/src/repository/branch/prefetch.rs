//! The first reads of a tree, named beside a published head and read in
//! one round trip.
//!
//! A reader that holds none of a tree reads it one level at a time: the
//! root names its children, and each child is one more round trip. The
//! writer holds the whole tree when it publishes. So it names, in the head
//! ([`Revision::prefetch`]), the nodes that a reader of the newest facts
//! reads first. A reader fetches the root and those nodes together. Older
//! leaves stay on the host until a query needs them.
//!
//! The newest facts are the facts of the revisions with the highest
//! editions. For each of these revisions, from the newest, the head names
//! the nodes that hold its history records, its revision record, and the
//! entity-ordered entries of its facts. A named entity-ordered leaf also
//! holds older facts. A reader shows those that sort before the last
//! newest fact, so the head then names the nodes that prove who wrote
//! them. The older facts after the last newest fact are past a first
//! screen, and a later read fetches their proofs. All names stop at a
//! limit.
//! These are the reads that show a fact with its author. Attribute-ordered
//! and value-ordered entries are not named, because a first screen reads
//! records by entity.

use std::collections::HashSet;

use dialog_artifacts::history::TreeHistory;
use dialog_artifacts::tree::TreeStorageBridge;
use dialog_artifacts::{Datum, DialogArtifactsError, ENTITY_KEY_TAG, Key as ArtifactKey, State};
use dialog_capability::Provider;
use dialog_common::{Blake3Hash as NodeHash, ConditionalSync, Priority};
use dialog_effects::archive::prelude::CatalogScope;
use dialog_search_tree::{ContentAddressedStorage, nodes_spanning, top_nodes};
use dialog_storage::{Blake3Hash, DialogStorageError, StorageBackend};
use futures_util::future::join_all;
use std::iter::once;

use crate::{HeadBlocks, Hydrate, HydrationRequest, RemoteRepository, Revision};

/// The most nodes a head names.
pub const MOST_PREFETCHED: usize = 64;

/// The most bytes of the nodes a head names. The nodes of the newest
/// revision are named even when they are larger.
pub const MOST_PREFETCHED_BYTES: usize = 1024 * 1024;

/// How many editions back from each origin's newest one a head looks for
/// the newest revisions.
pub const NEWEST_EDITIONS: u64 = 32;

/// The nodes below the root of `revision`'s tree that its head names: the
/// nodes that the reads of its newest revisions touch, newest first, and
/// then the nodes that prove the authors of the other facts in the named
/// entity-ordered leaves that sort before the last newest fact,
/// within [`MOST_PREFETCHED`] and [`MOST_PREFETCHED_BYTES`]. A head with
/// no causal context names the top of the tree, as [`top_nodes`] reads it.
pub async fn name_prefetch<S>(
    revision: &Revision,
    store: S,
) -> Result<Vec<[u8; 32]>, DialogArtifactsError>
where
    S: StorageBackend<Key = Blake3Hash, Value = Vec<u8>, Error = DialogStorageError>
        + Clone
        + ConditionalSync,
{
    let root = NodeHash::from(*revision.tree.hash());
    let storage = ContentAddressedStorage::new(TreeStorageBridge(store.clone()));
    let Some(context) = &revision.context else {
        let named =
            top_nodes::<ArtifactKey, State<Datum>, _>(&root, &storage, MOST_PREFETCHED).await?;
        return Ok(named.iter().map(|hash| *hash.as_bytes()).collect());
    };
    let history = TreeHistory::from_root(revision.tree.hash(), store);
    let reads = history.newest_reads(context, NEWEST_EDITIONS).await?;

    let mut named = Named::default();
    let mut shown = HashSet::new();
    let mut last: Option<ArtifactKey> = None;
    for read in &reads {
        shown.insert(read.version);
        if !named.add(&root, &storage, &read.ranges).await? {
            break;
        }
        let facts = read
            .ranges
            .iter()
            .map(|(_, upper)| upper)
            .filter(|key| key.as_ref().first() == Some(&ENTITY_KEY_TAG));
        last = facts.chain(last.as_ref()).max().cloned();
    }
    let Some(last) = last else {
        return Ok(named.nodes.iter().map(|hash| *hash.as_bytes()).collect());
    };
    // A named entity-ordered leaf holds older facts beside the newest
    // ones. A reader that reads by entity shows those that sort before the
    // last newest fact, with their authors. So the head also names the
    // nodes that prove who wrote them, while the names fit. The older facts
    // after the last newest fact are past a first screen.
    let mut at = 0;
    'leaves: while at < named.nodes.len() {
        let hash = named.nodes[at].clone();
        at += 1;
        for version in history.fact_versions(&hash, &last).await? {
            if shown.insert(version)
                && !named
                    .add(&root, &storage, &history.author_reads(version)?.ranges)
                    .await?
            {
                break 'leaves;
            }
        }
    }
    Ok(named.nodes.iter().map(|hash| *hash.as_bytes()).collect())
}

/// The nodes a head names so far, and their bytes.
#[derive(Default)]
struct Named {
    nodes: Vec<NodeHash>,
    seen: HashSet<NodeHash>,
    bytes: usize,
}

impl Named {
    /// Names the nodes that hold `ranges`, unless they would pass
    /// [`MOST_PREFETCHED`] or [`MOST_PREFETCHED_BYTES`]. The first ranges
    /// are named whatever their size. Returns whether they were named.
    async fn add<Backend>(
        &mut self,
        root: &NodeHash,
        storage: &ContentAddressedStorage<Backend>,
        ranges: &[(ArtifactKey, ArtifactKey)],
    ) -> Result<bool, DialogArtifactsError>
    where
        Backend: StorageBackend<Key = NodeHash, Value = Vec<u8>, Error = DialogStorageError>
            + ConditionalSync,
    {
        let ranges: Vec<(Vec<u8>, Vec<u8>)> = ranges
            .iter()
            .map(|(lower, upper)| (lower.as_ref().to_vec(), upper.as_ref().to_vec()))
            .collect();
        let nodes = nodes_spanning::<ArtifactKey, State<Datum>, _>(root, storage, &ranges).await?;
        let mut fresh = Vec::new();
        let mut size = 0;
        for node in nodes {
            if self.seen.contains(&node) {
                continue;
            }
            size += storage
                .retrieve(&node)
                .await?
                .map(|block| block.len())
                .unwrap_or_default();
            fresh.push(node);
        }
        if !self.nodes.is_empty()
            && (self.nodes.len() + fresh.len() > MOST_PREFETCHED
                || self.bytes + size > MOST_PREFETCHED_BYTES)
        {
            return Ok(false);
        }
        self.bytes += size;
        for node in fresh {
            self.seen.insert(node.clone());
            self.nodes.push(node);
        }
        Ok(true)
    }
}

/// Copies the root of a head's tree and the blocks the head names
/// ([`HeadBlocks`]) from `remote` into `catalog`, all at once. A block this
/// archive holds is not fetched again. A sealed head names these blocks in
/// the clear, so a reader fetches them before it holds the key.
///
/// A block is kept under the digest of its own bytes, so a block that
/// does not match its name is never read in place of it. A failed fetch
/// is dropped: the read that needs the block fetches it again.
pub async fn prefetch<Env>(
    env: &Env,
    remote: &RemoteRepository,
    catalog: &CatalogScope,
    head: &HeadBlocks,
) where
    Env: Provider<Hydrate> + ConditionalSync,
{
    let route = remote.address();
    let digests = once(*head.tree.hash())
        .chain(head.prefetch.iter().copied())
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

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use anyhow::Result;
    use dialog_artifacts::history::TreeHistory;
    use dialog_artifacts::tree::{
        ArtifactTree, ArtifactTreeExt as _, TreeStorageBridge, spill_cache,
    };
    use dialog_artifacts::{Artifact, ArtifactSelector, Datum, Instruction, Key, State, Value};
    use dialog_common::{Blake3Hash as NodeHash, Buffer, ConditionalSync};
    use dialog_crypto::BlockCodec;
    use dialog_operator::helpers::{test_operator_with_profile, unique_name};
    use dialog_search_tree::{ArchivedNodeBody, ContentAddressedStorage, PersistentNode};
    use dialog_storage::{DialogStorageError, MemoryStorageBackend, StorageBackend};
    use futures_util::{TryStreamExt as _, stream};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use super::{NEWEST_EDITIONS, name_prefetch};
    use crate::{LocalIndex, RepositoryExt as _};

    fn fact(entity: String, body: String) -> Result<Instruction> {
        Ok(Instruction::Assert(Artifact {
            the: "note/body".parse()?,
            of: entity.parse()?,
            is: Value::String(body),
            cause: None,
        }))
    }

    /// A reader that holds only the root and the nodes a head names shows
    /// the newest facts with their authors, and an older fact beside them
    /// with its author, and reads no other node. A reader of the newest
    /// facts and that older fact reads every named node. A larger tree is
    /// not named whole.
    #[dialog_common::test]
    async fn it_names_what_shows_the_newest_facts_with_their_authors() -> Result<()> {
        show_newest(300, 200, 20).await
    }

    /// A reader that holds only the root and the nodes a head names shows
    /// every fact under a prefix when a page holds them all.
    #[dialog_common::test]
    async fn it_names_what_shows_every_fact_of_a_small_tree() -> Result<()> {
        show_newest(40, 4_000, 240).await
    }

    async fn show_newest(notes: usize, body: usize, limit: usize) -> Result<()> {
        let (operator, profile) = test_operator_with_profile().await;
        let repository = profile
            .repository(unique_name("prefetch-newest"))
            .open()
            .perform(&operator)
            .await?;
        let branch = repository.branch("main").open().perform(&operator).await?;
        // The first fact sorts just before the notes, and each note id
        // sorts the newest first.
        branch
            .commit(stream::iter(vec![fact(
                "name:owner".into(),
                "Kaori".into(),
            )?]))
            .perform(&operator)
            .await?;
        for index in 0..notes {
            let note = fact(
                format!("note:{:04}", 9_999 - index),
                format!("{index} {}", "n".repeat(body)),
            )?;
            branch
                .commit(stream::iter(vec![note]))
                .perform(&operator)
                .await?;
        }
        let revision = branch.revision().expect("a head");
        let store = LocalIndex::new(&operator, branch.archive().index(), branch.codec().clone());
        let storage = ContentAddressedStorage::new(TreeStorageBridge(store.clone()));
        let root = NodeHash::from(*revision.tree.hash());
        let named = name_prefetch(&revision, store).await?;

        let root_block = storage.retrieve(&root).await?.expect("a root");
        let root_node =
            PersistentNode::<Key, State<Datum>>::try_from(Buffer::from(root_block.clone()))?;
        let ArchivedNodeBody::Index(index) = root_node.body() else {
            anyhow::bail!("the tree has more than one node")
        };
        assert!(
            named.len() < index.len(),
            "a larger tree is not named whole: {} of {}",
            named.len(),
            index.len()
        );

        let mut reader = MemoryStorageBackend::<[u8; 32], Vec<u8>>::default();
        reader.set(*root.as_bytes(), root_block).await?;
        for hash in &named {
            let block = storage
                .retrieve(&NodeHash::from(*hash))
                .await?
                .expect("a named node is stored");
            reader.set(*hash, block).await?;
        }
        show(&root, &reader, revision.tree.hash(), limit, notes).await?;

        // The newest editions are one note each, after the owner's name.
        let newest = usize::try_from(NEWEST_EDITIONS)?;
        let recorder = Recorder {
            inner: reader,
            read: Arc::default(),
        };
        show(&root, &recorder, revision.tree.hash(), newest, notes).await?;
        let read = recorder
            .read
            .lock()
            .map(|read| read.clone())
            .unwrap_or_default();
        let unread = named.iter().filter(|hash| !read.contains(*hash)).count();
        assert_eq!(unread, 0, "every named node is read");
        Ok(())
    }

    /// Shows the first `limit` notes and the owner's name, each with the
    /// author of each version, reading from `reader`.
    async fn show<Backend>(
        root: &NodeHash,
        reader: &Backend,
        tree: &[u8; 32],
        limit: usize,
        notes: usize,
    ) -> Result<()>
    where
        Backend: StorageBackend<Key = [u8; 32], Value = Vec<u8>, Error = DialogStorageError>
            + Clone
            + ConditionalSync
            + 'static,
    {
        let history = TreeHistory::from_root(tree, reader.clone());
        for (selector, rows) in [
            (
                ArtifactSelector::new()
                    .of_starting_with("note:")
                    .with_limit(limit),
                limit.min(notes),
            ),
            (ArtifactSelector::new().of("name:owner".parse()?), 1),
        ] {
            let views: Vec<_> = ArtifactTree::from_hash(root.clone())
                .scan(reader.clone(), spill_cache(), selector)
                .try_collect()
                .await?;
            assert_eq!(views.len(), rows);
            for view in &views {
                for version in view.versions() {
                    history.authorship(version).await?;
                }
            }
        }
        Ok(())
    }

    /// A reader that keeps the name of each block it reads.
    #[derive(Clone)]
    struct Recorder<Backend> {
        inner: Backend,
        read: Arc<Mutex<HashSet<[u8; 32]>>>,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl<Backend> StorageBackend for Recorder<Backend>
    where
        Backend: StorageBackend<Key = [u8; 32], Value = Vec<u8>, Error = DialogStorageError>
            + ConditionalSync,
    {
        type Key = [u8; 32];
        type Value = Vec<u8>;
        type Error = DialogStorageError;

        fn block_codec(&self) -> BlockCodec {
            self.inner.block_codec()
        }

        async fn set(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
            self.inner.set(key, value).await
        }

        async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
            if let Ok(mut read) = self.read.lock() {
                read.insert(*key);
            }
            self.inner.get(key).await
        }
    }
}
