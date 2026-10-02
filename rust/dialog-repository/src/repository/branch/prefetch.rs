//! The first reads of a tree, named beside a published head and read in
//! one round trip.
//!
//! A reader that holds none of a tree reads it one level at a time: the
//! root names its children, and each child is one more round trip. The
//! writer holds the whole tree when it publishes. So it names, in the head
//! ([`Revision::prefetch`]), the nodes that a reader of the newest facts
//! reads first. A pull adopts a head without reading its tree. The first
//! select that does not hold the root fetches the root and those nodes
//! together. Older leaves stay on the host until a query needs them.
//!
//! The newest facts are the facts of the revisions with the highest
//! editions. For each of these revisions, from the newest, the head names
//! the nodes that hold the entity-ordered entries of its facts. All names
//! stop at a limit. Attribute-ordered and value-ordered entries are not
//! named, because a first screen reads records by entity.

use std::collections::HashSet;

use dialog_artifacts::history::TreeHistory;
use dialog_artifacts::{ArchiveReader, Datum, DialogArtifactsError, Key as ArtifactKey, State};
use dialog_capability::Provider;
use dialog_common::{Blake3Hash as NodeHash, Buffer, ConditionalSync};
use dialog_search_tree::{
    DialogSearchTreeError, LoadBlock, NodeBody, PersistentNode, nodes_spanning, top_nodes,
};
use futures_util::future::{join, join_all};

use crate::Revision;

/// The most nodes a head names.
pub const MOST_PREFETCHED: usize = 64;

/// The most bytes of the nodes a head names. The nodes of the newest
/// revision are named even when they are larger.
pub const MOST_PREFETCHED_BYTES: usize = 1024 * 1024;

/// How many editions back from each origin's newest one a head looks for
/// the newest revisions.
pub const NEWEST_EDITIONS: u64 = 32;

/// The nodes below the root of `revision`'s tree that its head names. A
/// tree within [`MOST_PREFETCHED`] and [`MOST_PREFETCHED_BYTES`] is named
/// whole. A larger one has the nodes that the reads of its newest
/// revisions touch named, newest first, within the same limits. A head
/// with no causal context names the top of the tree, as [`top_nodes`]
/// reads it.
pub async fn name_prefetch<S>(
    revision: &Revision,
    store: S,
) -> Result<Vec<[u8; 32]>, DialogArtifactsError>
where
    S: ArchiveReader + Clone,
{
    let root = NodeHash::from(*revision.tree.hash());
    // A tree that fits within the limits is named whole, so a reader of
    // it waits for no second round trip whatever it reads.
    if let Some(whole) = whole_tree(&root, &store).await? {
        return Ok(whole.iter().map(|hash| *hash.as_bytes()).collect());
    }
    let Some(context) = &revision.context else {
        let named =
            top_nodes::<ArtifactKey, State<Datum>, _>(&root, &store, MOST_PREFETCHED).await?;
        return Ok(named.iter().map(|hash| *hash.as_bytes()).collect());
    };
    let history = TreeHistory::from_root(revision.tree.hash(), store.clone());
    let reads = history.newest_reads(context, NEWEST_EDITIONS).await?;

    let mut named = Named::default();
    for read in &reads {
        if !named.add(&root, &store, &read.ranges).await? {
            break;
        }
    }
    Ok(named.nodes.iter().map(|hash| *hash.as_bytes()).collect())
}

/// Every node below `root`, when they fit within [`MOST_PREFETCHED`] and
/// [`MOST_PREFETCHED_BYTES`].
async fn whole_tree<Env>(
    root: &NodeHash,
    env: &Env,
) -> Result<Option<Vec<NodeHash>>, DialogArtifactsError>
where
    Env: Provider<LoadBlock> + ConditionalSync,
{
    let named = top_nodes::<ArtifactKey, State<Datum>, _>(root, env, MOST_PREFETCHED).await?;
    let mut bytes = 0;
    for node in &named {
        bytes += LoadBlock::new(node.clone())
            .perform(env)
            .await?
            .map(|block| block.as_ref().len())
            .unwrap_or_default();
        if bytes > MOST_PREFETCHED_BYTES {
            return Ok(None);
        }
    }
    // The walk names whole levels, so the tree is named whole when the
    // last node it names is a leaf.
    let Some(last) = named.last() else {
        return Ok(None);
    };
    let Some(block) = LoadBlock::new(last.clone()).perform(env).await? else {
        return Ok(None);
    };
    let node = PersistentNode::<ArtifactKey, State<Datum>>::try_from(block)?;
    Ok(matches!(node.body(), NodeBody::Segment(_)).then_some(named))
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
    async fn add<Env>(
        &mut self,
        root: &NodeHash,
        env: &Env,
        ranges: &[(ArtifactKey, ArtifactKey)],
    ) -> Result<bool, DialogArtifactsError>
    where
        Env: Provider<LoadBlock> + ConditionalSync,
    {
        let ranges: Vec<(Vec<u8>, Vec<u8>)> = ranges
            .iter()
            .map(|(lower, upper)| (lower.as_ref().to_vec(), upper.as_ref().to_vec()))
            .collect();
        let nodes = nodes_spanning::<ArtifactKey, State<Datum>, _>(root, env, &ranges).await?;
        let mut fresh = Vec::new();
        let mut size = 0;
        for node in nodes {
            if self.seen.contains(&node) {
                continue;
            }
            size += LoadBlock::new(node.clone())
                .perform(env)
                .await?
                .map(|block| block.as_ref().len())
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

/// Reads the block `root` and the blocks `named` beside it, all at once,
/// and returns the root. Through a [`NetworkedIndex`](crate::NetworkedIndex)
/// each fetched block is kept locally, so the reads that follow find them.
///
/// A named block that does not match its name is never read in place of
/// it. A failed read of a named block is dropped: the read that needs the
/// block reads it again.
pub(crate) async fn load_root<S>(
    store: &S,
    root: &NodeHash,
    named: &[[u8; 32]],
) -> Result<Option<Buffer>, DialogSearchTreeError>
where
    S: Provider<LoadBlock> + ConditionalSync,
{
    let named = named.iter().map(|digest| async move {
        if let Err(error) = LoadBlock::new(NodeHash::from(*digest)).perform(store).await {
            tracing::debug!(
                target: "dialog::sync::prefetch",
                %error,
                "a named block was not prefetched"
            );
        }
    });
    let (root, _) = join(LoadBlock::new(root.clone()).perform(store), join_all(named)).await;
    root
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use std::collections::HashMap;
    use std::sync::Arc;

    use anyhow::Result;
    use async_trait::async_trait;
    use dialog_artifacts::tree::{ArtifactTree, ArtifactTreeExt as _, spill_cache};
    use dialog_artifacts::{
        Artifact, ArtifactSelector, Datum, DialogArtifactsError, Instruction, Key, LoadBlob, State,
        Value,
    };
    use dialog_capability::Provider;
    use dialog_common::{Blake3Hash as NodeHash, Buffer};
    use dialog_peer::helpers::{test_session_with_peer, unique_name};
    use dialog_search_tree::{DialogSearchTreeError, LoadBlock, NodeBody, PersistentNode};
    use futures_util::{TryStreamExt as _, stream};

    use super::name_prefetch;
    use crate::{LocalIndex, RepositoryExt as _};

    /// A reader that holds only the blocks it was given.
    #[derive(Clone, Default)]
    struct Holding(Arc<HashMap<NodeHash, Buffer>>);

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl Provider<LoadBlock> for Holding {
        async fn execute(&self, load: LoadBlock) -> Result<Option<Buffer>, DialogSearchTreeError> {
            Ok(self.0.get(&load.hash).cloned())
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl Provider<LoadBlob> for Holding {
        async fn execute(&self, _: LoadBlob) -> Result<Option<Buffer>, DialogArtifactsError> {
            Ok(None)
        }
    }

    /// A root that is not held yet is read in one wave with the nodes its
    /// head names, not before them.
    #[dialog_common::test]
    async fn it_reads_the_root_and_its_named_nodes_together() -> Result<()> {
        use dialog_search_tree::helpers::ObservingBlocks;

        let blocks = ObservingBlocks::new();
        let mut names = Vec::new();
        for index in 0u8..4 {
            let block = Buffer::from(vec![index; 16]);
            names.push(*block.blake3_hash().as_bytes());
            blocks.store(block);
        }
        let root = Buffer::from(b"root".to_vec());
        let root_hash = root.blake3_hash().clone();
        blocks.store(root.clone());

        let loaded = super::load_root(&blocks, &root_hash, &names).await?;
        assert_eq!(loaded, Some(root));
        assert_eq!(blocks.read_log().len(), 5);
        assert_eq!(
            blocks.peak_reads_in_flight(),
            5,
            "the root and its named nodes are read at once"
        );
        Ok(())
    }

    fn fact(entity: String, body: String) -> Result<Instruction> {
        Ok(Instruction::Assert(Artifact {
            the: "note/body".parse()?,
            of: entity.parse()?,
            is: Value::String(body),
            cause: None,
            meta: None,
        }))
    }

    /// A reader that holds only the root and the nodes a head names shows
    /// the newest facts, and reads no other node. A larger tree is not
    /// named whole.
    #[dialog_common::test]
    async fn it_names_what_shows_the_newest_facts() -> Result<()> {
        show_newest(1_500, 200, 20, false).await
    }

    /// A small tree is named whole, so a reader that holds only the root
    /// and the nodes a head names shows every fact under a prefix. The values
    /// stay in the tree: a value that spills out of it is not a node.
    #[dialog_common::test]
    async fn it_names_what_shows_every_fact_of_a_small_tree() -> Result<()> {
        let inline = dialog_search_tree::Manifest::default().inline_n as usize;
        show_newest(40, inline.saturating_sub(64).min(4_000), 240, true).await
    }

    async fn show_newest(notes: usize, body: usize, limit: usize, whole: bool) -> Result<()> {
        let (operator, profile) = test_session_with_peer().await;
        let repository = profile
            .space(unique_name("prefetch-newest"))
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
        let store = LocalIndex::new(&operator, branch.archive().index());
        let root = NodeHash::from(*revision.tree.hash());
        let named = name_prefetch(&revision, store.clone()).await?;

        let load = |hash: NodeHash| LoadBlock::new(hash).perform(&store);
        let root_block = load(root.clone()).await?.expect("a root");
        let root_node = PersistentNode::<Key, State<Datum>>::try_from(root_block.clone())?;
        let NodeBody::Index(index) = root_node.body() else {
            anyhow::bail!("the tree has more than one node")
        };
        let children: Vec<NodeHash> = index.links()?.into_iter().map(|link| link.node).collect();
        let named_children = children
            .iter()
            .filter(|child| named.contains(child.as_bytes()))
            .count();
        if whole {
            assert_eq!(
                named_children,
                children.len(),
                "a small tree is named whole"
            );
        } else {
            assert!(
                named_children < children.len(),
                "a larger tree is not named whole: {named_children} of {}",
                children.len()
            );
        }

        let mut held = HashMap::new();
        held.insert(root.clone(), root_block);
        for hash in &named {
            let hash = NodeHash::from(*hash);
            let block = load(hash.clone()).await?.expect("a named node is stored");
            held.insert(hash, block);
        }
        let reader = Holding(Arc::new(held));
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
        }
        Ok(())
    }
}
