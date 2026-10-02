//! The top of a tree: its nodes, level by level from the root.
//!
//! A reader that holds none of a tree reads it one level at a time,
//! because each node names the next. A writer holds the whole tree, so
//! it can name the upper levels up front, and a reader can fetch them
//! all in one round trip. A small tree is named whole, so a reader of
//! it waits for no second round trip.

use std::collections::HashSet;

use dialog_capability::Provider;
use dialog_common::{Blake3Hash, ConditionalSync};
use rkyv::{
    bytecheck::CheckBytes,
    rancor::Strategy,
    validation::{Validator, archive::ArchiveValidator, shared::SharedValidator},
};

use crate::{DialogSearchTreeError, LoadBlock, NodeBody, PersistentNode};

/// A key range, inclusive at both ends.
type KeyRange = (Vec<u8>, Vec<u8>);

/// The nodes below `root`, level by level from the top, while they fit
/// in `most`. A level is named whole or not at all. So a small tree is
/// named whole, leaves included, and a large one has its upper index
/// levels named. The root itself is never named, because it is known
/// already. A node the environment cannot load ends the walk.
///
/// The walk reads only index nodes: it learns what each level holds
/// from the index node above it.
pub async fn top_nodes<Key, Value, Env>(
    root: &Blake3Hash,
    env: &Env,
    most: usize,
) -> Result<Vec<Blake3Hash>, DialogSearchTreeError>
where
    Key: crate::Key,
    Value: crate::Value,
    Value::Archived: for<'a> CheckBytes<
        Strategy<Validator<ArchiveValidator<'a>, SharedValidator>, rkyv::rancor::Error>,
    >,
    Env: Provider<LoadBlock> + ConditionalSync,
{
    let mut named = Vec::new();
    let mut level = vec![root.clone()];
    loop {
        let mut children = Vec::new();
        for hash in &level {
            let Some(node) = load::<Key, Value, Env>(hash, env).await? else {
                return Ok(named);
            };
            match node.body() {
                NodeBody::Index(index) => {
                    children.extend(index.links()?.into_iter().map(|link| link.node));
                }
                // A leaf has no children, and every leaf is at one depth,
                // so this level was the last.
                NodeBody::Segment(_) => return Ok(named),
            }
        }
        if children.is_empty() || named.len() + children.len() > most {
            return Ok(named);
        }
        named.extend(children.iter().cloned());
        level = children;
    }
}

/// The nodes below `root` that hold keys in any of `ranges`, each range
/// inclusive at both ends: the index nodes on the paths and the leaves at
/// their ends. Each node is named once, and a node comes after its
/// parent. The root itself is not named. A node the environment cannot
/// load ends its path.
///
/// A writer names these for the reads it expects a reader to make first,
/// so that a reader fetches them all in one round trip.
pub async fn nodes_spanning<Key, Value, Env>(
    root: &Blake3Hash,
    env: &Env,
    ranges: &[KeyRange],
) -> Result<Vec<Blake3Hash>, DialogSearchTreeError>
where
    Key: crate::Key,
    Value: crate::Value,
    Value::Archived: for<'a> CheckBytes<
        Strategy<Validator<ArchiveValidator<'a>, SharedValidator>, rkyv::rancor::Error>,
    >,
    Env: Provider<LoadBlock> + ConditionalSync,
{
    let mut named = Vec::new();
    if ranges.is_empty() {
        return Ok(named);
    }
    let mut seen = HashSet::new();
    let mut level = vec![(root.clone(), ranges.to_vec())];
    while !level.is_empty() {
        let mut next = Vec::new();
        for (hash, ranges) in level {
            let Some(node) = load::<Key, Value, Env>(&hash, env).await? else {
                continue;
            };
            let NodeBody::Index(index) = node.body() else {
                continue;
            };
            let mut children: Vec<(usize, Vec<KeyRange>)> = Vec::new();
            for (lower, upper) in ranges {
                let start = index.route(&lower)?;
                let end = index
                    .children_within(core::ops::Bound::Included(upper.as_slice()))?
                    .max(start + 1);
                for at in start..end.min(index.len()) {
                    match children.iter_mut().find(|(child, _)| *child == at) {
                        Some((_, list)) => list.push((lower.clone(), upper.clone())),
                        None => children.push((at, vec![(lower.clone(), upper.clone())])),
                    }
                }
            }
            children.sort_by_key(|(at, _)| *at);
            for (at, ranges) in children {
                let child = index.hash_at(at)?.clone();
                if seen.insert(child.clone()) {
                    named.push(child.clone());
                    next.push((child, ranges));
                }
            }
        }
        level = next;
    }
    Ok(named)
}

/// The node stored under `hash`, or none when the environment cannot
/// load it.
async fn load<Key, Value, Env>(
    hash: &Blake3Hash,
    env: &Env,
) -> Result<Option<PersistentNode<Key, Value>>, DialogSearchTreeError>
where
    Key: crate::Key,
    Value: crate::Value,
    Value::Archived: for<'a> CheckBytes<
        Strategy<Validator<ArchiveValidator<'a>, SharedValidator>, rkyv::rancor::Error>,
    >,
    Env: Provider<LoadBlock> + ConditionalSync,
{
    match LoadBlock::new(hash.clone()).perform(env).await? {
        Some(buffer) => Ok(Some(PersistentNode::try_from(buffer)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use anyhow::Result;
    use dialog_common::Blake3Hash;

    use super::{nodes_spanning, top_nodes};
    use crate::helpers::JournaledBlocks;
    use crate::{Cache, Delta, Manifest, NodeBody, PersistentNode, TransientTree};

    /// A tree of 2,000 keys with a fanout near 4 and no byte pacing, so
    /// it has several levels of index nodes. Returns its root.
    async fn build_deep_tree(storage: &JournaledBlocks) -> Result<Blake3Hash> {
        let manifest = Manifest {
            fanout_n: 2,
            max_segment: 0,
            frame_ceiling_factor: 0,
            ..Manifest::default()
        };
        let mut edit =
            TransientTree::<[u8; 4], Vec<u8>>::empty_with_manifest(Cache::new(), manifest);
        for key in 0u32..2_000 {
            edit = edit.insert(key.to_be_bytes(), vec![1; 8], storage).await?;
        }
        let mut delta = Delta::zero();
        let tree = edit.persist(&mut delta)?;
        storage.flush(&mut delta);
        Ok(tree.root().clone())
    }

    fn open(storage: &JournaledBlocks, hash: &Blake3Hash) -> PersistentNode<[u8; 4], Vec<u8>> {
        let bytes = storage.get(hash).expect("the tree is stored");
        PersistentNode::try_from(bytes).expect("a valid node")
    }

    /// The nodes of each level below the root, top first, read in full.
    fn read_levels(root: &Blake3Hash, storage: &JournaledBlocks) -> Result<Vec<Vec<Blake3Hash>>> {
        let mut levels = Vec::new();
        let mut level = vec![root.clone()];
        loop {
            let mut children = Vec::new();
            for hash in &level {
                let node = open(storage, hash);
                if let NodeBody::Index(index) = node.body() {
                    children.extend(index.links()?.into_iter().map(|link| link.node));
                }
            }
            if children.is_empty() {
                return Ok(levels);
            }
            levels.push(children.clone());
            level = children;
        }
    }

    /// A key names the path to its leaf, one node per level below the
    /// root. A range names every leaf it covers, and the index nodes above
    /// them.
    #[dialog_common::test]
    async fn it_names_the_nodes_on_the_paths_of_a_range() -> Result<()> {
        let storage = JournaledBlocks::new();
        let root = build_deep_tree(&storage).await?;
        let levels = read_levels(&root, &storage)?;
        let leaves = levels.last().expect("the tree has leaves");

        let key = 1_000u32.to_be_bytes().to_vec();
        let path =
            nodes_spanning::<[u8; 4], Vec<u8>, _>(&root, &storage, &[(key.clone(), key.clone())])
                .await?;
        assert_eq!(
            path.len(),
            levels.len(),
            "one node per level below the root"
        );
        let leaf = path.last().expect("a path");
        assert!(leaves.contains(leaf));
        let node = open(&storage, leaf);
        let NodeBody::Segment(segment) = node.body() else {
            anyhow::bail!("a path ends at a leaf")
        };
        let mut keys = segment.keys::<[u8; 4]>()?;
        let mut found = false;
        while let Some((_, stored)) = keys.next_key()? {
            found |= stored == key.as_slice();
        }
        assert!(found, "the leaf holds the key");

        let everything = nodes_spanning::<[u8; 4], Vec<u8>, _>(
            &root,
            &storage,
            &[(0u32.to_be_bytes().to_vec(), 1_999u32.to_be_bytes().to_vec())],
        )
        .await?;
        assert_eq!(everything.len(), levels.concat().len());
        assert!(leaves.iter().all(|leaf| everything.contains(leaf)));
        Ok(())
    }

    #[dialog_common::test]
    async fn it_names_a_small_tree_whole() -> Result<()> {
        let storage = JournaledBlocks::new();
        let root = build_deep_tree(&storage).await?;
        let levels = read_levels(&root, &storage)?;
        assert!(levels.len() >= 3, "the tree has index nodes below its root");

        let named = top_nodes::<[u8; 4], Vec<u8>, _>(&root, &storage, usize::MAX).await?;
        assert_eq!(named, levels.concat());
        assert!(!named.contains(&root));
        Ok(())
    }

    #[dialog_common::test]
    async fn it_names_whole_levels_from_the_top_within_the_limit() -> Result<()> {
        let storage = JournaledBlocks::new();
        let root = build_deep_tree(&storage).await?;
        let levels = read_levels(&root, &storage)?;
        let (leaves, index_levels) = levels.split_last().expect("the tree has leaves");
        let index_nodes = index_levels.concat();

        let named = top_nodes::<[u8; 4], Vec<u8>, _>(&root, &storage, index_nodes.len()).await?;
        assert_eq!(named, index_nodes);
        assert!(leaves.iter().all(|leaf| !named.contains(leaf)));

        let top = levels.first().expect("the root has children").clone();
        let named = top_nodes::<[u8; 4], Vec<u8>, _>(&root, &storage, top.len()).await?;
        assert_eq!(named, top);

        let named = top_nodes::<[u8; 4], Vec<u8>, _>(&root, &storage, top.len() - 1).await?;
        assert!(named.is_empty());
        Ok(())
    }
}
