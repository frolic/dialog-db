//! The top of a tree: its nodes, level by level from the root.
//!
//! A reader that holds none of a tree reads it one level at a time,
//! because each node names the next. A writer holds the whole tree, so
//! it can name the upper levels up front, and a reader can fetch them
//! all in one round trip. A small tree is named whole, so a reader of
//! it waits for no second round trip.

use dialog_common::{Blake3Hash, Buffer, ConditionalSync, NULL_BLAKE3_HASH};
use dialog_storage::{DialogStorageError, StorageBackend};
use rkyv::{
    bytecheck::CheckBytes,
    rancor::Strategy,
    validation::{Validator, archive::ArchiveValidator, shared::SharedValidator},
};

use crate::{ArchivedNodeBody, ContentAddressedStorage, DialogSearchTreeError, PersistentNode};

/// The nodes below `root`, level by level from the top, while they fit
/// in `most`. A level is named whole or not at all. So a small tree is
/// named whole, leaves included, and a large one has its upper index
/// levels named. The root itself is never named, because it is known
/// already. A node the storage does not hold ends the walk.
///
/// The walk reads only index nodes: it learns what each level holds
/// from the index node above it.
pub async fn top_nodes<Key, Value, Backend>(
    root: &Blake3Hash,
    storage: &ContentAddressedStorage<Backend>,
    most: usize,
) -> Result<Vec<Blake3Hash>, DialogSearchTreeError>
where
    Key: crate::Key,
    Value: crate::Value,
    Value::Archived: for<'a> CheckBytes<
        Strategy<Validator<ArchiveValidator<'a>, SharedValidator>, rkyv::rancor::Error>,
    >,
    Backend: StorageBackend<Key = Blake3Hash, Value = Vec<u8>, Error = DialogStorageError>
        + ConditionalSync,
{
    let mut named = Vec::new();
    if root == NULL_BLAKE3_HASH {
        return Ok(named);
    }
    let mut level = vec![root.clone()];
    loop {
        let mut children = Vec::new();
        for hash in &level {
            match children_of::<Key, Value, Backend>(hash, storage).await? {
                Some(links) => children.extend(links),
                // A leaf has no children, and every leaf is at one depth,
                // so this level was the last.
                None => return Ok(named),
            }
        }
        if children.is_empty() || named.len() + children.len() > most {
            return Ok(named);
        }
        named.extend(children.iter().cloned());
        level = children;
    }
}

/// A key range, inclusive at both ends.
type KeyRange = (Vec<u8>, Vec<u8>);

/// The nodes below `root` that hold keys in any of `ranges`, each range
/// inclusive at both ends: the index nodes on the paths and the leaves at
/// their ends. Each node is named once, and a node comes after its
/// parent. The root itself is not named. A node the storage does not hold
/// ends its path.
///
/// A writer names these for the reads it expects a reader to make first,
/// so that a reader fetches them all in one round trip.
pub async fn nodes_spanning<Key, Value, Backend>(
    root: &Blake3Hash,
    storage: &ContentAddressedStorage<Backend>,
    ranges: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<Blake3Hash>, DialogSearchTreeError>
where
    Key: crate::Key,
    Value: crate::Value,
    Value::Archived: for<'a> CheckBytes<
        Strategy<Validator<ArchiveValidator<'a>, SharedValidator>, rkyv::rancor::Error>,
    >,
    Backend: StorageBackend<Key = Blake3Hash, Value = Vec<u8>, Error = DialogStorageError>
        + ConditionalSync,
{
    let mut named = Vec::new();
    if root == NULL_BLAKE3_HASH || ranges.is_empty() {
        return Ok(named);
    }
    let mut seen = std::collections::HashSet::new();
    let mut level = vec![(root.clone(), ranges.to_vec())];
    while !level.is_empty() {
        let mut next = Vec::new();
        for (hash, ranges) in level {
            let Some(bytes) = storage.retrieve(&hash).await? else {
                continue;
            };
            let node = PersistentNode::<Key, Value>::open(Buffer::from(bytes), storage.codec())?;
            let ArchivedNodeBody::Index(index) = node.body() else {
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

/// The children of the index node `hash`, or none when it is a leaf or
/// the storage does not hold it.
async fn children_of<Key, Value, Backend>(
    hash: &Blake3Hash,
    storage: &ContentAddressedStorage<Backend>,
) -> Result<Option<Vec<Blake3Hash>>, DialogSearchTreeError>
where
    Key: crate::Key,
    Value: crate::Value,
    Value::Archived: for<'a> CheckBytes<
        Strategy<Validator<ArchiveValidator<'a>, SharedValidator>, rkyv::rancor::Error>,
    >,
    Backend: StorageBackend<Key = Blake3Hash, Value = Vec<u8>, Error = DialogStorageError>
        + ConditionalSync,
{
    let Some(bytes) = storage.retrieve(hash).await? else {
        return Ok(None);
    };
    let node = PersistentNode::<Key, Value>::open(Buffer::from(bytes), storage.codec())?;
    match node.body() {
        ArchivedNodeBody::Index(index) => Ok(Some(
            index.links()?.into_iter().map(|link| link.node).collect(),
        )),
        ArchivedNodeBody::Segment(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use anyhow::Result;
    use dialog_common::{Blake3Hash, Buffer};
    use dialog_storage::MemoryStorageBackend;

    use super::{nodes_spanning, top_nodes};
    use crate::{
        ArchivedNodeBody, ContentAddressedStorage, Delta, Manifest, PersistentNode, PersistentTree,
        TransientTree,
    };

    type Storage = ContentAddressedStorage<MemoryStorageBackend<Blake3Hash, Vec<u8>>>;

    /// A tree of 2,000 keys with a fanout near 4 and no byte pacing, so
    /// it has several levels of index nodes.
    async fn build_deep_tree() -> Result<(PersistentTree<[u8; 4], Vec<u8>>, Storage)> {
        let mut storage = ContentAddressedStorage::new(MemoryStorageBackend::default());
        let manifest = Manifest {
            fanout_n: 2,
            max_segment: 0,
            frame_ceiling_factor: 0,
            ..Manifest::default()
        };
        let mut tree = PersistentTree::<[u8; 4], Vec<u8>>::empty();
        let mut delta = Delta::zero();
        for key in 0u32..2_000 {
            tree = TransientTree::with_manifest(tree.root().clone(), tree.node_cache(), manifest)
                .insert(key.to_be_bytes(), vec![1; 8], &storage)
                .await?
                .persist(&mut delta)?;
            for (_, buffer) in delta.flush() {
                storage
                    .store(buffer.as_ref().to_vec(), buffer.blake3_hash())
                    .await?;
            }
        }
        Ok((tree, storage))
    }

    /// The nodes of each level below the root, top first, read in full.
    async fn read_levels(root: &Blake3Hash, storage: &Storage) -> Result<Vec<Vec<Blake3Hash>>> {
        let mut levels = Vec::new();
        let mut level = vec![root.clone()];
        loop {
            let mut children = Vec::new();
            for hash in &level {
                let bytes = storage.retrieve(hash).await?.expect("the tree is stored");
                let node =
                    PersistentNode::<[u8; 4], Vec<u8>>::open(Buffer::from(bytes), storage.codec())?;
                if let ArchivedNodeBody::Index(index) = node.body() {
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
        let (tree, storage) = build_deep_tree().await?;
        let levels = read_levels(tree.root(), &storage).await?;
        let leaves = levels.last().expect("the tree has leaves");

        let key = 1_000u32.to_be_bytes().to_vec();
        let path = nodes_spanning::<[u8; 4], Vec<u8>, _>(
            tree.root(),
            &storage,
            &[(key.clone(), key.clone())],
        )
        .await?;
        assert_eq!(
            path.len(),
            levels.len(),
            "one node per level below the root"
        );
        let leaf = path.last().expect("a path");
        assert!(leaves.contains(leaf));
        let bytes = storage.retrieve(leaf).await?.expect("stored");
        let node = PersistentNode::<[u8; 4], Vec<u8>>::open(Buffer::from(bytes), storage.codec())?;
        let ArchivedNodeBody::Segment(segment) = node.body() else {
            anyhow::bail!("a path ends at a leaf")
        };
        let mut keys = segment.keys::<[u8; 4]>()?;
        let mut found = false;
        while let Some((_, stored)) = keys.next_key()? {
            found |= stored == key.as_slice();
        }
        assert!(found, "the leaf holds the key");

        let everything = nodes_spanning::<[u8; 4], Vec<u8>, _>(
            tree.root(),
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
        let (tree, storage) = build_deep_tree().await?;
        let levels = read_levels(tree.root(), &storage).await?;
        assert!(levels.len() >= 3, "the tree has index nodes below its root");

        let named = top_nodes::<[u8; 4], Vec<u8>, _>(tree.root(), &storage, usize::MAX).await?;
        assert_eq!(named, levels.concat());
        assert!(!named.contains(tree.root()));
        Ok(())
    }

    #[dialog_common::test]
    async fn it_names_whole_levels_from_the_top_within_the_limit() -> Result<()> {
        let (tree, storage) = build_deep_tree().await?;
        let levels = read_levels(tree.root(), &storage).await?;
        let (leaves, index_levels) = levels.split_last().expect("the tree has leaves");
        let index_nodes = index_levels.concat();

        let named =
            top_nodes::<[u8; 4], Vec<u8>, _>(tree.root(), &storage, index_nodes.len()).await?;
        assert_eq!(named, index_nodes);
        assert!(leaves.iter().all(|leaf| !named.contains(leaf)));

        let top = levels.first().expect("the root has children").clone();
        let named = top_nodes::<[u8; 4], Vec<u8>, _>(tree.root(), &storage, top.len()).await?;
        assert_eq!(named, top);

        let named = top_nodes::<[u8; 4], Vec<u8>, _>(tree.root(), &storage, top.len() - 1).await?;
        assert!(named.is_empty());
        Ok(())
    }
}
