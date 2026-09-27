//! A tree over sealed storage: every node is stored sealed, addressed by
//! the hash of its sealed bytes, and read back through the same codec.

#![allow(unexpected_cfgs)]

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

use anyhow::Result;
use dialog_common::Blake3Hash;
use dialog_crypto::{KeyRing, SEALED_BLOCK_MAGIC, SealError, SealKey};
use dialog_search_tree::{
    BlockCodec, ContentAddressedStorage, DialogSearchTreeError, PersistentTree, TreeDifference,
};
use dialog_storage::{MemoryStorageBackend, StorageSource};
use futures_util::{StreamExt, TryStreamExt};

type Backend = MemoryStorageBackend<Blake3Hash, Vec<u8>>;
type Store = ContentAddressedStorage<Backend>;
type Tree = PersistentTree<[u8; 4], Vec<u8>>;

const MARKER: &[u8] = b"plaintext-marker-that-must-stay-inside-the-seal";

fn sealed(byte: u8) -> BlockCodec {
    BlockCodec::sealed(KeyRing::new(SealKey::from([byte; 32])))
}

fn store(codec: BlockCodec) -> Store {
    Store::encoded_with(Backend::default(), codec)
}

/// A value large enough that a few thousand of them span several leaves
/// under an index, each carrying the marker.
fn value(index: u32) -> Vec<u8> {
    let mut value = index.to_be_bytes().repeat(40);
    value.extend_from_slice(MARKER);
    value
}

/// Inserts `keys` in one batch on top of `tree`, persisting through the
/// store's own delta and flushing into the store.
async fn insert(tree: &Tree, keys: impl Iterator<Item = u32>, store: &mut Store) -> Result<Tree> {
    let mut edit = tree.edit();
    for key in keys {
        edit = edit.insert(key.to_be_bytes(), value(key), store).await?;
    }
    let mut delta = store.delta();
    let tree = edit.persist(&mut delta)?;
    for (hash, block) in delta.flush() {
        store.store(block.as_ref().to_vec(), &hash).await?;
    }
    Ok(tree)
}

async fn stored_blocks(store: &Store) -> Result<Vec<(Blake3Hash, Vec<u8>)>> {
    let mut blocks: Vec<_> = store.backend().read().try_collect().await?;
    blocks.sort();
    Ok(blocks)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A sealed tree reads back every entry, from a fresh handle that shares
/// nothing with the writer but the store.
#[dialog_common::test]
async fn it_reads_back_a_sealed_tree() -> Result<()> {
    let mut store = store(sealed(1));
    let tree = insert(&Tree::empty(), 0..2000, &mut store).await?;

    let reopened = Tree::from_hash(tree.root().clone());
    for key in [0u32, 1, 999, 1999] {
        assert_eq!(
            reopened.get(&key.to_be_bytes(), &store).await?,
            Some(value(key))
        );
    }
    let entries: Vec<_> = reopened.stream(&store).try_collect().await?;
    assert_eq!(entries.len(), 2000);
    Ok(())
}

/// Every stored block is sealed and none carries plaintext; the same data
/// in a plain store does, which shows the scan would find it.
#[dialog_common::test]
async fn it_stores_no_plaintext() -> Result<()> {
    let mut sealed_store = store(sealed(1));
    insert(&Tree::empty(), 0..2000, &mut sealed_store).await?;
    let blocks = stored_blocks(&sealed_store).await?;
    assert!(blocks.len() > 3, "the tree spans several nodes");
    for (hash, bytes) in &blocks {
        assert!(bytes.starts_with(&SEALED_BLOCK_MAGIC));
        assert!(!contains(bytes, MARKER));
        assert_eq!(&Blake3Hash::hash(bytes), hash, "address is the sealed hash");
    }

    let mut plain_store = store(BlockCodec::Plain);
    insert(&Tree::empty(), 0..2000, &mut plain_store).await?;
    let plain = stored_blocks(&plain_store).await?;
    assert!(plain.iter().any(|(_, bytes)| contains(bytes, MARKER)));
    Ok(())
}

/// Two replicas with the same key build the same tree to the same root and
/// the same blocks, byte for byte. Another key gives another root.
#[dialog_common::test]
async fn it_seals_the_same_tree_to_the_same_blocks_on_every_replica() -> Result<()> {
    let mut first = store(sealed(1));
    let mut second = store(sealed(1));
    let first_tree = insert(&Tree::empty(), 0..1500, &mut first).await?;
    // The second replica inserts in another order and in two batches.
    let partial = insert(&Tree::empty(), (750..1500).rev(), &mut second).await?;
    let second_tree = insert(&partial, 0..750, &mut second).await?;
    assert_eq!(first_tree.root(), second_tree.root());

    // The first replica wrote its tree in one batch, so every block it holds
    // belongs to the final tree; the second holds each of them, byte for byte.
    let second_blocks = stored_blocks(&second).await?;
    for block in stored_blocks(&first).await? {
        assert!(second_blocks.contains(&block));
    }

    let mut other = store(sealed(2));
    let other_tree = insert(&Tree::empty(), 0..1500, &mut other).await?;
    assert_ne!(first_tree.root(), other_tree.root());
    Ok(())
}

/// A sealed tree cannot be read with another key or without one.
#[dialog_common::test]
async fn it_refuses_to_read_with_the_wrong_key() -> Result<()> {
    let mut store = store(sealed(1));
    let tree = insert(&Tree::empty(), 0..100, &mut store).await?;

    let other_key = Store::encoded_with(store.backend().clone(), sealed(2));
    let reopened = Tree::from_hash(tree.root().clone());
    let result = reopened.get(&7u32.to_be_bytes(), &other_key).await;
    assert!(matches!(
        result,
        Err(DialogSearchTreeError::Seal(SealError::Authentication))
    ));

    let no_key = Store::new(store.backend().clone());
    let reopened = Tree::from_hash(tree.root().clone());
    assert!(reopened.get(&7u32.to_be_bytes(), &no_key).await.is_err());
    Ok(())
}

/// Sync between sealed replicas works on the sealed blocks: the novel nodes
/// of an edit, copied as they are, make the edit readable on a replica that
/// held the base, and concurrent edits merge to one root on both sides.
#[dialog_common::test]
async fn it_syncs_and_merges_sealed_replicas() -> Result<()> {
    let mut ours = store(sealed(1));
    let base = insert(&Tree::empty(), 0..1000, &mut ours).await?;
    let mut theirs = store(sealed(1));
    for (hash, bytes) in stored_blocks(&ours).await? {
        theirs.store(bytes, &hash).await?;
    }

    let our_edit = insert(&base, 1000..1100, &mut ours).await?;
    let their_edit = insert(&base, 2000..2100, &mut theirs).await?;

    // Ship our novelty to them as stored blocks.
    {
        let difference = TreeDifference::compute(&base, &our_edit, &ours, &ours).await?;
        let nodes = difference.novel_nodes();
        futures_util::pin_mut!(nodes);
        while let Some(node) = nodes.next().await {
            let node = node?;
            assert!(node.buffer().as_ref().starts_with(&SEALED_BLOCK_MAGIC));
            theirs
                .store(node.buffer().as_ref().to_vec(), node.hash())
                .await?;
        }
    }
    let shipped = Tree::from_hash(our_edit.root().clone());
    assert_eq!(
        shipped.get(&1050u32.to_be_bytes(), &theirs).await?,
        Some(value(1050))
    );

    // Ship theirs back the same way.
    {
        let difference = TreeDifference::compute(&base, &their_edit, &theirs, &theirs).await?;
        let nodes = difference.novel_nodes();
        futures_util::pin_mut!(nodes);
        while let Some(node) = nodes.next().await {
            let node = node?;
            ours.store(node.buffer().as_ref().to_vec(), node.hash())
                .await?;
        }
    }

    // Each side integrates the other's changes over its own edit.
    let mut delta = ours.delta();
    let merged_ours = our_edit
        .edit()
        .integrate(base.differentiate(&their_edit, &ours, &ours), &ours)
        .await?
        .persist(&mut delta)?;
    for (hash, block) in delta.flush() {
        ours.store(block.as_ref().to_vec(), &hash).await?;
    }
    let mut delta = theirs.delta();
    let merged_theirs = their_edit
        .edit()
        .integrate(base.differentiate(&our_edit, &theirs, &theirs), &theirs)
        .await?
        .persist(&mut delta)?;
    for (hash, block) in delta.flush() {
        theirs.store(block.as_ref().to_vec(), &hash).await?;
    }

    assert_eq!(merged_ours.root(), merged_theirs.root());
    let merged: Vec<_> = Tree::from_hash(merged_ours.root().clone())
        .stream(&theirs)
        .try_collect()
        .await?;
    assert_eq!(merged.len(), 1200);
    Ok(())
}
