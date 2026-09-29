//! Byte measurements of a feed-shaped tree.
//!
//! A cold reader fetches the blocks of a tree before it shows anything,
//! so the size of those blocks is the cost of a first screen. This
//! module builds a tree the way a photo feed writes it (one post per
//! commit), and prints where its bytes are: the root, the other index
//! nodes, and the leaves, split by the index each entry belongs to. It
//! also counts the blocks a first screen reads that the head does not
//! name, since each is one more round trip.
//!
//! Not part of the regular suite. Run it explicitly, in release, with
//! output:
//!
//! ```no_run
//! // cargo test -p dialog-repository --release tree_bytes -- --ignored --nocapture
//! ```

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use dialog_artifacts::history::TreeHistory;
use dialog_artifacts::inspect::key_components;
use dialog_artifacts::tree::{ArtifactTree, ArtifactTreeExt as _, TreeStorageBridge, spill_cache};
use dialog_artifacts::{Artifact, ArtifactSelector, Datum, Instruction, Key, State, Value};
use dialog_common::{Blake3Hash as NodeHash, Buffer, ConditionalSync};
use dialog_operator::helpers::{test_operator_with_profile, unique_name};
use dialog_search_tree::{ArchivedNodeBody, ContentAddressedStorage, PersistentNode};
use dialog_storage::{BlockCodec, TestSealing};
use dialog_storage::{DialogStorageError, StorageBackend};
use futures_util::{TryStreamExt as _, stream};
use rkyv::rancor::Error as RkyvError;

use crate::{LocalIndex, RepositoryExt as _};

/// One fact of a post: entity, attribute, and value.
type Fact = (String, &'static str, Value);

/// The facts of one post as the till feed test writes it: a caption, a
/// time, and one to three photos with five fields each.
fn post(at: u64, index: u64) -> Vec<Fact> {
    let id = format!("post:{:012x}{:08x}", (1u64 << 48) - 1 - at, index);
    let mut facts = vec![
        (
            id.clone(),
            "post/caption",
            Value::String(format!("a walk by the river, day {index}")),
        ),
        (id.clone(), "post/at", Value::UnsignedInt(u128::from(at))),
    ];
    for photo in 0..1 + index % 3 {
        let entity = format!("{id}.p{photo}");
        let mut blob = format!("blob:{index:08x}{photo}");
        while blob.len() < 52 {
            blob.push('x');
        }
        facts.push((entity.clone(), "photo/blob", Value::String(blob)));
        facts.push((
            entity.clone(),
            "photo/index",
            Value::UnsignedInt(u128::from(photo)),
        ));
        facts.push((entity.clone(), "photo/width", Value::UnsignedInt(1080)));
        facts.push((entity.clone(), "photo/height", Value::UnsignedInt(1350)));
        facts.push((entity, "photo/placeholder", Value::String("p".repeat(300))));
    }
    facts
}

/// The size of `facts` as the JSON a client sends: one object per fact.
fn json_bytes(facts: &[Fact]) -> usize {
    facts
        .iter()
        .map(|(entity, attribute, value)| {
            let value = match value {
                Value::String(text) => serde_json::to_string(text).unwrap_or_default(),
                Value::UnsignedInt(number) => number.to_string(),
                other => format!("{other:?}"),
            };
            format!(
                r#"{{"assert":{{"entity":"{entity}","attribute":"{attribute}","value":{value}}}}},"#
            )
            .len()
        })
        .sum()
}

fn instructions(facts: Vec<Fact>) -> Result<Vec<Instruction>> {
    facts
        .into_iter()
        .map(|(entity, attribute, value)| {
            Ok(Instruction::Assert(Artifact {
                the: attribute.parse()?,
                of: entity.parse()?,
                is: value,
                cause: None,
            }))
        })
        .collect()
}

/// Where the bytes of one tree are.
#[derive(Default, Debug)]
struct Breakdown {
    root: usize,
    root_novelty: usize,
    index_nodes: usize,
    index_bytes: usize,
    leaves: usize,
    leaf_bytes: usize,
    levels: usize,
    /// Leaf bytes by region, shared out by the raw size of each entry.
    regions: BTreeMap<&'static str, f64>,
    /// Entries by region.
    entries: BTreeMap<&'static str, usize>,
}

/// The region a key belongs to: its index, and for fact indexes whether
/// the fact is the application's or a revision record.
fn region(key: &[u8]) -> &'static str {
    let components = key_components(key);

    let system = components
        .iter()
        .any(|component| component.kind == "attribute" && component.text.starts_with("dialog."));
    match (key.first(), system) {
        (Some(0), false) => "EAV",
        (Some(1), false) => "AEV",
        (Some(2), false) => "VAE",
        (Some(0), true) => "EAV (revision records)",
        (Some(1), true) => "AEV (revision records)",
        (Some(2), true) => "VAE (revision records)",
        (Some(3), _) => "history",
        (Some(4), _) => "blob",
        (Some(5), _) => "coverage",
        _ => "other",
    }
}

/// Every node of the tree under `root`, with its level and bytes.
async fn read_tree<Backend>(
    root: &NodeHash,
    storage: &ContentAddressedStorage<Backend>,
) -> Result<Vec<(usize, NodeHash, Vec<u8>)>>
where
    Backend: StorageBackend<Key = NodeHash, Value = Vec<u8>, Error = DialogStorageError>
        + ConditionalSync,
{
    let mut nodes = Vec::new();
    let mut level = vec![root.clone()];
    let mut depth = 0;
    while !level.is_empty() {
        let mut next = Vec::new();
        for hash in level {
            let Some(bytes) = storage.retrieve(&hash).await? else {
                continue;
            };
            let node = PersistentNode::<Key, State<Datum>>::open(
                Buffer::from(bytes.clone()),
                storage.codec(),
            )?;
            if let ArchivedNodeBody::Index(index) = node.body() {
                next.extend(index.links()?.into_iter().map(|link| link.node));
            }
            nodes.push((depth, hash, bytes));
        }
        level = next;
        depth += 1;
    }
    Ok(nodes)
}

fn break_down(nodes: &[(usize, NodeHash, Vec<u8>)], codec: &BlockCodec) -> Result<Breakdown> {
    let mut breakdown = Breakdown::default();
    for (depth, _, bytes) in nodes {
        breakdown.levels = breakdown.levels.max(depth + 1);
        let node = PersistentNode::<Key, State<Datum>>::open(Buffer::from(bytes.clone()), codec)?;
        if *depth == 0 {
            breakdown.root = bytes.len();
        }
        if let Ok(index) = node.as_index() {
            if *depth == 0 {
                breakdown.root_novelty = index.novelty_len();
            }
            if *depth > 0 {
                breakdown.index_nodes += 1;
                breakdown.index_bytes += bytes.len();
            }
            continue;
        }
        if *depth > 0 {
            breakdown.leaves += 1;
            breakdown.leaf_bytes += bytes.len();
        }
        let segment = node.as_segment()?;
        let mut cursor = segment.keys::<Key>()?;
        let mut raw: BTreeMap<&'static str, usize> = BTreeMap::new();
        while let Some((at, key)) = cursor.next_key()? {
            let key = key.to_vec();
            let state: State<Datum> =
                rkyv::deserialize::<State<Datum>, RkyvError>(segment.value_at(at)?)?;
            let value = rkyv::to_bytes::<RkyvError>(&state)?.len();
            let name = region(&key);
            *raw.entry(name).or_default() += key.len() + value;
            *breakdown.entries.entry(name).or_default() += 1;
        }
        let total: usize = raw.values().sum();
        for (name, size) in raw {
            *breakdown.regions.entry(name).or_default() +=
                bytes.len() as f64 * size as f64 / total.max(1) as f64;
        }
    }
    Ok(breakdown)
}

/// Builds a sealed repository with a name and `posts` posts, one commit
/// each, and prints where the bytes of its tree are.
async fn measure(posts: u64) -> Result<String> {
    let (operator, profile) = test_operator_with_profile().await;
    let repository = profile
        .repository(unique_name("tree-bytes"))
        .open()
        .sealed(TestSealing::new(7))
        .perform(&operator)
        .await?;
    let branch = repository.branch("main").open().perform(&operator).await?;
    let storage = ContentAddressedStorage::new(TreeStorageBridge(LocalIndex::new(
        &operator,
        branch.archive().index(),
        branch.codec().clone(),
    )));
    let name = vec![(
        "person:did:key:owner".to_string(),
        "person/name",
        Value::String("Kaori".into()),
    )];
    let mut json = json_bytes(&name);
    branch
        .commit(stream::iter(instructions(name)?))
        .perform(&operator)
        .await?;
    let mut seen = HashSet::new();
    let mut written = 0;
    let mut roots = 0;
    let start = 1_767_225_600_000u64;
    for index in 0..posts {
        let facts = post(start + index * 3_600_000, index);
        json += json_bytes(&facts);
        branch
            .commit(stream::iter(instructions(facts)?))
            .perform(&operator)
            .await?;
        let root = NodeHash::from(*branch.revision().expect("a head").tree.hash());
        for (depth, hash, bytes) in read_tree(&root, &storage).await? {
            if depth == 0 {
                roots += bytes.len();
            }
            if seen.insert(hash) {
                written += bytes.len();
            }
        }
    }
    let revision = branch.revision().expect("a head");
    let root = NodeHash::from(*revision.tree.hash());
    let nodes = read_tree(&root, &storage).await?;
    let named = crate::name_prefetch(&revision, storage.backend().0.clone()).await?;
    let mut named_bytes = 0;
    for hash in &named {
        let block = storage
            .retrieve(&NodeHash::from(*hash))
            .await?
            .unwrap_or_default();
        named_bytes += block.len();
    }
    let breakdown = break_down(&nodes, storage.codec())?;
    let total = breakdown.root + breakdown.index_bytes + breakdown.leaf_bytes;
    let regions = breakdown
        .regions
        .iter()
        .map(|(name, bytes)| {
            format!(
                "{name} {:.1} KB ({} entries)",
                bytes / 1024.0,
                breakdown.entries.get(name).copied().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        "| {posts} | {:.1} KB | {:.1} KB | {:.1} KB ({} ops) | {} | {:.1} KB | {} | {:.1} KB | {} | {:.1}x | {:.1} KB | {:.1} KB | {} nodes, {:.1} KB |\n  regions: {regions}",
        json as f64 / 1024.0,
        total as f64 / 1024.0,
        breakdown.root as f64 / 1024.0,
        breakdown.root_novelty,
        breakdown.index_nodes,
        breakdown.index_bytes as f64 / 1024.0,
        breakdown.leaves,
        breakdown.leaf_bytes as f64 / 1024.0,
        breakdown.levels,
        total as f64 / json as f64,
        written as f64 / posts.max(1) as f64 / 1024.0,
        roots as f64 / posts.max(1) as f64 / 1024.0,
        named.len(),
        (breakdown.root + named_bytes) as f64 / 1024.0,
    ))
}

/// Prints where the bytes of a feed tree are, for a few sizes.
/// `#[ignore]`d: a measurement, not an assertion.
#[dialog_common::test]
#[ignore]
async fn tree_bytes() -> Result<()> {
    let mut rows = vec![
        "| posts | facts as JSON | tree | root | index nodes | index bytes | leaves | leaf bytes | levels | tree / JSON | written per commit | mean root | head names (with root) |".to_string(),
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |".to_string(),
    ];
    for posts in [0, 10, 50, 200, 400] {
        rows.push(measure(posts).await?);
    }
    println!("{}", rows.join("\n"));
    Ok(())
}

/// The blocks read that a head did not name.
type Misses = Arc<Mutex<Vec<[u8; 32]>>>;

/// A reader that holds all blocks and records each read of a block the
/// head did not name.
#[derive(Clone)]
struct NamedReader<Backend> {
    inner: Backend,
    named: Arc<HashSet<[u8; 32]>>,
    misses: Misses,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<Backend> StorageBackend for NamedReader<Backend>
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
        if !self.named.contains(key)
            && let Ok(mut misses) = self.misses.lock()
        {
            misses.push(*key);
        }
        self.inner.get(key).await
    }
}

/// The region of the first and the last entry of the leaf `bytes`.
fn leaf_edges(bytes: Vec<u8>, codec: &BlockCodec) -> Result<String> {
    let node = PersistentNode::<Key, State<Datum>>::open(Buffer::from(bytes), codec)?;
    let Ok(segment) = node.as_segment() else {
        return Ok("index node".into());
    };
    let mut cursor = segment.keys::<Key>()?;
    let mut first = None;
    let mut last = "";
    while let Some((_, key)) = cursor.next_key()? {
        last = region(key);
        first.get_or_insert(last);
    }
    Ok(format!("{} .. {last}", first.unwrap_or_default()))
}

/// Prints how many blocks a first screen reads that the head of a sealed
/// feed tree does not name: the newest posts, the owner's name, and the
/// author of each fact shown.
#[dialog_common::test]
#[ignore]
async fn named_misses() -> Result<()> {
    for posts in [10u64, 200] {
        for _ in 0..8 {
            let (operator, profile) = test_operator_with_profile().await;
            let repository = profile
                .repository(unique_name("misses"))
                .open()
                .sealed(TestSealing::new(7))
                .perform(&operator)
                .await?;
            let branch = repository.branch("main").open().perform(&operator).await?;
            let store =
                LocalIndex::new(&operator, branch.archive().index(), branch.codec().clone());
            let storage = ContentAddressedStorage::new(TreeStorageBridge(store.clone()));
            let owner = "person:did:key:owner".to_string();
            let name = vec![(owner.clone(), "person/name", Value::String("Kaori".into()))];
            branch
                .commit(stream::iter(instructions(name)?))
                .perform(&operator)
                .await?;
            for index in 0..posts {
                let facts = post(1_767_225_600_000 + index * 3_600_000, index);
                branch
                    .commit(stream::iter(instructions(facts)?))
                    .perform(&operator)
                    .await?;
            }
            let revision = branch.revision().expect("a head");
            let root = NodeHash::from(*revision.tree.hash());
            let mut named: HashSet<[u8; 32]> = crate::name_prefetch(&revision, store.clone())
                .await?
                .into_iter()
                .collect();
            named.insert(*root.as_bytes());
            let reader = NamedReader {
                inner: store.clone(),
                named: Arc::new(named),
                misses: Misses::default(),
            };
            let history = TreeHistory::from_root(revision.tree.hash(), reader.clone());
            for selector in [
                ArtifactSelector::new()
                    .of_starting_with("post:")
                    .with_limit(240),
                ArtifactSelector::new().of(owner.parse()?),
            ] {
                let views: Vec<_> = ArtifactTree::from_hash(root.clone())
                    .scan(reader.clone(), spill_cache(), selector)
                    .try_collect()
                    .await?;
                for view in &views {
                    for version in view.versions() {
                        history.authorship(version).await?;
                    }
                }
            }
            let misses = reader
                .misses
                .lock()
                .map(|misses| misses.clone())
                .unwrap_or_default();
            let mut leaves = Vec::new();
            for miss in misses {
                let bytes = storage
                    .retrieve(&NodeHash::from(miss))
                    .await?
                    .unwrap_or_default();
                leaves.push(leaf_edges(bytes, storage.codec())?);
            }
            println!(
                "posts {posts}: named {}, read unnamed {}: {leaves:?}",
                reader.named.len(),
                leaves.len()
            );
        }
    }
    Ok(())
}
