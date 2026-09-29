#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

use anyhow::Result;
use dialog_artifacts::tree::TreeStorageBridge;
use dialog_artifacts::{
    Artifact, ArtifactSelector, DialogArtifactsError, Entity, Instruction, Value,
};
use dialog_common::Blake3Hash as NodeHash;
use dialog_common::{Blake3Hash, Buffer, ConditionalSend};
use dialog_crypto::{BlockCodec, KeyRing, SEALED_BLOCK_MAGIC, SealError};
use dialog_effects::archive::prelude::ArchiveScope;
use dialog_effects::blob::{BlobError, BlobReader, ByteRange};
use dialog_identity::{Profile, SpaceHandle};
use dialog_operator::Operator;
use dialog_operator::helpers::{test_operator_with_profile, unique_name};
use dialog_search_tree::{ContentAddressedStorage, Traversable as _, Visit};
use dialog_storage::provider::storage::VolatileSpace;
use futures_util::{Stream, StreamExt as _, stream};

use crate::{
    Blob, Branch, CommitError, Index, LoadRepositoryError, NetworkedIndex, OpenRepositoryError,
    Repository, RepositoryExt as _, RepositorySealError, SealKey,
};

fn key(byte: u8) -> SealKey {
    SealKey::from([byte; 32])
}

fn sealed_codec(byte: u8) -> BlockCodec {
    BlockCodec::sealed(KeyRing::new(key(byte)))
}

fn space(profile: &Profile, name: &str) -> SpaceHandle {
    SpaceHandle {
        profile_did: dialog_varsig::Principal::did(profile),
        name: name.to_string(),
    }
}

fn note(index: usize, body: &str) -> Result<Instruction> {
    Ok(Instruction::Assert(Artifact {
        the: "note/body".parse()?,
        of: format!("note:{index}").parse()?,
        is: Value::String(body.to_string()),
        cause: None,
    }))
}

async fn commit_notes(
    branch: &Branch,
    operator: &Operator<VolatileSpace>,
    marker: &str,
) -> Result<()> {
    let notes = (0..200)
        .map(|index| note(index, &format!("{index} {marker}")))
        .collect::<Result<Vec<_>>>()?;
    branch.commit(stream::iter(notes)).perform(operator).await?;
    Ok(())
}

async fn read_notes(branch: &Branch, operator: &Operator<VolatileSpace>) -> Result<Vec<Artifact>> {
    let notes = branch
        .claims()
        .select(ArtifactSelector::new().the("note/body".parse()?))
        .to_owned()
        .perform(operator)
        .await?
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(notes)
}

/// Every block of the tree the branch's head names, as stored.
async fn stored_tree_blocks<C: dialog_varsig::Principal>(
    operator: &Operator<VolatileSpace>,
    repository: &Repository<C>,
    branch: &Branch,
) -> Result<Vec<Vec<u8>>> {
    let catalog = ArchiveScope::new(repository.subject()).index();
    let index = NetworkedIndex::new(operator, catalog, None, repository.codec().clone());
    let storage = ContentAddressedStorage::new(TreeStorageBridge(index));
    let root = branch.revision().expect("the branch has a commit").tree;
    let tree = Index::from_hash(NodeHash::from(*root.hash()));
    let mut blocks = Vec::new();
    let visits = tree.traverse_available(&storage);
    futures_util::pin_mut!(visits);
    while let Some(visit) = visits.next().await {
        let Visit::Present(node) = visit? else {
            panic!("a local repository holds its whole tree");
        };
        blocks.push(node.buffer().as_ref().to_vec());
    }
    Ok(blocks)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// What a sealed repository commits reads back through a fresh load of the
/// repository with the same key.
#[dialog_common::test]
async fn it_reads_back_what_a_sealed_repository_commits() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let name = unique_name("sealed");
    let repository = space(&profile, &name)
        .create()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    assert!(repository.codec().is_sealed());
    let branch = repository.branch("main").open().perform(&operator).await?;
    commit_notes(&branch, &operator, "first").await?;

    let reloaded = space(&profile, &name)
        .load()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    let branch = reloaded.branch("main").open().perform(&operator).await?;
    let notes = read_notes(&branch, &operator).await?;
    assert_eq!(notes.len(), 200);
    assert!(
        notes
            .iter()
            .any(|note| note.is == Value::String("7 first".into()))
    );

    // A second commit on the reloaded handle builds on the sealed tree.
    branch
        .commit(stream::iter(vec![note(500, "second")?]))
        .perform(&operator)
        .await?;
    assert_eq!(read_notes(&branch, &operator).await?.len(), 201);
    Ok(())
}

/// Every tree block of a sealed repository is stored sealed, and no fact
/// value appears in it. The same commit in a plain repository shows the
/// value, which shows the scan finds it.
#[dialog_common::test]
async fn it_stores_only_sealed_tree_blocks() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let marker = unique_name("plaintext-marker");

    let sealed = space(&profile, &unique_name("sealed"))
        .create()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    let branch = sealed.branch("main").open().perform(&operator).await?;
    commit_notes(&branch, &operator, &marker).await?;
    let blocks = stored_tree_blocks(&operator, &sealed, &branch).await?;
    assert!(blocks.len() > 1, "the tree spans several blocks");
    for block in &blocks {
        assert!(block.starts_with(&SEALED_BLOCK_MAGIC));
        assert!(!contains(block, &marker));
    }

    let plain = space(&profile, &unique_name("plain"))
        .create()
        .perform(&operator)
        .await?;
    let branch = plain.branch("main").open().perform(&operator).await?;
    commit_notes(&branch, &operator, &marker).await?;
    let blocks = stored_tree_blocks(&operator, &plain, &branch).await?;
    assert!(blocks.iter().any(|block| contains(block, &marker)));
    Ok(())
}

/// A sealed repository opens only with its key, and a plain one only
/// without a key.
#[dialog_common::test]
async fn it_opens_a_sealed_repository_only_with_its_key() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let sealed = unique_name("sealed");
    space(&profile, &sealed)
        .create()
        .sealed(key(1))
        .perform(&operator)
        .await?;

    let without_key = space(&profile, &sealed).load().perform(&operator).await;
    assert!(matches!(
        without_key,
        Err(LoadRepositoryError::Seal(RepositorySealError::KeyRequired))
    ));
    let wrong_key = space(&profile, &sealed)
        .load()
        .sealed(key(2))
        .perform(&operator)
        .await;
    assert!(matches!(
        wrong_key,
        Err(LoadRepositoryError::Seal(RepositorySealError::WrongKey))
    ));
    let opened_without_key = space(&profile, &sealed).open().perform(&operator).await;
    assert!(matches!(
        opened_without_key,
        Err(OpenRepositoryError::Seal(RepositorySealError::KeyRequired))
    ));
    let opened = space(&profile, &sealed)
        .open()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    assert!(opened.codec().is_sealed());

    let plain = unique_name("plain");
    space(&profile, &plain).create().perform(&operator).await?;
    let with_key = space(&profile, &plain)
        .load()
        .sealed(key(1))
        .perform(&operator)
        .await;
    assert!(matches!(
        with_key,
        Err(LoadRepositoryError::Seal(RepositorySealError::NotSealed))
    ));
    assert!(
        !space(&profile, &plain)
            .load()
            .perform(&operator)
            .await?
            .codec()
            .is_sealed()
    );
    Ok(())
}

/// Opening a missing repository with a key creates it sealed under that
/// key.
#[dialog_common::test]
async fn it_creates_a_sealed_repository_on_open() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let name = unique_name("sealed");
    let created = space(&profile, &name)
        .open()
        .sealed(key(3))
        .perform(&operator)
        .await?;
    assert!(created.codec().is_sealed());
    let reloaded = space(&profile, &name).load().perform(&operator).await;
    assert!(matches!(
        reloaded,
        Err(LoadRepositoryError::Seal(RepositorySealError::KeyRequired))
    ));
    Ok(())
}

/// A value too large to stay inside a tree node is refused by a sealed
/// repository instead of being stored unsealed.
#[dialog_common::test]
async fn it_refuses_a_value_that_would_leave_the_sealed_tree() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let repository = space(&profile, &unique_name("sealed"))
        .create()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    let branch = repository.branch("main").open().perform(&operator).await?;
    let large = "x".repeat(dialog_search_tree::Manifest::default().inline_n as usize + 1);
    let result = branch
        .commit(stream::iter(vec![note(0, &large)?]))
        .perform(&operator)
        .await;
    assert!(
        matches!(
            result,
            Err(CommitError::Artifact(DialogArtifactsError::SealedSpill(_)))
        ),
        "{result:?}"
    );
    assert!(branch.revision().is_none());
    Ok(())
}

/// A blob of several chunks whose bytes repeat `marker`.
fn marked_blob(marker: &str) -> Vec<u8> {
    marker.bytes().cycle().take(150_000).collect()
}

fn blob_chunks(
    payload: &[u8],
) -> impl Stream<Item = Result<Vec<u8>, BlobError>> + ConditionalSend + Unpin + use<> {
    let chunks: Vec<Result<Vec<u8>, BlobError>> = payload
        .chunks(10_000)
        .map(|chunk| Ok(chunk.to_vec()))
        .collect();
    stream::iter(chunks)
}

async fn drain(mut reader: BlobReader) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = reader.next().await? {
        bytes.extend(chunk);
    }
    Ok(bytes)
}

/// The bytes the blob store holds for `entity`, read without the codec.
async fn stored_blob<C: dialog_varsig::Principal>(
    operator: &Operator<VolatileSpace>,
    repository: &Repository<C>,
    entity: &Entity,
) -> Result<Vec<u8>> {
    let hash = entity.blob_hash().expect("a blob entity");
    let reader = ArchiveScope::new(repository.subject())
        .blob()
        .read(Blake3Hash::from(hash))
        .perform(operator)
        .await?;
    drain(reader).await
}

/// Writes `payload` as a blob to the `main` branch of `repository`.
async fn write_blob<C: dialog_varsig::Principal>(
    operator: &Operator<VolatileSpace>,
    repository: &Repository<C>,
    payload: &[u8],
) -> Result<(Branch, Entity)> {
    let branch = repository.branch("main").open().perform(operator).await?;
    let entity = Blob::import(blob_chunks(payload))
        .write((&branch).into())
        .perform(operator)
        .await?;
    Ok((branch, entity))
}

/// A sealed repository reads back a blob it wrote, whole and in part, and
/// reports the blob's plaintext size.
#[dialog_common::test]
async fn it_reads_back_a_sealed_blob() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let name = unique_name("sealed");
    let repository = space(&profile, &name)
        .create()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    let payload: Vec<u8> = (0..150_000u32).map(|index| (index % 251) as u8).collect();
    let (_, entity) = write_blob(&operator, &repository, &payload).await?;

    // A fresh load with the key reads what the first handle wrote.
    let reloaded = space(&profile, &name)
        .load()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    let branch = reloaded.branch("main").open().perform(&operator).await?;
    let whole = Blob::from(entity.clone())
        .read((&branch).into())
        .perform(&operator)
        .await?;
    assert_eq!(drain(whole).await?, payload);
    let slice = Blob::from(entity.clone())
        .slice(ByteRange {
            offset: 65_530,
            length: Some(20),
        })
        .read((&branch).into())
        .perform(&operator)
        .await?;
    assert_eq!(drain(slice).await?, payload[65_530..65_550]);
    assert_eq!(
        Blob::from(entity)
            .size((&branch).into())
            .perform(&operator)
            .await?,
        Some(payload.len() as u64)
    );
    Ok(())
}

/// A sealed blob reaches the blob store sealed, under the hash of the
/// sealed bytes, and its plaintext does not appear there. The same blob in
/// a plain repository shows the plaintext, which shows the scan finds it.
#[dialog_common::test]
async fn it_stores_a_sealed_blob_as_ciphertext() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let marker = unique_name("plaintext-marker");
    let payload = marked_blob(&marker);

    let sealed = space(&profile, &unique_name("sealed"))
        .create()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    let (_, entity) = write_blob(&operator, &sealed, &payload).await?;
    let stored = stored_blob(&operator, &sealed, &entity).await?;
    assert!(stored.starts_with(&SEALED_BLOCK_MAGIC));
    assert!(!contains(&stored, &marker));
    assert_eq!(
        Some(*Buffer::from(stored).blake3_hash().as_bytes()),
        entity.blob_hash()
    );

    let plain = space(&profile, &unique_name("plain"))
        .create()
        .perform(&operator)
        .await?;
    let (_, plain_entity) = write_blob(&operator, &plain, &payload).await?;
    let stored = stored_blob(&operator, &plain, &plain_entity).await?;
    assert_eq!(stored, payload);
    assert!(contains(&stored, &marker));
    assert_ne!(plain_entity, entity);
    Ok(())
}

/// The stored bytes of a sealed blob open only with the key they were
/// sealed under. Without a key they are ciphertext, and a repository
/// sealed under another key cannot read the blob.
#[dialog_common::test]
async fn it_reads_a_sealed_blob_only_with_its_key() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let marker = unique_name("plaintext-marker");
    let payload = marked_blob(&marker);
    let repository = space(&profile, &unique_name("sealed"))
        .create()
        .sealed(key(1))
        .perform(&operator)
        .await?;
    let (_, entity) = write_blob(&operator, &repository, &payload).await?;
    let stored = stored_blob(&operator, &repository, &entity).await?;
    assert_ne!(stored, payload);

    let open_with = |codec: BlockCodec| -> Result<Vec<u8>, SealError> {
        let mut opener = codec.blob_opener(0, None).expect("a sealed codec");
        let mut plaintext = opener.open(&stored)?;
        plaintext.extend(opener.finish()?);
        Ok(plaintext)
    };
    assert_eq!(open_with(sealed_codec(1))?, payload);
    assert_eq!(open_with(sealed_codec(2)), Err(SealError::Authentication));

    // A repository sealed under another key that holds the same stored
    // bytes cannot read the blob through them.
    let other = space(&profile, &unique_name("sealed"))
        .create()
        .sealed(key(2))
        .perform(&operator)
        .await?;
    let hash = Blake3Hash::from(entity.blob_hash().expect("a blob entity"));
    let mut sink = ArchiveScope::new(other.subject())
        .blob()
        .import(hash, stored.len() as u64)
        .perform(&operator)
        .await?;
    sink.write_all(&stored).await?;
    sink.finish().await?;
    let branch = other.branch("main").open().perform(&operator).await?;
    let read = match Blob::from(entity)
        .read((&branch).into())
        .perform(&operator)
        .await
    {
        Ok(reader) => drain(reader).await,
        Err(error) => Err(error.into()),
    };
    let error = read.expect_err("another key must not read the blob");
    assert!(error.to_string().contains("authentication"), "{error}");
    Ok(())
}

/// Two repositories sealed under the same key store the same blob at the
/// same address, so replicas deduplicate and converge on it. Another key
/// gives another address.
#[dialog_common::test]
async fn it_addresses_a_sealed_blob_the_same_on_every_replica() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let payload = marked_blob("same bytes on every replica");
    let mut entities = Vec::new();
    for byte in [1, 1, 2] {
        let repository = space(&profile, &unique_name("sealed"))
            .create()
            .sealed(key(byte))
            .perform(&operator)
            .await?;
        entities.push(write_blob(&operator, &repository, &payload).await?.1);
    }
    assert_eq!(entities[0], entities[1]);
    assert_ne!(entities[0], entities[2]);
    Ok(())
}
