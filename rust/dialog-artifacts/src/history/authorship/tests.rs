#![allow(clippy::unwrap_used)]

use anyhow::Result;
use base58::ToBase58 as _;
use dialog_search_tree::{ContentAddressedStorage, Delta};
use dialog_storage::{
    Blake3Hash, CborEncoder, DialogStorageError, MemoryStorageBackend, Storage, StorageBackend,
};
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::stream;

use crate::history::{
    History as _, REVISION_RECORD_FORMAT, RevisionRecord, TreeHistory, Version, endorsement_payload,
};
use crate::key::artifact_index_keys;
use crate::tree::{ArtifactTree, ArtifactTreeExt as _, TreeStorageBridge};
use crate::{Artifact, Datum, Entity, Instruction, State, Value};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

type Store = Storage<CborEncoder, MemoryStorageBackend<Blake3Hash, Vec<u8>>>;

fn store() -> Store {
    Storage {
        encoder: CborEncoder,
        backend: MemoryStorageBackend::default(),
    }
}

fn did(key: &SigningKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(key.verifying_key().as_bytes());
    format!("did:key:z{}", bytes.to_base58())
}

/// A profile and the operator key it acts through.
struct Writer {
    profile: SigningKey,
    operator: SigningKey,
}

impl Writer {
    fn new(seed: u8) -> Self {
        Self {
            profile: SigningKey::from_bytes(&[seed; 32]),
            operator: SigningKey::from_bytes(&[seed.wrapping_add(100); 32]),
        }
    }

    /// The profile's endorsement of the operator.
    fn endorsement(&self) -> Vec<u8> {
        self.profile
            .sign(&endorsement_payload(&did(&self.operator)))
            .to_bytes()
            .to_vec()
    }

    /// An unsigned record for a first revision on `branch`, which claims
    /// `authority` and carries `endorsement`.
    fn record(&self, branch: &Entity, authority: String, endorsement: Vec<u8>) -> RevisionRecord {
        RevisionRecord {
            format: REVISION_RECORD_FORMAT,
            branch: branch.clone(),
            issuer: did(&self.operator),
            authority,
            parents: Vec::new(),
            skips: Vec::new(),
            claims: Vec::new(),
            endorsement,
            signature: Vec::new(),
        }
    }
}

async fn flush(
    store: &mut Store,
    delta: &mut Delta<dialog_common::Blake3Hash, dialog_common::Buffer>,
) -> Result<(), DialogStorageError> {
    for (digest, buffer) in delta.flush() {
        store.set(*digest.as_bytes(), buffer.into_vec()).await?;
    }
    Ok(())
}

/// Commits `facts` the way a branch commit does: history records under the
/// record's version, then the record signed over their digest.
async fn commit(
    tree: &mut ArtifactTree,
    store: &mut Store,
    operator: &SigningKey,
    mut record: RevisionRecord,
    facts: Vec<Artifact>,
) -> Result<Version> {
    let version = record.version();
    let mut delta = Delta::zero();
    tree.apply_versioned(
        store,
        &mut delta,
        Some(version),
        stream::iter(facts.into_iter().map(Instruction::Assert)),
    )
    .await?;
    flush(store, &mut delta).await?;
    let history = TreeHistory::new(tree.clone(), store.clone());
    record.claims = history.claims_digest(&version).await?.to_vec();
    record.signature = operator.sign(&record.payload()?).to_bytes().to_vec();
    let manifest = tree
        .manifest(&ContentAddressedStorage::new(TreeStorageBridge(
            store.clone(),
        )))
        .await?;
    tree.record(store, &mut delta, record.entries(&manifest)?)
        .await?;
    flush(store, &mut delta).await?;
    Ok(version)
}

fn post(entity: &str, caption: &str) -> Result<Artifact> {
    Ok(Artifact {
        the: "post/caption".parse()?,
        of: entity.parse()?,
        is: Value::String(caption.into()),
        cause: None,
    })
}

/// A revision's claims digest verifies, and names the profile that wrote
/// each fact it asserted.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn it_names_the_profile_that_wrote_a_fact() -> Result<()> {
    let mut store = store();
    let mut tree = ArtifactTree::empty();
    let alice = Writer::new(1);
    let branch = Entity::new()?;
    let hello = post("post:1", "hello")?;
    let record = alice.record(&branch, did(&alice.profile), alice.endorsement());
    let version = commit(
        &mut tree,
        &mut store,
        &alice.operator,
        record,
        vec![hello.clone()],
    )
    .await?;

    let history = TreeHistory::new(tree.clone(), store.clone());
    let authorship = history.authorship(&version).await?.unwrap();
    assert_eq!(authorship.author(), did(&alice.profile));
    assert!(authorship.asserted(&hello));
    assert!(!authorship.asserted(&post("post:2", "never written")?));
    Ok(())
}

/// A fact another writer files under a revision, with its history record,
/// changes that revision's claims digest, so no fact of the revision is
/// attributed any more. A fact filed without a history record is not one
/// the revision asserted.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn it_refuses_a_fact_filed_under_another_profiles_revision() -> Result<()> {
    let mut store = store();
    let mut tree = ArtifactTree::empty();
    let alice = Writer::new(1);
    let branch = Entity::new()?;
    let record = alice.record(&branch, did(&alice.profile), alice.endorsement());
    let version = commit(
        &mut tree,
        &mut store,
        &alice.operator,
        record,
        vec![post("post:1", "hello")?],
    )
    .await?;

    // A fact filed as an index entry that names the revision, with no
    // history record, is not an assertion of that revision.
    let forged = post("post:2", "claims to be alice")?;
    let mut filed = tree.clone();
    let manifest = filed
        .manifest(&ContentAddressedStorage::new(TreeStorageBridge(
            store.clone(),
        )))
        .await?;
    let (entity_key, attribute_key, value_key) = artifact_index_keys(&forged, &manifest);
    let mut datum = Datum::for_artifact(&forged);
    datum.version = Some(version);
    let mut delta = Delta::zero();
    filed
        .record(
            &mut store,
            &mut delta,
            vec![
                (entity_key, State::Added(datum.clone())),
                (attribute_key, State::Added(datum.clone())),
                (value_key, State::Added(datum)),
            ],
        )
        .await?;
    flush(&mut store, &mut delta).await?;
    let history = TreeHistory::new(filed, store.clone());
    let authorship = history.authorship(&version).await?.unwrap();
    assert!(!authorship.asserted(&forged));

    // A fact written with a history record under the revision changes its
    // digest, so the revision attributes nothing.
    let mut rewritten = tree.clone();
    let mut delta = Delta::zero();
    rewritten
        .apply_versioned(
            &mut store,
            &mut delta,
            Some(version),
            stream::iter([Instruction::Assert(forged)]),
        )
        .await?;
    flush(&mut store, &mut delta).await?;
    let history = TreeHistory::new(rewritten, store.clone());
    assert!(history.authorship(&version).await?.is_none());
    Ok(())
}

/// A revision that names a profile which did not endorse its issuer is
/// not attributed, and a record whose digest was changed after signing
/// does not verify.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn it_refuses_a_revision_that_claims_another_profile() -> Result<()> {
    let mut store = store();
    let mut tree = ArtifactTree::empty();
    let alice = Writer::new(1);
    let bob = Writer::new(2);
    let branch = Entity::new()?;

    // Bob signs a revision that names Alice, with his own endorsement.
    let record = bob.record(&branch, did(&alice.profile), bob.endorsement());
    let version = commit(
        &mut tree,
        &mut store,
        &bob.operator,
        record,
        vec![post("post:1", "from alice, says bob")?],
    )
    .await?;
    let history = TreeHistory::new(tree.clone(), store.clone());
    assert!(history.revision_record(&version).await?.is_some());
    assert!(history.authorship(&version).await?.is_none());

    // A record whose digest changed after signing does not verify.
    let mut record = bob.record(&branch, did(&bob.profile), bob.endorsement());
    record.claims = vec![0; 32];
    record.signature = bob.operator.sign(&record.payload()?).to_bytes().to_vec();
    let mut tampered = record.clone();
    tampered.claims = vec![1; 32];
    assert!(tampered.verify(&record.version()).is_err());
    Ok(())
}
