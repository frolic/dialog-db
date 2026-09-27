//! Sealed repositories syncing through an FS remote.
//!
//! Two repositories share one seal key and one vault directory. What they
//! push and pull is the sealed blocks as stored, so both sides converge on
//! the same tree, and nothing they write to the vault shows a fact value.
//! A replica with another key cannot read what was pushed.

use anyhow::Result;
use dialog_artifacts::{Artifact, ArtifactSelector, Instruction, Value};
use dialog_credentials::{Credential, SignerCredential};
use dialog_effects::credential::prelude::*;
use dialog_effects::storage::Location;
use dialog_operator::helpers::{test_operator_with_profile, unique_name};
use dialog_operator::{Operator, Profile};
use dialog_remote_fs::FsAddress;
use dialog_repository::{Branch, Repository, RepositoryExt as _, SealKey, SiteAddress};
use dialog_storage::provider::FileSystem;
use dialog_storage::provider::storage::VolatileSpace;
use dialog_storage::resource::Resource;
use futures_util::{StreamExt, stream};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Seed a fresh directory as the space for `repository` by writing its
/// credential to `credential/key/self`.
async fn seed_vault(repository: &Repository<SignerCredential>) -> Result<(Location, FsAddress)> {
    let location = Location::temp(unique_name("fs-sealed-vault"));
    let filesystem = FileSystem::open(&location).await?;
    let credential = Credential::Signer(repository.credential().clone());
    repository
        .did()
        .credential()
        .key("self")
        .save(credential)
        .perform(&filesystem)
        .await?;
    Ok((location.clone(), FsAddress::new(location)))
}

/// Create a repository sealed under `key`, seed an FS vault as its space,
/// and add the vault as `origin` with an upstream-tracking `main`.
async fn sealed_repo_with_fs_remote(
    operator: &Operator<VolatileSpace>,
    profile: &Profile,
    name: &str,
    key: SealKey,
) -> Result<(Repository<SignerCredential>, Location, Branch)> {
    let repository = profile
        .repository(unique_name(name))
        .create()
        .sealed(key)
        .perform(operator)
        .await?;
    let chain = repository
        .access()
        .claim(&repository)
        .delegate(profile.did())
        .perform(operator)
        .await?;
    profile.access().save(chain).perform(operator).await?;

    let (location, address) = seed_vault(&repository).await?;
    let origin = repository
        .remote("origin")
        .create(SiteAddress::Fs(address))
        .perform(operator)
        .await?;
    let branch = repository.branch("main").open().perform(operator).await?;
    let remote = origin.branch("main").open().perform(operator).await?;
    branch.set_upstream(remote).perform(operator).await?;
    Ok((repository, location, branch))
}

/// Every file in the vault is free of `marker`, and the vault holds sealed
/// blocks, so the check has something to look at.
#[cfg(not(target_arch = "wasm32"))]
async fn assert_vault_is_sealed(location: &Location, marker: &str) -> Result<()> {
    use dialog_crypto::SEALED_BLOCK_MAGIC;
    use std::path::PathBuf;

    let filesystem = FileSystem::open(location).await?;
    let root: PathBuf = filesystem.handle().clone().try_into()?;
    let mut pending = vec![root];
    let mut sealed = 0;
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
            continue;
        }
        let bytes = std::fs::read(&path)?;
        assert!(
            !bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "{} holds plaintext",
            path.display()
        );
        if bytes.starts_with(&SEALED_BLOCK_MAGIC) {
            sealed += 1;
        }
    }
    assert!(sealed > 0, "the vault holds sealed blocks");
    Ok(())
}

fn key(byte: u8) -> SealKey {
    SealKey::from([byte; 32])
}

fn note(of: &str, body: &str) -> Result<Instruction> {
    Ok(Instruction::Assert(Artifact {
        the: "note/body".parse()?,
        of: of.parse()?,
        is: Value::String(body.into()),
        cause: None,
    }))
}

async fn read_notes(branch: &Branch, operator: &Operator<VolatileSpace>) -> Result<Vec<Value>> {
    let notes = branch
        .claims()
        .select(ArtifactSelector::new().the("note/body".parse()?))
        .to_owned()
        .perform(operator)
        .await?
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|artifact| artifact.map(|artifact| artifact.is))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(notes)
}

/// A second repository, opened with `key`, whose `main` tracks the `main`
/// branch of `upstream` in the vault at `location`.
async fn replica(
    operator: &Operator<VolatileSpace>,
    profile: &Profile,
    upstream: &Repository<SignerCredential>,
    location: Location,
    key: Option<SealKey>,
) -> Result<Branch> {
    let handle = profile.repository(unique_name("fs-sealed-replica"));
    let repository = match key {
        Some(key) => handle.open().sealed(key).perform(operator).await?,
        None => handle.open().perform(operator).await?,
    };
    let chain = upstream
        .access()
        .claim(upstream)
        .delegate(profile.did())
        .perform(operator)
        .await?;
    profile.access().save(chain).perform(operator).await?;
    let origin = repository
        .remote("origin")
        .create(SiteAddress::Fs(FsAddress::new(location)))
        .subject(upstream.did())
        .perform(operator)
        .await?;
    let branch = repository.branch("main").open().perform(operator).await?;
    let remote = origin.branch("main").open().perform(operator).await?;
    branch.set_upstream(remote).perform(operator).await?;
    Ok(branch)
}

#[dialog_common::test]
async fn it_syncs_sealed_repositories_through_an_fs_remote() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let marker = unique_name("plaintext-marker");
    let (alice, location, alice_branch) =
        sealed_repo_with_fs_remote(&operator, &profile, "fs-sealed", key(7)).await?;

    let notes = (0..100)
        .map(|index| note(&format!("note:{index}"), &format!("{index} {marker}")))
        .collect::<Result<Vec<_>>>()?;
    alice_branch
        .commit(stream::iter(notes))
        .perform(&operator)
        .await?;
    alice_branch.push().perform(&operator).await?;

    // Bob pulls Alice's sealed tree and reads it with the shared key. The
    // blocks are adopted as they are, so his head names the same tree.
    let bob_branch = replica(&operator, &profile, &alice, location.clone(), Some(key(7))).await?;
    assert!(bob_branch.pull().perform(&operator).await?.is_some());
    assert_eq!(read_notes(&bob_branch, &operator).await?.len(), 100);
    assert_eq!(
        bob_branch.revision().map(|revision| revision.tree),
        alice_branch.revision().map(|revision| revision.tree)
    );

    // Bob's edit travels back the same way.
    bob_branch
        .commit(stream::iter(vec![note("note:bob", "from bob")?]))
        .perform(&operator)
        .await?;
    bob_branch.push().perform(&operator).await?;
    assert!(alice_branch.pull().perform(&operator).await?.is_some());
    let notes = read_notes(&alice_branch, &operator).await?;
    assert_eq!(notes.len(), 101);
    assert!(notes.contains(&Value::String("from bob".into())));
    assert_eq!(
        alice_branch.revision().map(|revision| revision.tree),
        bob_branch.revision().map(|revision| revision.tree)
    );

    #[cfg(not(target_arch = "wasm32"))]
    assert_vault_is_sealed(&location, &marker).await?;
    Ok(())
}

#[dialog_common::test]
async fn it_cannot_pull_a_sealed_remote_with_another_key_or_none() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let (alice, location, alice_branch) =
        sealed_repo_with_fs_remote(&operator, &profile, "fs-sealed-key", key(7)).await?;
    alice_branch
        .commit(stream::iter(vec![note("note:1", "secret")?]))
        .perform(&operator)
        .await?;
    alice_branch.push().perform(&operator).await?;

    // A pull may adopt the upstream head by reference without reading its
    // tree; reading it is what needs the key.
    let other_key = replica(&operator, &profile, &alice, location.clone(), Some(key(8))).await?;
    let pulled = other_key.pull().perform(&operator).await;
    let read = read_notes(&other_key, &operator).await;
    assert!(
        pulled.is_err() || read.is_err(),
        "another key must not read: {read:?}"
    );

    let no_key = replica(&operator, &profile, &alice, location, None).await?;
    let pulled = no_key.pull().perform(&operator).await;
    let read = read_notes(&no_key, &operator).await;
    assert!(
        pulled.is_err() || read.is_err(),
        "a plain replica must not read: {read:?}"
    );
    Ok(())
}
