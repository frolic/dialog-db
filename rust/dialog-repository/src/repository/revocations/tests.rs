#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

use anyhow::Result;
use dialog_artifacts::{Artifact, Instruction, Value};
use dialog_credentials::Signer;
use dialog_identity::SpaceHandle;
use dialog_operator::Operator;
use dialog_operator::helpers::{test_operator_with_profile, unique_name};
use dialog_storage::provider::storage::VolatileSpace;
use dialog_ucan_core::helpers::generate_signer;
use dialog_ucan_core::revocation::{RevocationChecker, RevocationSelector};
use dialog_ucan_core::subject::Subject;
use dialog_ucan_core::{Delegation, DelegationBuilder};
use dialog_varsig::{AnySignature, Principal};
use futures_util::stream;

use super::{BranchRevocations, REVOCATION_ATTRIBUTE, revocation_entity, revoke};
use crate::{Branch, Repository, RepositoryExt as _};

async fn delegation(issuer: &Signer, audience: &Signer) -> Result<Delegation<AnySignature>> {
    Ok(DelegationBuilder::new()
        .issuer(issuer.clone())
        .audience(&audience.did())
        .subject(Subject::Specific(issuer.did()))
        .command(vec!["archive".to_string()])
        .try_build()
        .await?)
}

async fn access_branch(
    operator: &Operator<VolatileSpace>,
    profile_did: dialog_varsig::Did,
) -> Result<(Repository, Branch)> {
    let repository = SpaceHandle {
        profile_did,
        name: unique_name("revocations"),
    }
    .open()
    .perform(operator)
    .await?;
    let branch = repository.branch("access").open().perform(operator).await?;
    Ok((repository, branch))
}

#[dialog_common::test]
async fn it_finds_a_revocation_signed_by_an_issuer_in_the_chain() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let (repository, branch) = access_branch(&operator, profile.did()).await?;
    let alice = generate_signer().await;
    let bob = generate_signer().await;
    let carol = generate_signer().await;
    let granted = delegation(&alice, &bob).await?;
    let other = delegation(&alice, &carol).await?;

    let revocation = revoke(alice.clone(), &granted).await?;
    branch
        .commit(stream::iter([revocation]))
        .perform(&operator)
        .await?;

    let revocations = BranchRevocations::load(&operator, repository.branch("access")).await?;
    let chain = [alice.did(), bob.did()];
    let found = revocations
        .query(RevocationSelector::new(granted.to_cid(), &chain))
        .await?
        .expect("the stored revocation matches");
    assert_eq!(found.principal, alice.did());

    // A revocation counts only when its signer may revoke the link.
    let others = [carol.did()];
    assert!(
        revocations
            .query(RevocationSelector::new(granted.to_cid(), &others))
            .await?
            .is_none()
    );
    // Another delegation is not revoked.
    assert!(
        revocations
            .query(RevocationSelector::new(other.to_cid(), &chain))
            .await?
            .is_none()
    );
    Ok(())
}

#[dialog_common::test]
async fn it_ignores_a_stored_revocation_that_does_not_verify() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let (repository, branch) = access_branch(&operator, profile.did()).await?;
    let alice = generate_signer().await;
    let bob = generate_signer().await;
    let mallory = generate_signer().await;
    let granted = delegation(&alice, &bob).await?;

    // Mallory can write the branch, but her revocation is not one alice or
    // bob signed, and bytes that are not a revocation prove nothing.
    let forged = revoke(mallory.clone(), &granted).await?;
    let garbage = Instruction::Assert(Artifact {
        the: REVOCATION_ATTRIBUTE.parse()?,
        of: revocation_entity(&granted.to_cid())?,
        is: Value::Bytes(vec![1, 2, 3]),
        cause: None,
    });
    branch
        .commit(stream::iter([forged, garbage]))
        .perform(&operator)
        .await?;

    let revocations = BranchRevocations::load(&operator, repository.branch("access")).await?;
    let chain = [alice.did(), bob.did()];
    assert!(
        revocations
            .query(RevocationSelector::new(granted.to_cid(), &chain))
            .await?
            .is_none()
    );
    Ok(())
}

#[dialog_common::test]
async fn it_holds_no_revocations_on_a_branch_with_no_head() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let (repository, _) = access_branch(&operator, profile.did()).await?;
    let alice = generate_signer().await;
    let bob = generate_signer().await;
    let granted = delegation(&alice, &bob).await?;

    let revocations = BranchRevocations::load(&operator, repository.branch("access")).await?;
    let chain = [alice.did()];
    assert!(
        revocations
            .query(RevocationSelector::new(granted.to_cid(), &chain))
            .await?
            .is_none()
    );
    Ok(())
}

fn stored_bytes(instruction: &Instruction) -> Result<Vec<u8>> {
    match instruction {
        Instruction::Assert(Artifact {
            is: Value::Bytes(bytes),
            ..
        }) => Ok(bytes.clone()),
        _ => anyhow::bail!("a revocation is an assertion of bytes"),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[dialog_common::test]
async fn it_stores_a_revocation_as_the_hash_of_the_delegation() -> Result<()> {
    let alice = generate_signer().await;
    let bob = generate_signer().await;
    let granted = delegation(&alice, &bob).await?;

    let stored = stored_bytes(&revoke(alice.clone(), &granted).await?)?;
    let delegation_bytes = serde_ipld_dagcbor::to_vec(&granted)?;

    // The fact names the delegation by its CID and holds no copy of it.
    assert!(contains(&stored, &granted.to_cid().to_bytes()));
    assert!(!contains(&stored, &delegation_bytes));
    Ok(())
}

#[dialog_common::test]
async fn it_ignores_a_revocation_whose_hash_is_forged() -> Result<()> {
    let (operator, profile) = test_operator_with_profile().await;
    let (repository, branch) = access_branch(&operator, profile.did()).await?;
    let alice = generate_signer().await;
    let bob = generate_signer().await;
    let carol = generate_signer().await;
    let granted = delegation(&alice, &bob).await?;
    let other = delegation(&alice, &carol).await?;

    // Alice revoked another delegation. A writer of the branch copies her
    // revocation under the entity of `granted`, once as it is and once
    // with the CID it names changed to the CID of `granted`.
    let signed = stored_bytes(&revoke(alice.clone(), &other).await?)?;
    let other_cid = other.to_cid().to_bytes();
    let granted_cid = granted.to_cid().to_bytes();
    let position = signed
        .windows(other_cid.len())
        .position(|window| window == other_cid.as_slice())
        .expect("the revocation names the CID it revokes");
    let mut forged = signed.clone();
    forged[position..position + other_cid.len()].copy_from_slice(&granted_cid);
    let under_granted = |bytes: Vec<u8>| -> Result<Instruction> {
        Ok(Instruction::Assert(Artifact {
            the: REVOCATION_ATTRIBUTE.parse()?,
            of: revocation_entity(&granted.to_cid())?,
            is: Value::Bytes(bytes),
            cause: None,
        }))
    };
    branch
        .commit(stream::iter([
            under_granted(signed)?,
            under_granted(forged)?,
        ]))
        .perform(&operator)
        .await?;

    let revocations = BranchRevocations::load(&operator, repository.branch("access")).await?;
    let chain = [alice.did(), bob.did()];
    assert!(
        revocations
            .query(RevocationSelector::new(granted.to_cid(), &chain))
            .await?
            .is_none()
    );
    Ok(())
}
