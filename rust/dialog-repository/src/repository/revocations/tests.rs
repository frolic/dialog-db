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
