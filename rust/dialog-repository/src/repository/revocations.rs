//! Revocations kept as facts on a branch.
//!
//! A UCAN revocation needs a store that a verifier can ask, and upstream has
//! none: the only shipped [`RevocationChecker`] looks nothing up. This module
//! keeps each revocation as a fact on a branch of the repository it concerns,
//! so revocations replicate, sync, and move with the repository like any
//! other fact. [`revoke`] signs a revocation and returns the fact that stores
//! it. [`BranchRevocations`] answers a verifier from that branch.
//!
//! The branch is data, and anyone who can write the branch can write a fact
//! on it. So a stored revocation counts only when its signature verifies and
//! its signer may revoke the delegation it names: an issuer at or above that
//! link in the chain being verified, or the link's audience.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use dialog_artifacts::tree::{ArtifactTreeExt as _, SpillCache};
use dialog_artifacts::{
    Artifact, ArtifactSelector, Attribute, DialogArtifactsError, EMPTY_TREE_HASH, Entity,
    Instruction, Value,
};
use dialog_capability::Provider;
use dialog_common::Blake3Hash as NodeHash;
use dialog_common::ConditionalSync;
use dialog_credentials::DidKeyResolver;
use dialog_effects::archive::prelude::ArchiveScope;
use dialog_effects::archive::{Get, Put};
use dialog_effects::memory::Resolve;
use dialog_ucan_core::revocation::{RevocationChecker, RevocationMatch, RevocationSelector};
use dialog_ucan_core::{Delegation, InvocationChain, RevocationBuilder, RevocationChain};
use dialog_varsig::{AnySignature, Did, Principal, Signer};
use futures_util::StreamExt as _;
use ipld_core::cid::Cid;
use thiserror::Error;

use crate::{BranchReference, Index, LocalIndex};

/// The attribute a revocation is stored under. Its value is the revocation
/// container: the signed `/ucan/revoke` invocation and the delegation it
/// names.
pub const REVOCATION_ATTRIBUTE: &str = "ucan/revocation";

/// The entity every revocation of `delegation` is stored under.
pub fn revocation_entity(delegation: &Cid) -> Result<Entity, DialogArtifactsError> {
    format!("revocation:{delegation}").parse()
}

/// Why a revocation could not be made or looked up.
#[derive(Debug, Error)]
pub enum RevocationStoreError {
    /// The revocation could not be signed or encoded.
    #[error("Could not make the revocation: {0}")]
    Revoke(String),

    /// The branch holding revocations could not be read.
    #[error("Could not read revocations: {0}")]
    Read(String),
}

/// Signs a revocation of `delegation` by `revoker`, and returns the fact
/// that stores it on a branch.
pub async fn revoke<I>(
    revoker: I,
    delegation: &Delegation<AnySignature>,
) -> Result<Instruction, RevocationStoreError>
where
    I: Signer<AnySignature> + Principal + 'static,
{
    let failed = |error: &dyn Display| RevocationStoreError::Revoke(error.to_string());
    let revoked = delegation.to_cid();
    let revocation = RevocationBuilder::new(revoker, revoked)
        .try_build()
        .await
        .map_err(|error| failed(&error))?;
    let chain = RevocationChain::assemble(
        revocation,
        HashMap::from([(revoked, Arc::new(delegation.clone()))]),
    )
    .map_err(|error| failed(&error))?;
    let bytes = chain.to_bytes().map_err(|error| failed(&error))?;
    Ok(Instruction::Assert(Artifact {
        the: attribute(),
        of: revocation_entity(&revoked).map_err(|error| failed(&error))?,
        is: Value::Bytes(bytes),
        cause: None,
    }))
}

fn attribute() -> Attribute {
    Attribute::try_from(REVOCATION_ATTRIBUTE.to_string())
        .unwrap_or_else(|_| unreachable!("the revocation attribute is a valid attribute"))
}

/// A [`RevocationChecker`] that reads revocations from one branch.
///
/// Load it once for a verification. It reads the branch head and the
/// revocations under it once, and answers every link's query from them.
/// A branch with no head costs one read of its head.
pub struct BranchRevocations {
    stored: HashMap<String, Vec<Vec<u8>>>,
}

impl BranchRevocations {
    /// Reads the revocations stored on `branch` through `env`. A branch
    /// with no head holds none.
    pub async fn load<Env>(env: &Env, branch: BranchReference) -> Result<Self, RevocationStoreError>
    where
        Env: Provider<Get> + Provider<Put> + Provider<Resolve> + ConditionalSync + 'static,
    {
        let read = |error: &dyn Display| RevocationStoreError::Read(error.to_string());
        let mut stored: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let head = branch.revision();
        head.resolve()
            .perform(env)
            .await
            .map_err(|error| read(&error))?;
        let Some(revision) = head.content() else {
            return Ok(Self { stored });
        };
        let tree = *revision.tree.hash();
        if tree == EMPTY_TREE_HASH {
            return Ok(Self { stored });
        }
        let store = LocalIndex::new(
            env,
            ArchiveScope::new(branch.subject()).index(),
            branch.codec().clone(),
        );
        let selector = ArtifactSelector::new().the(attribute());
        let facts = Index::from_hash(NodeHash::from(tree))
            .scan_owned(store, SpillCache::with_budget(0), selector)
            .collect::<Vec<_>>()
            .await;
        for fact in facts {
            let fact = fact.map_err(|error| read(&error))?;
            if let Value::Bytes(bytes) = fact.is {
                stored.entry(fact.of.to_string()).or_default().push(bytes);
            }
        }
        Ok(Self { stored })
    }

    /// The revocation of `delegation`, when one is stored, signed, and made
    /// by one of `by`.
    async fn find(
        &self,
        delegation: Cid,
        by: &[Did],
    ) -> Result<Option<RevocationMatch>, RevocationStoreError> {
        let entity = revocation_entity(&delegation)
            .map_err(|error| RevocationStoreError::Read(error.to_string()))?;
        for bytes in self.stored.get(&entity.to_string()).into_iter().flatten() {
            if let Some(found) = check(bytes, delegation, by).await {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }
}

/// The match a stored revocation makes, when it names `delegation`, its
/// signer is one of `by`, and its signature verifies.
async fn check(bytes: &[u8], delegation: Cid, by: &[Did]) -> Option<RevocationMatch> {
    let chain = InvocationChain::<AnySignature>::try_from(bytes).ok()?;
    let chain = RevocationChain::try_from(chain).ok()?;
    if chain.revoked().to_cid() != delegation || !by.contains(chain.revoker()) {
        return None;
    }
    let invocation = chain.revocation().invocation();
    invocation.verify_signature(&DidKeyResolver).await.ok()?;
    Some(RevocationMatch {
        revocation: invocation.to_cid(),
        principal: chain.revoker().clone(),
    })
}

impl RevocationChecker for BranchRevocations {
    type Error = RevocationStoreError;

    async fn query(
        &self,
        selector: RevocationSelector<'_>,
    ) -> Result<Option<RevocationMatch>, Self::Error> {
        self.find(selector.delegation, selector.by).await
    }
}

#[cfg(test)]
mod tests;
