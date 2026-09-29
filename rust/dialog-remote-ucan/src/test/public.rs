//! Public reads against the service, on native and on wasm: a sealed
//! address reads a block or a whole blob with a plain GET and sends no
//! invocation; a GET that does not return the right bytes falls back to
//! the invocation; a plain address sends no GET.

use super::{blob, drain, issued, owner};
use crate::helpers::{REQUESTS_PATH, RequestCounts, UcanServiceAddress};
use crate::{UcanAddress, UcanSite};
use dialog_capability::{Ability, Capability, Effect, ForkInvocation, Provider, Subject};
use dialog_common::{Blake3Hash, Buffer};
use dialog_credentials::Ed25519Signer;
use dialog_effects::MethodExt as _;
use dialog_effects::archive::prelude::*;
use dialog_effects::blob::prelude::*;

/// Perform `capability` at `address`, signed by `signer`.
async fn perform_at<Fx>(
    address: &UcanAddress,
    signer: &Ed25519Signer,
    capability: Capability<Fx>,
) -> Fx::Output
where
    Fx: Effect + Clone,
    Capability<Fx>: Ability,
    UcanSite: Provider<ForkInvocation<UcanSite, Fx>>,
{
    let authorization = issued(signer, &capability).await;
    UcanSite::default()
        .execute(ForkInvocation::new(
            capability,
            address.clone(),
            authorization,
        ))
        .await
}

/// How many public reads and invocations the service has received.
async fn counts(service: &UcanServiceAddress) -> anyhow::Result<RequestCounts> {
    let url = format!("{}{REQUESTS_PATH}", service.endpoint);
    let bytes = reqwest::get(url).await?.bytes().await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Store a block in the `index` catalog of `subject` and return its
/// bytes and digest.
async fn stored_block(
    address: &UcanAddress,
    signer: &Ed25519Signer,
    subject: &Subject,
) -> anyhow::Result<(Vec<u8>, Blake3Hash)> {
    let content = b"a sealed block, served to anyone who names it".to_vec();
    let digest = Blake3Hash::hash(&content);
    perform_at(
        address,
        signer,
        subject
            .clone()
            .writer()
            .archive()
            .catalog("index")
            .put(Buffer::from(content.clone())),
    )
    .await?;
    Ok((content, digest))
}

/// Store a blob of `subject` and return its bytes and digest.
async fn stored_blob(
    address: &UcanAddress,
    signer: &Ed25519Signer,
    subject: &Subject,
) -> anyhow::Result<(Vec<u8>, Blake3Hash)> {
    let content = blob();
    let digest = Blake3Hash::hash(&content);
    let mut sink = perform_at(
        address,
        signer,
        subject
            .clone()
            .writer()
            .archive()
            .blob()
            .import(digest.clone(), content.len() as u64),
    )
    .await?;
    sink.write_all(&content).await?;
    sink.finish().await?;
    Ok((content, digest))
}

#[dialog_common::test]
async fn it_reads_a_sealed_block_with_a_get_and_no_invocation(
    service: UcanServiceAddress,
) -> anyhow::Result<()> {
    let (signer, subject) = owner().await;
    let address = UcanAddress::new(&service.endpoint).sealed();
    let (content, digest) = stored_block(&address, &signer, &subject).await?;
    let before = counts(&service).await?;

    let served = perform_at(
        &address,
        &signer,
        subject.reader().archive().catalog("index").get(digest),
    )
    .await?;

    let after = counts(&service).await?;
    assert_eq!(served, Some(content));
    assert_eq!(after.gets - before.gets, 1, "one GET read the block");
    assert_eq!(
        after.invocations, before.invocations,
        "the read sent no invocation"
    );
    Ok(())
}

#[dialog_common::test]
async fn it_reads_a_sealed_blob_with_a_get_and_no_invocation(
    service: UcanServiceAddress,
) -> anyhow::Result<()> {
    let (signer, subject) = owner().await;
    let address = UcanAddress::new(&service.endpoint).sealed();
    let (content, digest) = stored_blob(&address, &signer, &subject).await?;
    let before = counts(&service).await?;

    let reader = perform_at(
        &address,
        &signer,
        subject.reader().archive().blob().read(digest),
    )
    .await?;
    let (served, _) = drain(reader).await?;

    let after = counts(&service).await?;
    assert_eq!(served, content);
    assert_eq!(after.gets - before.gets, 1, "one GET read the blob");
    assert_eq!(
        after.invocations, before.invocations,
        "the read sent no invocation"
    );
    Ok(())
}

#[dialog_common::test]
async fn it_reads_a_range_of_a_sealed_blob_with_an_invocation(
    service: UcanServiceAddress,
) -> anyhow::Result<()> {
    let (signer, subject) = owner().await;
    let address = UcanAddress::new(&service.endpoint).sealed();
    let (content, digest) = stored_blob(&address, &signer, &subject).await?;
    let before = counts(&service).await?;

    let reader = perform_at(
        &address,
        &signer,
        subject
            .reader()
            .archive()
            .blob()
            .invoke(dialog_effects::blob::Read::range(digest, 100, Some(50))),
    )
    .await?;
    let (served, _) = drain(reader).await?;

    let after = counts(&service).await?;
    assert_eq!(served, content[100..150]);
    assert_eq!(after.gets, before.gets, "a range is not read with a GET");
    assert_eq!(after.invocations - before.invocations, 1);
    Ok(())
}

#[dialog_common::test(public_reads = crate::helpers::PublicReads::Missing)]
async fn it_falls_back_to_the_invocation_when_the_get_is_not_found(
    service: UcanServiceAddress,
) -> anyhow::Result<()> {
    let (signer, subject) = owner().await;
    let address = UcanAddress::new(&service.endpoint).sealed();
    let (content, digest) = stored_block(&address, &signer, &subject).await?;
    let before = counts(&service).await?;

    let served = perform_at(
        &address,
        &signer,
        subject.reader().archive().catalog("index").get(digest),
    )
    .await?;

    let after = counts(&service).await?;
    assert_eq!(served, Some(content));
    assert_eq!(after.gets - before.gets, 1, "the GET was tried first");
    assert_eq!(
        after.invocations - before.invocations,
        1,
        "the invocation read the block"
    );
    Ok(())
}

#[dialog_common::test(public_reads = crate::helpers::PublicReads::Tampered)]
async fn it_refuses_bytes_from_a_get_that_do_not_hash_to_the_digest(
    service: UcanServiceAddress,
) -> anyhow::Result<()> {
    let (signer, subject) = owner().await;
    let address = UcanAddress::new(&service.endpoint).sealed();
    let (content, digest) = stored_block(&address, &signer, &subject).await?;
    let (blob_content, blob_digest) = stored_blob(&address, &signer, &subject).await?;
    let before = counts(&service).await?;

    let served = perform_at(
        &address,
        &signer,
        subject
            .clone()
            .reader()
            .archive()
            .catalog("index")
            .get(digest),
    )
    .await?;
    let reader = perform_at(
        &address,
        &signer,
        subject.reader().archive().blob().read(blob_digest),
    )
    .await?;
    let (blob_served, _) = drain(reader).await?;

    let after = counts(&service).await?;
    assert_eq!(served, Some(content), "the invocation's bytes are returned");
    assert_eq!(blob_served, blob_content);
    assert_eq!(after.gets - before.gets, 2);
    assert_eq!(after.invocations - before.invocations, 2);
    Ok(())
}

#[dialog_common::test]
async fn it_sends_no_get_for_a_plain_repository(service: UcanServiceAddress) -> anyhow::Result<()> {
    let (signer, subject) = owner().await;
    let address = UcanAddress::new(&service.endpoint);
    let (content, digest) = stored_block(&address, &signer, &subject).await?;
    let (blob_content, blob_digest) = stored_blob(&address, &signer, &subject).await?;
    let before = counts(&service).await?;

    let served = perform_at(
        &address,
        &signer,
        subject
            .clone()
            .reader()
            .archive()
            .catalog("index")
            .get(digest),
    )
    .await?;
    let reader = perform_at(
        &address,
        &signer,
        subject.reader().archive().blob().read(blob_digest),
    )
    .await?;
    let (blob_served, _) = drain(reader).await?;

    let after = counts(&service).await?;
    assert_eq!(served, Some(content));
    assert_eq!(blob_served, blob_content);
    assert_eq!(after.gets, before.gets, "a plain address sends no GET");
    assert_eq!(after.invocations - before.invocations, 2);
    Ok(())
}
