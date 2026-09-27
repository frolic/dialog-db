//! A public read: a plain GET of a sealed block or blob, sent before the
//! invocation that would read it.
//!
//! A sealed block is ciphertext, and its name is the digest of its
//! bytes. So a service can serve it to anyone, and a browser and an
//! edge cache can keep it forever. This read carries no credentials and
//! no custom headers, so a browser sends it with no CORS preflight.
//! The bytes are accepted only when they hash to the digest they were
//! asked for. Any other answer returns nothing, and the caller sends
//! the invocation.

use base58::ToBase58;
use dialog_capability::Did;
use dialog_common::Blake3Hash;
use dialog_remote_s3::http_client;

use crate::address::UcanAddress;

/// The URL a public read of `digest` in `catalog` of `subject` goes to:
/// `{endpoint}/{subject}/{catalog}/{digest}`, with the digest in base58.
/// That is the key the service stores the block under.
pub(crate) fn public_url(
    address: &UcanAddress,
    subject: &Did,
    catalog: &str,
    digest: &Blake3Hash,
) -> Option<reqwest::Url> {
    let mut url = reqwest::Url::parse(address.endpoint()).ok()?;
    let name = digest.as_bytes().to_base58();
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .extend([subject.as_str(), catalog, name.as_str()]);
    url.set_query(None);
    Some(url)
}

/// Read `digest` in `catalog` of `subject` with a plain GET. Returns the
/// bytes when the service answers 200 with bytes that hash to `digest`,
/// and nothing otherwise.
pub(crate) async fn read_public(
    address: &UcanAddress,
    subject: &Did,
    catalog: &str,
    digest: &Blake3Hash,
) -> Option<Vec<u8>> {
    let url = public_url(address, subject, catalog, digest)?;
    let response = http_client().get(url).send().await.ok()?;
    if response.status().as_u16() != 200 {
        return None;
    }
    let bytes = response.bytes().await.ok()?.to_vec();
    if Blake3Hash::hash(&bytes) != *digest {
        tracing::warn!(
            target: "dialog::remote::ucan",
            block = %digest.as_bytes().to_base58(),
            "a public read answered bytes that do not hash to the digest; reading with an invocation"
        );
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use super::*;

    /// The path is the key the service stores the block under:
    /// `{subject}/{catalog}/{base58 digest}`, below the endpoint's root.
    #[dialog_common::test]
    fn it_names_the_block_by_subject_catalog_and_base58_digest() {
        let subject: Did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let digest = Blake3Hash::hash(b"a block");
        let name = digest.as_bytes().to_base58();
        for endpoint in ["https://access.example", "https://access.example/?cmd=x"] {
            let url = public_url(&UcanAddress::new(endpoint), &subject, "index", &digest).unwrap();
            assert_eq!(
                url.as_str(),
                format!("https://access.example/{subject}/index/{name}")
            );
        }
        let url = public_url(
            &UcanAddress::new("https://access.example/ucan/"),
            &subject,
            "blob",
            &digest,
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            format!("https://access.example/ucan/{subject}/blob/{name}")
        );
    }
}
