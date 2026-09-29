#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

use crate::Datum;
use crate::history::{Edition, Origin, Version};

fn version(origin: u8, edition: u64) -> Version {
    Version::new(Origin([origin; 32]), Edition::new(edition))
}

fn claim(version: Version, meta: &[u8]) -> Datum {
    Datum {
        cause: None,
        blob: None,
        version: Some(version),
        collapsed: Vec::new(),
        supersedes: Vec::new(),
        retraction: false,
        meta: Some(meta.to_vec()),
        collapsed_meta: Vec::new(),
    }
}

/// Two writers' claims of one fact keep their own metadata, and the
/// folded entry has the same bytes whichever claim arrives first.
#[dialog_common::test]
fn it_keeps_each_claims_metadata_in_either_order() {
    let alice = claim(version(1, 3), b"alice");
    let bob = claim(version(2, 5), b"bob");

    let mut first = alice.clone();
    first.absorb(&bob);
    let mut second = bob.clone();
    second.absorb(&alice);

    assert_eq!(first, second);
    assert_eq!(first.version, Some(version(1, 3)));
    assert_eq!(first.meta.as_deref(), Some(b"alice".as_slice()));
    assert_eq!(first.collapsed, vec![version(2, 5)]);
    assert_eq!(first.collapsed_meta, vec![Some(b"bob".to_vec())]);
}

/// Retiring the primary claim leaves the other claim with its own
/// metadata, as if it had arrived alone.
#[dialog_common::test]
fn it_keeps_a_surviving_claims_metadata() {
    let mut both = claim(version(1, 3), b"alice");
    both.absorb(&claim(version(2, 5), b"bob"));

    let survivor = both.retire_covered(&[version(1, 3)]).expect("bob stands");

    assert_eq!(survivor, claim(version(2, 5), b"bob"));
    assert_eq!(both.retire_covered(&[version(1, 3), version(2, 5)]), None);
}

/// A claim known only by its version carries no metadata.
#[dialog_common::test]
fn it_folds_a_bare_version_without_metadata() {
    let mut entry = claim(version(2, 5), b"bob");
    entry.absorb_versions([&version(1, 3)]);

    assert_eq!(entry.version, Some(version(1, 3)));
    assert_eq!(entry.meta, None);
    assert_eq!(entry.collapsed_meta, vec![Some(b"bob".to_vec())]);
}
