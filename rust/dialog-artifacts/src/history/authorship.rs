use std::collections::BTreeSet;

use dialog_search_tree::Manifest;

use crate::{Artifact, Key, history_key};

use super::Version;

/// Who wrote one revision's claims, as a reader can prove it.
///
/// A reader gets one from
/// [`TreeHistory::authorship`](super::TreeHistory::authorship) only when
/// three checks pass. The revision record verifies under its issuer. The
/// record's authority endorsed that issuer. The history records under the
/// revision's version hash to the claims digest the record signs. So a
/// writer cannot file a fact under another profile's revision: the fact
/// either has no history record there, or its record changes the digest.
#[derive(Debug, Clone)]
pub struct Authorship {
    author: String,
    version: Version,
    manifest: Manifest,
    asserted: BTreeSet<Key>,
}

impl Authorship {
    /// The authorship of the revision `version`, by `author`, which asserted
    /// the history records at `asserted` (keys built under `manifest`).
    pub fn new(
        author: String,
        version: Version,
        manifest: Manifest,
        asserted: BTreeSet<Key>,
    ) -> Self {
        Self {
            author,
            version,
            manifest,
            asserted,
        }
    }

    /// The DID of the profile that wrote the revision.
    pub fn author(&self) -> &str {
        &self.author
    }

    /// The version of the revision.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Whether the revision asserted `artifact`.
    pub fn asserted(&self, artifact: &Artifact) -> bool {
        let key = history_key(
            &self.version,
            &artifact.of,
            &artifact.the,
            &artifact.is,
            &self.manifest,
        );
        self.asserted.contains(&key)
    }
}

#[cfg(test)]
mod tests;
