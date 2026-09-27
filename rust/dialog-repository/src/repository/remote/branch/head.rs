//! A branch head as a remote stores it.
//!
//! A remote serves a sealed branch's tree blocks as ciphertext, so the head
//! that names them is sealed too. The head of a sealed branch keeps two
//! fields in the clear: the tree root and the nodes the head names below it.
//! Both are names of sealed blocks that anyone may read, and a reader that
//! holds no key yet fetches them while it reads the key. The issuer, the
//! branch, the edition, the causal context, and the signature are sealed
//! under the branch's key. A plain branch's head is stored as it is.
//!
//! A sealed branch reads a plain head too: a remote keeps the last head a
//! build that stored heads plain wrote, until the next push replaces it. The
//! head's signature is checked either way, and a remote can already serve any
//! older head, so a plain head gives a remote no new power.

use std::fmt::Debug;
use std::mem::take;

use async_trait::async_trait;
use dialog_common::{Buffer, ConditionalSync};
use dialog_storage::{BlockCodec, CborEncoder, DialogStorageError, Encoder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Revision, TreeReference};

/// Encodes a branch head for a remote: as it is for a plain branch, and
/// sealed with the branch's codec for a sealed one, apart from the blocks
/// a first read fetches ([`HeadBlocks`]).
///
/// A sealed head is sealed with the same codec as the branch's tree
/// blocks, whose nonce derives from the sealed bytes. Each head carries its
/// own signature, so two heads never seal to the same bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeadCodec(BlockCodec);

impl HeadCodec {
    /// Encodes heads with `codec`, the codec of the branch's tree blocks.
    pub fn new(codec: BlockCodec) -> Self {
        Self(codec)
    }
}

/// The blocks a head names for a first read: its tree root and the nodes
/// below the root it names ([`Revision::prefetch`]). A reader reads them from
/// a sealed head without the key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct HeadBlocks {
    /// The root of the head's tree.
    pub tree: TreeReference,
    /// The nodes below the root that a first read fetches with it.
    #[serde(default)]
    pub prefetch: Vec<[u8; 32]>,
}

impl HeadBlocks {
    /// The blocks a stored head names, from its bytes, whether the head is
    /// sealed or plain.
    pub async fn read(bytes: &[u8]) -> Result<Self, DialogStorageError> {
        CborEncoder.decode(bytes).await
    }
}

impl From<&Revision> for HeadBlocks {
    fn from(revision: &Revision) -> Self {
        Self {
            tree: revision.tree.clone(),
            prefetch: revision.prefetch.clone(),
        }
    }
}

/// A sealed head as a remote stores it.
#[derive(Debug, Serialize, Deserialize)]
struct SealedHead {
    tree: TreeReference,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    prefetch: Vec<[u8; 32]>,
    /// The head without its prefetch names, sealed with the branch's codec.
    #[serde(with = "serde_bytes")]
    sealed: Vec<u8>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Encoder for HeadCodec {
    type Bytes = Vec<u8>;
    type Hash = [u8; 32];
    type Error = DialogStorageError;

    async fn encode<T>(&self, head: &T) -> Result<(Self::Hash, Self::Bytes), Self::Error>
    where
        T: Serialize + ConditionalSync + Debug,
    {
        if !self.0.is_sealed() {
            return CborEncoder.encode(head).await;
        }
        let (_, plain) = CborEncoder.encode(head).await?;
        let mut revision: Revision = CborEncoder.decode(&plain).await.map_err(|error| {
            DialogStorageError::EncodeFailed(format!("a sealed head is a revision: {error}"))
        })?;
        let prefetch = take(&mut revision.prefetch);
        let (_, inner) = CborEncoder.encode(&revision).await?;
        let sealed = self
            .0
            .encode(Buffer::from(inner))
            .map_err(|error| DialogStorageError::EncodeFailed(error.to_string()))?;
        CborEncoder
            .encode(&SealedHead {
                tree: revision.tree,
                prefetch,
                sealed: sealed.as_ref().to_vec(),
            })
            .await
    }

    async fn decode<T>(&self, bytes: &[u8]) -> Result<T, Self::Error>
    where
        T: DeserializeOwned + ConditionalSync,
    {
        if !self.0.is_sealed() {
            return CborEncoder.decode(bytes).await;
        }
        let Ok(head) = CborEncoder.decode::<SealedHead>(bytes).await else {
            return CborEncoder.decode(bytes).await;
        };
        let inner = self
            .0
            .decode(Buffer::from(head.sealed))
            .map_err(|error| DialogStorageError::DecodeFailed(error.to_string()))?;
        let mut revision: Revision = CborEncoder.decode(inner.as_ref()).await?;
        if revision.tree != head.tree {
            return Err(DialogStorageError::DecodeFailed(
                "a sealed head names another tree than the one it seals".to_string(),
            ));
        }
        revision.prefetch = head.prefetch;
        let (_, plain) = CborEncoder.encode(&revision).await?;
        CborEncoder.decode(&plain).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(unexpected_cfgs)]

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use std::collections::BTreeMap;

    use anyhow::Result;
    use dialog_capability::Did;
    use dialog_crypto::{KeyRing, SealKey};
    use dialog_storage::{BlockCodec, CborEncoder, Encoder};
    use serde::de::IgnoredAny;

    use super::{HeadBlocks, HeadCodec};
    use crate::{Revision, TreeReference};

    fn head() -> Result<Revision> {
        let issuer: Did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".parse()?;
        let branch: dialog_artifacts::Entity = "branch:main".parse()?;
        let mut revision = Revision::new(TreeReference::from([7; 32]), branch, issuer);
        revision.signature = vec![9; 64];
        revision.prefetch = vec![[1; 32], [2; 32]];
        Ok(revision)
    }

    fn sealed() -> HeadCodec {
        HeadCodec::new(BlockCodec::sealed(KeyRing::new(SealKey::from([3; 32]))))
    }

    #[dialog_common::test]
    async fn it_stores_a_plain_head_as_it_is() -> Result<()> {
        let revision = head()?;
        let (_, stored) = HeadCodec::default().encode(&revision).await?;
        let (_, plain) = CborEncoder.encode(&revision).await?;
        assert_eq!(stored, plain);
        Ok(())
    }

    #[dialog_common::test]
    async fn it_keeps_only_the_first_blocks_of_a_sealed_head_in_the_clear() -> Result<()> {
        let revision = head()?;
        let (_, stored) = sealed().encode(&revision).await?;

        let fields: BTreeMap<String, IgnoredAny> = CborEncoder.decode(&stored).await?;
        let names: Vec<&str> = fields.keys().map(String::as_str).collect();
        assert_eq!(names, ["prefetch", "sealed", "tree"]);
        let text = String::from_utf8_lossy(&stored);
        assert!(!text.contains("did:key"));
        assert!(!stored.windows(64).any(|window| window == [9; 64]));

        assert_eq!(
            HeadBlocks::read(&stored).await?,
            HeadBlocks::from(&revision)
        );
        let opened: Revision = sealed().decode(&stored).await?;
        assert_eq!(opened, revision);
        Ok(())
    }

    #[dialog_common::test]
    async fn it_reads_a_plain_head_on_a_sealed_branch() -> Result<()> {
        let revision = head()?;
        let (_, plain) = CborEncoder.encode(&revision).await?;
        let read: Revision = sealed().decode(&plain).await?;
        assert_eq!(read, revision);
        Ok(())
    }

    #[dialog_common::test]
    async fn it_refuses_a_sealed_head_without_its_key() -> Result<()> {
        let (_, stored) = sealed().encode(&head()?).await?;
        let other = HeadCodec::new(BlockCodec::sealed(KeyRing::new(SealKey::from([4; 32]))));
        assert!(other.decode::<Revision>(&stored).await.is_err());
        assert!(
            HeadCodec::default()
                .decode::<Revision>(&stored)
                .await
                .is_err()
        );
        Ok(())
    }
}
