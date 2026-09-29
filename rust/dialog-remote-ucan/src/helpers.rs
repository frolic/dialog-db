//! Test helpers: a store that holds everything in memory, and an access
//! service over it that a client under test reaches over loopback, on
//! native and on wasm alike.
//!
//! The service is [`Access`](crate::Access) itself behind a small HTTP
//! server, so what the tests exercise is the layer an embedder ships,
//! not a stand-in for it.

use serde::{Deserialize, Serialize};

mod store;
pub use store::MemoryStore;

#[cfg(not(target_arch = "wasm32"))]
mod server;
#[cfg(not(target_arch = "wasm32"))]
pub use server::*;

/// Where a provisioned access service listens. What a test receives:
/// the endpoint it points a [`UcanAddress`](crate::UcanAddress) at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcanServiceAddress {
    /// The service's endpoint URL.
    pub endpoint: String,
}

/// The path a provisioned service answers with its [`RequestCounts`].
pub const REQUESTS_PATH: &str = "/requests";

/// How many public reads and invocations a provisioned service has
/// received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestCounts {
    /// Plain GETs of a block or blob.
    pub gets: u64,
    /// Invocations.
    pub invocations: u64,
}
