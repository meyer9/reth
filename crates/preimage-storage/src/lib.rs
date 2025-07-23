//! Preimage storage interface for Reth
//!
//! This crate provides a generic interface for storing and retrieving preimages
//! with support for various backends including DynamoDB.

pub mod error;
pub mod extractor;
pub mod traits;

#[cfg(feature = "dynamodb")]
pub mod dynamodb;

pub mod local;

pub use error::{PreimageStorageError, PreimageStorageResult};
use reth_trie::Nibbles;
pub use traits::{PreimageStorage, StorageStatistics};

#[cfg(feature = "dynamodb")]
pub use dynamodb::DynamoDbPreimageStorage;

pub use extractor::{TriePreimageData, TriePreimageExtractor, TriePreimageStatistics};
pub use local::LocalPreimageStorage;

/// A preimage entry containing a hash and its corresponding data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreimageEntry {
    /// The hash of the data
    pub hash: alloy_primitives::B256,
    // The path of the node in the trie (should help with pruning old preimages)
    pub path: Nibbles,
    /// The original data that produces the hash
    pub data: Vec<u8>,
}

impl PreimageEntry {
    /// Create a new preimage entry
    pub fn new(hash: alloy_primitives::B256, path: Nibbles, data: Vec<u8>) -> Self {
        Self { hash, path, data }
    }
}

/// Configuration for preimage storage
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreimageStorageConfig {
    /// Batch size for bulk operations
    pub batch_size: usize,
    /// Table name for DynamoDB (if using DynamoDB backend)
    pub table_name: Option<String>,
    /// AWS region for DynamoDB (if using DynamoDB backend)
    pub aws_region: Option<String>,
    /// Custom endpoint URL for DynamoDB (useful for local testing)
    pub dynamodb_endpoint_url: Option<String>,
    /// Local file path for local storage (if using local backend)
    pub local_path: Option<std::path::PathBuf>,
}

impl Default for PreimageStorageConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            table_name: Some("reth-preimages".to_string()),
            aws_region: Some("us-east-1".to_string()),
            dynamodb_endpoint_url: None,
            local_path: None,
        }
    }
}
