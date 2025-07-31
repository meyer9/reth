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
mod hash_builder_2;

pub use error::{PreimageStorageError, PreimageStorageResult};
use reth_trie::Nibbles;
pub use traits::{PreimageStorage, StorageStatistics};

#[cfg(feature = "dynamodb")]
pub use dynamodb::DynamoDbPreimageStorage;

pub use extractor::TriePreimageExtractor;
pub use local::LocalPreimageStorage;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountPreimageEntry {
    pub hash: alloy_primitives::B256,
    pub path: Nibbles,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoragePreimageEntry {
    pub hash: alloy_primitives::B256,
    pub hashed_address: alloy_primitives::B256,
    pub path: Nibbles,
    pub data: Vec<u8>,
}

/// A preimage entry containing a hash and its corresponding data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PreimageEntry {
    Storage(StoragePreimageEntry),
    Account(AccountPreimageEntry),
}

impl PreimageEntry {
    /// Create a new preimage entry
    pub fn new_storage(hash: alloy_primitives::B256, hashed_address: alloy_primitives::B256, path: Nibbles, data: Vec<u8>) -> Self {
        Self::Storage(StoragePreimageEntry { hash, hashed_address, path, data })
    }

    pub fn new_account(hash: alloy_primitives::B256, path: Nibbles, data: Vec<u8>) -> Self {
        Self::Account(AccountPreimageEntry { hash, path, data })
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
