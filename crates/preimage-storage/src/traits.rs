//! Trait definitions for preimage storage

use crate::{PreimageEntry, PreimageStorageResult};
use alloy_primitives::B256;
use async_trait::async_trait;

/// Trait for preimage storage backends
#[async_trait]
pub trait PreimageStorage: Send + Sync {
    /// Store a single preimage entry
    async fn store_preimage(&self, entry: PreimageEntry) -> PreimageStorageResult<()>;

    /// Store multiple preimage entries in a batch
    async fn store_preimages(&self, entries: Vec<PreimageEntry>) -> PreimageStorageResult<()>;

    /// Retrieve a preimage by its hash
    async fn get_preimage(&self, hash: &B256) -> PreimageStorageResult<Option<Vec<u8>>>;

    /// Retrieve multiple preimages by their hashes
    async fn get_preimages(&self, hashes: &[B256]) -> PreimageStorageResult<Vec<Vec<u8>>>;

    /// Check if a preimage exists for the given hash
    async fn contains_preimage(&self, hash: &B256) -> PreimageStorageResult<bool>;

    /// Delete a preimage by its hash
    async fn delete_preimage(&self, hash: &B256) -> PreimageStorageResult<()>;

    /// Delete multiple preimages by their hashes
    async fn delete_preimages(&self, hashes: &[B256]) -> PreimageStorageResult<()>;

    /// Get the total number of preimages stored
    async fn count_preimages(&self) -> PreimageStorageResult<u64>;

    /// List all preimage hashes (for debugging/admin purposes)
    async fn list_preimage_hashes(&self) -> PreimageStorageResult<Vec<B256>>;

    /// Clear all preimages (for testing purposes)
    async fn clear_all_preimages(&self) -> PreimageStorageResult<()>;

    /// Get storage statistics
    async fn get_statistics(&self) -> PreimageStorageResult<StorageStatistics>;
}

/// Statistics about the preimage storage
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageStatistics {
    /// Total number of preimages stored
    pub total_preimages: u64,
    /// Total size of all preimages in bytes
    pub total_size_bytes: u64,
    /// Average preimage size in bytes
    pub average_size_bytes: u64,
    /// Storage backend type
    pub backend_type: String,
}

impl StorageStatistics {
    /// Create new storage statistics
    pub fn new(total_preimages: u64, total_size_bytes: u64, backend_type: String) -> Self {
        let average_size_bytes =
            if total_preimages > 0 { total_size_bytes / total_preimages } else { 0 };

        Self { total_preimages, total_size_bytes, average_size_bytes, backend_type }
    }
}
