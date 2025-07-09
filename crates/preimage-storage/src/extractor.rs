//! Trie preimage extractor for reading from reth database

use crate::{PreimageEntry, PreimageStorageResult, PreimageStorageError};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Encodable;
use reth_db_api::{
    cursor::DbCursorRO,
    tables::{AccountsTrie, StoragesTrie},
    transaction::DbTx,
};
use reth_trie::{BranchNodeCompact, Nibbles, StorageTrieEntry, StoredNibbles, StoredNibblesSubKey};
use std::collections::HashMap;
use tracing::{debug, info, trace};

/// Trie preimage extractor for reading from reth database
pub struct TriePreimageExtractor;

impl TriePreimageExtractor {
    /// Extract all preimages from the trie database
    pub fn extract_all_preimages<TX: DbTx>(
        tx: &TX,
    ) -> PreimageStorageResult<TriePreimageData> {
        let mut preimage_data = TriePreimageData::new();
        
        // Extract account trie preimages
        let account_preimages = Self::extract_account_trie_preimages(tx)?;
        preimage_data.account_preimages = account_preimages;
        
        // Extract storage trie preimages
        let storage_preimages = Self::extract_storage_trie_preimages(tx)?;
        preimage_data.storage_preimages = storage_preimages;
        
        // Calculate the state root hash
        preimage_data.state_root = Self::calculate_state_root(tx)?;
        
        info!(
            "Extracted {} account preimages and {} storage preimages",
            preimage_data.account_preimages.len(),
            preimage_data.storage_preimages.len()
        );
        
        Ok(preimage_data)
    }
    
    /// Extract preimages from the account trie
    fn extract_account_trie_preimages<TX: DbTx>(
        tx: &TX,
    ) -> PreimageStorageResult<Vec<PreimageEntry>> {
        let mut preimages = Vec::new();
        let mut cursor = tx.cursor_read::<AccountsTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open accounts trie cursor: {}", e))
        })?;
        
        // Iterate through all account trie nodes
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to read first account trie entry: {}", e))
        })?;
        
        while let Some((stored_nibbles, branch_node)) = current {
            let preimage_entry = Self::create_preimage_from_account_node(&stored_nibbles, &branch_node)?;
            trace!("Extracted account trie preimage: {:x}", preimage_entry.hash);
            preimages.push(preimage_entry);
            
            
            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to read next account trie entry: {}", e))
            })?;
        }
        
        debug!("Extracted {} account trie preimages", preimages.len());
        Ok(preimages)
    }
    
    /// Extract preimages from storage tries
    fn extract_storage_trie_preimages<TX: DbTx>(
        tx: &TX,
    ) -> PreimageStorageResult<Vec<PreimageEntry>> {
        let mut preimages = Vec::new();
        let mut cursor = tx.cursor_dup_read::<StoragesTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open storage trie cursor: {}", e))
        })?;
        
        // Iterate through all storage trie nodes
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to read first storage trie entry: {}", e))
        })?;
        
        while let Some((hashed_address, storage_entry)) = current {
            let preimage_entry = Self::create_preimage_from_storage_node(&hashed_address, &storage_entry)?;
            preimages.push(preimage_entry.clone());
            
            trace!("Extracted storage trie preimage: {:x}", preimage_entry.hash);
            
            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to read next storage trie entry: {}", e))
            })?;
        }
        
        debug!("Extracted {} storage trie preimages", preimages.len());
        Ok(preimages)
    }
    
    /// Create a preimage entry from an account trie node
    fn create_preimage_from_account_node(
        stored_nibbles: &StoredNibbles,
        branch_node: &BranchNodeCompact,
    ) -> PreimageStorageResult<PreimageEntry> {
        // Create the node data that would be hashed
        let node_data = Self::encode_account_node(stored_nibbles, branch_node)?;
        
        // Calculate the hash of the node data
        let hash = keccak256(&node_data);
        
        Ok(PreimageEntry::new(hash, node_data.into()))
    }
    
    /// Create a preimage entry from a storage trie node
    fn create_preimage_from_storage_node(
        hashed_address: &B256,
        storage_entry: &StorageTrieEntry,
    ) -> PreimageStorageResult<PreimageEntry> {
        // Create the node data that would be hashed
        let node_data = Self::encode_storage_node(hashed_address, storage_entry)?;
        
        // Calculate the hash of the node data
        let hash = keccak256(&node_data);
        
        Ok(PreimageEntry::new(hash, node_data.into()))
    }
    
    /// Encode account trie node for hashing
    fn encode_account_node(
        stored_nibbles: &StoredNibbles,
        branch_node: &BranchNodeCompact,
    ) -> PreimageStorageResult<Vec<u8>> {
        let mut buf = Vec::new();
        
        // Encode the nibbles path
        stored_nibbles.0.encode(&mut buf);
        
        // Encode the branch node using serde
        let encoded_node = serde_json::to_vec(branch_node).map_err(|e| {
            PreimageStorageError::Serialization(e)
        })?;
        buf.extend(encoded_node);
        
        Ok(buf)
    }
    
    /// Encode storage trie node for hashing
    fn encode_storage_node(
        hashed_address: &B256,
        storage_entry: &StorageTrieEntry,
    ) -> PreimageStorageResult<Vec<u8>> {
        let mut buf = Vec::new();
        
        // Encode the hashed address
        hashed_address.encode(&mut buf);
        
        // Encode the storage entry using serde
        let encoded_entry = serde_json::to_vec(storage_entry).map_err(|e| {
            PreimageStorageError::Serialization(e)
        })?;
        buf.extend(encoded_entry);
        
        Ok(buf)
    }
    
    /// Calculate the state root hash from the database
    fn calculate_state_root<TX: DbTx>(tx: &TX) -> PreimageStorageResult<B256> {
        // This is a simplified approach - in practice, we'd need to build the trie
        // and calculate the proper Merkle root. For now, we'll use a placeholder
        // or try to get it from the database if available.
        
        // Try to get the latest state root from the database
        // This is a placeholder implementation
        Ok(B256::ZERO)
    }
}

/// Data structure containing extracted trie preimages
#[derive(Debug, Clone)]
pub struct TriePreimageData {
    /// Preimages from the account trie
    pub account_preimages: Vec<PreimageEntry>,
    /// Preimages from storage tries
    pub storage_preimages: Vec<PreimageEntry>,
    /// The state root hash
    pub state_root: B256,
}

impl TriePreimageData {
    /// Create new empty trie preimage data
    pub fn new() -> Self {
        Self {
            account_preimages: Vec::new(),
            storage_preimages: Vec::new(),
            state_root: B256::ZERO,
        }
    }
    
    /// Get all preimages as a single vector
    pub fn all_preimages(&self) -> Vec<PreimageEntry> {
        let mut all = Vec::new();
        all.extend(self.account_preimages.clone());
        all.extend(self.storage_preimages.clone());
        all
    }
    
    /// Get the total number of preimages
    pub fn total_count(&self) -> usize {
        self.account_preimages.len() + self.storage_preimages.len()
    }
    
    /// Get statistics about the preimage data
    pub fn statistics(&self) -> TriePreimageStatistics {
        let total_account_size: usize = self.account_preimages.iter()
            .map(|p| p.data.len())
            .sum();
        
        let total_storage_size: usize = self.storage_preimages.iter()
            .map(|p| p.data.len())
            .sum();
        
        TriePreimageStatistics {
            account_preimage_count: self.account_preimages.len(),
            storage_preimage_count: self.storage_preimages.len(),
            total_account_size_bytes: total_account_size,
            total_storage_size_bytes: total_storage_size,
            state_root: self.state_root,
        }
    }
}

/// Statistics about extracted trie preimages
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriePreimageStatistics {
    /// Number of account trie preimages
    pub account_preimage_count: usize,
    /// Number of storage trie preimages
    pub storage_preimage_count: usize,
    /// Total size of account preimages in bytes
    pub total_account_size_bytes: usize,
    /// Total size of storage preimages in bytes
    pub total_storage_size_bytes: usize,
    /// The state root hash
    pub state_root: B256,
}

impl TriePreimageStatistics {
    /// Get the total number of preimages
    pub fn total_count(&self) -> usize {
        self.account_preimage_count + self.storage_preimage_count
    }
    
    /// Get the total size of all preimages
    pub fn total_size_bytes(&self) -> usize {
        self.total_account_size_bytes + self.total_storage_size_bytes
    }
    
    /// Get the average preimage size
    pub fn average_preimage_size(&self) -> f64 {
        let total_count = self.total_count();
        if total_count == 0 {
            0.0
        } else {
            self.total_size_bytes() as f64 / total_count as f64
        }
    }
}

impl Default for TriePreimageData {
    fn default() -> Self {
        Self::new()
    }
} 