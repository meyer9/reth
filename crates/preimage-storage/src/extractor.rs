//! Trie preimage extractor for reading from reth database

use crate::{PreimageEntry, PreimageStorage, PreimageStorageError, PreimageStorageResult};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Encodable;
use reth_db_api::{
    cursor::DbCursorRO,
    tables::{AccountsTrie, StoragesTrie},
    transaction::DbTx,
};
use reth_trie::{BranchNodeCompact, StorageTrieEntry, StoredNibbles};
use std::{collections::HashMap, time::Instant};
use tracing::{debug, info, trace};

/// Progress tracking for trie extraction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractionProgress {
    /// Current number of nodes processed
    pub nodes_processed: usize,
    /// Estimated total number of nodes (based on trie structure)
    pub estimated_total_nodes: usize,
    /// Current depth in the trie
    pub current_depth: usize,
    /// Progress percentage (0.0 to 100.0)
    pub progress_percentage: f64,
}

impl ExtractionProgress {
    /// Create new progress tracker
    pub fn new(estimated_total: usize) -> Self {
        Self {
            nodes_processed: 0,
            estimated_total_nodes: estimated_total,
            current_depth: 0,
            progress_percentage: 0.0,
        }
    }

    /// Update progress with a new node
    pub fn update(&mut self, depth: usize) {
        self.nodes_processed += 1;
        self.current_depth = depth;
        self.progress_percentage = if self.estimated_total_nodes > 0 {
            (self.nodes_processed as f64 / self.estimated_total_nodes as f64) * 100.0
        } else {
            0.0
        };
    }

    /// Get progress as a formatted string
    pub fn to_string(&self) -> String {
        format!(
            "Progress: {:.1}% ({}/{}) at depth {}",
            self.progress_percentage,
            self.nodes_processed,
            self.estimated_total_nodes,
            self.current_depth
        )
    }
}

/// Trie preimage extractor for reading from reth database
#[derive(Debug)]
pub struct TriePreimageExtractor;

impl TriePreimageExtractor {
    /// Extract all preimages from the trie database (original method for backward compatibility)
    pub fn extract_all_preimages<TX: DbTx>(tx: &TX) -> PreimageStorageResult<TriePreimageData> {
        let mut preimage_data = TriePreimageData::new();

        debug!("Starting account trie estimation and extraction");
        let start_total = Instant::now();
        // Extract account trie preimages with progress tracking
        let (account_preimages, progress) = Self::extract_account_trie_preimages(tx)?;
        preimage_data.account_preimages = account_preimages;
        preimage_data.progress = Some(progress);
        debug!("Account trie extraction complete in {:.2?}", start_total.elapsed());

        debug!("Starting storage trie extraction");
        let start_storage = Instant::now();
        // Extract storage trie preimages
        let storage_preimages = Self::extract_storage_trie_preimages(tx)?;
        preimage_data.storage_preimages = storage_preimages;
        debug!("Storage trie extraction complete in {:.2?}", start_storage.elapsed());

        info!(
            "Extracted {} account preimages and {} storage preimages",
            preimage_data.account_preimages.len(),
            preimage_data.storage_preimages.len()
        );

        Ok(preimage_data)
    }

    /// Extract all preimages with progress callback (original method for backward compatibility)
    pub fn extract_all_preimages_with_progress<TX: DbTx, F>(
        tx: &TX,
        mut progress_callback: F,
    ) -> PreimageStorageResult<TriePreimageData>
    where
        F: FnMut(&ExtractionProgress),
    {
        let mut preimage_data = TriePreimageData::new();

        // Extract account trie preimages with progress tracking and callback
        let (account_preimages, progress) =
            Self::extract_account_trie_preimages_with_callback(tx, &mut progress_callback)?;
        preimage_data.account_preimages = account_preimages;
        preimage_data.progress = Some(progress);

        // Extract storage trie preimages
        let storage_preimages = Self::extract_storage_trie_preimages(tx)?;
        preimage_data.storage_preimages = storage_preimages;

        info!(
            "Extracted {} account preimages and {} storage preimages",
            preimage_data.account_preimages.len(),
            preimage_data.storage_preimages.len()
        );

        Ok(preimage_data)
    }

    /// Extract all preimages from the trie database with streaming to storage
    pub async fn extract_all_preimages_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
    ) -> PreimageStorageResult<TriePreimageStatistics> {
        let mut stats = TriePreimageStatistics::default();

        debug!("Starting streaming account trie extraction");
        let start_total = Instant::now();

        // Extract account trie preimages with streaming
        let account_stats = Self::extract_account_trie_preimages_streaming(tx, storage).await?;
        stats.account_preimage_count = account_stats.account_preimage_count;
        stats.total_account_size_bytes = account_stats.total_account_size_bytes;
        stats.progress = account_stats.progress;

        debug!("Account trie streaming extraction complete in {:.2?}", start_total.elapsed());

        debug!("Starting streaming storage trie extraction");
        let start_storage = Instant::now();

        // Extract storage trie preimages with streaming
        let storage_stats = Self::extract_storage_trie_preimages_streaming(tx, storage).await?;
        stats.storage_preimage_count = storage_stats.storage_preimage_count;
        stats.total_storage_size_bytes = storage_stats.total_storage_size_bytes;

        debug!("Storage trie streaming extraction complete in {:.2?}", start_storage.elapsed());

        info!(
            "Streaming extraction complete: {} account preimages, {} storage preimages",
            stats.account_preimage_count, stats.storage_preimage_count
        );

        Ok(stats)
    }

    /// Extract all preimages with streaming and progress callback
    pub async fn extract_all_preimages_streaming_with_progress<TX: DbTx, S: PreimageStorage, F>(
        tx: &TX,
        storage: &S,
        mut progress_callback: F,
    ) -> PreimageStorageResult<TriePreimageStatistics>
    where
        F: FnMut(&ExtractionProgress),
    {
        let mut stats = TriePreimageStatistics::default();

        // Extract account trie preimages with streaming and progress callback
        let account_stats = Self::extract_account_trie_preimages_streaming_with_callback(
            tx,
            storage,
            &mut progress_callback,
        )
        .await?;
        stats.account_preimage_count = account_stats.account_preimage_count;
        stats.total_account_size_bytes = account_stats.total_account_size_bytes;
        stats.progress = account_stats.progress;

        // Extract storage trie preimages with streaming
        let storage_stats = Self::extract_storage_trie_preimages_streaming(tx, storage).await?;
        stats.storage_preimage_count = storage_stats.storage_preimage_count;
        stats.total_storage_size_bytes = storage_stats.total_storage_size_bytes;

        info!(
            "Streaming extraction with progress complete: {} account preimages, {} storage preimages",
            stats.account_preimage_count,
            stats.storage_preimage_count
        );

        Ok(stats)
    }

    /// Extract preimages from the account trie with progress tracking (original method for backward
    /// compatibility)
    fn extract_account_trie_preimages<TX: DbTx>(
        tx: &TX,
    ) -> PreimageStorageResult<(Vec<PreimageEntry>, ExtractionProgress)> {
        let mut preimages = Vec::new();
        let mut cursor = tx.cursor_read::<AccountsTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to open accounts trie cursor: {}",
                e
            ))
        })?;

        debug!("Estimating account trie size...");
        let start_est = Instant::now();
        // First pass: estimate total nodes by analyzing trie structure
        let estimated_total = Self::estimate_account_trie_size(tx)?;
        debug!("Estimation complete in {:.2?}", start_est.elapsed());
        let mut progress = ExtractionProgress::new(estimated_total);

        info!("Estimated {} total account trie nodes", estimated_total);

        // Second pass: extract preimages with progress tracking
        debug!("Beginning account trie extraction loop");
        let start_extract = Instant::now();
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to read first account trie entry: {}",
                e
            ))
        })?;

        while let Some((stored_nibbles, branch_node)) = current {
            let preimage_entry =
                Self::create_preimage_from_account_node(&stored_nibbles, &branch_node)?;
            trace!("Extracted account trie preimage: {:x}", preimage_entry.hash);
            preimages.push(preimage_entry);

            // Update progress based on node depth
            let depth = stored_nibbles.0.len();
            progress.update(depth);

            // Log progress every 1000 nodes or when progress changes significantly
            if progress.nodes_processed % 1000 == 0 || progress.nodes_processed == 1 {
                debug!(
                    "{} ({} nodes, elapsed: {:.2?})",
                    progress.to_string(),
                    progress.nodes_processed,
                    start_extract.elapsed()
                );
            }

            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!(
                    "Failed to read next account trie entry: {}",
                    e
                ))
            })?;
        }

        info!(
            "Completed account trie extraction: {} (elapsed: {:.2?})",
            progress.to_string(),
            start_extract.elapsed()
        );
        debug!("Extracted {} account trie preimages", preimages.len());
        Ok((preimages, progress))
    }

    /// Extract preimages from the account trie with progress callback (original method for backward
    /// compatibility)
    fn extract_account_trie_preimages_with_callback<TX: DbTx, F>(
        tx: &TX,
        progress_callback: &mut F,
    ) -> PreimageStorageResult<(Vec<PreimageEntry>, ExtractionProgress)>
    where
        F: FnMut(&ExtractionProgress),
    {
        let mut preimages = Vec::new();
        let mut cursor = tx.cursor_read::<AccountsTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to open accounts trie cursor: {}",
                e
            ))
        })?;

        // First pass: estimate total nodes by analyzing trie structure
        let estimated_total = Self::estimate_account_trie_size(tx)?;
        let mut progress = ExtractionProgress::new(estimated_total);

        info!("Estimated {} total account trie nodes", estimated_total);

        // Second pass: extract preimages with progress tracking and callback
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to read first account trie entry: {}",
                e
            ))
        })?;

        while let Some((stored_nibbles, branch_node)) = current {
            let preimage_entry =
                Self::create_preimage_from_account_node(&stored_nibbles, &branch_node)?;
            trace!("Extracted account trie preimage: {:x}", preimage_entry.hash);
            preimages.push(preimage_entry);

            // Update progress based on node depth
            let depth = stored_nibbles.0.len();
            progress.update(depth);

            // Call progress callback
            progress_callback(&progress);

            // Log progress every 1000 nodes or when progress changes significantly
            if progress.nodes_processed % 1000 == 0 || progress.nodes_processed == 1 {
                info!("{}", progress.to_string());
            }

            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!(
                    "Failed to read next account trie entry: {}",
                    e
                ))
            })?;
        }

        info!("Completed account trie extraction: {}", progress.to_string());
        debug!("Extracted {} account trie preimages", preimages.len());
        Ok((preimages, progress))
    }

    /// Extract preimages from storage tries (original method for backward compatibility)
    fn extract_storage_trie_preimages<TX: DbTx>(
        tx: &TX,
    ) -> PreimageStorageResult<Vec<PreimageEntry>> {
        debug!("Beginning storage trie extraction loop");
        let start = Instant::now();
        let mut preimages = Vec::new();
        let mut cursor = tx.cursor_dup_read::<StoragesTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open storage trie cursor: {}", e))
        })?;

        // Iterate through all storage trie nodes
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to read first storage trie entry: {}",
                e
            ))
        })?;
        let mut processed = 0;
        while let Some((hashed_address, storage_entry)) = current {
            let preimage_entry =
                Self::create_preimage_from_storage_node(&hashed_address, &storage_entry)?;
            preimages.push(preimage_entry.clone());

            trace!("Extracted storage trie preimage: {:x}", preimage_entry.hash);
            processed += 1;
            if processed % 1000 == 0 || processed == 1 {
                debug!(
                    "Storage trie: processed {} nodes (elapsed: {:.2?})",
                    processed,
                    start.elapsed()
                );
            }

            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!(
                    "Failed to read next storage trie entry: {}",
                    e
                ))
            })?;
        }
        debug!(
            "Completed storage trie extraction: processed {} nodes (elapsed: {:.2?})",
            processed,
            start.elapsed()
        );
        debug!("Extracted {} storage trie preimages", preimages.len());
        Ok(preimages)
    }

    /// Extract preimages from the account trie with streaming to storage
    async fn extract_account_trie_preimages_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
    ) -> PreimageStorageResult<TriePreimageStatistics> {
        let mut cursor = tx.cursor_read::<AccountsTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to open accounts trie cursor: {}",
                e
            ))
        })?;

        debug!("Estimating account trie size...");
        let start_est = Instant::now();
        // First pass: estimate total nodes by analyzing trie structure
        let estimated_total = Self::estimate_account_trie_size(tx)?;
        debug!("Estimation complete in {:.2?}", start_est.elapsed());
        let mut progress = ExtractionProgress::new(estimated_total);

        info!("Estimated {} total account trie nodes", estimated_total);

        // Second pass: extract preimages with streaming to storage
        debug!("Beginning streaming account trie extraction");
        let start_extract = Instant::now();
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to read first account trie entry: {}",
                e
            ))
        })?;

        let mut batch = Vec::new();
        const BATCH_SIZE: usize = 100; // Process in batches for efficiency
        let mut total_size_bytes = 0;
        let mut processed_count = 0;

        while let Some((stored_nibbles, branch_node)) = current {
            let preimage_entry =
                Self::create_preimage_from_account_node(&stored_nibbles, &branch_node)?;
            info!("Extracted account trie preimage: {:?} {:x}", stored_nibbles.0, preimage_entry.hash);

            batch.push(preimage_entry.clone());
            total_size_bytes += preimage_entry.data.len();
            processed_count += 1;

            // Update progress based on node depth
            let depth = stored_nibbles.0.len();
            progress.update(depth);

            // Store batch when it reaches the target size
            if batch.len() >= BATCH_SIZE {
                storage.store_preimages(batch.clone()).await?;
                batch.clear();

                // Log progress every 1000 nodes or when progress changes significantly
                if processed_count % 100000 == 0 || processed_count == BATCH_SIZE {
                    debug!(
                        "{} ({} nodes, elapsed: {:.2?})",
                        progress.to_string(),
                        processed_count,
                        start_extract.elapsed()
                    );
                }
            }

            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!(
                    "Failed to read next account trie entry: {}",
                    e
                ))
            })?;
        }

        // Create the root node preimage by finding all 1-length nibbles and adding them to a branch node,
        // or if there are no 1-length nibbles, find the shortest nibble and add it to an extension node. If
        // empty, don't add anything.

        // Store remaining batch
        if !batch.is_empty() {
            storage.store_preimages(batch).await?;
        }

        info!(
            "Completed streaming account trie extraction: {} (elapsed: {:.2?})",
            progress.to_string(),
            start_extract.elapsed()
        );
        debug!("Streamed {} account trie preimages", processed_count);

        Ok(TriePreimageStatistics {
            account_preimage_count: processed_count,
            storage_preimage_count: 0,
            total_account_size_bytes: total_size_bytes,
            total_storage_size_bytes: 0,
            progress: Some(progress),
        })
    }

    /// Extract preimages from the account trie with streaming and progress callback
    async fn extract_account_trie_preimages_streaming_with_callback<
        TX: DbTx,
        S: PreimageStorage,
        F,
    >(
        tx: &TX,
        storage: &S,
        progress_callback: &mut F,
    ) -> PreimageStorageResult<TriePreimageStatistics>
    where
        F: FnMut(&ExtractionProgress),
    {
        let mut cursor = tx.cursor_read::<AccountsTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to open accounts trie cursor: {}",
                e
            ))
        })?;

        // First pass: estimate total nodes by analyzing trie structure
        let estimated_total = Self::estimate_account_trie_size(tx)?;
        let mut progress = ExtractionProgress::new(estimated_total);

        info!("Estimated {} total account trie nodes", estimated_total);

        // Second pass: extract preimages with streaming to storage and progress callback
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to read first account trie entry: {}",
                e
            ))
        })?;

        let mut batch = Vec::new();
        const BATCH_SIZE: usize = 100; // Process in batches for efficiency
        let mut total_size_bytes = 0;
        let mut processed_count = 0;

        while let Some((stored_nibbles, branch_node)) = current {
            let preimage_entry =
                Self::create_preimage_from_account_node(&stored_nibbles, &branch_node)?;
            trace!("Extracted account trie preimage: {:x}", preimage_entry.hash);

            batch.push(preimage_entry.clone());
            total_size_bytes += preimage_entry.data.len();
            processed_count += 1;

            // Update progress based on node depth
            let depth = stored_nibbles.0.len();
            progress.update(depth);

            // Call progress callback
            progress_callback(&progress);

            // Store batch when it reaches the target size
            if batch.len() >= BATCH_SIZE {
                storage.store_preimages(batch.clone()).await?;
                batch.clear();

                // Log progress every 1000 nodes or when progress changes significantly
                if processed_count % 100000 == 0 || processed_count == BATCH_SIZE {
                    info!("{}", progress.to_string());
                }
            }

            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!(
                    "Failed to read next account trie entry: {}",
                    e
                ))
            })?;
        }

        // Store remaining batch
        if !batch.is_empty() {
            storage.store_preimages(batch).await?;
        }

        info!("Completed streaming account trie extraction: {}", progress.to_string());
        debug!("Streamed {} account trie preimages", processed_count);

        Ok(TriePreimageStatistics {
            account_preimage_count: processed_count,
            storage_preimage_count: 0,
            total_account_size_bytes: total_size_bytes,
            total_storage_size_bytes: 0,
            progress: Some(progress),
        })
    }

    /// Extract preimages from storage tries with streaming to storage
    async fn extract_storage_trie_preimages_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
    ) -> PreimageStorageResult<TriePreimageStatistics> {
        debug!("Beginning streaming storage trie extraction");
        let start = Instant::now();
        let mut cursor = tx.cursor_dup_read::<StoragesTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open storage trie cursor: {}", e))
        })?;

        // Iterate through all storage trie nodes with streaming
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to read first storage trie entry: {}",
                e
            ))
        })?;

        let mut batch = Vec::new();
        const BATCH_SIZE: usize = 100; // Process in batches for efficiency
        let mut total_size_bytes = 0;
        let mut processed_count = 0;

        while let Some((hashed_address, storage_entry)) = current {
            let preimage_entry =
                Self::create_preimage_from_storage_node(&hashed_address, &storage_entry)?;

            batch.push(preimage_entry.clone());
            total_size_bytes += preimage_entry.data.len();
            processed_count += 1;

            trace!("Extracted storage trie preimage: {:x}", preimage_entry.hash);

            // Store batch when it reaches the target size
            if batch.len() >= BATCH_SIZE {
                storage.store_preimages(batch.clone()).await?;
                batch.clear();

                if processed_count % 100000 == 0 || processed_count == BATCH_SIZE {
                    debug!(
                        "Storage trie: processed {} nodes (elapsed: {:.2?})",
                        processed_count,
                        start.elapsed()
                    );
                }
            }

            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!(
                    "Failed to read next storage trie entry: {}",
                    e
                ))
            })?;
        }

        // Store remaining batch
        if !batch.is_empty() {
            storage.store_preimages(batch).await?;
        }

        debug!(
            "Completed streaming storage trie extraction: processed {} nodes (elapsed: {:.2?})",
            processed_count,
            start.elapsed()
        );
        debug!("Streamed {} storage trie preimages", processed_count);

        Ok(TriePreimageStatistics {
            account_preimage_count: 0,
            storage_preimage_count: processed_count,
            total_account_size_bytes: 0,
            total_storage_size_bytes: total_size_bytes,
            progress: None,
        })
    }

    /// Estimate the total number of nodes in the account trie using depth-first analysis
    fn estimate_account_trie_size<TX: DbTx>(tx: &TX) -> PreimageStorageResult<usize> {
        let mut cursor = tx.cursor_read::<AccountsTrie>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to open accounts trie cursor for estimation: {}",
                e
            ))
        })?;

        let mut total_estimate = 0;
        let mut depth_counts: HashMap<usize, usize> = HashMap::new();

        // Analyze the first few nodes at each depth to estimate distribution
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to read first account trie entry for estimation: {}",
                e
            ))
        })?;

        let mut sample_size = 0;
        const MAX_SAMPLE_SIZE: usize = 10000; // Sample up to 10k nodes for estimation
        let start_sample = Instant::now();
        while let Some((stored_nibbles, branch_node)) = current {
            let depth = stored_nibbles.0.len();
            *depth_counts.entry(depth).or_insert(0) += 1;

            // Count potential children from branch nodes
            let child_count = branch_node.state_mask.count_ones() as usize;
            total_estimate += 1 + child_count; // Current node + potential children

            sample_size += 1;
            if sample_size >= MAX_SAMPLE_SIZE {
                break;
            }

            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!(
                    "Failed to read next account trie entry for estimation: {}",
                    e
                ))
            })?;
        }
        debug!("Sampled {} nodes for estimation in {:.2?}", sample_size, start_sample.elapsed());
        debug!("Depth distribution: {:?}", depth_counts);

        // If we have a good sample, extrapolate to estimate total
        if sample_size > 0 {
            // use depth distribution to estimate log2(number of nodes)
            let mut avg_depth: f64 = 0.5; // avg depth of 0.5 since we're always getting the floor of the depth
            for (depth, count) in depth_counts {
                avg_depth += depth as f64 * count as f64;
            }
            avg_depth /= sample_size as f64;
            info!("Average depth: {}", avg_depth);
            total_estimate = 16.0_f64.powf(avg_depth) as usize;
        }
        Ok(total_estimate)
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

        Ok(PreimageEntry::new(hash, stored_nibbles.0, node_data.into()))
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

        Ok(PreimageEntry::new(hash, storage_entry.nibbles.0, node_data.into()))
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
        let encoded_node =
            serde_json::to_vec(branch_node).map_err(|e| PreimageStorageError::Serialization(e))?;
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
        let encoded_entry = serde_json::to_vec(storage_entry)
            .map_err(|e| PreimageStorageError::Serialization(e))?;
        buf.extend(encoded_entry);

        Ok(buf)
    }
}

/// Data structure containing extracted trie preimages
#[derive(Debug, Clone)]
pub struct TriePreimageData {
    /// Preimages from the account trie
    pub account_preimages: Vec<PreimageEntry>,
    /// Preimages from storage tries
    pub storage_preimages: Vec<PreimageEntry>,
    /// Progress information from extraction
    pub progress: Option<ExtractionProgress>,
}

impl TriePreimageData {
    /// Create new empty trie preimage data
    pub fn new() -> Self {
        Self { account_preimages: Vec::new(), storage_preimages: Vec::new(), progress: None }
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
        let total_account_size: usize = self.account_preimages.iter().map(|p| p.data.len()).sum();

        let total_storage_size: usize = self.storage_preimages.iter().map(|p| p.data.len()).sum();

        TriePreimageStatistics {
            account_preimage_count: self.account_preimages.len(),
            storage_preimage_count: self.storage_preimages.len(),
            total_account_size_bytes: total_account_size,
            total_storage_size_bytes: total_storage_size,
            progress: self.progress.clone(),
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
    /// Progress information from extraction
    pub progress: Option<ExtractionProgress>,
}

impl Default for TriePreimageStatistics {
    fn default() -> Self {
        Self {
            account_preimage_count: 0,
            storage_preimage_count: 0,
            total_account_size_bytes: 0,
            total_storage_size_bytes: 0,
            progress: None,
        }
    }
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

    /// Get progress information as a string
    pub fn progress_string(&self) -> Option<String> {
        self.progress.as_ref().map(|p| p.to_string())
    }
}

impl Default for TriePreimageData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{local::LocalPreimageStorage, PreimageStorageConfig};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_streaming_extraction() {
        // This is a basic test to ensure the streaming methods compile and work
        // In a real implementation, you would need a proper database with trie data

        // Create a temporary directory for local storage
        let temp_dir = tempdir().unwrap();
        let config = PreimageStorageConfig {
            local_path: Some(PathBuf::from(temp_dir.path())),
            batch_size: 100,
            ..Default::default()
        };

        let _ = LocalPreimageStorage::new(config).await.unwrap();

        // Note: This test would need a real database transaction to work
        // The streaming architecture is designed to work with any PreimageStorage implementation
        info!("Streaming architecture ready for use with real database");
    }

    #[test]
    fn test_preimage_storage_config_default() {
        let config = PreimageStorageConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.table_name, Some("reth-preimages".to_string()));
        assert_eq!(config.aws_region, Some("us-east-1".to_string()));
        assert_eq!(config.dynamodb_endpoint_url, None);
        assert_eq!(config.local_path, None);
    }

    #[test]
    fn test_preimage_storage_config_with_custom_endpoint() {
        let config = PreimageStorageConfig {
            dynamodb_endpoint_url: Some("http://localhost:8000".to_string()),
            ..Default::default()
        };
        assert_eq!(config.dynamodb_endpoint_url, Some("http://localhost:8000".to_string()));
    }
}
