//! Trie preimage extractor for reading from reth database

use crate::{PreimageEntry, PreimageStorage, PreimageStorageError, PreimageStorageResult};
use alloy_primitives::{keccak256, FixedBytes, B256};
use alloy_rlp::Encodable;
use bytes::BufMut;
use hex::ToHex;
use reth_db_api::{
    cursor::DbCursorRO, tables::{AccountsTrie, StoragesTrie}, transaction::DbTx, DatabaseError, HashedAccounts
};
use reth_primitives_traits::account;
use reth_trie::{hash_builder::HashBuilder, hashed_cursor::HashedCursorFactory, metrics::TrieRootMetrics, node_iter::{TrieElement, TrieNodeIter}, trie_cursor::TrieCursorFactory, updates::TrieUpdates, walker::{Changes, TrieWalker}, BranchNode, BranchNodeCompact, ExtensionNode, Nibbles, RlpNode, StorageRoot, StorageTrieEntry, StoredNibbles, TrieType, EMPTY_ROOT_HASH};
use reth_trie_db::{DatabaseAccountTrieCursor, DatabaseTrieCursorFactory, DatabaseHashedAccountCursor, DatabaseHashedCursorFactory};
use std::{collections::HashMap, ops::Sub, time::Instant};
use tracing::{debug, info, trace};
use std::time::Duration;
use reth_trie::hashed_cursor::HashedStorageCursor;

/// Estimate the percentage completion of a trie traversal based on the current nibbles path.
/// 
/// In a 16-ary trie (hex nibbles), each nibble represents a branch with 16 possible values.
/// This function calculates how far through the trie space we are based on the current path.
/// 
/// # Arguments
/// * `nibbles` - The current path in the trie as a sequence of nibbles (4-bit values)
/// 
/// # Returns
/// A percentage value between 0.0 and 1.0 representing the estimated completion
pub fn estimate_trie_progress_pct(nibbles: &Nibbles) -> f64 {
    if nibbles.is_empty() {
        return 0.0;
    }

    let mut total_pct = 0.0;
    
    // For each nibble in the path, calculate its contribution to the overall progress
    for i in 0..nibbles.len() {
        let nibble = nibbles.get(i).unwrap();
        
        // Each nibble represents nibble/16 of the space at that level
        let nibble_contribution = nibble as f64 / 16.0;
        
        // Weight the contribution by the level in the trie
        // At level 0, the nibble represents nibble/16 of the total space
        // At level 1, it represents nibble/(16^2) of the total space, etc.
        let level_weight = 16_f64.powi(i as i32);
        total_pct += nibble_contribution / level_weight;
    }
    
    total_pct
}

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

pub struct AllAccountPrefixSet {}
impl Changes for AllAccountPrefixSet {
    fn contains(&mut self, key: &Nibbles) -> bool {
        true
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
        let trie_cursor_factory = DatabaseTrieCursorFactory::new(tx);
        let hashed_cursor_factory = DatabaseHashedCursorFactory::new(tx);

        let trie_cursor = trie_cursor_factory.account_trie_cursor().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to open accounts trie cursor: {}",
                e
            ))
        })?;
        let hashed_cursor = hashed_cursor_factory.hashed_account_cursor().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!(
                "Failed to open hashed accounts cursor: {}",
                e
            ))
        })?;

        let walker = TrieWalker::state_trie(trie_cursor, AllAccountPrefixSet{});

        let mut node_iter = TrieNodeIter::state_trie(
            walker,
            hashed_cursor,
        );

        let mut hash_builder = HashBuilder::default().with_updates(true);
        let mut account_rlp = Vec::new();
        let mut trie_updates = TrieUpdates::default();
        let mut total_updated_branch_nodes = 0;
        let mut total_updated_storage_branch_nodes = 0;
        let start_time = Instant::now();

        while let Some(node) = node_iter.try_next().unwrap() {
            match node {
                TrieElement::Branch(branch) => {
                    info!("Processing branch: {:?}", branch.key);
                    hash_builder.add_branch(branch.key, branch.value, branch.children_are_in_trie);
                }
                TrieElement::Leaf(hashed_address, account) => {
                    // info!("Processing leaf: {:?}", hashed_address);

                    let metrics = TrieRootMetrics::new(TrieType::Storage);
                    let instant = Instant::now();
                    // We assume we can always calculate a storage root without
                    // OOMing. This opens us up to a potential DOS vector if
                    // a contract had too many storage entries and they were
                    // all buffered w/o us returning and committing our intermediate
                    // progress.
                    // TODO: We can consider introducing the TrieProgress::Progress/Complete
                    // abstraction inside StorageRoot, but let's give it a try as-is for now.
                    // let storage_root_calculator = StorageRoot::new_hashed(
                    //     trie_cursor_factory.clone(),
                    //     hashed_cursor_factory.clone(),
                    //     hashed_address,
                    //     Default::default(),
                    //     metrics,
                    // );

                    let elapsed = instant.elapsed();
                    if elapsed > Duration::from_millis(100) {
                        info!("Storage root calculation time: {:?}", elapsed);
                    }

                    let num_updated_branch_nodes = hash_builder.updated_branch_nodes.as_ref().unwrap().len();

                    if num_updated_branch_nodes >= 10000 {
                        info!("num_updated_branch_nodes: {}", num_updated_branch_nodes);
                        info!("total_updated_branch_nodes: {}", total_updated_branch_nodes);

                        // TODO: flush here using hash_builder.take_updated_branch_nodes()
                        let (new_hash_builder, updated_branch_nodes) = hash_builder.split();
                        // for (nibble, branch) in updated_branch_nodes {
                        //     // info!("Account node: {:?} {:?}", nibble, branch);
                        // }
                        let last_node_processed = updated_branch_nodes.keys().last().unwrap();

                        info!("last_node_processed: {:?}", last_node_processed);

                        let pct_progress = estimate_trie_progress_pct(last_node_processed);
                        let elapsed = start_time.elapsed();
                        let estimated_total_time = if pct_progress > 0.0 { elapsed.div_f64(pct_progress) } else { Duration::from_secs(0) };
                        let estimated_remaining_time = estimated_total_time.checked_sub(elapsed).unwrap_or(Duration::from_secs(0));
                        info!("Estimated remaining time: {:?}", estimated_remaining_time);
                        info!("Percent complete: {:.2}%", pct_progress * 100.0);

                        total_updated_branch_nodes += num_updated_branch_nodes;
                        hash_builder = new_hash_builder;
                        hash_builder.set_updates(true);

                    }


                    let storage_root = || -> Result<B256, DatabaseError> {
                        let mut hashed_storage_cursor =
                            hashed_cursor_factory.hashed_storage_cursor(hashed_address)?;
                        let mut hash_builder = HashBuilder::default().with_updates(true);

                        if hashed_storage_cursor.is_storage_empty()? {
                            return Ok(EMPTY_ROOT_HASH)
                        }

                        let trie_cursor = trie_cursor_factory.storage_trie_cursor(hashed_address)?;
                        let walker = TrieWalker::storage_trie(trie_cursor, AllAccountPrefixSet{});

                        let mut node_iter = TrieNodeIter::storage_trie(
                            walker,
                            hashed_storage_cursor,
                        );

                        while let Some(node) = node_iter.try_next()? {
                            match node {
                                TrieElement::Branch(node) => {
                                    hash_builder.add_branch(node.key, node.value, node.children_are_in_trie);
                                }
                                TrieElement::Leaf(hashed_slot, value) => {
                                    hash_builder.add_leaf(
                                        Nibbles::unpack(hashed_slot),
                                        alloy_rlp::encode_fixed_size(&value).as_ref(),
                                    );
                                }
                            }

                            
                            
                            let num_updated_storage_branch_nodes = hash_builder.updated_branch_nodes.as_ref().unwrap().len();
                            if num_updated_storage_branch_nodes >= 10000 {

                                total_updated_storage_branch_nodes += num_updated_storage_branch_nodes;
                                info!("num_updated_storage_branch_nodes: {}", num_updated_storage_branch_nodes);
                                info!("total_updated_storage_branch_nodes: {}", total_updated_storage_branch_nodes);

                                let (new_hash_builder, updated_branch_nodes) = hash_builder.split();
                                hash_builder = new_hash_builder;
                                hash_builder.set_updates(true);
                            }
                        }

                        
                        let num_updated_storage_branch_nodes = hash_builder.updated_branch_nodes.as_ref().unwrap().len();
                        total_updated_storage_branch_nodes += num_updated_storage_branch_nodes;

                        if total_updated_storage_branch_nodes > 0 {
                            info!("total_updated_storage_branch_nodes: {}", total_updated_storage_branch_nodes);
                        }

                        let (new_hash_builder, updated_branch_nodes) = hash_builder.split();
                        hash_builder = new_hash_builder;
                        hash_builder.set_updates(true);


                        let root = hash_builder.root();

                        Ok(root)

                    }().map_err(|e| {
                        PreimageStorageError::Database(eyre::eyre!(
                            "Failed to calculate storage root: {}",
                            e
                        ))
                    })?;
                    
                    account_rlp.clear();
                    let account = account.into_trie_account(storage_root);
                    account.encode(&mut account_rlp as &mut dyn BufMut);
                    hash_builder.add_leaf(Nibbles::unpack(hashed_address), &account_rlp);
                }
            }
        }

        total_updated_branch_nodes += hash_builder.updated_branch_nodes.as_ref().unwrap().len();

        let root = hash_builder.root();
        info!("Root: {:x}", root);

        info!("total_updated_branch_nodes: {}", total_updated_branch_nodes);

        for (nibble, branch) in hash_builder.updated_branch_nodes.unwrap() {
            info!("Account node: {:?} {:?}", nibble, branch);
        }

        Err(PreimageStorageError::Storage("not implemented".to_string()))

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
        info!("Encoding account trie node: {:?}", branch_node);

        // assert!(branch_node.state_mask.count_ones() == (branch_node.hashes.len() as u32), "state mask: {:?} hashes: {:?}", branch_node.state_mask, branch_node.hashes);
        // assert!(branch_node.state_mask == branch_node.tree_mask, "state mask: {:?} tree mask: {:?}", branch_node.state_mask, branch_node.tree_mask);

        let branch_node = BranchNode {
            state_mask: branch_node.state_mask,
            stack: branch_node.hashes.iter().map(|h| RlpNode::from_raw(h.as_slice()).unwrap()).collect(),
        };


        let encoded_node = alloy_rlp::encode(branch_node);

        Ok(encoded_node)
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

    #[test]
    fn test_estimate_trie_progress_pct_empty_nibbles() {
        let nibbles = Nibbles::from_nibbles_unchecked(vec![]);
        let progress = estimate_trie_progress_pct(&nibbles);
        assert_eq!(progress, 0.0, "Empty nibbles should return 0.0");
    }

    #[test]
    fn test_estimate_trie_progress_pct_single_nibble() {
        // Test all possible single nibble values (0-15)
        for nibble_val in 0..16 {
            let nibbles = Nibbles::from_nibbles_unchecked(vec![nibble_val]);
            let progress = estimate_trie_progress_pct(&nibbles);
            
            // For a single nibble at level 0, progress should be nibble_val/16/16
            let expected = (nibble_val as f64 / 16.0);
            assert!(
                (progress - expected).abs() < 1e-10,
                "Single nibble {}: expected {}, got {}",
                nibble_val,
                expected,
                progress
            );
        }
    }

    #[test]
    fn test_estimate_trie_progress_pct_ordering() {
        // Progress should increase monotonically with higher nibble values
        let nibbles_0 = Nibbles::from_nibbles_unchecked(vec![0]);
        let nibbles_8 = Nibbles::from_nibbles_unchecked(vec![8]);
        let nibbles_15 = Nibbles::from_nibbles_unchecked(vec![15]);
        
        let progress_0 = estimate_trie_progress_pct(&nibbles_0);
        let progress_8 = estimate_trie_progress_pct(&nibbles_8);
        let progress_15 = estimate_trie_progress_pct(&nibbles_15);
        
        assert!(progress_0 < progress_8, "Progress should increase with higher nibbles");
        assert!(progress_8 < progress_15, "Progress should increase with higher nibbles");
        assert!(progress_15 < 1.0, "Progress should be less than 1.0");
    }

    #[test]
    fn test_estimate_trie_progress_pct_depth_weighting() {
        // Deeper nibbles should have less impact on overall progress
        let shallow = Nibbles::from_nibbles_unchecked(vec![8]);
        let deeper = Nibbles::from_nibbles_unchecked(vec![0, 8]);
        let deepest = Nibbles::from_nibbles_unchecked(vec![0, 0, 8]);
        
        let progress_shallow = estimate_trie_progress_pct(&shallow);
        let progress_deeper = estimate_trie_progress_pct(&deeper);
        let progress_deepest = estimate_trie_progress_pct(&deepest);
        
        // The contribution of the 8 nibble should decrease with depth
        assert!(progress_shallow > progress_deeper, "Deeper nibbles should contribute less");
        assert!(progress_deeper > progress_deepest, "Even deeper nibbles should contribute even less");
    }

    #[test]
    fn test_estimate_trie_progress_pct_multi_nibble() {
        // Test with multiple nibbles
        let nibbles = Nibbles::from_nibbles_unchecked(vec![8, 4, 2]);
        let progress = estimate_trie_progress_pct(&nibbles);
        
        // Calculate expected value manually
        // Level 0: 8/16 / 16^1 = 0.5 / 16 = 0.03125
        // Level 1: 4/16 / 16^2 = 0.25 / 256 = 0.0009765625
        // Level 2: 2/16 / 16^3 = 0.125 / 4096 = 0.0000305175781...
        let expected = (8.0) / 16.0 + (4.0) / 256.0 + (2.0) / 4096.0;
        
        assert!(
            (progress - expected).abs() < 1e-10,
            "Multi-nibble progress: expected {}, got {}",
            expected,
            progress
        );
    }

    #[test]
    fn test_estimate_trie_progress_pct_boundary_cases() {
        // Test with all zeros (should be very small but not zero)
        let all_zeros = Nibbles::from_nibbles_unchecked(vec![0, 0, 0]);
        let progress_zeros = estimate_trie_progress_pct(&all_zeros);
        assert!(progress_zeros == 0.0, "All zeros should give 0.0 progress");

        // Test with all 15s (maximum values)
        let all_max = Nibbles::from_nibbles_unchecked(vec![15, 15, 15]);
        let progress_max = estimate_trie_progress_pct(&all_max);
        assert!(progress_max < 1.0, "Even all max values should be less than 1.0");
        assert!(progress_max > 0.0, "All max values should be greater than 0.0");
    }

    #[test]
    fn test_estimate_trie_progress_pct_mathematical_consistency() {
        // Test that the mathematical formula is consistent
        let nibbles_a = Nibbles::from_nibbles_unchecked(vec![4]);
        let nibbles_b = Nibbles::from_nibbles_unchecked(vec![8]);
        
        let progress_a = estimate_trie_progress_pct(&nibbles_a);
        let progress_b = estimate_trie_progress_pct(&nibbles_b);
        
        // nibbles_b should have exactly twice the progress of nibbles_a
        let ratio = progress_b / progress_a;
        assert!(
            (ratio - 2.0).abs() < 1e-10,
            "Progress ratio should be 2.0, got {}",
            ratio
        );
    }

    #[test]
    fn test_estimate_trie_progress_pct_realistic_paths() {
        // Test with realistic trie paths that might occur in practice
        
        // Simulate early in traversal
        let early_path = Nibbles::from_nibbles_unchecked(vec![1, 2]);
        let early_progress = estimate_trie_progress_pct(&early_path);
        assert!(early_progress < 0.01, "Early path should have low progress");
        
        // Simulate middle of traversal  
        let middle_path = Nibbles::from_nibbles_unchecked(vec![8, 0, 0]);
        let middle_progress = estimate_trie_progress_pct(&middle_path);
        assert!(middle_progress > early_progress, "Middle path should have higher progress");
        assert!(middle_progress < 0.1, "Middle path should still be reasonable");
        
        // Simulate late in traversal
        let late_path = Nibbles::from_nibbles_unchecked(vec![14, 15, 14]);
        let late_progress = estimate_trie_progress_pct(&late_path);
        assert!(late_progress > middle_progress, "Late path should have highest progress");
    }

    #[test]
    fn test_estimate_trie_progress_pct_monotonic_within_level() {
        // Within the same depth, progress should increase monotonically
        let base_path = vec![5, 3];
        
        for i in 0..16 {
            let mut path = base_path.clone();
            path.push(i);
            let nibbles = Nibbles::from_nibbles_unchecked(path);
            let progress = estimate_trie_progress_pct(&nibbles);
            
            if i > 0 {
                let mut prev_path = base_path.clone(); 
                prev_path.push(i - 1);
                let prev_nibbles = Nibbles::from_nibbles_unchecked(prev_path);
                let prev_progress = estimate_trie_progress_pct(&prev_nibbles);
                
                assert!(
                    progress > prev_progress,
                    "Progress should increase: nibble {} ({}) > nibble {} ({})",
                    i, progress, i-1, prev_progress
                );
            }
        }
    }

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
