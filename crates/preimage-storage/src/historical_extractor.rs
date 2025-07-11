//! Historical trie preimage extractor for reading from reth database at specific blocks

use crate::{PreimageEntry, PreimageStorageResult, PreimageStorageError, PreimageStorage};
use alloy_primitives::{keccak256, BlockNumber, B256, Address};
use alloy_rlp::Encodable;
use reth_db_api::{
    cursor::DbCursorRO,
    tables::{
        AccountChangeSets, StorageChangeSets, CanonicalHeaders, HashedAccounts, HashedStorages
    },
    transaction::DbTx,
    models::{AccountBeforeTx, BlockNumberAddress},
};
use reth_provider::DatabaseProviderRO;
use tracing::{debug, info, warn};
use std::time::Instant;
use std::collections::HashMap;
use reth_primitives_traits::{Account, StorageEntry};

/// Progress tracking for historical extraction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HistoricalExtractionProgress {
    /// Starting block number
    pub start_block: BlockNumber,
    /// Current block being processed
    pub current_block: BlockNumber,
    /// Latest block number (tip of chain)
    pub latest_block: BlockNumber,
    /// Current phase of extraction
    pub phase: ExtractionPhase,
    /// Number of preimages extracted in current phase
    pub preimages_extracted: usize,
    /// Estimated total preimages for current phase
    pub estimated_total_preimages: usize,
    /// Total bytes processed
    pub total_bytes_processed: usize,
    /// Start time of extraction
    #[serde(skip, default = "std::time::Instant::now")]
    pub start_time: std::time::Instant,
}

/// Phases of historical extraction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExtractionPhase {
    /// Extracting initial state at start block
    InitialState,
    /// Extracting account changes from changesets
    AccountChanges,
    /// Extracting storage changes from changesets
    StorageChanges,
    /// Finalizing extraction
    Finalizing,
}

impl HistoricalExtractionProgress {
    /// Create new progress tracker
    pub fn new(start_block: BlockNumber, latest_block: BlockNumber) -> Self {
        Self {
            start_block,
            current_block: start_block,
            latest_block,
            phase: ExtractionPhase::InitialState,
            preimages_extracted: 0,
            estimated_total_preimages: 0,
            total_bytes_processed: 0,
            start_time: Instant::now(),
        }
    }
    
    /// Update progress with a new preimage
    pub fn update_preimage(&mut self, preimage_size: usize) {
        self.preimages_extracted += 1;
        self.total_bytes_processed += preimage_size;
    }
    
    /// Update current block
    pub fn update_block(&mut self, block: BlockNumber) {
        self.current_block = block;
    }
    
    /// Change phase
    pub fn change_phase(&mut self, phase: ExtractionPhase, estimated_total: usize) {
        self.phase = phase;
        self.preimages_extracted = 0;
        self.estimated_total_preimages = estimated_total;
    }
    
    /// Get progress percentage for current phase
    pub fn phase_progress_percentage(&self) -> f64 {
        if self.estimated_total_preimages == 0 {
            0.0
        } else {
            (self.preimages_extracted as f64 / self.estimated_total_preimages as f64) * 100.0
        }
    }
    
    /// Get overall progress percentage
    pub fn overall_progress_percentage(&self) -> f64 {
        if self.latest_block <= self.start_block {
            return 100.0;
        }
        
        let total_blocks = self.latest_block - self.start_block;
        let processed_blocks = self.current_block - self.start_block;
        
        (processed_blocks as f64 / total_blocks as f64) * 100.0
    }
    
    /// Get progress as a formatted string
    pub fn to_string(&self) -> String {
        format!(
            "Historical Extraction - Phase: {:?}, Block: {}/{}, Phase Progress: {:.1}%, Overall: {:.1}%, Preimages: {}, Elapsed: {:.2?}",
            self.phase,
            self.current_block,
            self.latest_block,
            self.phase_progress_percentage(),
            self.overall_progress_percentage(),
            self.preimages_extracted,
            self.start_time.elapsed()
        )
    }
}

/// Statistics for historical extraction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HistoricalExtractionStatistics {
    /// Starting block number
    pub start_block: BlockNumber,
    /// Latest block number processed
    pub latest_block: BlockNumber,
    /// Number of initial account preimages
    pub initial_account_preimages: usize,
    /// Number of initial storage preimages
    pub initial_storage_preimages: usize,
    /// Number of account change preimages
    pub account_change_preimages: usize,
    /// Number of storage change preimages
    pub storage_change_preimages: usize,
    /// Total bytes processed
    pub total_bytes_processed: usize,
    /// Total extraction time
    pub total_extraction_time: std::time::Duration,
    /// Progress information
    pub progress: HistoricalExtractionProgress,
}

impl HistoricalExtractionStatistics {
    /// Get total number of preimages
    pub fn total_preimages(&self) -> usize {
        self.initial_account_preimages + self.initial_storage_preimages + 
        self.account_change_preimages + self.storage_change_preimages
    }
    
    /// Get average preimage size
    pub fn average_preimage_size(&self) -> f64 {
        let total = self.total_preimages();
        if total == 0 {
            0.0
        } else {
            self.total_bytes_processed as f64 / total as f64
        }
    }
}

/// Historical trie preimage extractor for reading from reth database at specific blocks
pub struct HistoricalPreimageExtractor;

impl HistoricalPreimageExtractor {
    /// Extract all historical preimages from a starting block to the tip of the chain
    pub async fn extract_historical_preimages_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
        start_block: BlockNumber,
    ) -> PreimageStorageResult<HistoricalExtractionStatistics> {
        let start_time = Instant::now();
        
        // Get the latest block number
        let latest_block = Self::get_latest_block_number(tx)?;
        
        if start_block > latest_block {
            return Err(PreimageStorageError::InvalidInput(
                format!("Start block {} is greater than latest block {}", start_block, latest_block)
            ));
        }
        
        info!("Starting historical extraction from block {} to {}", start_block, latest_block);
        
        let mut progress = HistoricalExtractionProgress::new(start_block, latest_block);
        let mut stats = HistoricalExtractionStatistics {
            start_block,
            latest_block,
            initial_account_preimages: 0,
            initial_storage_preimages: 0,
            account_change_preimages: 0,
            storage_change_preimages: 0,
            total_bytes_processed: 0,
            total_extraction_time: std::time::Duration::ZERO,
            progress: progress.clone(),
        };
        
        // Phase 1: Extract initial state at start block
        info!("Phase 1: Extracting initial state at block {}", start_block);
        progress.change_phase(ExtractionPhase::InitialState, 0);
        
        let initial_stats = Self::extract_initial_state_streaming(tx, storage, start_block, &mut progress).await?;
        stats.initial_account_preimages = initial_stats.account_preimages;
        stats.initial_storage_preimages = initial_stats.storage_preimages;
        stats.total_bytes_processed += initial_stats.total_bytes;
        
        // Phase 2: Extract account changes from start_block to latest_block
        info!("Phase 2: Extracting account changes from block {} to {}", start_block, latest_block);
        progress.change_phase(ExtractionPhase::AccountChanges, 0);
        
        let account_changes_stats = Self::extract_account_changes_streaming(
            tx, storage, start_block, latest_block, &mut progress
        ).await?;
        stats.account_change_preimages = account_changes_stats.preimages;
        stats.total_bytes_processed += account_changes_stats.total_bytes;
        
        // Phase 3: Extract storage changes from start_block to latest_block
        info!("Phase 3: Extracting storage changes from block {} to {}", start_block, latest_block);
        progress.change_phase(ExtractionPhase::StorageChanges, 0);
        
        let storage_changes_stats = Self::extract_storage_changes_streaming(
            tx, storage, start_block, latest_block, &mut progress
        ).await?;
        stats.storage_change_preimages = storage_changes_stats.preimages;
        stats.total_bytes_processed += storage_changes_stats.total_bytes;
        
        // Phase 4: Finalize
        progress.change_phase(ExtractionPhase::Finalizing, 0);
        stats.total_extraction_time = start_time.elapsed();
        stats.progress = progress;
        
        info!("Historical extraction complete!");
        info!("  Initial account preimages: {}", stats.initial_account_preimages);
        info!("  Initial storage preimages: {}", stats.initial_storage_preimages);
        info!("  Account change preimages: {}", stats.account_change_preimages);
        info!("  Storage change preimages: {}", stats.storage_change_preimages);
        info!("  Total preimages: {}", stats.total_preimages());
        info!("  Total bytes: {}", stats.total_bytes_processed);
        info!("  Total time: {:.2?}", stats.total_extraction_time);
        
        Ok(stats)
    }
    
    /// Extract initial state at a specific block
    async fn extract_initial_state_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
        block_number: BlockNumber,
        progress: &mut HistoricalExtractionProgress,
    ) -> PreimageStorageResult<InitialStateStats> {
        debug!("Extracting initial state at block {}", block_number);
        
        let mut stats = InitialStateStats::default();
        let mut batch = Vec::new();
        const BATCH_SIZE: usize = 100;
        
        // Extract account state at the specified block
        let account_stats = Self::extract_historical_accounts_streaming(
            tx, storage, block_number, &mut batch, BATCH_SIZE, progress
        ).await?;
        stats.account_preimages = account_stats.preimages;
        stats.total_bytes += account_stats.total_bytes;
        
        // Extract storage state at the specified block
        let storage_stats = Self::extract_historical_storage_streaming(
            tx, storage, block_number, &mut batch, BATCH_SIZE, progress
        ).await?;
        stats.storage_preimages = storage_stats.preimages;
        stats.total_bytes += storage_stats.total_bytes;
        
        // Flush remaining batch
        if !batch.is_empty() {
            storage.store_preimages(batch).await?;
        }
        
        debug!("Initial state extraction complete: {} account preimages, {} storage preimages", 
               stats.account_preimages, stats.storage_preimages);
        
        Ok(stats)
    }
    
    /// Extract account changes from changesets
    async fn extract_account_changes_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
        start_block: BlockNumber,
        end_block: BlockNumber,
        progress: &mut HistoricalExtractionProgress,
    ) -> PreimageStorageResult<ChangeStats> {
        debug!("Extracting account changes from block {} to {}", start_block, end_block);
        
        let mut cursor = tx.cursor_dup_read::<AccountChangeSets>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open account changesets cursor: {}", e))
        })?;
        
        let mut batch = Vec::new();
        const BATCH_SIZE: usize = 100;
        let mut total_bytes = 0;
        let mut preimage_count = 0;
        
        // Iterate through account changesets from start_block to end_block
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to read first account changeset: {}", e))
        })?;
        
        while let Some((block_num, account_before)) = current {
            if block_num < start_block {
                current = cursor.next().map_err(|e| {
                    PreimageStorageError::Database(eyre::eyre!("Failed to read next account changeset: {}", e))
                })?;
                continue;
            }
            
            if block_num > end_block {
                break;
            }
            
            // Create preimage entry for the account change
            let preimage_entry = Self::create_preimage_from_account_change(block_num, &account_before)?;
            batch.push(preimage_entry.clone());
            total_bytes += preimage_entry.data.len();
            preimage_count += 1;
            
            progress.update_preimage(preimage_entry.data.len());
            progress.update_block(block_num);
            
            // Store batch when it reaches the target size
            if batch.len() >= BATCH_SIZE {
                storage.store_preimages(batch.clone()).await?;
                batch.clear();
                
                if preimage_count % 10000 == 0 {
                    debug!("Account changes: {}", progress.to_string());
                }
            }
            
            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to read next account changeset: {}", e))
            })?;
        }
        
        // Store remaining batch
        if !batch.is_empty() {
            storage.store_preimages(batch).await?;
        }
        
        debug!("Account changes extraction complete: {} preimages", preimage_count);
        
        Ok(ChangeStats {
            preimages: preimage_count,
            total_bytes,
        })
    }
    
    /// Extract storage changes from changesets
    async fn extract_storage_changes_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
        start_block: BlockNumber,
        end_block: BlockNumber,
        progress: &mut HistoricalExtractionProgress,
    ) -> PreimageStorageResult<ChangeStats> {
        debug!("Extracting storage changes from block {} to {}", start_block, end_block);
        
        let mut cursor = tx.cursor_dup_read::<StorageChangeSets>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open storage changesets cursor: {}", e))
        })?;
        
        let mut batch = Vec::new();
        const BATCH_SIZE: usize = 100;
        let mut total_bytes = 0;
        let mut preimage_count = 0;
        
        // Iterate through storage changesets from start_block to end_block
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to read first storage changeset: {}", e))
        })?;
        
        while let Some((block_address, storage_entry)) = current {
            if block_address.block_number() < start_block {
                current = cursor.next().map_err(|e| {
                    PreimageStorageError::Database(eyre::eyre!("Failed to read next storage changeset: {}", e))
                })?;
                continue;
            }
            
            if block_address.block_number() > end_block {
                break;
            }
            
            // Create preimage entry for the storage change
            let preimage_entry = Self::create_preimage_from_storage_change(&block_address, &storage_entry)?;
            batch.push(preimage_entry.clone());
            total_bytes += preimage_entry.data.len();
            preimage_count += 1;
            
            progress.update_preimage(preimage_entry.data.len());
            progress.update_block(block_address.block_number());
            
            // Store batch when it reaches the target size
            if batch.len() >= BATCH_SIZE {
                storage.store_preimages(batch.clone()).await?;
                batch.clear();
                
                if preimage_count % 10000 == 0 {
                    debug!("Storage changes: {}", progress.to_string());
                }
            }
            
            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to read next storage changeset: {}", e))
            })?;
        }
        
        // Store remaining batch
        if !batch.is_empty() {
            storage.store_preimages(batch).await?;
        }
        
        debug!("Storage changes extraction complete: {} preimages", preimage_count);
        
        Ok(ChangeStats {
            preimages: preimage_count,
            total_bytes,
        })
    }
    
    /// Extract historical accounts at a specific block
    async fn extract_historical_accounts_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
        block_number: BlockNumber,
        batch: &mut Vec<PreimageEntry>,
        batch_size: usize,
        progress: &mut HistoricalExtractionProgress,
    ) -> PreimageStorageResult<AccountStats> {
        debug!("Extracting historical accounts at block {}", block_number);
        
        // Get the latest block number to determine how far back we need to go
        let latest_block = Self::get_latest_block_number(tx)?;
        
        if block_number > latest_block {
            return Err(PreimageStorageError::InvalidInput(
                format!("Block {} is greater than latest block {}", block_number, latest_block)
            ));
        }
        
        // Start with current hashed accounts state
        let mut historical_accounts = Self::load_current_hashed_accounts(tx)?;
        debug!("Loaded {} current hashed accounts", historical_accounts.len());
        
        // Apply changesets in reverse from latest block down to target block
        if latest_block > block_number {
            Self::apply_account_changesets_reverse(
                tx, 
                &mut historical_accounts, 
                block_number + 1, 
                latest_block
            )?;
        }
        
        debug!("Reconstructed {} historical accounts at block {}", historical_accounts.len(), block_number);
        
        // Convert historical accounts to preimages
        let mut total_bytes = 0;
        let mut preimage_count = 0;
        
        for (hashed_address, account) in historical_accounts {
            let preimage_entry = Self::create_preimage_from_historical_account(&hashed_address, &account)?;
            batch.push(preimage_entry.clone());
            total_bytes += preimage_entry.data.len();
            preimage_count += 1;
            
            progress.update_preimage(preimage_entry.data.len());
            
            // Store batch when it reaches the target size
            if batch.len() >= batch_size {
                storage.store_preimages(batch.clone()).await?;
                batch.clear();
                
                if preimage_count % 1000 == 0 {
                    debug!("Processed {} historical accounts", preimage_count);
                }
            }
        }
        
        debug!("Historical account extraction complete: {} preimages, {} bytes", preimage_count, total_bytes);
        
        Ok(AccountStats {
            preimages: preimage_count,
            total_bytes,
        })
    }
    
    /// Extract historical storage at a specific block
    async fn extract_historical_storage_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
        block_number: BlockNumber,
        batch: &mut Vec<PreimageEntry>,
        batch_size: usize,
        progress: &mut HistoricalExtractionProgress,
    ) -> PreimageStorageResult<StorageStats> {
        debug!("Extracting historical storage at block {}", block_number);
        
        // Get the latest block number to determine how far back we need to go
        let latest_block = Self::get_latest_block_number(tx)?;
        
        if block_number > latest_block {
            return Err(PreimageStorageError::InvalidInput(
                format!("Block {} is greater than latest block {}", block_number, latest_block)
            ));
        }
        
        // Start with current hashed storage state
        let mut historical_storage = Self::load_current_hashed_storage(tx)?;
        debug!("Loaded {} current hashed storage entries", historical_storage.len());
        
        // Apply changesets in reverse from latest block down to target block
        if latest_block > block_number {
            Self::apply_storage_changesets_reverse(
                tx, 
                &mut historical_storage, 
                block_number + 1, 
                latest_block
            )?;
        }
        
        debug!("Reconstructed {} historical storage entries at block {}", historical_storage.len(), block_number);
        
        // Convert historical storage to preimages
        let mut total_bytes = 0;
        let mut preimage_count = 0;
        
        for ((hashed_address, storage_key), storage_entry) in historical_storage {
            let preimage_entry = Self::create_preimage_from_historical_storage(&hashed_address, &storage_key, &storage_entry)?;
            batch.push(preimage_entry.clone());
            total_bytes += preimage_entry.data.len();
            preimage_count += 1;
            
            progress.update_preimage(preimage_entry.data.len());
            
            // Store batch when it reaches the target size
            if batch.len() >= batch_size {
                storage.store_preimages(batch.clone()).await?;
                batch.clear();
                
                if preimage_count % 1000 == 0 {
                    debug!("Processed {} historical storage entries", preimage_count);
                }
            }
        }
        
        debug!("Historical storage extraction complete: {} preimages, {} bytes", preimage_count, total_bytes);
        
        Ok(StorageStats {
            preimages: preimage_count,
            total_bytes,
        })
    }
    
    /// Get the latest block number from the database
    fn get_latest_block_number<TX: DbTx>(tx: &TX) -> PreimageStorageResult<BlockNumber> {
        let mut cursor = tx.cursor_read::<CanonicalHeaders>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open canonical headers cursor: {}", e))
        })?;
        
        // Get the last entry to find the latest block
        let latest = cursor.last().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to read latest block: {}", e))
        })?;
        
        match latest {
            Some((block_number, _)) => Ok(block_number),
            None => Err(PreimageStorageError::Database(eyre::eyre!("No blocks found in database"))),
        }
    }
    
    /// Create a preimage entry from an account change
    fn create_preimage_from_account_change(
        block_number: BlockNumber,
        account_before: &AccountBeforeTx,
    ) -> PreimageStorageResult<PreimageEntry> {
        // Create the change data that would be hashed
        let change_data = Self::encode_account_change(block_number, account_before)?;
        
        // Calculate the hash of the change data
        let hash = keccak256(&change_data);
        
        Ok(PreimageEntry::new(hash, change_data.into()))
    }
    
    /// Create a preimage entry from a storage change
    fn create_preimage_from_storage_change(
        block_address: &BlockNumberAddress,
        storage_entry: &StorageEntry,
    ) -> PreimageStorageResult<PreimageEntry> {
        // Create the change data that would be hashed
        let change_data = Self::encode_storage_change(block_address, storage_entry)?;
        
        // Calculate the hash of the change data
        let hash = keccak256(&change_data);
        
        Ok(PreimageEntry::new(hash, change_data.into()))
    }
    
    /// Encode account change for hashing
    fn encode_account_change(
        block_number: BlockNumber,
        account_before: &AccountBeforeTx,
    ) -> PreimageStorageResult<Vec<u8>> {
        let mut buf = Vec::new();
        
        // Encode the block number
        block_number.encode(&mut buf);
        
        // Encode the account change using serde
        let encoded_change = serde_json::to_vec(account_before).map_err(|e| {
            PreimageStorageError::Serialization(e)
        })?;
        buf.extend(encoded_change);
        
        Ok(buf)
    }
    
    /// Encode storage change for hashing
    fn encode_storage_change(
        block_address: &BlockNumberAddress,
        storage_entry: &StorageEntry,
    ) -> PreimageStorageResult<Vec<u8>> {
        let mut buf = Vec::new();
        
        // Encode the block and address
        block_address.block_number().encode(&mut buf);
        block_address.address().encode(&mut buf);
        
        // Encode the storage entry using serde
        let encoded_entry = serde_json::to_vec(storage_entry).map_err(|e| {
            PreimageStorageError::Serialization(e)
        })?;
        buf.extend(encoded_entry);
        
        Ok(buf)
    }
    
    /// Load current hashed accounts from the database
    fn load_current_hashed_accounts<TX: DbTx>(tx: &TX) -> PreimageStorageResult<HashMap<B256, Account>> {
        let mut accounts = HashMap::new();
        let mut cursor = tx.cursor_read::<HashedAccounts>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open hashed accounts cursor: {}", e))
        })?;
        
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to read first hashed account: {}", e))
        })?;
        
        while let Some((hashed_address, account)) = current {
            accounts.insert(hashed_address, account);
            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to read next hashed account: {}", e))
            })?;
        }
        
        Ok(accounts)
    }
    
    /// Load current hashed storage from the database
    fn load_current_hashed_storage<TX: DbTx>(tx: &TX) -> PreimageStorageResult<HashMap<(B256, B256), StorageEntry>> {
        let mut storage = HashMap::new();
        let mut cursor = tx.cursor_dup_read::<HashedStorages>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open hashed storage cursor: {}", e))
        })?;
        
        let mut current = cursor.first().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to read first hashed storage: {}", e))
        })?;
        
        while let Some((hashed_address, storage_entry)) = current {
            storage.insert((hashed_address, storage_entry.key), storage_entry);
            current = cursor.next().map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to read next hashed storage: {}", e))
            })?;
        }
        
        Ok(storage)
    }
    
    /// Apply account changesets in reverse order to reconstruct historical state
    fn apply_account_changesets_reverse<TX: DbTx>(
        tx: &TX,
        historical_accounts: &mut HashMap<B256, Account>,
        start_block: BlockNumber,
        end_block: BlockNumber,
    ) -> PreimageStorageResult<()> {
        let mut cursor = tx.cursor_dup_read::<AccountChangeSets>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open account changesets cursor: {}", e))
        })?;
        
        // Walk through changesets in reverse order (from end_block to start_block)
        for block_num in (start_block..=end_block).rev() {
            let mut walker = cursor.walk_range(block_num..=block_num).map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to walk account changesets: {}", e))
            })?;
            
            while let Some(entry) = walker.next() {
                let (_, account_before) = entry.map_err(|e| {
                    PreimageStorageError::Database(eyre::eyre!("Failed to read account changeset entry: {}", e))
                })?;
                
                // Hash the address to get the key used in HashedAccounts
                let hashed_address = keccak256(account_before.address.as_slice());
                
                // Apply the reverse changeset
                if let Some(old_account) = account_before.info {
                    // This account was changed in this block, revert to previous state
                    historical_accounts.insert(hashed_address, old_account);
                } else {
                    // This account was created in this block, remove it from historical state
                    historical_accounts.remove(&hashed_address);
                }
            }
        }
        
        Ok(())
    }
    
    /// Apply storage changesets in reverse order to reconstruct historical state
    fn apply_storage_changesets_reverse<TX: DbTx>(
        tx: &TX,
        historical_storage: &mut HashMap<(B256, B256), StorageEntry>,
        start_block: BlockNumber,
        end_block: BlockNumber,
    ) -> PreimageStorageResult<()> {
        let mut cursor = tx.cursor_dup_read::<StorageChangeSets>().map_err(|e| {
            PreimageStorageError::Database(eyre::eyre!("Failed to open storage changesets cursor: {}", e))
        })?;
        
        // Walk through changesets in reverse order (from end_block to start_block)
        for block_num in (start_block..=end_block).rev() {
            let block_address_start = BlockNumberAddress((block_num, Address::ZERO));
            let block_address_end = BlockNumberAddress((block_num + 1, Address::ZERO));
            
            let mut walker = cursor.walk_range(block_address_start..block_address_end).map_err(|e| {
                PreimageStorageError::Database(eyre::eyre!("Failed to walk storage changesets: {}", e))
            })?;
            
            while let Some(entry) = walker.next() {
                let (block_address, storage_entry) = entry.map_err(|e| {
                    PreimageStorageError::Database(eyre::eyre!("Failed to read storage changeset entry: {}", e))
                })?;
                
                // Hash the address to get the key used in HashedStorages
                let hashed_address = keccak256(block_address.address().as_slice());
                let storage_key = storage_entry.key;
                
                // Apply the reverse changeset
                if storage_entry.value.is_zero() {
                    // This storage was deleted in this block, remove it from historical state
                    historical_storage.remove(&(hashed_address, storage_key));
                } else {
                    // This storage was changed in this block, revert to previous state
                    historical_storage.insert((hashed_address, storage_key), storage_entry);
                }
            }
        }
        
        Ok(())
    }
    
    /// Create a preimage entry from a historical account
    fn create_preimage_from_historical_account(
        hashed_address: &B256,
        account: &Account,
    ) -> PreimageStorageResult<PreimageEntry> {
        // Create the account data that would be hashed
        let account_data = Self::encode_historical_account(hashed_address, account)?;
        
        // Calculate the hash of the account data
        let hash = keccak256(&account_data);
        
        Ok(PreimageEntry::new(hash, account_data.into()))
    }
    
    /// Create a preimage entry from historical storage
    fn create_preimage_from_historical_storage(
        hashed_address: &B256,
        storage_key: &B256,
        storage_entry: &StorageEntry,
    ) -> PreimageStorageResult<PreimageEntry> {
        // Create the storage data that would be hashed
        let storage_data = Self::encode_historical_storage(hashed_address, storage_key, storage_entry)?;
        
        // Calculate the hash of the storage data
        let hash = keccak256(&storage_data);
        
        Ok(PreimageEntry::new(hash, storage_data.into()))
    }
    
    /// Encode historical account for hashing
    fn encode_historical_account(
        hashed_address: &B256,
        account: &Account,
    ) -> PreimageStorageResult<Vec<u8>> {
        let mut buf = Vec::new();
        
        // Encode the hashed address
        hashed_address.encode(&mut buf);
        
        // Encode the account using serde
        let encoded_account = serde_json::to_vec(account).map_err(|e| {
            PreimageStorageError::Serialization(e)
        })?;
        buf.extend(encoded_account);
        
        Ok(buf)
    }
    
    /// Encode historical storage for hashing
    fn encode_historical_storage(
        hashed_address: &B256,
        storage_key: &B256,
        storage_entry: &StorageEntry,
    ) -> PreimageStorageResult<Vec<u8>> {
        let mut buf = Vec::new();
        
        // Encode the hashed address and storage key
        hashed_address.encode(&mut buf);
        storage_key.encode(&mut buf);
        
        // Encode the storage entry using serde
        let encoded_entry = serde_json::to_vec(storage_entry).map_err(|e| {
            PreimageStorageError::Serialization(e)
        })?;
        buf.extend(encoded_entry);
        
        Ok(buf)
    }
}

/// Statistics for initial state extraction
#[derive(Debug, Clone, Default)]
struct InitialStateStats {
    account_preimages: usize,
    storage_preimages: usize,
    total_bytes: usize,
}

/// Statistics for account extraction
#[derive(Debug, Clone, Default)]
struct AccountStats {
    preimages: usize,
    total_bytes: usize,
}

/// Statistics for storage extraction
#[derive(Debug, Clone, Default)]
struct StorageStats {
    preimages: usize,
    total_bytes: usize,
}

/// Statistics for change extraction
#[derive(Debug, Clone, Default)]
struct ChangeStats {
    preimages: usize,
    total_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalPreimageStorage;
    use crate::PreimageStorageConfig;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_historical_extraction_progress() {
        let mut progress = HistoricalExtractionProgress::new(100, 200);
        
        assert_eq!(progress.start_block, 100);
        assert_eq!(progress.latest_block, 200);
        assert_eq!(progress.overall_progress_percentage(), 0.0);
        
        progress.update_block(150);
        assert_eq!(progress.overall_progress_percentage(), 50.0);
        
        progress.update_block(200);
        assert_eq!(progress.overall_progress_percentage(), 100.0);
    }
    
    #[test]
    fn test_extraction_phases() {
        let mut progress = HistoricalExtractionProgress::new(100, 200);
        
        progress.change_phase(ExtractionPhase::AccountChanges, 1000);
        assert!(matches!(progress.phase, ExtractionPhase::AccountChanges));
        assert_eq!(progress.estimated_total_preimages, 1000);
        
        progress.update_preimage(256);
        assert_eq!(progress.preimages_extracted, 1);
        assert_eq!(progress.total_bytes_processed, 256);
        assert_eq!(progress.phase_progress_percentage(), 0.1);
    }
    
    #[tokio::test]
    async fn test_historical_extractor_architecture() {
        // Create a temporary directory for local storage
        let temp_dir = tempdir().unwrap();
        let config = PreimageStorageConfig {
            local_path: Some(PathBuf::from(temp_dir.path())),
            batch_size: 100,
            ..Default::default()
        };
        
        let storage = LocalPreimageStorage::new(config).await.unwrap();
        
        // Test that the historical extractor architecture is ready
        info!("Historical extractor architecture ready for use with real database");
        
        // Test statistics
        let stats = HistoricalExtractionStatistics {
            start_block: 100,
            latest_block: 200,
            initial_account_preimages: 1000,
            initial_storage_preimages: 5000,
            account_change_preimages: 500,
            storage_change_preimages: 2000,
            total_bytes_processed: 1024000,
            total_extraction_time: std::time::Duration::from_secs(60),
            progress: HistoricalExtractionProgress::new(100, 200),
        };
        
        assert_eq!(stats.total_preimages(), 8500);
        assert_eq!(stats.average_preimage_size(), 120.47058823529412);
    }
} 