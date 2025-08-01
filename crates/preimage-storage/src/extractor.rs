//! Trie preimage extractor for reading from reth database

use crate::{hash_builder_2::ProofRetainer, AccountPreimageEntry, PreimageEntry, PreimageStorage, PreimageStorageResult, StoragePreimageEntry};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Encodable;
use bytes::BufMut;
use reth_db_api::{
    transaction::DbTx, DatabaseError
};
use reth_trie::{hashed_cursor::{HashedCursorFactory}, node_iter::{TrieElement, TrieNodeIter}, trie_cursor::TrieCursorFactory, walker::{Changes, TrieWalker}, BranchNode, BranchNodeCompact, LeafNode, Nibbles, RlpNode, EMPTY_ROOT_HASH};
use reth_trie_db::{DatabaseTrieCursorFactory, DatabaseHashedCursorFactory};
use std::{time::Instant};
use tracing::{info};
use std::time::Duration;
use reth_trie::hashed_cursor::HashedStorageCursor;
use tokio::pin;
use tokio_stream::{Stream, StreamExt};
use async_stream::{try_stream, stream};

use crate::hash_builder_2::HashBuilder;

const FLUSH_THRESHOLD: usize = 200;

/// Statistics collected during trie preimage dump operations
#[derive(Debug, Clone, Default)]
pub struct DumpStatistics {
    /// Number of account leaves processed
    pub account_leaves: u64,
    /// Number of account preimages extracted
    pub account_preimages: u64,
    /// Number of storage leaves processed
    pub storage_leaves: u64,
    /// Number of storage preimages extracted
    pub storage_preimages: u64,
}

impl DumpStatistics {
    /// Get total number of leaves processed
    pub fn total_leaves(&self) -> u64 {
        self.account_leaves + self.storage_leaves
    }

    /// Get total number of preimages extracted
    pub fn total_preimages(&self) -> u64 {
        self.account_preimages + self.storage_preimages
    }
}

struct UniversalPrefixSet {}

impl Changes for UniversalPrefixSet {
    fn contains(&mut self, _key: &Nibbles) -> bool {
        true
    }
}


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
fn estimate_trie_progress_pct(nibbles: &Nibbles) -> f64 {
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

struct StorageTriePreimageExtractor<H, T> {
    hashed_cursor_factory: H,
    trie_cursor_factory: T,
    hashed_address: B256,
    root: B256,
}


impl<H: HashedCursorFactory, T: TrieCursorFactory> StorageTriePreimageExtractor<H, T> {
    fn new(
        hashed_cursor_factory: H,
        trie_cursor_factory: T,
        hashed_address: B256,
    ) -> Self {
        Self { hashed_cursor_factory, trie_cursor_factory, hashed_address, root: EMPTY_ROOT_HASH }
    }

    fn extract_trie_preimages<'a>(
        &'a mut self,
        stats: &'a mut DumpStatistics,
    ) -> impl Stream<Item = Result<PreimageEntry, DatabaseError>> + use<'a, H, T> {
        try_stream! {
            let mut hashed_storage_cursor =
                self.hashed_cursor_factory.hashed_storage_cursor(self.hashed_address)?;
            let mut hash_builder = HashBuilder::default().with_updates(true).with_proof_retainer(ProofRetainer::new());

            if hashed_storage_cursor.is_storage_empty()? {
                self.root = EMPTY_ROOT_HASH;
            } else {
                let trie_cursor = self.trie_cursor_factory.storage_trie_cursor(self.hashed_address)?;
                let walker = TrieWalker::storage_trie(trie_cursor, UniversalPrefixSet{});

                let mut node_iter = TrieNodeIter::storage_trie(
                    walker,
                    hashed_storage_cursor,
                );

                let start_time = Instant::now();

                while let Some(node) = node_iter.try_next()? {
                    match node {
                        TrieElement::Branch(_node) => {
                            panic!("should never get branch")
                        }
                        TrieElement::Leaf(hashed_slot, value) => {
                            stats.storage_leaves += 1;
                            hash_builder.add_leaf(
                                Nibbles::unpack(hashed_slot),
                                alloy_rlp::encode_fixed_size(&value).as_ref(),
                            );
                        }
                    }
                    
                    let num_updated_storage_branch_nodes = hash_builder.proof_retainer.as_ref().unwrap().len();
                    if num_updated_storage_branch_nodes >= FLUSH_THRESHOLD {
                        let proof_nodes = hash_builder.take_proof_nodes();
                        let (new_hash_builder, updated_branch_nodes) = hash_builder.split();

                        let last_node_processed = updated_branch_nodes.keys().last().unwrap();
                        let pct_progress = estimate_trie_progress_pct(last_node_processed);
                        let elapsed = start_time.elapsed();
                        let estimated_total_time = if pct_progress > 0.0 { elapsed.div_f64(pct_progress) } else { Duration::from_secs(0) };
                        let estimated_remaining_time = estimated_total_time.checked_sub(elapsed).unwrap_or(Duration::from_secs(0));
                        info!("Storage trie {:x} - Estimated remaining time: {:?}", self.hashed_address, estimated_remaining_time);
                        info!("Storage trie {:x} - Percent complete: {:.2}%", self.hashed_address, pct_progress * 100.0);
                        info!("Storage trie {:x} - Last node processed: {:?}", self.hashed_address, last_node_processed);

                        for (key, value) in proof_nodes.iter() {
                            let hash_data = keccak256(&value);
                            let storage_preimage_entry = PreimageEntry::new_storage(hash_data, self.hashed_address, *key, value.to_vec(), None);
                            stats.storage_preimages += 1;
                            yield storage_preimage_entry;
                        }

                        hash_builder = new_hash_builder.with_proof_retainer(ProofRetainer::new());
                        hash_builder.set_updates(true);
                    }
                }

                let root = hash_builder.root();
                let proof_nodes = hash_builder.take_proof_nodes();

                for (key, value) in proof_nodes.iter() {
                    let hash_data = keccak256(&value);
                    let storage_preimage_entry = PreimageEntry::new_storage(hash_data, self.hashed_address, *key, value.to_vec(), None);
                    stats.storage_preimages += 1;
                    yield storage_preimage_entry;
                }

                self.root = root;
            }
        }
    }
}

/// Extracts account trie preimages from the reth database.
struct AccountTriePreimageExtractor<H, T> {
    hashed_cursor_factory: H,
    trie_cursor_factory: T,
}

impl<H: HashedCursorFactory + Clone, T: TrieCursorFactory + Clone> AccountTriePreimageExtractor<H, T> {
    fn new(
        hashed_cursor_factory: H,
        trie_cursor_factory: T,
    ) -> Self {
        Self { hashed_cursor_factory, trie_cursor_factory }
    }

    fn extract_trie_preimages<'a>(
        &'a self,
        stats: &'a mut DumpStatistics,
    ) -> impl Stream<Item = Result<PreimageEntry, DatabaseError>> + use<'a, H, T> {
        try_stream! {
            let trie_cursor = self.trie_cursor_factory.account_trie_cursor()?;
            let hashed_cursor = self.hashed_cursor_factory.hashed_account_cursor()?;

            let walker = TrieWalker::state_trie(trie_cursor, UniversalPrefixSet{});

            let mut node_iter = TrieNodeIter::state_trie(
                walker,
                hashed_cursor,
            );

            let mut hash_builder = HashBuilder::default().with_updates(true).with_proof_retainer(ProofRetainer::new());
            let mut account_rlp = Vec::new();
            
            let start_time = Instant::now();

            while let Some(node) = node_iter.try_next().unwrap() {
                match node {
                    TrieElement::Branch(_branch) => {
                        panic!("should never get branch")
                    }
                    TrieElement::Leaf(hashed_address, account) => {
                        stats.account_leaves += 1;
                        let num_updated_branch_nodes = hash_builder.proof_retainer.as_ref().unwrap().len();

                        if num_updated_branch_nodes >= FLUSH_THRESHOLD {
                            let retained_proof_nodes = hash_builder.take_proof_nodes();
                            let (new_hash_builder, updated_branch_nodes) = hash_builder.split();

                            let last_node_processed = updated_branch_nodes.keys().last().unwrap();
                            let pct_progress = estimate_trie_progress_pct(last_node_processed);
                            let elapsed = start_time.elapsed();
                            let estimated_total_time = if pct_progress > 0.0 { elapsed.div_f64(pct_progress) } else { Duration::from_secs(0) };
                            let estimated_remaining_time = estimated_total_time.checked_sub(elapsed).unwrap_or(Duration::from_secs(0));
                            info!("Estimated remaining time: {:?}", estimated_remaining_time);
                            info!("Percent complete: {:.2}%", pct_progress * 100.0);
                            info!("Last node processed: {:?}", last_node_processed);

                            for (key, value) in retained_proof_nodes.iter() {
                                let hash_data = keccak256(&value);
                                let account_preimage_entry = PreimageEntry::new_account(hash_data, *key, value.to_vec(), None);
                                stats.account_preimages += 1;
                                yield account_preimage_entry;
                            }

                            hash_builder = new_hash_builder.with_proof_retainer(ProofRetainer::new());
                            hash_builder.set_updates(true);

                        }

                        let mut storage_root_extractor = StorageTriePreimageExtractor::new(
                            self.hashed_cursor_factory.clone(),
                            self.trie_cursor_factory.clone(),
                            hashed_address,
                        );
                        let storage_stream = storage_root_extractor.extract_trie_preimages(stats);
                        {
                            pin!(storage_stream);
                            while let Some(res) = storage_stream.next().await {
                                yield res?;
                            }
                        }

                        account_rlp.clear();
                        let account = account.into_trie_account(storage_root_extractor.root);
                        account.encode(&mut account_rlp as &mut dyn BufMut);
                        hash_builder.add_leaf(Nibbles::unpack(hashed_address), &account_rlp);
                    }
                }
            }

            hash_builder.root();
            let retained_proof_nodes = hash_builder.take_proof_nodes();

            for (key, value) in retained_proof_nodes.iter() {
                let hash_data = keccak256(&value);
                let account_preimage_entry = PreimageEntry::new_account(hash_data, *key, value.to_vec(), None);
                stats.account_preimages += 1;
                yield account_preimage_entry;
            }
        }
    }
}

// Takes a stream of items and batches them into chunks of size `batch_size`
fn batch_stream<T: Clone>(stream: impl Stream<Item = T>, batch_size: usize) -> impl Stream<Item = Vec<T>> {
    stream! {
        pin!(stream);
        let mut batch = Vec::new();
        while let Some(item) = stream.next().await {
            batch.push(item);
            if batch.len() >= batch_size {
                yield batch.clone();
                batch.clear();
            }
        }
        if !batch.is_empty() {
            yield batch;
        }
    }
}

/// Trie preimage extractor for reading from reth database
#[derive(Debug)]
pub struct TriePreimageExtractor;

impl TriePreimageExtractor {
    /// Extract all preimages from the trie database with streaming to storage
    pub async fn extract_all_preimages_streaming<TX: DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
    ) -> PreimageStorageResult<DumpStatistics> {
        let hashed_cursor_factory = DatabaseHashedCursorFactory::new(tx);
        let trie_cursor_factory = DatabaseTrieCursorFactory::new(tx);
        
        let mut stats = DumpStatistics::default();
        {
            let account_trie_extractor = AccountTriePreimageExtractor::new(
                hashed_cursor_factory,
                trie_cursor_factory,
            );

            let stream = account_trie_extractor.extract_trie_preimages(&mut stats);

            pin!(stream);

            let batch_stream = batch_stream(stream, 25);

            pin!(batch_stream);

            while let Some(batch) = batch_stream.next().await {
                // handle errors
                let batch = batch.into_iter().collect::<Result<Vec<PreimageEntry>, DatabaseError>>()?;
                storage.store_preimages(batch).await?;
            }

        }

        Ok(stats.clone())
    }
}