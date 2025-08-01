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
use async_stream::{try_stream};

use crate::hash_builder_2::HashBuilder;

const FLUSH_THRESHOLD: usize = 10000;

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
    ) -> impl Stream<Item = Result<StoragePreimageEntry, DatabaseError>> + 'a {
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

                while let Some(node) = node_iter.try_next()? {
                    match node {
                        TrieElement::Branch(_node) => {
                            panic!("should never get branch")
                        }
                        TrieElement::Leaf(hashed_slot, value) => {
                            info!("adding leaf: {:?} {:x}", hashed_slot, value);
                            hash_builder.add_leaf(
                                Nibbles::unpack(hashed_slot),
                                alloy_rlp::encode_fixed_size(&value).as_ref(),
                            );
                        }
                    }
                    
                    let num_updated_storage_branch_nodes = hash_builder.updated_branch_nodes.as_ref().unwrap().len();
                    if num_updated_storage_branch_nodes >= FLUSH_THRESHOLD {
                        let proof_nodes = hash_builder.take_proof_nodes();
                        let (new_hash_builder, _updated_branch_nodes) = hash_builder.split();

                        for (key, value) in proof_nodes.iter() {
                            let hash_data = keccak256(&value);
                            let storage_preimage_entry = StoragePreimageEntry {
                                hash: hash_data,
                                hashed_address: self.hashed_address,
                                path: *key,
                                data: value.to_vec(),
                            };
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
                    let storage_preimage_entry = StoragePreimageEntry {
                        hash: hash_data,
                        hashed_address: self.hashed_address,
                        path: *key,
                        data: value.to_vec(),
                    };
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
    root: Option<B256>,
}

impl<H: HashedCursorFactory + Clone, T: TrieCursorFactory + Clone> AccountTriePreimageExtractor<H, T> {
    fn new(
        hashed_cursor_factory: H,
        trie_cursor_factory: T,
    ) -> Self {
        Self { hashed_cursor_factory, trie_cursor_factory, root: None }
    }

    fn extract_trie_preimages(
        self,
    ) -> impl Stream<Item = Result<PreimageEntry, DatabaseError>> {
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
                        let num_updated_branch_nodes = hash_builder.updated_branch_nodes.as_ref().unwrap().len();

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

                            for (key, value) in retained_proof_nodes.iter() {
                                let hash_data = keccak256(&value);
                                let account_preimage_entry = PreimageEntry::Account(AccountPreimageEntry {
                                    hash: hash_data,
                                    path: *key,
                                    data: value.to_vec(),
                                });
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
                        let storage_stream = storage_root_extractor.extract_trie_preimages();
                        {
                            pin!(storage_stream);
                            while let Some(res) = storage_stream.next().await {
                                yield PreimageEntry::Storage(res?);
                            }
                        }

                        info!("storage root: {:?} {:x}", storage_root_extractor.root, hashed_address);

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
                let account_preimage_entry = PreimageEntry::Account(AccountPreimageEntry {
                    hash: hash_data,
                    path: *key,
                    data: value.to_vec(),
                });
                yield account_preimage_entry;
            }
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
    ) -> PreimageStorageResult<()> {
        let hashed_cursor_factory = DatabaseHashedCursorFactory::new(tx);
        let trie_cursor_factory = DatabaseTrieCursorFactory::new(tx);

        let account_trie_extractor = AccountTriePreimageExtractor::new(
            hashed_cursor_factory,
            trie_cursor_factory,
        );

        let stream = account_trie_extractor.extract_trie_preimages();

        pin!(stream);

        while let Some(res) = stream.next().await {
            let preimage = res?;
            storage.store_preimage(preimage).await?;
        }

        Ok(())
    }
}