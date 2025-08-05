use std::sync::{Arc, Mutex};

use crate::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use alloy_primitives::{keccak256, map::HashMap, Address, B256};
use reth_db_api::transaction::DbTx;
use reth_execution_errors::StateProofError;
use reth_trie::{
    hashed_cursor::HashedPostStateCursorFactory,
    proof::{Proof, StorageProof},
    trie_cursor::{CacheCursorFactory, CachedExternalTrieStore, ExternalTrieStore, InMemoryTrieCursorFactory},
    AccountProof, HashedPostStateSorted, HashedStorage, MultiProof, MultiProofTargets,
    StorageMultiProof, TrieInput,
};

/// Extends [`Proof`] with operations specific for working with a database transaction.
pub trait CachedDatabaseProof<'a, TX> {
    /// Create a new [Proof] from database transaction.
    fn from_tx(tx: &'a TX) -> Self;

    /// Generates the state proof for target account based on [`TrieInput`].
    fn cached_overlay_account_proof(
        tx: &'a TX,
        cache: Arc<Mutex<dyn ExternalTrieStore>>,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError>;

    /// Generates the state [`MultiProof`] for target hashed account and storage keys.
    fn cached_overlay_multiproof(
        tx: &'a TX,
        cache: Arc<Mutex<dyn ExternalTrieStore>>,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> Result<MultiProof, StateProofError>;
}

impl<'a, TX: DbTx> CachedDatabaseProof<'a, TX>
    for Proof<DatabaseTrieCursorFactory<'a, TX>, DatabaseHashedCursorFactory<'a, TX>>

{
    /// Create a new [Proof] instance from database transaction.
    fn from_tx(tx: &'a TX) -> Self {
        Self::new(DatabaseTrieCursorFactory::new(tx), DatabaseHashedCursorFactory::new(tx))
    }

    fn cached_overlay_account_proof(
        tx: &'a TX,
        cache: Arc<Mutex<dyn ExternalTrieStore>>,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError> {
        let nodes_sorted = input.nodes.into_sorted();
        let state_sorted = input.state.into_sorted();

        let cached_trie_store: Arc<Mutex<dyn ExternalTrieStore>> = Arc::new(Mutex::new(CachedExternalTrieStore::new(cache)));

        let cached_trie_factory = CacheCursorFactory::new(
            InMemoryTrieCursorFactory::new(
                DatabaseTrieCursorFactory::new(tx),
                &nodes_sorted,
            ),
            HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ),
            cached_trie_store,
        );

        Self::from_tx(tx)
            .with_trie_cursor_factory(cached_trie_factory.clone())
            .with_hashed_cursor_factory(cached_trie_factory)
            .with_prefix_sets_mut(input.prefix_sets)
            .account_proof(address, slots)
    }

    fn cached_overlay_multiproof(
        tx: &'a TX,
        cache: Arc<Mutex<dyn ExternalTrieStore>>,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> Result<MultiProof, StateProofError> {
        let nodes_sorted = input.nodes.into_sorted();
        let state_sorted = input.state.into_sorted();


        let cached_trie_factory = CacheCursorFactory::new(
            InMemoryTrieCursorFactory::new(
                DatabaseTrieCursorFactory::new(tx),
                &nodes_sorted,
            ),
            HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ),
            cache,
        );

        Self::from_tx(tx)
            .with_trie_cursor_factory(cached_trie_factory.clone())
            .with_hashed_cursor_factory(cached_trie_factory)
            .with_prefix_sets_mut(input.prefix_sets)
            .multiproof(targets)
    }
}


/// Extends [`StorageProof`] with operations specific for working with a database transaction.
pub trait CachedDatabaseStorageProof<'a, TX> {
    /// Create a new [`StorageProof`] from database transaction and account address.
    fn from_tx(tx: &'a TX, address: Address) -> Self;

    /// Generates the storage proof for target slot based on [`TrieInput`].
    fn cached_overlay_storage_proof(
        tx: &'a TX,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> Result<reth_trie::StorageProof, StateProofError>;

    /// Generates the storage multiproof for target slots based on [`TrieInput`].
    fn cached_overlay_storage_multiproof(
        tx: &'a TX,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> Result<StorageMultiProof, StateProofError>;
}

impl<'a, TX: DbTx> CachedDatabaseStorageProof<'a, TX>
    for StorageProof<DatabaseTrieCursorFactory<'a, TX>, DatabaseHashedCursorFactory<'a, TX>>
{
    fn from_tx(tx: &'a TX, address: Address) -> Self {
        Self::new(DatabaseTrieCursorFactory::new(tx), DatabaseHashedCursorFactory::new(tx), address)
    }

    fn cached_overlay_storage_proof(
        tx: &'a TX,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> Result<reth_trie::StorageProof, StateProofError> {
        let hashed_address = keccak256(address);
        let prefix_set = storage.construct_prefix_set();
        let state_sorted = HashedPostStateSorted::new(
            Default::default(),
            HashMap::from_iter([(hashed_address, storage.into_sorted())]),
        );
        Self::from_tx(tx, address)
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ))
            .with_prefix_set_mut(prefix_set)
            .storage_proof(slot)
    }

    fn cached_overlay_storage_multiproof(
        tx: &'a TX,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> Result<StorageMultiProof, StateProofError> {
        let hashed_address = keccak256(address);
        let targets = slots.iter().map(keccak256).collect();
        let prefix_set = storage.construct_prefix_set();
        let state_sorted = HashedPostStateSorted::new(
            Default::default(),
            HashMap::from_iter([(hashed_address, storage.into_sorted())]),
        );
        Self::from_tx(tx, address)
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ))
            .with_prefix_set_mut(prefix_set)
            .storage_multiproof(targets)
    }
}
