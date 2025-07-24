use crate::{
    AccountReader, BlockHashReader, HashedPostStateProvider, HistoricalStateProvider, ProviderError, StateProvider, StateRootProvider
};
use alloy_primitives::{Address, BlockNumber, Bytes, StorageKey, StorageValue, B256};
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    BlockNumReader, BytecodeReader, DBProvider, StateCommitmentProvider, StateProofProvider,
    StorageRootProvider,
};
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{
    proof::{Proof},
    trie_cursor::{ExternalTrieStore, TrieCursor, TrieCursorFactory},
    updates::TrieUpdates,
    AccountProof, BranchNodeCompact, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, Nibbles, StorageMultiProof, TrieInput,
};
use reth_trie_db::{
    CachedDatabaseProof
};
use revm_database::BundleState;
use std::{fmt::Debug, sync::Arc};

/// Cached trie cursor that first checks external cache before falling back to the inner cursor.
#[derive(Debug)]
pub struct CachedTrieCursor<C> {
    inner: C,
    cache: Arc<dyn ExternalTrieStore>,
}

impl<C> CachedTrieCursor<C> {
    /// Create a new cached trie cursor.
    pub fn new(inner: C, cache: Arc<dyn ExternalTrieStore>) -> Self {
        Self { inner, cache }
    }
}

impl<C: TrieCursor> TrieCursor for CachedTrieCursor<C> {
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, reth_storage_errors::db::DatabaseError> {
        // First try the cache
        if let Some(node) = self.cache.get_trie_node(&key).map_err(|e| {
            reth_storage_errors::db::DatabaseError::Other(format!("Cache error: {e}"))
        })? {
            return Ok(Some((key, node)));
        }

        // Fall back to inner cursor
        let result = self.inner.seek_exact(key)?;

        // Cache the result if found
        if let Some((found_key, ref node)) = result {
            let _ = self.cache.put_trie_node(found_key, node.clone());
        }

        Ok(result)
    }

    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, reth_storage_errors::db::DatabaseError> {
        // For seek operations, we can't easily check cache first since we need >= behavior
        let result = self.inner.seek(key)?;

        // Cache the result if found
        if let Some((found_key, ref node)) = result {
            let _ = self.cache.put_trie_node(found_key, node.clone());
        }

        Ok(result)
    }

    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, reth_storage_errors::db::DatabaseError> {
        let result = self.inner.next()?;

        // Cache the result if found
        if let Some((found_key, ref node)) = result {
            let _ = self.cache.put_trie_node(found_key, node.clone());
        }

        Ok(result)
    }

    fn current(&mut self) -> Result<Option<Nibbles>, reth_storage_errors::db::DatabaseError> {
        self.inner.current()
    }
}

/// Cached trie cursor factory that wraps cursors with caching.
#[derive(Debug)]
pub struct CachedTrieCursorFactory<F> {
    inner: F,
    cache: Arc<dyn ExternalTrieStore>,
}

impl<F> CachedTrieCursorFactory<F> {
    /// Create a new cached trie cursor factory.
    pub fn new(inner: F, cache: Arc<dyn ExternalTrieStore>) -> Self {
        Self { inner, cache }
    }
}

impl<F: TrieCursorFactory> TrieCursorFactory for CachedTrieCursorFactory<F> {
    type AccountTrieCursor = CachedTrieCursor<F::AccountTrieCursor>;
    type StorageTrieCursor = CachedTrieCursor<F::StorageTrieCursor>;

    fn account_trie_cursor(&self) -> Result<Self::AccountTrieCursor, reth_storage_errors::db::DatabaseError> {
        let inner = self.inner.account_trie_cursor()?;
        Ok(CachedTrieCursor::new(inner, self.cache.clone()))
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageTrieCursor, reth_storage_errors::db::DatabaseError> {
        let inner = self.inner.storage_trie_cursor(hashed_address)?;
        Ok(CachedTrieCursor::new(inner, self.cache.clone()))
    }
}


/// External historical cache wrapper that provides caching on top of HistoricalStateProvider.
///
/// This cache intercepts trie node accesses and attempts to serve them from an external
/// key-value store before falling back to the underlying provider.
#[derive(Debug)]
pub struct ExternalHistoricalCache<Provider> {
    /// Inner historical state provider
    inner: Box<HistoricalStateProvider<Provider>>,
    /// External trie store for caching trie nodes
    cache: Arc<dyn ExternalTrieStore + 'static>,
}

impl<Provider: DBProvider + BlockNumReader + StateCommitmentProvider>
    ExternalHistoricalCache<Provider>
{
    /// Create a new external historical cache wrapper.
    pub fn new(
        inner: HistoricalStateProvider<Provider>,
        cache: Arc<dyn ExternalTrieStore + 'static>,
    ) -> Self {
        Self { inner: Box::new(inner), cache }
    }
}

impl<Provider: StateCommitmentProvider> StateCommitmentProvider
    for ExternalHistoricalCache<Provider>
{
    type StateCommitment = Provider::StateCommitment;
}

impl<Provider: DBProvider + BlockNumReader + StateCommitmentProvider> AccountReader
    for ExternalHistoricalCache<Provider>
{
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.inner.basic_account(address)
    }
}

impl<Provider: DBProvider + BlockNumReader + BlockHashReader + StateCommitmentProvider> BlockHashReader
    for ExternalHistoricalCache<Provider>
{
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl<Provider: DBProvider + BlockNumReader + StateCommitmentProvider> StateRootProvider
    for ExternalHistoricalCache<Provider>
{
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        // Delegate to inner provider - the cache is primarily for trie node access
        // which happens automatically through the cached cursor factory in more complex operations
        self.inner.state_root(hashed_state)
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        // Delegate to inner provider
        self.inner.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        // Delegate to inner provider
        self.inner.state_root_with_updates(hashed_state)
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        // Delegate to inner provider
        self.inner.state_root_from_nodes_with_updates(input)
    }
}

impl<Provider: DBProvider + BlockNumReader + StateCommitmentProvider> StorageRootProvider
    for ExternalHistoricalCache<Provider>
{
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        self.inner.storage_root(address, hashed_storage)
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<reth_trie::StorageProof> {
        self.inner.storage_proof(address, slot, hashed_storage)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner.storage_multiproof(address, slots, hashed_storage)
    }
}

impl<Provider: DBProvider + BlockNumReader + StateCommitmentProvider> StateProofProvider
    for ExternalHistoricalCache<Provider>
{
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        Proof::cached_overlay_account_proof((*self.inner).as_ref().tx(), self.cache.clone(), input, address, slots)
            .map_err(ProviderError::from)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {        
        Proof::cached_overlay_multiproof((*self.inner).as_ref().tx(), self.cache.clone(), input, targets)
            .map_err(ProviderError::from)
    }

    fn witness(&self, input: TrieInput, target: HashedPostState) -> ProviderResult<Vec<Bytes>> {        
        // TODO: Implement witness generation with cache support
        self.inner.witness(input, target)
    }
}

impl<Provider: DBProvider + BlockNumReader + BlockHashReader + StateCommitmentProvider>
    StateProvider for ExternalHistoricalCache<Provider>
{
    fn storage(
        &self,
        address: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        self.inner.storage(address, storage_key)
    }
}

impl<Provider: StateCommitmentProvider + BlockNumReader + DBProvider> HashedPostStateProvider for ExternalHistoricalCache<Provider> {
    fn hashed_post_state(&self, bundle_state: &BundleState) -> HashedPostState {
        (*self.inner).as_ref().hashed_post_state(bundle_state)
    }
}

impl<Provider: DBProvider + BlockNumReader + StateCommitmentProvider> BytecodeReader
    for ExternalHistoricalCache<Provider>
{
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.inner.bytecode_by_hash(code_hash)
    }
}