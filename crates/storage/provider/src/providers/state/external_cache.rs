use crate::{
    providers::state::macros::delegate_provider_impls, AccountReader, BlockHashReader, CachedDatabaseProvider, DatabaseProvider, HashedPostStateProvider, HistoricalStateProvider, HistoricalStateProviderRef, ProviderError, StateProvider, StateRootProvider
};
use alloy_primitives::{Address, BlockNumber, Bytes, StorageKey, StorageValue, B256};
use reth_db::transaction::DbTx;
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    BlockNumReader, BytecodeReader, DBProvider, StateCommitmentProvider, StateProofProvider,
    StorageRootProvider,
};
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{
    proof::Proof,
    trie_cursor::{ExternalTrieStore, ExternalTrieStoreHandle, TrieCursor, TrieCursorFactory},
    updates::TrieUpdates,
    AccountProof, BranchNodeCompact, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, Nibbles, StorageMultiProof, TrieInput, TrieNode,
};
use reth_trie_db::{
    CachedDatabaseProof
};
use revm_database::BundleState;
use std::{fmt::Debug, sync::{Arc, Mutex}};
use futures::executor::block_on;

/// Cached trie cursor that first checks external cache before falling back to the inner cursor.
#[derive(Debug)]
pub struct CachedTrieCursor<C> {
    inner: C,
    cache: Arc<Mutex<dyn ExternalTrieStore>>,
}

impl<C> CachedTrieCursor<C> {
    /// Create a new cached trie cursor.
    pub fn new(inner: C, cache: Arc<Mutex<dyn ExternalTrieStore>>) -> Self {
        Self { inner, cache }
    }
}

impl<C: TrieCursor> TrieCursor for CachedTrieCursor<C> {
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, reth_storage_errors::db::DatabaseError> {
        // First try the cache
        if let Some(TrieNode::Branch(branch_node)) = self.cache.lock().unwrap().get_trie_node(&key, None).map_err(|e| {
            reth_storage_errors::db::DatabaseError::Other(format!("Cache error: {e}"))
        })? {

        let branch_node_compact = BranchNodeCompact::new(
            branch_node.state_mask,
            branch_node.state_mask,
            branch_node.state_mask,
            branch_node.stack.iter().map(|node| node.as_hash().unwrap()).collect(),
            None,
        );
            return Ok(Some((key, branch_node_compact)));
        }

        // Fall back to inner cursor
        let result = self.inner.seek_exact(key)?;

        Ok(result)
    }

    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, reth_storage_errors::db::DatabaseError> {
        // For seek operations, we can't easily check cache first since we need >= behavior
        let result = self.inner.seek(key)?;


        Ok(result)
    }

    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, reth_storage_errors::db::DatabaseError> {
        let result = self.inner.next()?;

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
    cache: Arc<Mutex<dyn ExternalTrieStore>>,
}

impl<F> CachedTrieCursorFactory<F> {
    /// Create a new cached trie cursor factory.
    pub fn new(inner: F, cache: Arc<Mutex<dyn ExternalTrieStore>>) -> Self {
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

pub struct ExternalHistoricalCacheRef<'a, Provider> {
    provider: HistoricalStateProviderRef<'a, Provider>,
    cache: ExternalTrieStoreHandle,
}

impl<'a, Provider> ExternalHistoricalCacheRef<'a, Provider> {
    /// Create a new reference to the external historical cache.
    pub fn new(provider: HistoricalStateProviderRef<'a, Provider>, cache: ExternalTrieStoreHandle) -> Self {
        Self { provider, cache }
    }
}

delegate_provider_impls!(ExternalHistoricalCache<Provider> where [Provider: DBProvider + BlockNumReader + BlockHashReader + StateCommitmentProvider]);

/// External historical cache wrapper that provides caching on top of HistoricalStateProvider.
///
/// This cache intercepts trie node accesses and attempts to serve them from an external
/// key-value store before falling back to the underlying provider.
#[derive(Debug)]
pub struct ExternalHistoricalCache<Provider> {
    /// Inner historical state provider
    inner: HistoricalStateProvider<Provider>,
    /// External trie store for caching trie nodes
    cache: ExternalTrieStoreHandle,
}

impl<Provider: BlockNumReader + DBProvider + StateCommitmentProvider> ExternalHistoricalCache<Provider> {
    /// Create a new external historical cache wrapper.
    pub fn new(
        inner: HistoricalStateProvider<Provider>,
        cache: ExternalTrieStoreHandle,
    ) -> Self {
        Self { inner, cache }
    }

    /// Returns a new provider that takes the `TX` as reference
    #[inline(always)]
    pub fn as_ref(&self) -> ExternalHistoricalCacheRef<'_, Provider> {
        ExternalHistoricalCacheRef::new(self.inner.as_ref(), self.cache.clone())
    }
}

impl<Provider: StateCommitmentProvider> StateCommitmentProvider
    for ExternalHistoricalCache<Provider>
{
    type StateCommitment = Provider::StateCommitment;
}

impl<'a, Provider: DBProvider + BlockNumReader + BlockHashReader + StateCommitmentProvider> StateProvider for ExternalHistoricalCacheRef<'a, Provider>
{
    /// Get the storage of a given account.
    fn storage(&self, account: Address, storage_key: StorageKey) -> ProviderResult<Option<StorageValue>> {
        self.provider.storage(account, storage_key)
    }
}

impl<Provider: BlockNumReader + DBProvider + StateCommitmentProvider> AccountReader for ExternalHistoricalCacheRef<'_, Provider> {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.provider.basic_account(address)
    }
}

impl <Provider: BlockHashReader + BlockNumReader + DBProvider> BlockHashReader for ExternalHistoricalCacheRef<'_, Provider> {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        self.provider.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.provider.canonical_hashes_range(start, end)
    }
}

impl<'a, Provider: DBProvider + BlockNumReader + StateCommitmentProvider> StateRootProvider
    for ExternalHistoricalCacheRef<'a, Provider>
{
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        // Delegate to inner provider - the cache is primarily for trie node access
        // which happens automatically through the cached cursor factory in more complex operations
        self.provider.state_root(hashed_state)
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        // Delegate to inner provider
        self.provider.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        // Delegate to inner provider
        self.provider.state_root_with_updates(hashed_state)
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        // Delegate to inner provider
        self.provider.state_root_from_nodes_with_updates(input)
    }
}

impl<'a, Provider: DBProvider + BlockNumReader + StateCommitmentProvider> StorageRootProvider
    for ExternalHistoricalCacheRef<'a, Provider>
{
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        self.provider.storage_root(address, hashed_storage)
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<reth_trie::StorageProof> {
        self.provider.storage_proof(address, slot, hashed_storage)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.provider.storage_multiproof(address, slots, hashed_storage)
    }
}

impl<'a, Provider: DBProvider + BlockNumReader + StateCommitmentProvider> StateProofProvider
    for ExternalHistoricalCacheRef<'a, Provider>
{
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        Proof::cached_overlay_account_proof(self.provider.tx(), self.cache.clone(), input, address, slots)
            .map_err(ProviderError::from)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {        
        Proof::cached_overlay_multiproof(self.provider.tx(), self.cache.clone(), input, targets)
            .map_err(ProviderError::from)
    }

    fn witness(&self, input: TrieInput, target: HashedPostState) -> ProviderResult<Vec<Bytes>> {        
        // TODO: Implement witness generation with cache support
        self.provider.witness(input, target)
    }
}


impl<'a, Provider: StateCommitmentProvider> HashedPostStateProvider for ExternalHistoricalCacheRef<'a, Provider> {
    fn hashed_post_state(&self, bundle_state: &BundleState) -> HashedPostState {
       self.provider.hashed_post_state(bundle_state)
    }
}

impl<'a, Provider: BlockNumReader + StateCommitmentProvider + DBProvider> BytecodeReader
    for ExternalHistoricalCacheRef<'a, Provider>
{
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.provider.bytecode_by_hash(code_hash)
    }
}
