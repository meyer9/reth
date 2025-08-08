use std::sync::{Arc, Mutex};

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
    trie_cursor::{ExternalTrieStore, ExternalTrieStoreHandle, ExternalTrieStoreWithMaxBlockNumber, TrieCursor, TrieCursorFactory},
    updates::TrieUpdates,
    AccountProof, BranchNodeCompact, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, Nibbles, StorageMultiProof, TrieInput, TrieNode,
};
use reth_trie_db::{
    CachedDatabaseProof
};
use revm_database::BundleState;

pub struct ExternalHistoricalCacheRef<'a, Provider> {
    provider: HistoricalStateProviderRef<'a, Provider>,
    cache: ExternalTrieStoreHandle,
    block_number: u64,
}

impl<'a, Provider> ExternalHistoricalCacheRef<'a, Provider> {
    /// Create a new reference to the external historical cache.
    pub fn new(provider: HistoricalStateProviderRef<'a, Provider>, cache: ExternalTrieStoreHandle, block_number: u64) -> Self {
        Self { provider, cache, block_number }
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

    block_number: u64,
}

impl<Provider: BlockNumReader + DBProvider + StateCommitmentProvider> ExternalHistoricalCache<Provider> {
    /// Create a new external historical cache wrapper.
    pub fn new(
        inner: HistoricalStateProvider<Provider>,
        cache: ExternalTrieStoreHandle,
        block_number: u64,
    ) -> Self {
        Self { inner, cache, block_number }
    }

    /// Returns a new provider that takes the `TX` as reference
    #[inline(always)]
    pub fn as_ref(&self) -> ExternalHistoricalCacheRef<'_, Provider> {
        ExternalHistoricalCacheRef::new(self.inner.as_ref(), self.cache.clone(), self.block_number)
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
        Proof::cached_overlay_account_proof(self.provider.tx(), ExternalTrieStoreWithMaxBlockNumber::new(self.cache.clone(), self.block_number), input, address, slots)
            .map_err(ProviderError::from)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {        
        Proof::cached_overlay_multiproof(self.provider.tx(), ExternalTrieStoreWithMaxBlockNumber::new(self.cache.clone(), self.block_number), input, targets)
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
