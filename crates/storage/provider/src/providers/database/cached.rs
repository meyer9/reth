use super::DatabaseProvider;
use crate::{
    providers::{StaticFileProvider},
    AccountReader, BlockHashReader, BlockNumReader, BlockReader,
    ChainStateBlockReader, ChangeSetReader, DBProvider, HeaderProvider,
    ProviderResult, ReceiptProvider,
    StageCheckpointReader, StateCommitmentProvider,
    StateProviderBox, StaticFileProviderFactory, StatsReader, StorageReader,
    TransactionsProvider,
};
use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{Address, BlockHash, BlockNumber, B256};
use reth_chainspec::{ChainInfo, ChainSpecProvider};
use reth_db_api::{transaction::DbTx};
use reth_node_types::NodeTypes;
use reth_stages_types::{StageCheckpoint, StageId};
use reth_storage_api::{
    BlockBodyIndicesProvider, NodePrimitivesProvider, StorageChangeSetReader, TryIntoHistoricalStateProvider
};
use reth_trie::trie_cursor::ExternalTrieStore;
use std::{fmt::Debug, ops::RangeInclusive, sync::Arc};

/// A wrapper around [`DatabaseProvider`] that adds external caching capabilities for trie nodes.
///
/// This provider delegates all operations to the inner [`DatabaseProvider`] but provides
/// additional methods to create cached historical state providers that can fetch trie nodes
/// from an external key-value store before falling back to the local database.
#[derive(Debug)]
pub struct CachedDatabaseProvider<TX, N: NodeTypes> {
    /// Inner database provider
    inner: DatabaseProvider<TX, N>,
    /// External trie store for caching trie nodes
    cache: Arc<dyn ExternalTrieStore>,
}

impl<TX, N: NodeTypes> CachedDatabaseProvider<TX, N> {
    /// Create a new cached database provider
    pub fn new(inner: DatabaseProvider<TX, N>, cache: Arc<dyn ExternalTrieStore>) -> Self {
        Self { inner, cache }
    }

    /// Get access to the inner provider
    pub fn inner(&self) -> &DatabaseProvider<TX, N> {
        &self.inner
    }

    /// Get access to the cache
    pub fn cache(&self) -> &Arc<dyn ExternalTrieStore> {
        &self.cache
    }

    /// Consume the wrapper and return the inner provider
    pub fn into_inner(self) -> DatabaseProvider<TX, N> {
        self.inner
    }
}

// Delegate all DatabaseProvider trait implementations to the inner provider
impl<TX, N: NodeTypes> NodePrimitivesProvider for CachedDatabaseProvider<TX, N> {
    type Primitives = N::Primitives;
}

impl<TX, N: NodeTypes> StaticFileProviderFactory for CachedDatabaseProvider<TX, N> {
    fn static_file_provider(&self) -> StaticFileProvider<Self::Primitives> {
        self.inner.static_file_provider()
    }
}

impl<TX: Debug + Send + Sync, N: NodeTypes> ChainSpecProvider for CachedDatabaseProvider<TX, N>
where
    N::ChainSpec: reth_chainspec::EthChainSpec + 'static,
{
    type ChainSpec = N::ChainSpec;

    fn chain_spec(&self) -> Arc<Self::ChainSpec> {
        self.inner.chain_spec()
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> TryIntoHistoricalStateProvider
    for CachedDatabaseProvider<TX, N>
{
    fn try_into_history_at_block(
        self,
        block_number: BlockNumber,
    ) -> ProviderResult<StateProviderBox> {
        self.inner.try_into_history_at_block(block_number)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> StateCommitmentProvider for CachedDatabaseProvider<TX, N> {
    type StateCommitment = N::StateCommitment;
}

impl<TX: DbTx, N: NodeTypes> AccountReader for CachedDatabaseProvider<TX, N> {
    fn basic_account(
        &self,
        address: &Address,
    ) -> ProviderResult<Option<reth_primitives_traits::Account>> {
        self.inner.basic_account(address)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> BlockHashReader for CachedDatabaseProvider<TX, N> {
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

impl<TX: DbTx + 'static, N: NodeTypes> BlockNumReader for CachedDatabaseProvider<TX, N> {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        self.inner.chain_info()
    }

    fn best_block_number(&self) -> ProviderResult<BlockNumber> {
        self.inner.best_block_number()
    }

    fn last_block_number(&self) -> ProviderResult<BlockNumber> {
        self.inner.last_block_number()
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<BlockNumber>> {
        self.inner.block_number(hash)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> BlockReader for CachedDatabaseProvider<TX, N>
where
    N: crate::providers::NodeTypesForProvider,
{
    type Block = <DatabaseProvider<TX, N> as BlockReader>::Block;

    fn find_block_by_hash(
        &self,
        hash: B256,
        source: reth_storage_api::BlockSource,
    ) -> ProviderResult<Option<Self::Block>> {
        self.inner.find_block_by_hash(hash, source)
    }

    fn block(&self, id: BlockHashOrNumber) -> ProviderResult<Option<Self::Block>> {
        self.inner.block(id)
    }

    fn pending_block(&self) -> ProviderResult<Option<reth_primitives_traits::RecoveredBlock<Self::Block>>> {
        self.inner.pending_block()
    }

    fn pending_block_and_receipts(&self) -> ProviderResult<Option<(reth_primitives_traits::RecoveredBlock<Self::Block>, Vec<Self::Receipt>)>> {
        self.inner.pending_block_and_receipts()
    }

    fn recovered_block(
        &self,
        id: BlockHashOrNumber,
        transaction_kind: crate::TransactionVariant,
    ) -> ProviderResult<Option<reth_primitives_traits::RecoveredBlock<Self::Block>>> {
        self.inner.recovered_block(id, transaction_kind)
    }

    fn sealed_block_with_senders(
        &self,
        id: BlockHashOrNumber,
        transaction_kind: crate::TransactionVariant,
    ) -> ProviderResult<Option<reth_primitives_traits::RecoveredBlock<Self::Block>>> {
        self.inner.sealed_block_with_senders(id, transaction_kind)
    }

    fn block_range(&self, range: RangeInclusive<BlockNumber>) -> ProviderResult<Vec<Self::Block>> {
        self.inner.block_range(range)
    }

    fn block_with_senders_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives_traits::RecoveredBlock<Self::Block>>> {
        self.inner.block_with_senders_range(range)
    }

    fn recovered_block_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<reth_primitives_traits::RecoveredBlock<Self::Block>>> {
        self.inner.recovered_block_range(range)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> HeaderProvider for CachedDatabaseProvider<TX, N>
where
    N: crate::providers::NodeTypesForProvider,
{
    type Header = <DatabaseProvider<TX, N> as HeaderProvider>::Header;

    fn header(&self, block_hash: &BlockHash) -> ProviderResult<Option<Self::Header>> {
        self.inner.header(block_hash)
    }

    fn header_by_number(&self, num: BlockNumber) -> ProviderResult<Option<Self::Header>> {
        self.inner.header_by_number(num)
    }

    fn header_td(&self, block_hash: &BlockHash) -> ProviderResult<Option<alloy_primitives::U256>> {
        self.inner.header_td(block_hash)
    }

    fn header_td_by_number(&self, number: BlockNumber) -> ProviderResult<Option<alloy_primitives::U256>> {
        self.inner.header_td_by_number(number)
    }

    fn headers_range(
        &self,
        range: impl std::ops::RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Self::Header>> {
        self.inner.headers_range(range)
    }

    fn sealed_header(
        &self,
        number: BlockNumber,
    ) -> ProviderResult<Option<reth_primitives_traits::SealedHeader<Self::Header>>> {
        self.inner.sealed_header(number)
    }

    fn sealed_headers_while(
        &self,
        range: impl std::ops::RangeBounds<BlockNumber>,
        predicate: impl FnMut(&reth_primitives_traits::SealedHeader<Self::Header>) -> bool,
    ) -> ProviderResult<Vec<reth_primitives_traits::SealedHeader<Self::Header>>> {
        self.inner.sealed_headers_while(range, predicate)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> TransactionsProvider for CachedDatabaseProvider<TX, N>
where
    N: crate::providers::NodeTypesForProvider,
{
    type Transaction = <DatabaseProvider<TX, N> as TransactionsProvider>::Transaction;

    fn transaction_id(&self, tx_hash: alloy_primitives::TxHash) -> ProviderResult<Option<alloy_primitives::TxNumber>> {
        self.inner.transaction_id(tx_hash)
    }

    fn transaction_by_id(&self, id: alloy_primitives::TxNumber) -> ProviderResult<Option<Self::Transaction>> {
        self.inner.transaction_by_id(id)
    }

    fn transaction_by_id_unhashed(&self, id: alloy_primitives::TxNumber) -> ProviderResult<Option<Self::Transaction>> {
        self.inner.transaction_by_id_unhashed(id)
    }

    fn transaction_by_hash(&self, hash: alloy_primitives::TxHash) -> ProviderResult<Option<Self::Transaction>> {
        self.inner.transaction_by_hash(hash)
    }

    fn transaction_by_hash_with_meta(
        &self,
        tx_hash: alloy_primitives::TxHash,
    ) -> ProviderResult<Option<(Self::Transaction, alloy_consensus::transaction::TransactionMeta)>> {
        self.inner.transaction_by_hash_with_meta(tx_hash)
    }

    fn transaction_block(&self, id: alloy_primitives::TxNumber) -> ProviderResult<Option<BlockNumber>> {
        self.inner.transaction_block(id)
    }

    fn transactions_by_block(
        &self,
        id: BlockHashOrNumber,
    ) -> ProviderResult<Option<Vec<Self::Transaction>>> {
        self.inner.transactions_by_block(id)
    }

    fn transactions_by_block_range(
        &self,
        range: impl std::ops::RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Transaction>>> {
        self.inner.transactions_by_block_range(range)
    }

    fn transactions_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<alloy_primitives::TxNumber>,
    ) -> ProviderResult<Vec<Self::Transaction>> {
        self.inner.transactions_by_tx_range(range)
    }

    fn senders_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<alloy_primitives::TxNumber>,
    ) -> ProviderResult<Vec<Address>> {
        self.inner.senders_by_tx_range(range)
    }

    fn transaction_sender(&self, id: alloy_primitives::TxNumber) -> ProviderResult<Option<Address>> {
        self.inner.transaction_sender(id)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> ReceiptProvider for CachedDatabaseProvider<TX, N>
where
    N: crate::providers::NodeTypesForProvider,
{
    type Receipt = <DatabaseProvider<TX, N> as ReceiptProvider>::Receipt;

    fn receipt(&self, id: alloy_primitives::TxNumber) -> ProviderResult<Option<Self::Receipt>> {
        self.inner.receipt(id)
    }

    fn receipt_by_hash(&self, hash: alloy_primitives::TxHash) -> ProviderResult<Option<Self::Receipt>> {
        self.inner.receipt_by_hash(hash)
    }

    fn receipts_by_block(&self, block: BlockHashOrNumber) -> ProviderResult<Option<Vec<Self::Receipt>>> {
        self.inner.receipts_by_block(block)
    }

    fn receipts_by_tx_range(
        &self,
        range: impl std::ops::RangeBounds<alloy_primitives::TxNumber>,
    ) -> ProviderResult<Vec<Self::Receipt>> {
        self.inner.receipts_by_tx_range(range)
    }

    fn receipts_by_block_range(
        &self,
        block_range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<Vec<Self::Receipt>>> {
        self.inner.receipts_by_block_range(block_range)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> BlockBodyIndicesProvider for CachedDatabaseProvider<TX, N>
where
    N: crate::providers::NodeTypesForProvider,
{
    fn block_body_indices(&self, num: u64) -> ProviderResult<Option<reth_db_api::models::StoredBlockBodyIndices>> {
        self.inner.block_body_indices(num)
    }

    fn block_body_indices_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<Vec<reth_db_api::models::StoredBlockBodyIndices>> {
        self.inner.block_body_indices_range(range)
    }
}

impl<TX: DbTx, N: NodeTypes> StageCheckpointReader for CachedDatabaseProvider<TX, N> {
    fn get_stage_checkpoint(&self, id: StageId) -> ProviderResult<Option<StageCheckpoint>> {
        self.inner.get_stage_checkpoint(id)
    }

    fn get_stage_checkpoint_progress(&self, id: StageId) -> ProviderResult<Option<Vec<u8>>> {
        self.inner.get_stage_checkpoint_progress(id)
    }

    fn get_all_checkpoints(&self) -> ProviderResult<Vec<(String, StageCheckpoint)>> {
        self.inner.get_all_checkpoints()
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> StorageReader for CachedDatabaseProvider<TX, N> {
    fn plain_state_storages(
        &self,
        addresses_with_keys: impl IntoIterator<Item = (Address, impl IntoIterator<Item = B256>)>,
    ) -> ProviderResult<Vec<(Address, Vec<reth_primitives_traits::StorageEntry>)>> {
        self.inner.plain_state_storages(addresses_with_keys)
    }

    fn changed_storages_with_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<std::collections::BTreeMap<Address, std::collections::BTreeSet<B256>>> {
        self.inner.changed_storages_with_range(range)
    }

    fn changed_storages_and_blocks_with_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> ProviderResult<std::collections::BTreeMap<(Address, B256), Vec<u64>>> {
        self.inner.changed_storages_and_blocks_with_range(range)
    }
}

impl<TX: DbTx, N: NodeTypes> StorageChangeSetReader for CachedDatabaseProvider<TX, N> {
    fn storage_changeset(
        &self,
        block_number: BlockNumber,
    ) -> ProviderResult<Vec<(reth_db_api::models::BlockNumberAddress, reth_primitives_traits::StorageEntry)>> {
        self.inner.storage_changeset(block_number)
    }
}

impl<TX: DbTx, N: NodeTypes> ChangeSetReader for CachedDatabaseProvider<TX, N> {
    fn account_block_changeset(
        &self,
        block_number: BlockNumber,
    ) -> ProviderResult<Vec<reth_db_api::models::AccountBeforeTx>> {
        self.inner.account_block_changeset(block_number)
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> StatsReader for CachedDatabaseProvider<TX, N>
where
    N: crate::providers::NodeTypesForProvider,
{
    fn count_entries<T: reth_db_api::table::Table>(&self) -> ProviderResult<usize> {
        self.inner.count_entries::<T>()
    }
}

impl<TX: DbTx + 'static, N: NodeTypes> ChainStateBlockReader for CachedDatabaseProvider<TX, N> {
    fn last_finalized_block_number(&self) -> ProviderResult<Option<BlockNumber>> {
        self.inner.last_finalized_block_number()
    }

    fn last_safe_block_number(&self) -> ProviderResult<Option<BlockNumber>> {
        self.inner.last_safe_block_number()
    }
}

impl<TX: DbTx + 'static, N: NodeTypes + 'static> DBProvider for CachedDatabaseProvider<TX, N> {
    type Tx = TX;

    fn tx_ref(&self) -> &Self::Tx {
        self.inner.tx_ref()
    }

    fn tx_mut(&mut self) -> &mut Self::Tx {
        self.inner.tx_mut()
    }

    fn into_tx(self) -> Self::Tx {
        self.inner.into_tx()
    }

    fn prune_modes_ref(&self) -> &reth_prune_types::PruneModes {
        self.inner.prune_modes_ref()
    }
}
