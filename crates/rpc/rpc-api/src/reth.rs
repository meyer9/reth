use alloy_eips::BlockId;
use alloy_primitives::{map::AddressMap, Bytes, B256, U256, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

// Required for the subscription attributes below
use reth_chain_state as _;

/// Reth API namespace for reth-specific methods
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "reth"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "reth"))]
pub trait RethApi {
    /// Returns all ETH balance changes in a block
    #[method(name = "getBalanceChangesInBlock")]
    async fn reth_get_balance_changes_in_block(
        &self,
        block_id: BlockId,
    ) -> RpcResult<AddressMap<U256>>;

    /// Re-executes a block (or a range of blocks) and returns the execution outcome including
    /// receipts, state changes, and EIP-7685 requests.
    ///
    /// If `count` is provided, re-executes `count` consecutive blocks starting from `block_id`
    /// and returns the merged execution outcome.
    #[method(name = "getBlockExecutionOutcome")]
    async fn reth_get_block_execution_outcome(
        &self,
        block_id: BlockId,
        count: Option<U64>,
    ) -> RpcResult<Option<serde_json::Value>>;

    /// Controls the JIT backend, if one is configured.
    #[method(name = "jit")]
    async fn reth_jit(&self, action: RethJitAction) -> RpcResult<()>;

    /// Returns the current QMDB/MMR root (candidate `stateRoot`) and leaf count.
    #[method(name = "mmrGetRoot")]
    async fn reth_mmr_get_root(&self) -> RpcResult<MmrRootResponse>;

    /// Returns an MMR inclusion proof for the active QMDB op at `key`.
    ///
    /// Key encoding matches the QMDB eth bridge: `0x61 || hashedAddress` for accounts,
    /// `0x73 || hashedAddress || hashedSlot` for storage.
    #[method(name = "mmrGetProof")]
    async fn reth_mmr_get_proof(&self, key: Bytes) -> RpcResult<MmrProofResponse>;

    /// Subscribe to json `ChainNotifications`
    #[subscription(
        name = "subscribeChainNotifications",
        unsubscribe = "unsubscribeChainNotifications",
        item = reth_chain_state::CanonStateNotification
    )]
    async fn reth_subscribe_chain_notifications(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Subscribe to persisted block notifications.
    ///
    /// Emits a notification with the block number and hash when a new block is persisted to disk.
    #[subscription(
        name = "subscribePersistedBlock",
        unsubscribe = "unsubscribePersistedBlock",
        item = alloy_eips::BlockNumHash
    )]
    async fn reth_subscribe_persisted_block(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Subscribe to finalized chain notifications.
    ///
    /// Buffers committed chain notifications and emits them once a new finalized block is received.
    /// Each notification contains all committed chain segments up to the finalized block.
    #[subscription(
        name = "subscribeFinalizedChainNotifications",
        unsubscribe = "unsubscribeFinalizedChainNotifications",
        item = Vec<reth_chain_state::CanonStateNotification>
    )]
    async fn reth_subscribe_finalized_chain_notifications(
        &self,
    ) -> jsonrpsee::core::SubscriptionResult;
}

/// Response for [`RethApi::reth_mmr_get_root`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MmrRootResponse {
    /// QMDB/MMR root digest.
    pub root: B256,
    /// Number of leaves (ops) in the MMR.
    pub leaves: u64,
}

/// Response for [`RethApi::reth_mmr_get_proof`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MmrProofResponse {
    /// Leaf location of the proven op.
    pub location: u64,
    /// Encoded operation bytes that are the MMR leaf element.
    pub leaf: Bytes,
    /// Sibling / peak digests for the inclusion proof.
    pub proof: Vec<B256>,
    /// Root the proof commits to.
    pub root: B256,
}

/// Supported `reth_jit` control actions.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RethJitAction {
    /// Enable JIT compilation for the backend.
    Enable,
    /// Disable JIT compilation for the backend.
    Disable,
    /// Pause background JIT compilation.
    Pause,
    /// Resume background JIT compilation.
    Unpause,
    /// Clear resident and persisted JIT artifacts.
    Clear,
}
