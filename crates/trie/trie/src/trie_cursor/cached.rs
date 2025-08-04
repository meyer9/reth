use crate::{hashed_cursor::HashedCursorFactory, BranchNodeCompact, Nibbles};
use alloy_primitives::B256;
use reth_storage_errors::{db::DatabaseError, provider::ProviderError};
use reth_trie_common::BranchNode;
use tracing::{info, warn};
use std::{collections::HashMap, fmt::Debug, sync::{Arc}};
// Add DynamoDB imports
use aws_sdk_dynamodb::{
    error::DisplayErrorContext,
    types::{AttributeDefinition, AttributeValue, KeySchemaElement, ProvisionedThroughput},
    Client,
};
use aws_config::Region;
use alloy_rlp::{Decodable, Encodable};
use async_trait::async_trait;
use std::sync::mpsc;

use super::{TrieCursor, TrieCursorFactory};

/// DynamoDB-based external trie store for caching trie nodes
#[derive(Debug)]
pub struct DynamoDBExternalTrieStore {
    client: Client,
    table_name: String,
}

#[derive(Debug)]
pub struct DynamoDBExternalTrieStoreHandle {
    sender: mpsc::Sender<Message>,
}

impl DynamoDBExternalTrieStoreHandle {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

pub struct Message {
    pub key: Nibbles,
    pub hashed_account: Option<B256>,
    // TODO: allow non-branches
    pub response: mpsc::Sender<Result<Option<BranchNodeCompact>, ProviderError>>,
}

impl DynamoDBExternalTrieStore {
    /// Create a new DynamoDB external trie store
    pub async fn new(
        table_name: String,
        aws_region: Option<String>,
        dynamodb_endpoint_url: Option<String>,
    ) -> Result<Self, ProviderError> {
        // Load AWS configuration with optional custom endpoint
        let mut aws_config_builder =
            aws_config::defaults(aws_config::BehaviorVersion::v2025_01_17());

        // Set region if provided
        if let Some(region) = aws_region {
            aws_config_builder = aws_config_builder.region(Region::new(region));
        }

        let aws_config = aws_config_builder.load().await;

        // Create client with optional custom endpoint
        let client = if let Some(endpoint_url) = dynamodb_endpoint_url {
            info!("Using custom DynamoDB endpoint: {}", endpoint_url);
            Client::from_conf(
                aws_sdk_dynamodb::config::Builder::from(&aws_config)
                    .endpoint_url(endpoint_url)
                    .build(),
            )
        } else {
            Client::new(&aws_config)
        };

        let store = Self { client, table_name };

        Ok(store)
    }

    /// Convert Nibbles path to DynamoDB key
    fn path_to_key(&self, path: &Nibbles) -> Vec<u8> {
        let mut encoded = Vec::new();
        path.encode(&mut encoded);
        encoded
    }

    /// Convert DynamoDB item to BranchNodeCompact
    fn item_to_node(&self, item: &HashMap<String, AttributeValue>) -> Result<BranchNodeCompact, ProviderError> {
        let node_data = item
            .get("data")
            .and_then(|v| v.as_b().ok())
            .ok_or_else(|| {
                ProviderError::Database(DatabaseError::Other("Missing node_data field".to_string()))
            })?;

        let hash = item
            .get("hash")
            .and_then(|v| v.as_b().ok())
            .ok_or_else(|| {
                ProviderError::Database(DatabaseError::Other("Missing hash field".to_string()))
            })?;

        if hash.as_ref().len() != 32 {
            return Err(ProviderError::Database(DatabaseError::Other("Invalid hash length".to_string())));
        }

        let hash = B256::from_slice(hash.as_ref());

        let mut node_data = node_data.as_ref(); 
        let branch_node = BranchNode::decode(&mut node_data)?;

        let branch_node_compact = BranchNodeCompact::new(
            branch_node.state_mask,
            branch_node.state_mask,
            branch_node.state_mask,
            branch_node.stack.iter().map(|node| node.as_hash().unwrap()).collect(),
            Some(hash),
        );

        Ok(branch_node_compact)
    }


    async fn get_trie_node(&self, key: &Nibbles) -> Result<Option<BranchNodeCompact>, ProviderError> {
        let mut key_map = HashMap::new();

        key_map.insert("full_path".to_string(), AttributeValue::B(self.path_to_key(&key).into()));
        key_map.insert("block_number".to_string(), AttributeValue::N("0".to_string()));

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(key_map))
            .send()
            .await
            .map_err(|e| {
                ProviderError::Database(DatabaseError::Other(format!(
                    "Failed to get trie node: {}",
                    DisplayErrorContext(e)
                )))
            })?;

        if let Some(item) = response.item {
            let Ok(node) = self.item_to_node(&item) else {
                warn!("Invalid trie node in DynamoDB for key: {:?}", key);
                return Ok(None);
            };
            info!("Retrieved trie node from DynamoDB for key: {:?}", key);
            Ok(Some(node))
        } else {
            info!("Trie node not found in DynamoDB for key: {:?}", key);
            Ok(None)
        }
    }

    pub async fn serve(&self, receiver: &mut mpsc::Receiver<Message>) {
        loop {
            let message = receiver.recv().unwrap();
            let key = message.key;
            // let hashed_account = message.hashed_account;
            let tx = message.response;

            let result = self.get_trie_node(&key).await;
            tx.send(result).unwrap();
        }
    }
}

impl ExternalTrieStore for DynamoDBExternalTrieStoreHandle {
    fn get_trie_node(&self, key: &Nibbles) -> Result<Option<BranchNodeCompact>, ProviderError> {
        info!("Fetching trie node from cache for key: {:?}", key);
        let (tx, rx) = mpsc::channel();
        let message = Message { key: key.clone(), hashed_account: None, response: tx };
        self.sender.send(message).unwrap();
        rx.recv().unwrap()
    }
}

/// Example in-memory external cache for trie nodes.
#[derive(Debug, Clone)]
pub struct InMemoryExternalTrieStore {
}

impl InMemoryExternalTrieStore {
    pub fn new() -> Self {
        Self {
        }
    }
}

impl ExternalTrieStore for InMemoryExternalTrieStore {
    fn get_trie_node(&self, key: &Nibbles) -> Result<Option<BranchNodeCompact>, ProviderError> {
        info!("Fetching trie node from cache for key: {:?}", key);
        Ok(None)
    }
}

/// Trait for external key-value storage of trie nodes.
pub trait ExternalTrieStore: Send + Sync + Debug {
    /// Get a trie node by its key.
    fn get_trie_node(&self, key: &Nibbles) -> Result<Option<BranchNodeCompact>, ProviderError>;
}

/// Cached trie cursor that first checks external cache before falling back to the inner cursor.
#[derive(Debug)]
pub struct CachedTrieCursor<C> {
    inner: C,
    cache: Arc<dyn ExternalTrieStore>,
    current: Option<(Nibbles, BranchNodeCompact)>,
}

impl<C> CachedTrieCursor<C> {
    /// Create a new cached trie cursor.
    pub fn new(inner: C, cache: Arc<dyn ExternalTrieStore>) -> Self {
        Self { inner, cache, current: None }
    }
}

impl<C: TrieCursor> TrieCursor for CachedTrieCursor<C> {
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {

            // First try the cache
            if let Some(node) = self.cache.get_trie_node(&key).map_err(|e| {
                DatabaseError::Other(format!("Cache error: {e}"))
            })? {
                return Ok(Some((key, node)));
            }

            // Fall back to inner cursor
            self.current = None;
            warn!("seeking exact");
            let result = self.inner.seek_exact(key)?;

            Ok(result)
    }

    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        // First try the cache
        if let Some(node) = self.cache.get_trie_node(&key).map_err(|e| {
            DatabaseError::Other(format!("Cache error: {e}"))
        })? {
            return Ok(Some((key, node)));
        }

        // Fall back to inner cursor
        self.current = None;
        warn!("seeking");
        let result = self.inner.seek(key)?;

        Ok(result)
    }

    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        panic!("not implemented");

        // Ok(result)
    }

    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        if let Some(current) = &self.current {
            Ok(Some(current.0))
        } else {
            Ok(None)
        }
    }
}

/// Cached trie cursor factory that wraps cursors with caching.
#[derive(Debug, Clone)]
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

    fn account_trie_cursor(&self) -> Result<Self::AccountTrieCursor, DatabaseError> {
        let inner = self.inner.account_trie_cursor()?;
        Ok(CachedTrieCursor::new(inner, self.cache.clone()))
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageTrieCursor, DatabaseError> {
        let inner = self.inner.storage_trie_cursor(hashed_address)?;
        Ok(CachedTrieCursor::new(inner, self.cache.clone()))
    }
}

/// Cache cursor factory that wraps both trie cursor and hashed cursor factories with caching.
///
/// This factory provides caching for both trie nodes (branches) and hashed key-value pairs (leaves).
/// It first tries to fetch data from the external cache before falling back to the underlying
/// cursor factories.
#[derive(Debug, Clone)]
pub struct CacheCursorFactory<T, H> {
    /// Trie cursor factory for fetching trie nodes (branches)
    trie_cursor_factory: CachedTrieCursorFactory<T>,
    /// Hashed cursor factory for fetching account/storage key-value pairs (leaves)
    hashed_cursor_factory: H,
    /// External cache for trie nodes
    cache: Arc<dyn ExternalTrieStore>,
}

impl<T, H> CacheCursorFactory<T, H> {
    /// Create a new cache cursor factory.
    ///
    /// # Arguments
    /// * `trie_cursor_factory` - Factory for creating trie cursors (for branch nodes)
    /// * `hashed_cursor_factory` - Factory for creating hashed cursors (for leaf data)
    /// * `cache` - External cache for storing/retrieving trie nodes
    pub fn new(
        trie_cursor_factory: T,
        hashed_cursor_factory: H,
        cache: Arc<dyn ExternalTrieStore>,
    ) -> Self {
        Self {
            trie_cursor_factory: CachedTrieCursorFactory::new(trie_cursor_factory, cache.clone()),
            hashed_cursor_factory,
            cache,
        }
    }
}

impl<T: TrieCursorFactory, H> TrieCursorFactory for CacheCursorFactory<T, H> {
    type AccountTrieCursor = <CachedTrieCursorFactory<T> as TrieCursorFactory>::AccountTrieCursor;
    type StorageTrieCursor = <CachedTrieCursorFactory<T> as TrieCursorFactory>::StorageTrieCursor;

    fn account_trie_cursor(&self) -> Result<Self::AccountTrieCursor, DatabaseError> {
        self.trie_cursor_factory.account_trie_cursor()
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageTrieCursor, DatabaseError> {
        self.trie_cursor_factory.storage_trie_cursor(hashed_address)
    }
}

impl<T, H: HashedCursorFactory> HashedCursorFactory for CacheCursorFactory<T, H> {
    type AccountCursor = H::AccountCursor;
    type StorageCursor = H::StorageCursor;

    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor, DatabaseError> {
        // TODO: Add caching logic for hashed cursors
        self.hashed_cursor_factory.hashed_account_cursor()
    }

    fn hashed_storage_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageCursor, DatabaseError> {
        // TODO: Add caching logic for hashed storage cursors
        self.hashed_cursor_factory.hashed_storage_cursor(hashed_address)
    }
}