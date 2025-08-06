use crate::{hashed_cursor::{HashedCursor, HashedCursorFactory}, BranchNodeCompact, Nibbles};
use alloy_primitives::B256;
use alloy_trie::{TrieAccount, TrieMask, KECCAK_EMPTY};
use reth_storage_errors::{db::DatabaseError, provider::ProviderError};
use reth_trie_common::{BranchNode, TrieNode};
use tracing::{info, warn};
use std::{cmp::min, collections::HashMap, fmt::Debug, ops::{Deref, DerefMut}, sync::{Arc, Mutex, RwLock}};
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
use schnellru::{ByLength, LruMap};
use reth_primitives_traits::Account;


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
    pub response: mpsc::Sender<Result<Option<TrieNode>, ProviderError>>,
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
    fn item_to_node(&self, item: &HashMap<String, AttributeValue>) -> Result<TrieNode, ProviderError> {
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

        let mut node_data = node_data.as_ref(); 
        let node = TrieNode::decode(&mut node_data).map_err(|e| {
            ProviderError::Database(DatabaseError::Other(format!("Failed to decode trie node: {e}")))
        })?;

        Ok(node)
    }


    async fn get_trie_node(&self, key: &Nibbles) -> Result<Option<TrieNode>, ProviderError> {
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
    fn get_trie_node(&mut self, key: &Nibbles) -> Result<Option<TrieNode>, ProviderError> {
        info!("Fetching trie node from cache for key: {:?}", key);
        let (tx, rx) = mpsc::channel();
        let message = Message { key: key.clone(), hashed_account: None, response: tx };
        self.sender.send(message).unwrap();
        let node = rx.recv().unwrap();
        info!("Got trie node from cache for key: {:?}", key);
        return node;
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
    fn get_trie_node(&mut self, key: &Nibbles) -> Result<Option<TrieNode>, ProviderError> {
        info!("Fetching trie node from cache for key: {:?}", key);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct CachedExternalTrieStore {
    inner: Arc<Mutex<dyn ExternalTrieStore>>,
    cache: Arc<Mutex<LruMap<Nibbles, TrieNode>>>,
}

impl CachedExternalTrieStore {
    pub fn new(inner: Arc<Mutex<dyn ExternalTrieStore>>) -> Self {
        Self { inner, cache: Arc::new(Mutex::new(LruMap::new(ByLength::new(100000)))) }
    }
}

impl ExternalTrieStore for CachedExternalTrieStore {
    fn get_trie_node(&mut self, key: &Nibbles) -> Result<Option<TrieNode>, ProviderError> {
        let cloned_node = {
            let mut cache = self.cache.lock().unwrap();
            cache.get(key).cloned()
        }.clone();
        if let Some(node) = cloned_node {
            Ok(Some(node))
        } else {
            let node = self.inner.lock().unwrap().get_trie_node(key)?.clone();
            if let Some(trie_node) = node {
                let node_clone = trie_node.clone();
                self.cache.lock().unwrap().insert(key.clone(), node_clone.clone());
                return Ok(Some(node_clone));
            }
            Ok(None)
        }
    }
}

/// Trait for external key-value storage of trie nodes.
pub trait ExternalTrieStore: Send + Sync + Debug {
    /// Get a trie node by its key.
    fn get_trie_node(&mut self, key: &Nibbles) -> Result<Option<TrieNode>, ProviderError>;
}

/// Cached trie cursor that first checks external cache before falling back to the inner cursor.
#[derive(Debug)]
pub struct CachedTrieCursor<C> {
    inner: C,
    cache: Arc<Mutex<dyn ExternalTrieStore>>,
    current: Option<(Nibbles, BranchNodeCompact)>,
}

impl<C> CachedTrieCursor<C> {
    /// Create a new cached trie cursor.
    pub fn new(inner: C, cache: Arc<Mutex<dyn ExternalTrieStore>>) -> Self {
        Self { inner, cache, current: None }
    }
}

impl<C: TrieCursor> TrieCursor for CachedTrieCursor<C> {
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        info!("seeking exact in cache for key: {:?}", key);

            let parent_node = {
                self.cache.lock().unwrap().get_trie_node(&key).map_err(|e| {
                    DatabaseError::Other(format!("Cache error: {e}"))
                })
            }.clone()?;

            // First try the cache
            if let Some(node) = parent_node {
                if let TrieNode::Branch(branch_node) = node {
                    // Calculate tree_mask: set bit only for children that are branch/extension nodes
                    let mut tree_mask = TrieMask::default();
                    let mut child_keys = Vec::new();
                    
                    // Collect all child keys that exist
                    for i in 0..16u8 {
                        if branch_node.state_mask.is_bit_set(i) {
                            let mut child_key = key.clone();
                            child_key.push(i);
                            child_keys.push((i, child_key));
                        }
                    }
                    
                    // Check child node types in parallel (conceptually - using batch lookup)
                    let cache = self.cache.clone();
                    for (nibble, child_key) in child_keys {
                        // TODO: error handle
                        if let Ok(Some(child_node)) = cache.lock().unwrap().get_trie_node(&child_key).clone() {
                            match child_node {
                                TrieNode::Branch(_) | TrieNode::Extension(_) => {
                                    // Child is an intermediate node - set tree_mask bit
                                    tree_mask.set_bit(nibble);
                                }
                                TrieNode::Leaf(_) | TrieNode::EmptyRoot => {
                                    // Child is a leaf - don't set tree_mask bit
                                }
                            }
                        }
                    }
                    
                    let branch_node_compact = BranchNodeCompact::new(
                        branch_node.state_mask,
                        tree_mask, // Only set for children that are branch/extension nodes
                        branch_node.state_mask, // hash_mask: all children have hashes available
                        branch_node.stack.iter().map(|node| node.as_hash().unwrap()).collect(),
                        None,
                    );
                    self.current = Some((key.clone(), branch_node_compact.clone()));
                    return Ok(Some((key, branch_node_compact)));
                } else {
                    return Ok(None);
                }
            }

            // Fall back to inner cursor
            self.current = None;
            let result = self.inner.seek_exact(key)?;

            Ok(result)
    }

    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        info!("seeking in cache for key: {:?}", key);

        let parent_node = {
            self.cache.lock().unwrap().get_trie_node(&key).map_err(|e| {
                DatabaseError::Other(format!("Cache error: {e}"))
            })
        }.clone()?;

        // First try the cache
        if let Some(node) = parent_node {
            if let TrieNode::Branch(branch_node) = node {
                // Calculate tree_mask: set bit only for children that are branch/extension nodes
                let mut tree_mask = TrieMask::default();
                let mut child_keys = Vec::new();
                
                // Collect all child keys that exist
                for i in 0..16u8 {
                    if branch_node.state_mask.is_bit_set(i) {
                        let mut child_key = key.clone();
                        child_key.push(i);
                        child_keys.push((i, child_key));
                    }
                }
                
                // Check child node types in parallel (conceptually - using batch lookup)
                let cache = self.cache.clone();
                for (nibble, child_key) in child_keys {
                    if let Ok(Some(child_node)) = cache.lock().unwrap().get_trie_node(&child_key).clone() {
                        match child_node {
                            TrieNode::Branch(_) | TrieNode::Extension(_) => {
                                // Child is an intermediate node - set tree_mask bit
                                tree_mask.set_bit(nibble);
                            }
                            TrieNode::Leaf(_) | TrieNode::EmptyRoot => {
                                // Child is a leaf - don't set tree_mask bit
                            }
                        }
                    }
                }
                
                let branch_node_compact = BranchNodeCompact::new(
                    branch_node.state_mask,
                    tree_mask, // Only set for children that are branch/extension nodes
                    branch_node.state_mask, // hash_mask: all children have hashes available
                    branch_node.stack.iter().map(|node| node.as_hash().unwrap()).collect(),
                    None,
                );
                self.current = Some((key.clone(), branch_node_compact.clone()));
                return Ok(Some((key, branch_node_compact)));
            } else {
                return Ok(None);
            }
        }

        // Fall back to inner cursor
        self.current = None;
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

    fn account_trie_cursor(&self) -> Result<Self::AccountTrieCursor, DatabaseError> {
        info!("creating account trie cursor with cache");
        let inner = self.inner.account_trie_cursor()?;
        Ok(CachedTrieCursor::new(inner, self.cache.clone()))
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageTrieCursor, DatabaseError> {
        info!("creating storage trie cursor with cache");
        let inner = self.inner.storage_trie_cursor(hashed_address)?;
        Ok(CachedTrieCursor::new(inner, self.cache.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct CachedHashedTrieCursor<F> {
    inner: F,
    cache: Arc<Mutex<dyn ExternalTrieStore>>,

    current_key_parent_path: Option<Nibbles>,
    current_key: Option<B256>,
}

impl<F: HashedCursor<Value = Account>> CachedHashedTrieCursor<F> {
    pub fn new(inner: F, cache: Arc<Mutex<dyn ExternalTrieStore>>) -> Self {
        Self { inner, cache, current_key: None, current_key_parent_path: None }
    }


    fn traverse_tree(&mut self, key: B256) -> Result<Option<(B256, Account)>, DatabaseError> {
        let mut parent_key = Nibbles::new();
        let mut current_key = Nibbles::new();
        let mut current = self.cache.lock().unwrap().get_trie_node(&current_key).map_err(|e| {
            DatabaseError::Other(format!("Cache error: {e}"))
        })?.expect("root hash not found").clone();
        let mut nibbles = Nibbles::unpack(key);
        let mut nibbles_iter = nibbles.to_vec().into_iter();

        loop {
            info!("current key: {:?}", current_key);
            if let TrieNode::Branch(branch_node) = current {
                let child_nibble = nibbles_iter.next().unwrap();
                info!("child nibble: {:?}, branch node: {:?}", child_nibble, branch_node.state_mask);

                // first bit after or equal to nibble, otherwise, go up one level
                let next_branch = (child_nibble..=15).find(|&i| branch_node.state_mask.is_bit_set(i));
                parent_key = current_key.clone();
                current_key.push(next_branch.unwrap_or(15));

                // if there is a branch to traverse, follow it
                if let Some(next_branch) = next_branch {
                    current = self.cache.lock().unwrap().get_trie_node(&current_key).ok().flatten().expect("child not found").clone();
                } else {
                    // no branch to traverse >= key, so find the first child after the current key
                    return self.move_to_first_leaf_after(&current_key);
                }
            } else if let TrieNode::Extension(extension_node) = current {
                parent_key = current_key.clone();
                current_key.extend(&extension_node.key);
                let key_nibbles = Nibbles::unpack(key);

                if key_nibbles.starts_with(&current_key) {
                    // move iterator forward and check 
                    current = self.cache.lock().unwrap().get_trie_node(&current_key).ok().flatten().expect("child not found").clone();
                } else {
                    // no branch to traverse >= key, so find the first child after the current key
                    return self.move_to_first_leaf_after(&current_key);
                }
            } else if let TrieNode::Leaf(leaf_node) = current {
                let key_nibbles = current_key.join(&leaf_node.key);
                let full_key = B256::from_slice(&key_nibbles.pack());
                self.current_key = Some(full_key);
                self.current_key_parent_path = Some(parent_key);
                let trie_account = TrieAccount::decode(&mut leaf_node.value.as_slice()).map_err(|e| {
                    DatabaseError::Other(format!("Failed to decode trie account: {e}"))
                })?;
                let account = Account {
                    nonce: trie_account.nonce,
                    balance: trie_account.balance,  
                    bytecode_hash: if trie_account.code_hash == KECCAK_EMPTY { None } else { Some(trie_account.code_hash) },
                };
                return Ok(Some((full_key, account)));
            } else {
                return Ok(None);
            }
        }

    }

    fn move_to_first_leaf_after(&mut self, trie_path: &Nibbles) -> Result<Option<(B256, Account)>, DatabaseError> {
        info!("finding first leaf after trie path: {:?}", trie_path);
        let mut current_key = Nibbles::new();
        let mut current = self.cache.lock().unwrap().get_trie_node(&current_key).map_err(|e| {
            DatabaseError::Other(format!("Cache error: {e}"))
        })?.expect("root hash not found").clone();
        let mut nibbles_iter = trie_path.to_vec().into_iter();

        loop {
            info!("current key: {:?}", current_key);
            if let TrieNode::Branch(branch_node) = current {
                info!("found branch node: {:?}", branch_node.state_mask);
                self.current_key_parent_path = Some(current_key.clone());

                let child_nibble = nibbles_iter.next().unwrap_or_else(|| branch_node.state_mask.first_set_bit_index().expect("no children"));

                // first bit before or equal to child nibble
                let next_branch = (0..=child_nibble).rev().find(|&i| branch_node.state_mask.is_bit_set(i)).unwrap_or(branch_node.state_mask.first_set_bit_index().expect("no children"));
                current_key.push(next_branch);
                current = self.cache.lock().unwrap().get_trie_node(&current_key).ok().flatten().expect("child not found").clone();
            } else if let TrieNode::Extension(extension_node) = current {
                info!("found extension node: {:?}", extension_node.key);
                self.current_key_parent_path = Some(current_key.clone());

                // consume the extension key
                for _ in 0..extension_node.key.len() {
                    nibbles_iter.next();
                }

                current_key.extend(&extension_node.key);
                current = self.cache.lock().unwrap().get_trie_node(&current_key).ok().flatten().expect("child not found").clone();
            } else if let TrieNode::Leaf(leaf_node) = current {
                info!("found leaf node: {:?}", leaf_node.key);
                let key_nibbles = current_key.join(&leaf_node.key);
                let full_key = B256::from_slice(&key_nibbles.pack());
                let trie_account = TrieAccount::decode(&mut leaf_node.value.as_slice()).map_err(|e| {
                    DatabaseError::Other(format!("Failed to decode trie account: {e}"))
                })?;
                let account = Account {
                    nonce: trie_account.nonce,
                    balance: trie_account.balance,
                    bytecode_hash: if trie_account.code_hash == KECCAK_EMPTY { None } else { Some(trie_account.code_hash) },
                };
                self.current_key = Some(full_key);
                return Ok(Some((full_key, account)));
            }
        }
    }
    
    fn next_child(&mut self) -> Result<Option<(B256, Account)>, DatabaseError> {
        let Some((mut current_key_parent_path, current_key)) = self.current_key_parent_path.zip(self.current_key) else {
            return Ok(None);
        };

        let current_key = Nibbles::unpack(current_key);
        info!("finding next child after key: {:?}", current_key);

        while current_key_parent_path.len() > 0 {
            info!("current key parent path: {:?}", current_key_parent_path);
            // get parent
            let Some(parent_node) = self.cache.lock().unwrap().get_trie_node(&current_key_parent_path).map_err(|e| {
                DatabaseError::Other(format!("Cache error: {e}"))
            })?.clone() else {
                current_key_parent_path.pop();
                continue;
            };
            if let TrieNode::Branch(branch_node) = parent_node {
                let child_nibble = current_key.get(current_key_parent_path.len()).expect("key is not long enough");
                // check if there is another child after this one, otherwise go up one level (remove last nibble)
                for i in (child_nibble+1)..=15 {
                    info!("checking child nibble: {:?}, branch node: {:?}", i, branch_node.state_mask);
                    if branch_node.state_mask.is_bit_set(i) {
                        info!("found child nibble: {:?}", i);
                        let next_key = current_key_parent_path.join(&Nibbles::from_nibbles(&[i as u8]));

                        return self.move_to_first_leaf_after(&next_key);
                    }
                }
                info!("got branch node, going up one level");
                // no more children, go up one level
                current_key_parent_path.pop();
            } else if let TrieNode::Extension(extension_node) = parent_node {
                info!("got extension node, going up one level");
                // no more children, go up one level
                current_key_parent_path.pop();
            } else if let TrieNode::Leaf(leaf_node) = parent_node {
                panic!("leaf node found in parent");
            }
        }

        Ok(None)
    }
}

impl<F: HashedCursor<Value = Account>> HashedCursor for CachedHashedTrieCursor<F> {
    type Value = F::Value;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        info!("seeking in hashed cache for key: {:?}", key);
        // shadow mode, check that result matches inner cursor
        let result = self.traverse_tree(key);
        let inner_result = self.inner.seek(key);
        if result.as_ref().unwrap() != inner_result.as_ref().unwrap() {
            info!("result: {:?}", result.as_ref().unwrap());
            info!("inner result: {:?}", inner_result.as_ref().unwrap());
        }
        inner_result
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        let result = self.next_child();
        let inner_result = self.inner.next();
        if result.as_ref().unwrap() != inner_result.as_ref().unwrap() {
            info!("result: {:?}", result.as_ref().unwrap());
            info!("inner result: {:?}", inner_result.as_ref().unwrap());
        }
        inner_result
    }
}

#[derive(Debug, Clone)]
pub struct CachedHashedCursorFactory<F> {
    inner: F,
    cache: Arc<Mutex<dyn ExternalTrieStore>>,
}

impl<F> CachedHashedCursorFactory<F> {
    pub fn new(inner: F, cache: Arc<Mutex<dyn ExternalTrieStore>>) -> Self {
        Self { inner, cache }
    }
}

impl<F: HashedCursorFactory> HashedCursorFactory for CachedHashedCursorFactory<F> {
    type AccountCursor = CachedHashedTrieCursor<F::AccountCursor>;
    type StorageCursor = F::StorageCursor;

    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor, DatabaseError> {
        info!("creating account cursor with cache");
        let inner = self.inner.hashed_account_cursor()?;
        Ok(CachedHashedTrieCursor::new(inner, self.cache.clone()))
    }

    fn hashed_storage_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageCursor, DatabaseError> {
        info!("creating storage cursor with cache");
        let inner = self.inner.hashed_storage_cursor(hashed_address)?;
        Ok(inner)
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
    hashed_cursor_factory: CachedHashedCursorFactory<H>,
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
        cache: Arc<Mutex<dyn ExternalTrieStore>>,
    ) -> Self {
        Self {
            trie_cursor_factory: CachedTrieCursorFactory::new(trie_cursor_factory, cache.clone()),
            hashed_cursor_factory: CachedHashedCursorFactory::new(hashed_cursor_factory, cache),
        }
    }
}

impl<T: TrieCursorFactory, H: HashedCursorFactory> TrieCursorFactory for CacheCursorFactory<T, H> {
    type AccountTrieCursor = CachedTrieCursor<T::AccountTrieCursor>;
    type StorageTrieCursor = CachedTrieCursor<T::StorageTrieCursor>;

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
    type AccountCursor = CachedHashedTrieCursor<H::AccountCursor>;
    type StorageCursor = H::StorageCursor;

    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor, DatabaseError> {
        self.hashed_cursor_factory.hashed_account_cursor()
    }

    fn hashed_storage_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageCursor, DatabaseError> {
        self.hashed_cursor_factory.hashed_storage_cursor(hashed_address)
    }
}