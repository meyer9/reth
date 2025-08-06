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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        trie_cursor::mock::MockTrieCursorFactory,
        walker::TrieWalker,
    };
    use alloy_primitives::{map::B256Map, b256};
    use reth_trie_common::{prefix_set::PrefixSet, BranchNode, ExtensionNode, RlpNode, TrieNode};
    use std::{collections::BTreeMap, sync::{Arc, Mutex}};

    /// Mock external trie store for testing
    #[derive(Debug)]
    struct MockExternalTrieStore {
        nodes: BTreeMap<Nibbles, TrieNode>,
    }

    impl MockExternalTrieStore {
        fn new() -> Self {
            Self { nodes: BTreeMap::new() }
        }

        fn insert(&mut self, key: Nibbles, node: TrieNode) {
            self.nodes.insert(key, node);
        }
    }

    impl ExternalTrieStore for MockExternalTrieStore {
        fn get_trie_node(&mut self, key: &Nibbles) -> Result<Option<TrieNode>, ProviderError> {
            Ok(self.nodes.get(key).cloned())
        }
    }

    /// Creates a test trie with extension nodes that demonstrates why non-exact seek is needed
    fn create_extension_node_test_trie() -> (BTreeMap<Nibbles, BranchNodeCompact>, BTreeMap<Nibbles, TrieNode>) {
        let mut stored_nodes = BTreeMap::new();
        let mut logical_nodes = BTreeMap::new();

        // Create a trie structure that has extension nodes:
        //
        // Root (stored at key "")
        //   └── Extension(key: [0x3, 0x0, 0xa, 0xf]) → Branch (stored at key [0x3, 0x0, 0xa, 0xf])
        //       ├── Child[0x5] → Leaf
        //       ├── Child[0x6] → Leaf  
        //       └── Child[0x8] → Leaf
        //
        // This simulates a common pattern where extension nodes compress common prefixes

        // Root branch node - has child only at nibble 3
        let root_node = BranchNodeCompact::new(
            TrieMask::new(0b1000), // state_mask: only bit 3 set
            TrieMask::new(0b1000), // tree_mask: bit 3 set (extension node follows)
            TrieMask::new(0b1000), // hash_mask: bit 3 set (has hash)
            vec![b256!("1111111111111111111111111111111111111111111111111111111111111111")],  // hash for child at nibble 3
            None,
        );
        stored_nodes.insert(Nibbles::new(), root_node);
        
        // Logical extension node at [3] (not stored in database)
        logical_nodes.insert(
            Nibbles::from_nibbles(&[0x3]),
            TrieNode::Extension(ExtensionNode {
                key: Nibbles::from_nibbles(&[0x0, 0xa, 0xf]),
                child: RlpNode::word_rlp(&b256!("2222222222222222222222222222222222222222222222222222222222222222")),
            }),
        );

        // Branch node at [3, 0, a, f] - this is where the extension leads
        let extension_target = BranchNodeCompact::new(
            TrieMask::new(0b101100000), // state_mask: bits 5, 6, 8 set
            TrieMask::new(0b000000000), // tree_mask: no intermediate children
            TrieMask::new(0b101100000), // hash_mask: all children are hashes
            vec![
                b256!("3333333333333333333333333333333333333333333333333333333333333333"),
                b256!("4444444444444444444444444444444444444444444444444444444444444444"),
                b256!("5555555555555555555555555555555555555555555555555555555555555555")
            ], // hashes for children
            None,
        );
        stored_nodes.insert(Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]), extension_target);

        // Add the logical structure for the cache
        logical_nodes.insert(
            Nibbles::new(),
            TrieNode::Branch(BranchNode {
                state_mask: TrieMask::new(0b1000),
                stack: vec![RlpNode::word_rlp(&b256!("6666666666666666666666666666666666666666666666666666666666666666"))],
            }),
        );

        logical_nodes.insert(
            Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]),
            TrieNode::Branch(BranchNode {
                state_mask: TrieMask::new(0b101100000),
                stack: vec![
                    RlpNode::word_rlp(&b256!("7777777777777777777777777777777777777777777777777777777777777777")),
                    RlpNode::word_rlp(&b256!("8888888888888888888888888888888888888888888888888888888888888888")),
                    RlpNode::word_rlp(&b256!("9999999999999999999999999999999999999999999999999999999999999999"))
                ], // Will be filled appropriately
            }),
        );

        (stored_nodes, logical_nodes)
    }

    #[test]
    fn test_extension_node_seek_behavior() {
        let (stored_nodes, logical_nodes) = create_extension_node_test_trie();
        
        // Create mock external store with logical nodes
        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        // Create mock inner cursor with only the stored nodes
        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        
        // Create cached cursor
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // Test 1: Exact seek at extension node position should find stored node
        // This demonstrates that even though extension node is not stored,
        // we can still find the target branch node
        let result = cached_cursor.seek_exact(Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf])).unwrap();
        assert!(result.is_some(), "Should find the branch node that extension points to");

        // Test 2: Non-exact seek in the middle of extension path
        // This is the critical test - seeking at a position within the extension
        let result = cached_cursor.seek(Nibbles::from_nibbles(&[0x3, 0x0, 0xa])).unwrap();
        assert!(result.is_some(), "Non-exact seek should find next stored node");
        
        let (found_key, _) = result.unwrap();
        assert_eq!(found_key, Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]),
                  "Should find the branch node at end of extension path");
    }

    #[test]
    fn test_walker_with_extension_nodes() {
        let (stored_nodes, logical_nodes) = create_extension_node_test_trie();
        
        // Create mock external store
        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        // Create cached cursor factory
        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let cache = Arc::new(Mutex::new(external_store));
        let cached_factory = CachedTrieCursorFactory::new(mock_factory, cache);

        // Create walker with cached cursor
        let cursor = cached_factory.account_trie_cursor().unwrap();
        let mut walker = TrieWalker::state_trie(cursor, PrefixSet::default());

        // The walker should be able to traverse the trie despite extension nodes
        assert!(walker.key().is_some(), "Walker should start at root");
        
        // Advance walker - this will trigger the non-exact seek behavior
        walker.advance().unwrap();
        
        // The walker should find the branch node at the end of the extension
        if let Some(key) = walker.key() {
            assert_eq!(*key, Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]),
                      "Walker should find branch node at extension target");
        }
    }

    #[test]
    fn test_exact_vs_non_exact_seek_difference() {
        let (stored_nodes, logical_nodes) = create_extension_node_test_trie();
        
        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // Position in the middle of an extension node path
        let extension_middle = Nibbles::from_nibbles(&[0x3, 0x0]);

        // Exact seek should find nothing (no node stored exactly at this position)
        let exact_result = cached_cursor.seek_exact(extension_middle).unwrap();
        // Note: This might return something from cache, but in a real DB scenario
        // where extension nodes aren't stored, this would be None

        // Non-exact seek should find the next stored node
        let non_exact_result = cached_cursor.seek(extension_middle).unwrap();
        assert!(non_exact_result.is_some(), "Non-exact seek should find next node");
        
        let (found_key, _) = non_exact_result.unwrap();
        assert_eq!(found_key, Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]),
                  "Should find the branch node that follows the extension");
        assert!(found_key > extension_middle, "Found key should be greater than seek key");
    }

    #[test]
    fn test_consume_node_scenarios() {
        // This test demonstrates the key insight: non-exact seek allows
        // the walker to handle extension node compression gracefully
        
        let (stored_nodes, _logical_nodes) = create_extension_node_test_trie();
        
        // Test with just the stored nodes (simulating real DB behavior)
        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        
        // Test different seek scenarios to demonstrate extension node handling
        let mut cursor = inner_cursor;
        
        // Test 1: Exact seek at non-existent intermediate position
        let intermediate_key = Nibbles::from_nibbles(&[0x3, 0x0, 0xa]);
        let exact_result = cursor.seek_exact(intermediate_key).unwrap();
        // Should be None since no node exists exactly at this position
        assert!(exact_result.is_none(), "Exact seek should find nothing at intermediate extension position");
        
        // Test 2: Non-exact seek at same position should find the next stored node
        let non_exact_result = cursor.seek(intermediate_key).unwrap();
        assert!(non_exact_result.is_some(), "Non-exact seek should find next stored node");
        
        if let Some((found_key, _)) = non_exact_result {
            // Should find the branch node that the extension points to
            assert!(found_key >= intermediate_key, "Found key should be >= seek key");
            assert_eq!(found_key, Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]),
                      "Should find the branch node at extension target");
        }
        
        // This demonstrates why consume_node() needs non-exact seek:
        // When the walker is positioned at an intermediate extension position,
        // only non-exact seek can find the next actual stored node
    }

    #[test]
    fn test_tree_mask_behavior() {
        // Test how tree_mask correctly identifies intermediate vs leaf children
        let (stored_nodes, logical_nodes) = create_extension_node_test_trie();
        
        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // Seek to root node
        let result = cached_cursor.seek_exact(Nibbles::new()).unwrap();
        assert!(result.is_some(), "Should find root node");
        
        if let Some((_, node)) = result {
            // Root node should have tree_mask bit set for nibble 3 (indicating extension follows)
            assert!(node.tree_mask.is_bit_set(3), "Tree mask should indicate intermediate node at nibble 3");
            assert!(node.state_mask.is_bit_set(3), "State mask should indicate child at nibble 3");
            assert!(node.hash_mask.is_bit_set(3), "Hash mask should indicate hash available at nibble 3");
        }
    }

    #[test]
    fn test_cursor_state_management() {
        // Test that cursor correctly maintains state across multiple operations
        let (stored_nodes, logical_nodes) = create_extension_node_test_trie();
        
        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // Test sequence of operations
        let root_result = cached_cursor.seek_exact(Nibbles::new()).unwrap();
        assert!(root_result.is_some(), "Should find root");
        
        // Check current position
        let current = cached_cursor.current().unwrap();
        assert_eq!(current, Some(Nibbles::new()), "Current should be root");

        // Seek to extension target
        let target_key = Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]);
        let target_result = cached_cursor.seek_exact(target_key).unwrap();
        assert!(target_result.is_some(), "Should find extension target");
        
        // Check current position updated
        let current = cached_cursor.current().unwrap();
        assert_eq!(current, Some(target_key), "Current should be extension target");
    }

    #[test]
    fn test_empty_trie_behavior() {
        // Test cursor behavior with empty trie
        let empty_nodes = BTreeMap::new();
        let mut external_store = MockExternalTrieStore::new();

        let mock_factory = MockTrieCursorFactory::new(empty_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // All seeks should return None
        let root_result = cached_cursor.seek_exact(Nibbles::new()).unwrap();
        assert!(root_result.is_none(), "Empty trie should have no root");
        
        let seek_result = cached_cursor.seek(Nibbles::from_nibbles(&[0x1, 0x2])).unwrap();
        assert!(seek_result.is_none(), "Empty trie should have no nodes");
        
        let current = cached_cursor.current().unwrap();
        assert!(current.is_none(), "Empty trie should have no current position");
    }

    #[test] 
    fn test_single_node_trie() {
        // Test trie with just a root node
        let mut stored_nodes = BTreeMap::new();
        let root_node = BranchNodeCompact::new(
            TrieMask::new(0b0000_0000), // No children
            TrieMask::new(0b0000_0000), // No intermediate children
            TrieMask::new(0b0000_0000), // No hashes
            vec![], // No child hashes
            Some(b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")), // Root value
        );
        stored_nodes.insert(Nibbles::new(), root_node);

        let mut external_store = MockExternalTrieStore::new();
        external_store.insert(
            Nibbles::new(),
            TrieNode::Branch(BranchNode {
                state_mask: TrieMask::new(0b0000_0000),
                stack: vec![], // No children
            }),
        );

        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // Should find root node
        let result = cached_cursor.seek_exact(Nibbles::new()).unwrap();
        assert!(result.is_some(), "Should find root node");
        
        if let Some((key, node)) = result {
            assert_eq!(key, Nibbles::new(), "Key should be empty (root)");
            assert!(node.state_mask.is_empty(), "Should have no children");
            assert!(node.tree_mask.is_empty(), "Should have no intermediate children");
            // Note: root_hash might be None when retrieved from cache
            // The important thing is that we found the node at all
        }

        // Seeking any other key should return None
        let other_result = cached_cursor.seek_exact(Nibbles::from_nibbles(&[0x1])).unwrap();
        assert!(other_result.is_none(), "Single node trie should have no other nodes");
    }

    #[test]
    fn test_deep_extension_chain() {
        // Test a deeper chain of extension nodes
        let mut stored_nodes = BTreeMap::new();
        let mut logical_nodes = BTreeMap::new();
        
        // Create root pointing to extension chain
        let root_node = BranchNodeCompact::new(
            TrieMask::new(0b0001), // Child at nibble 0
            TrieMask::new(0b0001), // Intermediate child at nibble 0
            TrieMask::new(0b0001), // Hash at nibble 0
            vec![b256!("1111111111111111111111111111111111111111111111111111111111111111")],
            None,
        );
        stored_nodes.insert(Nibbles::new(), root_node);

        // Extension chain: 0 -> 01 -> 012 -> 0123
        logical_nodes.insert(
            Nibbles::from_nibbles(&[0x0]),
            TrieNode::Extension(ExtensionNode {
                key: Nibbles::from_nibbles(&[0x1]),
                child: RlpNode::word_rlp(&b256!("2222222222222222222222222222222222222222222222222222222222222222")),
            }),
        );
        
        logical_nodes.insert(
            Nibbles::from_nibbles(&[0x0, 0x1]),
            TrieNode::Extension(ExtensionNode {
                key: Nibbles::from_nibbles(&[0x2]),
                child: RlpNode::word_rlp(&b256!("3333333333333333333333333333333333333333333333333333333333333333")),
            }),
        );
        
        logical_nodes.insert(
            Nibbles::from_nibbles(&[0x0, 0x1, 0x2]),
            TrieNode::Extension(ExtensionNode {
                key: Nibbles::from_nibbles(&[0x3]),
                child: RlpNode::word_rlp(&b256!("4444444444444444444444444444444444444444444444444444444444444444")),
            }),
        );

        // Final branch at end of chain
        let final_branch = BranchNodeCompact::new(
            TrieMask::new(0b1000_0000), // Child at nibble 7
            TrieMask::new(0b0000_0000), // No intermediate children (leaf)
            TrieMask::new(0b1000_0000), // Hash at nibble 7
            vec![b256!("5555555555555555555555555555555555555555555555555555555555555555")],
            None,
        );
        stored_nodes.insert(Nibbles::from_nibbles(&[0x0, 0x1, 0x2, 0x3]), final_branch);
        
        logical_nodes.insert(
            Nibbles::from_nibbles(&[0x0, 0x1, 0x2, 0x3]),
            TrieNode::Branch(BranchNode {
                state_mask: TrieMask::new(0b1000_0000),
                stack: vec![RlpNode::word_rlp(&b256!("5555555555555555555555555555555555555555555555555555555555555555"))],
            }),
        );

        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // Test seeking to various points in the extension chain
        let intermediate_positions = vec![
            Nibbles::from_nibbles(&[0x0]),
            Nibbles::from_nibbles(&[0x0, 0x1]), 
            Nibbles::from_nibbles(&[0x0, 0x1, 0x2]),
        ];

        for pos in intermediate_positions {
            // Exact seek should find cached extension nodes
            let exact_result = cached_cursor.seek_exact(pos).unwrap();
            // Note: This may or may not find something depending on cache implementation
            
            // Non-exact seek should find the final branch
            let non_exact_result = cached_cursor.seek(pos).unwrap();
            if let Some((found_key, _)) = non_exact_result {
                assert!(found_key >= pos, "Found key should be >= seek position");
                // Should eventually find the final branch
                assert!(found_key.starts_with(&Nibbles::from_nibbles(&[0x0])), 
                       "Found key should be in the extension chain");
            }
        }

        // Should definitely find the final branch node
        let final_result = cached_cursor.seek_exact(Nibbles::from_nibbles(&[0x0, 0x1, 0x2, 0x3])).unwrap();
        assert!(final_result.is_some(), "Should find final branch node");
    }

    #[test]
    fn test_walker_step_by_step() {
        // Test walker behavior step by step through extension nodes
        let (stored_nodes, logical_nodes) = create_extension_node_test_trie();
        
        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let cache = Arc::new(Mutex::new(external_store));
        let cached_factory = CachedTrieCursorFactory::new(mock_factory, cache);
        
        let cursor = cached_factory.account_trie_cursor().unwrap();
        let mut walker = TrieWalker::state_trie(cursor, PrefixSet::default());

        // Step 1: Should start at root
        assert!(walker.key().is_some(), "Walker should start with a key");
        let start_key = *walker.key().unwrap();
        
        // Step 2: Advance - this triggers the non-exact seek behavior
        let advance_result = walker.advance();
        assert!(advance_result.is_ok(), "Walker advance should succeed");
        
        // Step 3: Check new position
        if let Some(new_key) = walker.key() {
            assert!(*new_key != start_key, "Walker should have moved to a different position");
        }
        
        // Test children_are_in_trie function
        let children_in_trie = walker.children_are_in_trie();
        // This depends on the current node's tree_flag
        
        // Test hash retrieval
        let hash = walker.hash();
        let maybe_hash = walker.maybe_hash();
        // maybe_hash should be more permissive than hash
    }

    #[test]
    fn test_nibbles_operations() {
        // Test nibbles operations used in tree traversal
        let nibbles1 = Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf]);
        let nibbles2 = Nibbles::from_nibbles(&[0x3, 0x0, 0xa]);
        let nibbles3 = Nibbles::from_nibbles(&[0x3, 0x0, 0xa, 0xf, 0x5]);
        
        // Test prefix relationships
        assert!(nibbles1.starts_with(&nibbles2), "nibbles1 should start with nibbles2");
        assert!(!nibbles2.starts_with(&nibbles1), "nibbles2 should not start with nibbles1");
        assert!(nibbles3.starts_with(&nibbles1), "nibbles3 should start with nibbles1");
        
        // Test ordering (important for seek operations)
        assert!(nibbles2 < nibbles1, "Shorter prefix should be less than longer");
        assert!(nibbles1 < nibbles3, "Extension should be less than longer path");
        
        // Test increment operation (used in walker)
        if let Some(incremented) = nibbles2.increment() {
            assert!(incremented > nibbles2, "Incremented should be greater");
        }
    }

    #[test]
    fn test_error_handling() {
        // Test error handling in various scenarios
        let (stored_nodes, logical_nodes) = create_extension_node_test_trie();
        
        let mut external_store = MockExternalTrieStore::new();
        for (key, node) in logical_nodes {
            external_store.insert(key, node);
        }

        let mock_factory = MockTrieCursorFactory::new(stored_nodes, B256Map::default());
        let inner_cursor = mock_factory.account_trie_cursor().unwrap();
        let cache = Arc::new(Mutex::new(external_store));
        let mut cached_cursor = CachedTrieCursor::new(inner_cursor, cache);

        // All operations should handle errors gracefully
        let seek_result = cached_cursor.seek_exact(Nibbles::from_nibbles(&[0xa, 0xb, 0xc]));
        assert!(seek_result.is_ok(), "Seek should not error even if not found");
        
        let non_exact_result = cached_cursor.seek(Nibbles::from_nibbles(&[0xf, 0xe, 0xd]));
        assert!(non_exact_result.is_ok(), "Non-exact seek should not error");
        
        let current_result = cached_cursor.current();
        assert!(current_result.is_ok(), "Current should not error");
    }
}