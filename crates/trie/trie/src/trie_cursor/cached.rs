use crate::{hashed_cursor::HashedCursorFactory, BranchNodeCompact, Nibbles};
use alloy_primitives::B256;
use reth_storage_errors::{db::DatabaseError, provider::ProviderError};
use tracing::info;
use std::{collections::HashMap, fmt::Debug, sync::Arc};

use super::{TrieCursor, TrieCursorFactory};

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
    fn get_trie_nodes(
        &self,
        keys: &[Nibbles],
    ) -> Result<Vec<Option<BranchNodeCompact>>, ProviderError> {
        Ok(
            keys.iter()
                .map(|key| {
                    info!("Fetching trie node from cache for key: {:?}", key);
                    None
                })
                .collect::<Vec<_>>(),
        )
    }

}

/// Trait for external key-value storage of trie nodes.
pub trait ExternalTrieStore: Send + Sync + Debug {
    /// Get a trie node by its key.
    fn get_trie_node(&self, key: &Nibbles) -> Result<Option<BranchNodeCompact>, ProviderError>;

    /// Get multiple trie nodes by their keys.
    fn get_trie_nodes(
        &self,
        keys: &[Nibbles],
    ) -> Result<Vec<Option<BranchNodeCompact>>, ProviderError>;
}

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
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        // First try the cache
        if let Some(node) = self.cache.get_trie_node(&key).map_err(|e| {
            DatabaseError::Other(format!("Cache error: {e}"))
        })? {
            return Ok(Some((key, node)));
        }

        // Fall back to inner cursor
        let result = self.inner.seek_exact(key)?;

        Ok(result)
    }

    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        // For seek operations, we can't easily check cache first since we need >= behavior
        let result = self.inner.seek(key)?;

        Ok(result)
    }

    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let result = self.inner.next()?;

        Ok(result)
    }

    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        self.inner.current()
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