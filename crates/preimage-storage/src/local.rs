//! Local file system implementation for preimage storage

use crate::{
    PreimageEntry, PreimageStorage, PreimageStorageConfig, PreimageStorageError,
    PreimageStorageResult, StorageStatistics,
};
use alloy_primitives::B256;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{debug, info, warn};

/// Local file system implementation of PreimageStorage
pub struct LocalPreimageStorage {
    base_path: PathBuf,
    batch_size: usize,
}

impl LocalPreimageStorage {
    /// Create a new local preimage storage instance
    pub async fn new(config: PreimageStorageConfig) -> PreimageStorageResult<Self> {
        let base_path = config.local_path.ok_or_else(|| {
            PreimageStorageError::InvalidConfig("local_path is required for local storage".to_string())
        })?;

        // Create the base directory if it doesn't exist
        fs::create_dir_all(&base_path).await?;

        Ok(Self {
            base_path,
            batch_size: config.batch_size,
        })
    }

    /// Get the file path for a given hash
    fn get_file_path(&self, hash: &B256) -> PathBuf {
        let hash_str = format!("{:x}", hash);
        // Use the first 2 characters as directory name for better file system performance
        let dir = &hash_str[..2];
        let filename = &hash_str[2..];
        
        self.base_path.join(dir).join(filename)
    }

    /// Ensure the directory exists for the given hash
    async fn ensure_directory(&self, hash: &B256) -> PreimageStorageResult<()> {
        let file_path = self.get_file_path(hash);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(())
    }

    /// Read preimage from file
    async fn read_preimage_file(&self, hash: &B256) -> PreimageStorageResult<Option<PreimageEntry>> {
        let file_path = self.get_file_path(hash);
        
        if !file_path.exists() {
            return Ok(None);
        }

        let mut file = fs::File::open(&file_path).await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        // First 32 bytes are the hash, rest is the data
        if buffer.len() < 32 {
            return Err(PreimageStorageError::Storage(
                "Invalid file format: too short".to_string()
            ));
        }

        let stored_hash = B256::from_slice(&buffer[..32]);
        if stored_hash != *hash {
            return Err(PreimageStorageError::Storage(
                "Hash mismatch in stored file".to_string()
            ));
        }

        let data = buffer[32..].to_vec();
        Ok(Some(PreimageEntry::new(*hash, data.into())))
    }

    /// Write preimage to file
    async fn write_preimage_file(&self, entry: &PreimageEntry) -> PreimageStorageResult<()> {
        self.ensure_directory(&entry.hash).await?;
        
        let file_path = self.get_file_path(&entry.hash);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file_path)
            .await?;

        // Write hash first, then data
        file.write_all(entry.hash.as_slice()).await?;
        file.write_all(&entry.data).await?;
        file.sync_all().await?;

        Ok(())
    }

    /// Delete preimage file
    async fn delete_preimage_file(&self, hash: &B256) -> PreimageStorageResult<()> {
        let file_path = self.get_file_path(hash);
        
        if file_path.exists() {
            fs::remove_file(&file_path).await?;
            
            // Try to remove empty parent directory
            if let Some(parent) = file_path.parent() {
                if parent != self.base_path {
                    let _ = fs::remove_dir(parent).await; // Ignore errors
                }
            }
        }
        
        Ok(())
    }

    /// List all preimage files
    async fn list_all_files(&self) -> PreimageStorageResult<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut stack = vec![self.base_path.clone()];

        while let Some(dir) = stack.pop() {
            let mut entries = fs::read_dir(&dir).await?;
            
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.is_file() {
                    files.push(path);
                }
            }
        }

        Ok(files)
    }

    /// Parse hash from file path
    fn parse_hash_from_path(&self, path: &Path) -> Option<B256> {
        let relative_path = path.strip_prefix(&self.base_path).ok()?;
        let path_str = relative_path.to_str()?;
        
        // Remove directory separator and reconstruct hash
        let hash_str = path_str.replace(std::path::MAIN_SEPARATOR, "");
        
        if hash_str.len() == 64 {
            hex::decode(&hash_str).ok()
                .and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut array = [0u8; 32];
                        array.copy_from_slice(&bytes);
                        Some(B256::from(array))
                    } else {
                        None
                    }
                })
        } else {
            None
        }
    }
}

#[async_trait]
impl PreimageStorage for LocalPreimageStorage {
    async fn store_preimage(&self, entry: PreimageEntry) -> PreimageStorageResult<()> {
        self.write_preimage_file(&entry).await?;
        debug!("Stored preimage with hash: {:x}", entry.hash);
        Ok(())
    }

    async fn store_preimages(&self, entries: Vec<PreimageEntry>) -> PreimageStorageResult<()> {
        if entries.is_empty() {
            return Ok(());
        }

        info!("Storing {} preimages to local storage", entries.len());
        
        // Process in batches to avoid overwhelming the file system
        for chunk in entries.chunks(self.batch_size) {
            for entry in chunk {
                self.write_preimage_file(entry).await?;
            }
        }

        Ok(())
    }

    async fn get_preimage(&self, hash: &B256) -> PreimageStorageResult<Option<PreimageEntry>> {
        self.read_preimage_file(hash).await
    }

    async fn get_preimages(&self, hashes: &[B256]) -> PreimageStorageResult<Vec<PreimageEntry>> {
        let mut results = Vec::new();

        for hash in hashes {
            if let Some(entry) = self.read_preimage_file(hash).await? {
                results.push(entry);
            }
        }

        Ok(results)
    }

    async fn contains_preimage(&self, hash: &B256) -> PreimageStorageResult<bool> {
        let file_path = self.get_file_path(hash);
        Ok(file_path.exists())
    }

    async fn delete_preimage(&self, hash: &B256) -> PreimageStorageResult<()> {
        self.delete_preimage_file(hash).await?;
        debug!("Deleted preimage with hash: {:x}", hash);
        Ok(())
    }

    async fn delete_preimages(&self, hashes: &[B256]) -> PreimageStorageResult<()> {
        for hash in hashes {
            self.delete_preimage_file(hash).await?;
        }
        Ok(())
    }

    async fn count_preimages(&self) -> PreimageStorageResult<u64> {
        let files = self.list_all_files().await?;
        Ok(files.len() as u64)
    }

    async fn list_preimage_hashes(&self) -> PreimageStorageResult<Vec<B256>> {
        let files = self.list_all_files().await?;
        let mut hashes = Vec::new();

        for file in files {
            if let Some(hash) = self.parse_hash_from_path(&file) {
                hashes.push(hash);
            }
        }

        Ok(hashes)
    }

    async fn clear_all_preimages(&self) -> PreimageStorageResult<()> {
        warn!("Clearing all preimages from local storage at {:?}", self.base_path);
        
        let files = self.list_all_files().await?;
        for file in files {
            fs::remove_file(&file).await?;
        }

        // Try to remove empty directories
        let _ = fs::remove_dir_all(&self.base_path).await;
        let _ = fs::create_dir_all(&self.base_path).await;

        Ok(())
    }

    async fn get_statistics(&self) -> PreimageStorageResult<StorageStatistics> {
        let files = self.list_all_files().await?;
        let total_preimages = files.len() as u64;
        let mut total_size_bytes = 0u64;

        for file in files {
            if let Ok(metadata) = fs::metadata(&file).await {
                // Subtract 32 bytes for the hash prefix
                let data_size = metadata.len().saturating_sub(32);
                total_size_bytes += data_size;
            }
        }

        Ok(StorageStatistics::new(
            total_preimages,
            total_size_bytes,
            "Local".to_string(),
        ))
    }
} 