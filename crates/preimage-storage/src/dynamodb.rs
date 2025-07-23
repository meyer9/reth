//! DynamoDB implementation for preimage storage

use crate::{
    PreimageEntry, PreimageStorage, PreimageStorageConfig, PreimageStorageError,
    PreimageStorageResult, StorageStatistics,
};
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use async_trait::async_trait;
use aws_config::Region;
use aws_sdk_dynamodb::{
    types::{AttributeValue, DeleteRequest, PutRequest, Select, WriteRequest},
    Client,
};
use reth_db_api::table::Encode;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// DynamoDB implementation of PreimageStorage
#[derive(Debug, Clone)]
pub struct DynamoDbPreimageStorage {
    client: Client,
    table_name: String,
    batch_size: usize,
}

impl DynamoDbPreimageStorage {
    /// Create a new DynamoDB preimage storage instance
    pub async fn new(config: PreimageStorageConfig) -> PreimageStorageResult<Self> {
        let table_name = config.table_name.ok_or_else(|| {
            PreimageStorageError::InvalidConfig("table_name is required for DynamoDB".to_string())
        })?;

        // Load AWS configuration with optional custom endpoint
        let mut aws_config_builder =
            aws_config::defaults(aws_config::BehaviorVersion::v2025_01_17());

        // Set region if provided
        if let Some(region) = config.aws_region {
            aws_config_builder = aws_config_builder.region(Region::new(region));
        }

        let aws_config = aws_config_builder.load().await;

        // Create client with optional custom endpoint
        let client = if let Some(endpoint_url) = config.dynamodb_endpoint_url {
            info!("Using custom DynamoDB endpoint: {}", endpoint_url);
            Client::from_conf(
                aws_sdk_dynamodb::config::Builder::from(&aws_config)
                    .endpoint_url(endpoint_url)
                    .build(),
            )
        } else {
            Client::new(&aws_config)
        };

        // Verify table exists
        let storage = Self { client, table_name, batch_size: config.batch_size };

        storage.ensure_table_exists().await?;

        Ok(storage)
    }

    /// Ensure the DynamoDB table exists
    async fn ensure_table_exists(&self) -> PreimageStorageResult<()> {
        match self.client.describe_table().table_name(&self.table_name).send().await {
            Ok(_) => {
                info!("DynamoDB table '{}' exists", self.table_name);
                Ok(())
            }
            Err(e) => {
                error!("Failed to describe table '{}': {}", self.table_name, e);
                Err(PreimageStorageError::Database(eyre::eyre!(
                    "Table '{}' does not exist or is not accessible: {}",
                    self.table_name,
                    e
                )))
            }
        }
    }

    /// Convert a preimage entry to DynamoDB item
    fn entry_to_item(&self, entry: &PreimageEntry) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();

        // Use hex-encoded hash as primary key
        item.insert("hash".to_string(), AttributeValue::S(format!("{:x}", entry.hash)));

        let mut buf = Vec::new();
        entry.path.encode(&mut buf);
        item.insert("path".to_string(), AttributeValue::B(buf.into()));

        // Store data as binary
        item.insert("data".to_string(), AttributeValue::B(entry.data.to_vec().into()));

        item
    }

    /// Convert DynamoDB item to preimage entry
    fn get_item_data(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> PreimageStorageResult<Vec<u8>> {
        let data = item
            .get("data")
            .and_then(|v| v.as_b().ok().cloned())
            .ok_or_else(|| PreimageStorageError::Storage("Missing data field".to_string()))?;

        Ok(data.clone().as_ref().into())
    }

    /// Store preimages in batches
    async fn store_preimages_batch(
        &self,
        entries: Vec<PreimageEntry>,
    ) -> PreimageStorageResult<()> {
        let mut chunks = entries.chunks(self.batch_size);

        for chunk in chunks {
            let write_requests: Vec<WriteRequest> = chunk
                .iter()
                .map(|entry| {
                    WriteRequest::builder()
                        .put_request(
                            PutRequest::builder()
                                .set_item(Some(self.entry_to_item(entry)))
                                .build()
                                .unwrap(),
                        )
                        .build()
                })
                .collect();

            let mut request_items = HashMap::new();
            request_items.insert(self.table_name.clone(), write_requests);

            info!(
                "DynamoDB: Storing {} preimages in batch of size {}",
                chunk.len(),
                self.batch_size
            );
            self.client
                .batch_write_item()
                .set_request_items(Some(request_items))
                .send()
                .await
                .map_err(|e| {
                    PreimageStorageError::BatchOperationFailed(format!(
                        "Failed to write batch: {}",
                        e
                    ))
                })?;
        }

        Ok(())
    }
}

#[async_trait]
impl PreimageStorage for DynamoDbPreimageStorage {
    async fn store_preimage(&self, entry: PreimageEntry) -> PreimageStorageResult<()> {
        let item = self.entry_to_item(&entry);

        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| {
                PreimageStorageError::Storage(format!("Failed to store preimage: {}", e))
            })?;

        debug!("Stored preimage with hash: {:x}", entry.hash);
        Ok(())
    }

    async fn store_preimages(&self, entries: Vec<PreimageEntry>) -> PreimageStorageResult<()> {
        if entries.is_empty() {
            return Ok(());
        }

        info!("Storing {} preimages in batches", entries.len());
        self.store_preimages_batch(entries).await
    }

    async fn get_preimage(&self, hash: &B256) -> PreimageStorageResult<Option<Vec<u8>>> {
        let mut key = HashMap::new();
        key.insert("hash".to_string(), AttributeValue::S(format!("{:x}", hash)));

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .send()
            .await
            .map_err(|e| PreimageStorageError::Storage(format!("Failed to get preimage: {}", e)))?;

        if let Some(item) = response.item {
            Ok(Some(self.get_item_data(&item)?))
        } else {
            Ok(None)
        }
    }

    async fn get_preimages(&self, hashes: &[B256]) -> PreimageStorageResult<Vec<Vec<u8>>> {
        let mut results = Vec::new();

        // Process hashes in batches (DynamoDB has a limit of 100 items per batch_get_item)
        for chunk in hashes.chunks(100) {
            let mut keys = Vec::new();
            for hash in chunk {
                let mut key = HashMap::new();
                key.insert("hash".to_string(), AttributeValue::S(format!("{:x}", hash)));
                keys.push(key);
            }

            let keys_and_attributes = aws_sdk_dynamodb::types::KeysAndAttributes::builder()
                .set_keys(Some(keys))
                .build()
                .unwrap();

            let mut request_items = HashMap::new();
            request_items.insert(self.table_name.clone(), keys_and_attributes);

            let response = self
                .client
                .batch_get_item()
                .set_request_items(Some(request_items))
                .send()
                .await
                .map_err(|e| {
                    PreimageStorageError::BatchOperationFailed(format!(
                        "Failed to get preimages: {}",
                        e
                    ))
                })?;

            if let Some(responses) = response.responses {
                if let Some(items) = responses.get(&self.table_name) {
                    for item in items {
                        results.push(self.get_item_data(item)?.into());
                    }
                }
            }
        }

        Ok(results)
    }

    async fn contains_preimage(&self, hash: &B256) -> PreimageStorageResult<bool> {
        let mut key = HashMap::new();
        key.insert("hash".to_string(), AttributeValue::S(format!("{:x}", hash)));

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .projection_expression("hash")
            .send()
            .await
            .map_err(|e| {
                PreimageStorageError::Storage(format!("Failed to check preimage existence: {}", e))
            })?;

        Ok(response.item.is_some())
    }

    async fn delete_preimage(&self, hash: &B256) -> PreimageStorageResult<()> {
        let mut key = HashMap::new();
        key.insert("hash".to_string(), AttributeValue::S(format!("{:x}", hash)));

        self.client
            .delete_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .send()
            .await
            .map_err(|e| {
                PreimageStorageError::Storage(format!("Failed to delete preimage: {}", e))
            })?;

        debug!("Deleted preimage with hash: {:x}", hash);
        Ok(())
    }

    async fn delete_preimages(&self, hashes: &[B256]) -> PreimageStorageResult<()> {
        for chunk in hashes.chunks(self.batch_size) {
            let write_requests: Vec<WriteRequest> = chunk
                .iter()
                .map(|hash| {
                    let mut key = HashMap::new();
                    key.insert("hash".to_string(), AttributeValue::S(format!("{:x}", hash)));

                    WriteRequest::builder()
                        .delete_request(
                            DeleteRequest::builder().set_key(Some(key)).build().unwrap(),
                        )
                        .build()
                })
                .collect();

            let mut request_items = HashMap::new();
            request_items.insert(self.table_name.clone(), write_requests);

            self.client
                .batch_write_item()
                .set_request_items(Some(request_items))
                .send()
                .await
                .map_err(|e| {
                    PreimageStorageError::BatchOperationFailed(format!(
                        "Failed to delete preimages: {}",
                        e
                    ))
                })?;
        }

        Ok(())
    }

    async fn count_preimages(&self) -> PreimageStorageResult<u64> {
        let response = self
            .client
            .scan()
            .table_name(&self.table_name)
            .select(Select::Count)
            .send()
            .await
            .map_err(|e| {
                PreimageStorageError::Storage(format!("Failed to count preimages: {}", e))
            })?;

        Ok(response.count as u64)
    }

    async fn list_preimage_hashes(&self) -> PreimageStorageResult<Vec<B256>> {
        let mut hashes = Vec::new();
        let mut last_evaluated_key = None;

        loop {
            let mut scan_request =
                self.client.scan().table_name(&self.table_name).projection_expression("hash");

            if let Some(key) = last_evaluated_key {
                scan_request = scan_request.set_exclusive_start_key(Some(key));
            }

            let response = scan_request.send().await.map_err(|e| {
                PreimageStorageError::Storage(format!("Failed to list preimage hashes: {}", e))
            })?;

            if let Some(items) = response.items {
                for item in items {
                    if let Some(hash_attr) = item.get("hash") {
                        if let Ok(hash_str) = hash_attr.as_s() {
                            if let Ok(hash) = B256::from_str(hash_str) {
                                hashes.push(hash);
                            }
                        }
                    }
                }
            }

            last_evaluated_key = response.last_evaluated_key;
            if last_evaluated_key.is_none() {
                break;
            }
        }

        Ok(hashes)
    }

    async fn clear_all_preimages(&self) -> PreimageStorageResult<()> {
        warn!("Clearing all preimages from DynamoDB table '{}'", self.table_name);

        let hashes = self.list_preimage_hashes().await?;
        if !hashes.is_empty() {
            self.delete_preimages(&hashes).await?;
        }

        Ok(())
    }

    async fn get_statistics(&self) -> PreimageStorageResult<StorageStatistics> {
        let response = self
            .client
            .scan()
            .table_name(&self.table_name)
            .select(Select::AllAttributes)
            .send()
            .await
            .map_err(|e| {
                PreimageStorageError::Storage(format!("Failed to get statistics: {}", e))
            })?;

        let mut total_preimages = 0u64;
        let mut total_size_bytes = 0u64;

        if let Some(items) = response.items {
            total_preimages = items.len() as u64;

            for item in items {
                if let Some(size_attr) = item.get("size") {
                    if let Ok(size_str) = size_attr.as_n() {
                        if let Ok(size) = size_str.parse::<u64>() {
                            total_size_bytes += size;
                        }
                    }
                }
            }
        }

        Ok(StorageStatistics::new(total_preimages, total_size_bytes, "DynamoDB".to_string()))
    }
}

/// Helper trait for B256 string conversion
trait B256Ext {
    fn from_str(s: &str) -> Result<B256, PreimageStorageError>;
}

impl B256Ext for B256 {
    fn from_str(s: &str) -> Result<B256, PreimageStorageError> {
        let bytes = hex::decode(s)
            .map_err(|e| PreimageStorageError::Storage(format!("Invalid hex string: {}", e)))?;

        if bytes.len() != 32 {
            return Err(PreimageStorageError::Storage("Hash must be exactly 32 bytes".to_string()));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(B256::from(array))
    }
}
