//! Database command for dumping trie preimages

use clap::Parser;
use reth_cli::chainspec::ChainSpecParser;
use reth_db_common::DbTool;
use reth_preimage_storage::PreimageStorage;
use reth_provider::{providers::ProviderNodeTypes, DatabaseProviderFactory};
use std::path::PathBuf;
use tracing::{info};

use crate::common::EnvironmentArgs;

/// The arguments for the `reth db dump-preimages` command
#[derive(Parser, Debug)]
pub struct Command<C: ChainSpecParser> {
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    /// Storage backend to use
    #[arg(long, default_value = "local")]
    pub storage: StorageBackend,

    /// Batch size for processing preimages
    #[arg(long, default_value = "100")]
    pub batch_size: usize,

    /// Local storage path (for local backend)
    #[arg(long)]
    pub local_path: Option<PathBuf>,

    /// DynamoDB table name (for DynamoDB backend)
    #[arg(long)]
    pub table_name: Option<String>,

    /// AWS region (for DynamoDB backend)
    #[arg(long)]
    pub aws_region: Option<String>,

    /// DynamoDB endpoint URL (for DynamoDB backend)
    #[arg(long)]
    pub dynamodb_endpoint_url: Option<String>,
}

/// Storage backend options
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum StorageBackend {
    /// Local file system storage
    Local,
    /// AWS DynamoDB storage
    #[cfg(feature = "dynamodb")]
    DynamoDB,
}

impl<C: ChainSpecParser> Command<C> {
    /// Execute the dump preimages command asynchronously
    pub async fn execute<N: ProviderNodeTypes>(self, tool: &DbTool<N>) -> eyre::Result<()> {
        use reth_preimage_storage::{
            LocalPreimageStorage, PreimageStorageConfig, TriePreimageExtractor,
        };

        #[cfg(feature = "dynamodb")]
        use reth_preimage_storage::DynamoDbPreimageStorage;

        info!("Starting streaming trie preimage extraction...");

        let provider = tool.provider_factory.database_provider_ro()?;
        let tx = provider.tx_ref();

        // Configure storage based on the selected backend
        let storage: Box<dyn PreimageStorage> = match self.storage {
            StorageBackend::Local => {
                let local_path = self.local_path.clone().unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("preimages")
                });

                let config = PreimageStorageConfig {
                    batch_size: self.batch_size,
                    local_path: Some(local_path),
                    table_name: self.table_name.clone(),
                    aws_region: self.aws_region.clone(),
                    dynamodb_endpoint_url: self.dynamodb_endpoint_url.clone(),
                };

                info!("Using local storage at: {:?}", config.local_path);
                Box::new(LocalPreimageStorage::new(config).await?)
            }

            #[cfg(feature = "dynamodb")]
            StorageBackend::DynamoDB => {
                let config = PreimageStorageConfig {
                    batch_size: self.batch_size,
                    table_name: self.table_name.clone(),
                    aws_region: self.aws_region.clone(),
                    local_path: self.local_path.clone(),
                    dynamodb_endpoint_url: self.dynamodb_endpoint_url.clone(),
                };

                info!("Using DynamoDB storage");
                Box::new(DynamoDbPreimageStorage::new(config).await?)
            }
        };

        // Extract and stream preimages directly to storage
        let stats = TriePreimageExtractor::extract_all_preimages_streaming(tx, &*storage).await?;

        drop(provider);

        info!("Streaming extraction complete!");
        info!("Statistics:");
        info!("  Total preimages: {}", stats.total_count());
        info!("  Account preimages: {}", stats.account_preimage_count);
        info!("  Storage preimages: {}", stats.storage_preimage_count);
        info!("  Total size: {} bytes", stats.total_size_bytes());
        info!("  Average size: {:.2} bytes", stats.average_preimage_size());

        // Get final storage statistics
        let storage_stats = storage.get_statistics().await?;
        info!("Storage complete! Stored {} preimages", storage_stats.total_preimages);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use reth_ethereum_cli::chainspec::EthereumChainSpecParser;

    #[test]
    fn test_parse_command() {
        let args = vec![
            "dump-preimages",
            "--storage",
            "local",
            "--batch-size",
            "50",
            "--local-path",
            "/tmp/preimages",
        ];

        let command = Command::<EthereumChainSpecParser>::try_parse_from(args).unwrap();

        assert!(matches!(command.storage, StorageBackend::Local));
        assert_eq!(command.batch_size, 50);
        assert_eq!(command.local_path, Some(PathBuf::from("/tmp/preimages")));
    }

    #[test]
    fn test_parse_dynamodb_command() {
        let args = vec![
            "dump-preimages",
            "--storage",
            "dynamodb",
            "--table-name",
            "test-table",
            "--aws-region",
            "us-west-2",
        ];

        let command = Command::<EthereumChainSpecParser>::try_parse_from(args).unwrap();

        #[cfg(feature = "dynamodb")]
        assert!(matches!(command.storage, StorageBackend::DynamoDB));
        assert_eq!(command.table_name, Some("test-table".to_string()));
        assert_eq!(command.aws_region, Some("us-west-2".to_string()));
    }
}
