//! Database command for dumping historical trie preimages from a specific block

use clap::Parser;
use reth_cli::chainspec::ChainSpecParser;
use reth_db_common::DbTool;
use reth_preimage_storage::{
    PreimageStorage, HistoricalPreimageExtractor, HistoricalExtractionProgress,
    HistoricalExtractionStatistics, PreimageStorageConfig,
};
use reth_provider::{providers::ProviderNodeTypes, DatabaseProviderFactory};
use alloy_primitives::BlockNumber;
use std::path::PathBuf;
use tracing::{info, warn};

use crate::common::EnvironmentArgs;

/// The arguments for the `reth db dump-historical-preimages` command
#[derive(Parser, Debug)]
pub struct Command<C: ChainSpecParser> {
    #[command(flatten)]
    env: EnvironmentArgs<C>,

    /// Starting block number for historical extraction
    #[arg(long, short = 'b')]
    pub start_block: BlockNumber,

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

    /// Enable progress callbacks (will print progress every 10 seconds)
    #[arg(long)]
    pub progress: bool,
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
    /// Execute the dump historical preimages command asynchronously
    pub async fn execute<N: ProviderNodeTypes>(
        self,
        tool: &DbTool<N>,
    ) -> eyre::Result<()> {
        use reth_preimage_storage::LocalPreimageStorage;
        
        #[cfg(feature = "dynamodb")]
        use reth_preimage_storage::DynamoDbPreimageStorage;
        
        info!("Starting historical preimage extraction from block {}...", self.start_block);

        let provider = tool.provider_factory.database_provider_ro()?;
        let tx = provider.tx_ref();
        
        // Configure storage based on the selected backend
        let storage: Box<dyn PreimageStorage> = match self.storage {
            StorageBackend::Local => {
                let local_path = self.local_path.clone().unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("historical_preimages")
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
        
        // Extract historical preimages with optional progress tracking
        let stats = if self.progress {
            Self::extract_with_progress(tx, &*storage, self.start_block).await?
        } else {
            HistoricalPreimageExtractor::extract_historical_preimages_streaming(
                tx, &*storage, self.start_block
            ).await?
        };
        
        drop(provider);
        
        info!("Historical extraction complete!");
        Self::print_statistics(&stats);
        
        // Get final storage statistics
        let storage_stats = storage.get_statistics().await?;
        info!("Storage complete! Stored {} preimages", storage_stats.total_preimages);
        
        Ok(())
    }
    
    /// Extract with progress callbacks
    async fn extract_with_progress<TX: reth_db_api::transaction::DbTx>(
        tx: &TX,
        storage: &dyn PreimageStorage,
        start_block: BlockNumber,
    ) -> eyre::Result<HistoricalExtractionStatistics> {
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};
        
        let progress = Arc::new(Mutex::new(None::<HistoricalExtractionProgress>));
        let progress_clone = Arc::clone(&progress);
        
        // Start progress logging task
        let progress_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                if let Ok(guard) = progress_clone.lock() {
                    if let Some(ref p) = *guard {
                        info!("Progress: {}", p.to_string());
                    }
                }
            }
        });
        
        // Extract with progress callback
        let mut callback = |p: &HistoricalExtractionProgress| {
            if let Ok(mut guard) = progress.lock() {
                *guard = Some(p.clone());
            }
        };
        
        let stats = HistoricalPreimageExtractor::extract_historical_preimages_streaming(
            tx, storage, start_block
        ).await?;
        
        // Stop progress logging
        progress_task.abort();
        
        Ok(stats)
    }
    
    /// Print extraction statistics
    fn print_statistics(stats: &HistoricalExtractionStatistics) {
        info!("Historical Extraction Statistics:");
        info!("  Start block: {}", stats.start_block);
        info!("  Latest block: {}", stats.latest_block);
        info!("  Initial account preimages: {}", stats.initial_account_preimages);
        info!("  Initial storage preimages: {}", stats.initial_storage_preimages);
        info!("  Account change preimages: {}", stats.account_change_preimages);
        info!("  Storage change preimages: {}", stats.storage_change_preimages);
        info!("  Total preimages: {}", stats.total_preimages());
        info!("  Total bytes processed: {}", stats.total_bytes_processed);
        info!("  Average preimage size: {:.2} bytes", stats.average_preimage_size());
        info!("  Total extraction time: {:.2?}", stats.total_extraction_time);
        
        info!("  Final progress: {}", stats.progress.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use reth_ethereum_cli::chainspec::EthereumChainSpecParser;

    #[test]
    fn test_parse_historical_command() {
        let args = vec![
            "dump-historical-preimages",
            "--start-block", "1000000",
            "--storage", "local",
            "--batch-size", "50",
            "--local-path", "/tmp/historical_preimages",
            "--progress",
        ];
        
        let command = Command::<EthereumChainSpecParser>::try_parse_from(args).unwrap();
        
        assert_eq!(command.start_block, 1000000);
        assert!(matches!(command.storage, StorageBackend::Local));
        assert_eq!(command.batch_size, 50);
        assert_eq!(command.local_path, Some(PathBuf::from("/tmp/historical_preimages")));
        assert!(command.progress);
    }
    
    #[test]
    fn test_parse_historical_dynamodb_command() {
        let args = vec![
            "dump-historical-preimages",
            "--start-block", "2000000",
            "--storage", "dynamodb",
            "--table-name", "test-historical-table",
            "--aws-region", "us-west-2",
        ];
        
        let command = Command::<EthereumChainSpecParser>::try_parse_from(args).unwrap();
        
        assert_eq!(command.start_block, 2000000);
        #[cfg(feature = "dynamodb")]
        assert!(matches!(command.storage, StorageBackend::DynamoDB));
        assert_eq!(command.table_name, Some("test-historical-table".to_string()));
        assert_eq!(command.aws_region, Some("us-west-2".to_string()));
        assert!(!command.progress);
    }
    
    #[test]
    fn test_default_values() {
        let args = vec![
            "dump-historical-preimages",
            "--start-block", "1000000",
        ];
        
        let command = Command::<EthereumChainSpecParser>::try_parse_from(args).unwrap();
        
        assert_eq!(command.start_block, 1000000);
        assert!(matches!(command.storage, StorageBackend::Local));
        assert_eq!(command.batch_size, 100);
        assert_eq!(command.local_path, None);
        assert!(!command.progress);
    }
} 