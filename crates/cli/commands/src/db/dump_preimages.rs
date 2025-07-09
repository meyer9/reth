//! Database command for dumping trie preimages

use clap::Parser;
use reth_db_common::DbTool;
use reth_preimage_storage::PreimageStorage;
use reth_provider::providers::ProviderNodeTypes;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use tracing::{info, warn};

/// The arguments for the `reth db dump-preimages` command
#[derive(Parser, Debug)]
pub struct Command {
    /// Output format
    #[arg(long, default_value = "json")]
    pub format: OutputFormat,
    
    /// Storage backend to use
    #[arg(long, default_value = "local")]
    pub storage: StorageBackend,
    
    /// Batch size for processing preimages
    #[arg(long, default_value = "100")]
    pub batch_size: usize,
    
    /// Output file path (for JSON format)
    #[arg(long)]
    pub output_file: Option<PathBuf>,
    
    /// Local storage path (for local backend)
    #[arg(long)]
    pub local_path: Option<PathBuf>,
    
    /// DynamoDB table name (for DynamoDB backend)
    #[arg(long)]
    pub table_name: Option<String>,
    
    /// AWS region (for DynamoDB backend)
    #[arg(long)]
    pub aws_region: Option<String>,
    
    /// Show statistics only, don't store preimages
    #[arg(long)]
    pub stats_only: bool,
    
    /// Verbose output
    #[arg(long, short)]
    pub verbose: bool,
}

/// Output format for preimage data
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    /// JSON format
    Json,
    /// Binary format
    Binary,
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

impl Command {
    /// Execute the dump preimages command
    pub fn execute<N: ProviderNodeTypes>(
        self,
        tool: &DbTool<N>,
    ) -> eyre::Result<()> {
        // Create a Tokio runtime for async operations
        let rt = Runtime::new()?;
        
        rt.block_on(async {
            self.execute_async(tool).await
        })
    }
    
    /// Execute the dump preimages command asynchronously
    async fn execute_async<N: ProviderNodeTypes>(
        self,
        tool: &DbTool<N>,
    ) -> eyre::Result<()> {
        use reth_preimage_storage::{
            LocalPreimageStorage, PreimageStorageConfig, TriePreimageExtractor,
        };
        
        #[cfg(feature = "dynamodb")]
        use reth_preimage_storage::DynamoDbPreimageStorage;
        
        info!("Starting trie preimage extraction...");

        let provider = tool.provider_factory.provider_rw()?;
        let tx = provider.tx_ref();
        
        // Extract preimages from the database
        let preimage_data = TriePreimageExtractor::extract_all_preimages(tx)?;

        drop(provider);
        
        let stats = preimage_data.statistics();
        info!("Extraction complete!");
        info!("Statistics:");
        info!("  Total preimages: {}", stats.total_count());
        info!("  Account preimages: {}", stats.account_preimage_count);
        info!("  Storage preimages: {}", stats.storage_preimage_count);
        info!("  Total size: {} bytes", stats.total_size_bytes());
        info!("  Average size: {:.2} bytes", stats.average_preimage_size());
        info!("  State root: {:x}", stats.state_root);
        
        // If stats only, return early
        if self.stats_only {
            return Ok(());
        }
        
        // Configure storage
        let config = PreimageStorageConfig {
            batch_size: self.batch_size,
            table_name: self.table_name.clone(),
            aws_region: self.aws_region.clone(),
            local_path: self.local_path.clone(),
        };
        
        // Store preimages based on the selected backend
        match self.storage {
            StorageBackend::Local => {
                let local_path = self.local_path.clone().unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("preimages")
                });
                
                let config = PreimageStorageConfig {
                    local_path: Some(local_path),
                    ..config
                };
                
                info!("Using local storage at: {:?}", config.local_path);
                let storage = LocalPreimageStorage::new(config).await?;
                
                info!("Storing preimages to local storage...");
                storage.store_preimages(preimage_data.all_preimages()).await?;
                
                let storage_stats = storage.get_statistics().await?;
                info!("Storage complete! Stored {} preimages", storage_stats.total_preimages);
            }
            
            #[cfg(feature = "dynamodb")]
            StorageBackend::DynamoDB => {
                info!("Using DynamoDB storage");
                let storage = DynamoDbPreimageStorage::new(config).await?;
                
                info!("Storing preimages to DynamoDB...");
                storage.store_preimages(preimage_data.all_preimages()).await?;
                
                let storage_stats = storage.get_statistics().await?;
                info!("Storage complete! Stored {} preimages", storage_stats.total_preimages);
            }
        }
        
        // Output to file if requested
        if let Some(output_file) = &self.output_file {
            match self.format {
                OutputFormat::Json => {
                    let json_data = serde_json::json!({
                        "statistics": stats,
                        "preimages": preimage_data.all_preimages()
                    });
                    
                    tokio::fs::write(output_file, serde_json::to_string_pretty(&json_data)?).await?;
                    info!("Saved preimage data to: {:?}", output_file);
                }
                OutputFormat::Binary => {
                    warn!("Binary output format not yet implemented");
                }
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    
    #[test]
    fn test_parse_command() {
        let args = vec![
            "dump-preimages",
            "--format", "json",
            "--storage", "local",
            "--batch-size", "50",
            "--local-path", "/tmp/preimages",
            "--stats-only",
        ];
        
        let command = Command::try_parse_from(args).unwrap();
        
        assert!(matches!(command.format, OutputFormat::Json));
        assert!(matches!(command.storage, StorageBackend::Local));
        assert_eq!(command.batch_size, 50);
        assert_eq!(command.local_path, Some(PathBuf::from("/tmp/preimages")));
        assert!(command.stats_only);
    }
    
    #[test]
    fn test_parse_dynamodb_command() {
        let args = vec![
            "dump-preimages",
            "--storage", "dynamodb",
            "--table-name", "test-table",
            "--aws-region", "us-west-2",
        ];
        
        let command = Command::try_parse_from(args).unwrap();
        
        #[cfg(feature = "dynamodb")]
        assert!(matches!(command.storage, StorageBackend::DynamoDB));
        assert_eq!(command.table_name, Some("test-table".to_string()));
        assert_eq!(command.aws_region, Some("us-west-2".to_string()));
    }
} 