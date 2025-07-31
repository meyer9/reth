//! Error types for preimage storage operations

use alloy_primitives::B256;
use reth_db_api::DatabaseError;

/// Errors that can occur during preimage storage operations
#[derive(Debug, thiserror::Error)]
pub enum PreimageStorageError {
    /// Database operation failed
    #[error("Database error: {0}")]
    Database(#[from] eyre::Report),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// DynamoDB error
    #[cfg(feature = "dynamodb")]
    #[error("DynamoDB error: {0}")]
    DynamoDb(#[from] aws_sdk_dynamodb::Error),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid input parameters
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Preimage not found
    #[error("Preimage not found for hash: {0}")]
    PreimageNotFound(B256),

    /// Batch operation failed
    #[error("Batch operation failed: {0}")]
    BatchOperationFailed(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Storage full or quota exceeded
    #[error("Storage quota exceeded")]
    StorageQuotaExceeded,

    /// Generic storage error
    #[error("Storage error: {0}")]
    Storage(String),
}

impl From<DatabaseError> for PreimageStorageError {
    fn from(error: DatabaseError) -> Self {
        PreimageStorageError::Database(eyre::eyre!(error))
    }
}

/// Result type for preimage storage operations
pub type PreimageStorageResult<T> = Result<T, PreimageStorageError>;
