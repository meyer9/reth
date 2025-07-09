# Plan: DB Subcommand for Trie Preimage Dump

## Overview
Create a new DB subcommand that dumps the current trie (account and storage nodes) as preimages and publishes them to a preimage storage interface (e.g., DynamoDB).

## Key Components

### 1. Database Tables Understanding
- **AccountsTrie**: Stores account trie nodes with key `StoredNibbles` and value `BranchNodeCompact`
- **StoragesTrie**: Stores storage trie nodes with key `B256` (hashed address) and subkey `StoredNibblesSubKey` and value `StorageTrieEntry`

### 2. Preimage Concept
- Each node in the MPT is referenced by its hash
- The preimage is the original data that produces this hash
- The trie can be serialized as a list of preimages plus a root hash

## Implementation Steps

### Step 1: Create Preimage Storage Interface
- [ ] Define a generic `PreimageStorage` trait for publishing preimages
- [ ] Implement DynamoDB backend for the trait
- [ ] Include methods for batch publishing and error handling

### Step 2: Create Trie Preimage Extractor
- [ ] Implement logic to iterate through AccountsTrie and StoragesTrie tables
- [ ] Extract node data and compute hashes
- [ ] Convert trie nodes to preimage format (hash -> data mapping)

### Step 3: Add New DB Subcommand
- [ ] Create `dump_preimages.rs` in `crates/cli/commands/src/db/`
- [ ] Add command to `Subcommands` enum in `db/mod.rs`
- [ ] Implement command execution logic

### Step 4: Configuration and CLI Options
- [ ] Add command line options for:
  - Output format (JSON, binary, etc.)
  - Storage backend selection (DynamoDB, local file, etc.)
  - Batch size for processing
  - Root hash output

### Step 5: Error Handling and Validation
- [ ] Handle database errors gracefully
- [ ] Validate trie integrity during extraction
- [ ] Provide progress reporting for large tries

## File Structure
```
crates/cli/commands/src/db/
├── dump_preimages.rs          # New DB subcommand implementation
├── mod.rs                     # Updated to include new subcommand
crates/preimage-storage/       # New crate for preimage storage
├── src/
│   ├── lib.rs                 # Main library exports
│   ├── traits.rs              # PreimageStorage trait
│   ├── dynamodb.rs            # DynamoDB implementation
│   └── local.rs               # Local file implementation (for testing)
└── Cargo.toml                 # Dependencies (AWS SDK, etc.)
```

## Dependencies
- AWS SDK for DynamoDB integration
- Serialization libraries (serde, bincode)
- Progress reporting (indicatif)

## Testing Strategy
- Unit tests for preimage extraction logic
- Integration tests with mock DynamoDB
- End-to-end tests with actual trie data 