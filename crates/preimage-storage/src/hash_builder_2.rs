//! The implementation of the hash builder.

use alloy_primitives::{keccak256, map::HashMap, B256};
use alloy_rlp::EMPTY_STRING_CODE;
use reth_trie::{hash_builder::{HashBuilderValue, HashBuilderValueRef}, BranchNodeCompact, BranchNodeRef, ExtensionNodeRef, LeafNodeRef, Nibbles, RlpNode, TrieMask, EMPTY_ROOT_HASH};
use core::cmp;
use tracing::{info, trace};
use alloy_trie::proof::ProofNodes;

use alloy_primitives::Bytes;

/// Proof retainer is used to store proofs during merkle trie construction.
/// It is intended to be used within the [`HashBuilder`](crate::HashBuilder).
#[derive(Default, Clone, Debug)]
pub struct ProofRetainer {
    /// The map retained trie node keys to RLP serialized trie nodes.
    proof_nodes: ProofNodes,
}

impl ProofRetainer {
    /// Create new retainer with target nibbles.
    pub fn new() -> Self {
        Self { proof_nodes: Default::default() }
    }

    /// Returns `true` if the given prefix matches the retainer target.
    pub fn matches(&self, _prefix: &Nibbles) -> bool {
        true
    }

    /// Returns all collected proofs.
    pub fn into_proof_nodes(self) -> ProofNodes {
        self.proof_nodes
    }

    /// Retain the proof if the key matches any of the targets.
    pub fn retain(&mut self, prefix: &Nibbles, proof: &[u8]) {
        if prefix.is_empty() || self.matches(prefix) {
            self.proof_nodes.insert(*prefix, Bytes::from(proof.to_vec()));
        }
    }

    pub fn len(&self) -> usize {
        self.proof_nodes.len()
    }
}


/// A component used to construct the root hash of the trie.
///
/// The primary purpose of a Hash Builder is to build the Merkle proof that is essential for
/// verifying the integrity and authenticity of the trie's contents. It achieves this by
/// constructing the root hash from the hashes of child nodes according to specific rules, depending
/// on the type of the node (branch, extension, or leaf).
///
/// Here's an overview of how the Hash Builder works for each type of node:
///  * Branch Node: The Hash Builder combines the hashes of all the child nodes of the branch node,
///    using a cryptographic hash function like SHA-256. The child nodes' hashes are concatenated
///    and hashed, and the result is considered the hash of the branch node. The process is repeated
///    recursively until the root hash is obtained.
///  * Extension Node: In the case of an extension node, the Hash Builder first encodes the node's
///    shared nibble path, followed by the hash of the next child node. It concatenates these values
///    and then computes the hash of the resulting data, which represents the hash of the extension
///    node.
///  * Leaf Node: For a leaf node, the Hash Builder first encodes the key-path and the value of the
///    leaf node. It then concatenates the encoded key-path and value, and computes the hash of this
///    concatenated data, which represents the hash of the leaf node.
///
/// The Hash Builder operates recursively, starting from the bottom of the trie and working its way
/// up, combining the hashes of child nodes and ultimately generating the root hash. The root hash
/// can then be used to verify the integrity and authenticity of the trie's data by constructing and
/// verifying Merkle proofs.
#[derive(Debug, Clone, Default)]
#[allow(missing_docs)]
pub struct HashBuilder {
    pub key: Nibbles,
    pub value: HashBuilderValue,
    pub stack: Vec<RlpNode>,

    pub state_masks: Vec<TrieMask>,
    pub tree_masks: Vec<TrieMask>,
    pub hash_masks: Vec<TrieMask>,

    pub stored_in_database: bool,

    pub updated_branch_nodes: Option<HashMap<Nibbles, BranchNodeCompact>>,
    pub proof_retainer: Option<ProofRetainer>,

    pub rlp_buf: Vec<u8>,
}

impl HashBuilder {
    /// Enables the Hash Builder to store updated branch nodes.
    ///
    /// Call [HashBuilder::split] to get the updates to branch nodes.
    pub fn with_updates(mut self, retain_updates: bool) -> Self {
        self.set_updates(retain_updates);
        self
    }

    /// Enable specified proof retainer.
    pub fn with_proof_retainer(mut self, retainer: ProofRetainer) -> Self {
        self.proof_retainer = Some(retainer);
        self
    }

    /// Enables the Hash Builder to store updated branch nodes.
    ///
    /// Call [HashBuilder::split] to get the updates to branch nodes.
    pub fn set_updates(&mut self, retain_updates: bool) {
        if retain_updates {
            self.updated_branch_nodes = Some(HashMap::default());
        }
    }

    /// Splits the [HashBuilder] into a [HashBuilder] and hash builder updates.
    pub fn split(mut self) -> (Self, HashMap<Nibbles, BranchNodeCompact>) {
        let updates = self.updated_branch_nodes.take();
        (self, updates.unwrap_or_default())
    }

    /// Take and return retained proof nodes.
    pub fn take_proof_nodes(&mut self) -> ProofNodes {
        self.proof_retainer.take().map(ProofRetainer::into_proof_nodes).unwrap_or_default()
    }

    /// The number of total updates accrued.
    /// Returns `0` if [Self::with_updates] was not called.
    pub fn updates_len(&self) -> usize {
        self.updated_branch_nodes.as_ref().map(|u| u.len()).unwrap_or(0)
    }

    /// Print the current stack of the Hash Builder.
    #[cfg(feature = "std")]
    pub fn print_stack(&self) {
        println!("============ STACK ===============");
        for item in &self.stack {
            println!("{}", alloy_primitives::hex::encode(item));
        }
        println!("============ END STACK ===============");
    }

    /// Adds a new leaf element and its value to the trie hash builder.
    ///
    /// # Panics
    ///
    /// Panics if the new key does not come after the current key.
    pub fn add_leaf(&mut self, key: Nibbles, value: &[u8]) {
        assert!(key > self.key, "add_leaf key {:?} self.key {:?}", key, self.key);
        self.add_leaf_unchecked(key, value);
    }

    /// Adds a new leaf element and its value to the trie hash builder,
    /// without checking the order of the new key. This is only for
    /// performance-critical usage that guarantees keys are inserted
    /// in sorted order.
    pub fn add_leaf_unchecked(&mut self, key: Nibbles, value: &[u8]) {
        debug_assert!(key > self.key, "add_leaf_unchecked key {:?} self.key {:?}", key, self.key);
        if !self.key.is_empty() {
            self.update(&key);
        }
        self.set_key_value(key, HashBuilderValueRef::Bytes(value));
    }

    /// Adds a new branch element and its hash to the trie hash builder.
    pub fn add_branch(&mut self, key: Nibbles, value: B256, stored_in_database: bool) {
        assert!(
            key > self.key || (self.key.is_empty() && key.is_empty()),
            "add_branch key {:?} self.key {:?}",
            key,
            self.key
        );
        if !self.key.is_empty() {
            self.update(&key);
        } else if key.is_empty() {
            self.stack.push(RlpNode::word_rlp(&value));
        }
        self.set_key_value(key, HashBuilderValueRef::Hash(&value));
        self.stored_in_database = stored_in_database;
    }

    /// Returns the current root hash of the trie builder.
    pub fn root(&mut self) -> B256 {
        // Clears the internal state
        if !self.key.is_empty() {
            self.update(&Nibbles::default());
            self.key.clear();
            self.value.clear();
        }
        let root = self.current_root();
        if root == EMPTY_ROOT_HASH {
            if let Some(proof_retainer) = self.proof_retainer.as_mut() {
                proof_retainer.retain(&Nibbles::default(), &[EMPTY_STRING_CODE])
            }
        }
        root
    }

    #[inline]
    fn set_key_value(&mut self, key: Nibbles, value: HashBuilderValueRef<'_>) {
        self.log_key_value("old value");
        self.key = key;
        self.value.set_from_ref(value);
        self.log_key_value("new value");
    }

    fn log_key_value(&self, msg: &str) {
        trace!(target: "trie::hash_builder",
            key = ?self.key,
            value = ?self.value,
            "{msg}",
        );
    }

    fn current_root(&self) -> B256 {
        if let Some(node_ref) = self.stack.last() {
            if let Some(hash) = node_ref.as_hash() { hash } else { keccak256(node_ref) }
        } else {
            EMPTY_ROOT_HASH
        }
    }

    /// Given a new element, it appends it to the stack and proceeds to loop through the stack state
    /// and convert the nodes it can into branch / extension nodes and hash them. This ensures
    /// that the top of the stack always contains the merkle root corresponding to the trie
    /// built so far.
    fn update(&mut self, succeeding: &Nibbles) {
        let mut build_extensions = false;
        // current / self.key is always the latest added element in the trie
        let mut current = self.key;
        debug_assert!(!current.is_empty());

        trace!(target: "trie::hash_builder", ?current, ?succeeding, "updating merkle tree");

        let mut i = 0usize;
        loop {
            let _span = tracing::trace_span!(target: "trie::hash_builder", "loop", i, ?current, build_extensions).entered();

            let preceding_exists = !self.state_masks.is_empty();
            let preceding_len = self.state_masks.len().saturating_sub(1);

            let common_prefix_len = succeeding.common_prefix_length(&current);
            let len = cmp::max(preceding_len, common_prefix_len);
            assert!(len < current.len(), "len {} current.len {}", len, current.len());

            trace!(
                target: "trie::hash_builder",
                ?len,
                ?common_prefix_len,
                ?preceding_len,
                preceding_exists,
                "prefix lengths after comparing keys"
            );

            // Adjust the state masks for branch calculation
            let extra_digit = current.get_unchecked(len);
            if self.state_masks.len() <= len {
                let new_len = len + 1;
                trace!(target: "trie::hash_builder", new_len, old_len = self.state_masks.len(), "scaling state masks to fit");
                self.state_masks.resize(new_len, TrieMask::default());
            }
            self.state_masks[len] |= TrieMask::from_nibble(extra_digit);
            trace!(
                target: "trie::hash_builder",
                ?extra_digit,
                state_masks = ?self.state_masks,
            );

            // Adjust the tree masks for exporting to the DB
            if self.tree_masks.len() < current.len() {
                self.resize_masks(current.len());
            }

            let mut len_from = len;
            if !succeeding.is_empty() || preceding_exists {
                len_from += 1;
            }
            trace!(target: "trie::hash_builder", "skipping {len_from} nibbles");

            // The key without the common prefix
            let short_node_key = current.slice(len_from..);
            trace!(target: "trie::hash_builder", ?short_node_key);

            // Concatenate the 2 nodes together
            if !build_extensions {
                match self.value.as_ref() {
                    HashBuilderValueRef::Bytes(leaf_value) => {
                        let leaf_node = LeafNodeRef::new(&short_node_key, leaf_value);
                        self.rlp_buf.clear();
                        let rlp = leaf_node.rlp(&mut self.rlp_buf);

                        let path = current.slice(..len_from);
                        trace!(
                            target: "trie::hash_builder",
                            ?path,
                            ?leaf_node,
                            ?rlp,
                            "pushing leaf node",
                        );
                        self.stack.push(rlp);
                        self.retain_proof_from_buf(&path);
                    }
                    HashBuilderValueRef::Hash(hash) => {
                        trace!(target: "trie::hash_builder", ?hash, "pushing branch node hash");
                        self.stack.push(RlpNode::word_rlp(hash));

                        if self.stored_in_database {
                            self.tree_masks[current.len() - 1] |=
                                TrieMask::from_nibble(current.last().unwrap());
                        }
                        self.hash_masks[current.len() - 1] |=
                            TrieMask::from_nibble(current.last().unwrap());

                        build_extensions = true;
                    }
                }
            }

            if build_extensions && !short_node_key.is_empty() {
                self.update_masks(&current, len_from);
                let stack_last = self.stack.pop().expect("there should be at least one stack item");
                let extension_node = ExtensionNodeRef::new(&short_node_key, &stack_last);

                self.rlp_buf.clear();
                let rlp = extension_node.rlp(&mut self.rlp_buf);

                let path = current.slice(..len_from);
                trace!(
                    target: "trie::hash_builder",
                    ?path,
                    ?extension_node,
                    ?rlp,
                    "pushing extension node",
                );
                self.stack.push(rlp);
                self.retain_proof_from_buf(&path);
                self.resize_masks(len_from);
            }

            if preceding_len <= common_prefix_len && !succeeding.is_empty() {
                trace!(target: "trie::hash_builder", "no common prefix to create branch nodes from, returning");
                return;
            }

            // Insert branch nodes in the stack
            if !succeeding.is_empty() || preceding_exists {
                // Pushes the corresponding branch node to the stack
                let children = self.push_branch_node(&current, len);
                // Need to store the branch node in an efficient format outside of the hash builder
                self.store_branch_node(&current, len, children);
            }

            self.state_masks.resize(len, TrieMask::default());
            self.resize_masks(len);

            if preceding_len == 0 {
                trace!(target: "trie::hash_builder", "0 or 1 state masks means we have no more elements to process");
                return;
            }

            current.truncate(preceding_len);
            trace!(target: "trie::hash_builder", ?current, "truncated nibbles to {} bytes", preceding_len);

            trace!(target: "trie::hash_builder", state_masks = ?self.state_masks, "popping empty state masks");
            while self.state_masks.last() == Some(&TrieMask::default()) {
                self.state_masks.pop();
            }

            build_extensions = true;

            i += 1;
        }
    }

    /// Given the size of the longest common prefix, it proceeds to create a branch node
    /// from the state mask and existing stack state, and store its RLP to the top of the stack,
    /// after popping all the relevant elements from the stack.
    ///
    /// Returns the hashes of the children of the branch node, only if `updated_branch_nodes` is
    /// enabled.
    fn push_branch_node(&mut self, current: &Nibbles, len: usize) -> Vec<B256> {
        let state_mask = self.state_masks[len];
        let hash_mask = self.hash_masks[len];
        let branch_node = BranchNodeRef::new(&self.stack, state_mask);
        // Avoid calculating this value if it's not needed.
        let children = if self.updated_branch_nodes.is_some() {
            branch_node.child_hashes(hash_mask).collect()
        } else {
            vec![]
        };

        self.rlp_buf.clear();
        let rlp = branch_node.rlp(&mut self.rlp_buf);
        let path = current.slice(..len);
        trace!(
            target: "trie::hash_builder",
            ?path,
            ?branch_node,
            ?rlp,
            "pushing branch node",
        );
        self.retain_proof_from_buf(&path);

        // Clears the stack from the branch node elements
        let first_child_idx = self.stack.len() - state_mask.count_ones() as usize;
        trace!(
            target: "trie::hash_builder",
            new_len = first_child_idx,
            old_len = self.stack.len(),
            "resizing stack to prepare branch node"
        );
        self.stack.resize_with(first_child_idx, Default::default);

        self.stack.push(rlp);
        children
    }

    /// Given the current nibble prefix and the highest common prefix length, proceeds
    /// to update the masks for the next level and store the branch node and the
    /// masks in the database. We will use that when consuming the intermediate nodes
    /// from the database to efficiently build the trie.
    fn store_branch_node(&mut self, current: &Nibbles, len: usize, children: Vec<B256>) {
        if len > 0 {
            let parent_index = len - 1;
            self.hash_masks[parent_index] |=
                TrieMask::from_nibble(current.get_unchecked(parent_index));
        }

        let store_in_db_trie = !self.tree_masks[len].is_empty() || !self.hash_masks[len].is_empty();
        if store_in_db_trie {
            if len > 0 {
                let parent_index = len - 1;
                self.tree_masks[parent_index] |=
                    TrieMask::from_nibble(current.get_unchecked(parent_index));
            }

            if self.updated_branch_nodes.is_some() {
                let common_prefix = current.slice(..len);
                let node = BranchNodeCompact::new(
                    self.state_masks[len],
                    self.tree_masks[len],
                    self.hash_masks[len],
                    children,
                    (len == 0).then(|| self.current_root()),
                );
                self.updated_branch_nodes.as_mut().unwrap().insert(common_prefix, node);
            }
        }
    }

    fn retain_proof_from_buf(&mut self, prefix: &Nibbles) {
        if let Some(proof_retainer) = self.proof_retainer.as_mut() {
            proof_retainer.retain(prefix, &self.rlp_buf)
        }
    }

    fn update_masks(&mut self, current: &Nibbles, len_from: usize) {
        if len_from > 0 {
            let flag = TrieMask::from_nibble(current.get_unchecked(len_from - 1));

            self.hash_masks[len_from - 1] &= !flag;

            if !self.tree_masks[current.len() - 1].is_empty() {
                self.tree_masks[len_from - 1] |= flag;
            }
        }
    }

    fn resize_masks(&mut self, new_len: usize) {
        trace!(
            target: "trie::hash_builder",
            new_len,
            old_tree_mask_len = self.tree_masks.len(),
            old_hash_mask_len = self.hash_masks.len(),
            "resizing tree/hash masks"
        );
        self.tree_masks.resize(new_len, TrieMask::default());
        self.hash_masks.resize(new_len, TrieMask::default());
    }
}
