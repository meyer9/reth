//! The implementation of the hash builder.

use reth_trie::{HashBuilder, Nibbles};
use alloy_trie::proof::{ProofNodes, ProofRetainer};

use alloy_primitives::Bytes;

/// Proof retainer is used to store proofs during merkle trie construction.
/// It is intended to be used within the [`HashBuilder`](crate::HashBuilder).
#[derive(Default, Clone, Debug)]
pub struct UniversalProofRetainer {
    /// The map retained trie node keys to RLP serialized trie nodes.
    proof_nodes: ProofNodes,
}

impl UniversalProofRetainer {
    /// Create new retainer with target nibbles.
    pub fn new() -> Self {
        Self { proof_nodes: Default::default() }
    }


    pub fn len(&self) -> usize {
        self.proof_nodes.len()
    }
}

impl ProofRetainer for UniversalProofRetainer {
    /// Returns `true` if the given prefix matches the retainer target.
    fn matches(&self, _prefix: &Nibbles) -> bool {
        true
    }

    /// Returns all collected proofs.
    fn into_proof_nodes(self) -> ProofNodes {
        self.proof_nodes
    }

    /// Retain the proof if the key matches any of the targets.
    fn retain(&mut self, prefix: &Nibbles, proof: &[u8]) {
        if prefix.is_empty() || self.matches(prefix) {
            self.proof_nodes.insert(*prefix, Bytes::from(proof.to_vec()));
        }
    }
}