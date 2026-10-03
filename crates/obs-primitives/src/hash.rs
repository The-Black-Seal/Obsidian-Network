//! 32-byte hashes, domain-separated commitments and Merkle roots.

use obs_crypto::encoding::hex_encode;
use obs_crypto::sha2::sha256;
use core::fmt;

/// A 32-byte hash value (block hash, transaction id, state root, ...).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// The all-zero hash (used as the "null" parent in genesis definitions).
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Hash32 {
        Hash32(bytes)
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex representation.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Parses a 64-character lowercase or uppercase hex string.
    pub fn from_hex(s: &str) -> Option<Hash32> {
        let bytes = obs_crypto::encoding::hex_decode(s)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(Hash32(out))
    }

    /// Domain-separated hash of the concatenation of `parts`.
    pub fn tagged(tag: &str, parts: &[&[u8]]) -> Hash32 {
        Hash32::from_bytes(sha256(&tagged_preimage(tag, parts)))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

/// Returns the exact byte string that [`Hash32::tagged`] hashes.
///
/// Signatures cover this pre-image, so a signed structure is bound to its
/// domain tag without either side having to re-hash it.
pub fn tagged_preimage(tag: &str, parts: &[&[u8]]) -> Vec<u8> {
    let tag_bytes = tag.as_bytes();
    let mut out = Vec::with_capacity(8 + tag_bytes.len() + parts.iter().map(|p| p.len() + 8).sum::<usize>());
    out.extend_from_slice(&(tag_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(tag_bytes);
    out.push(0);
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

// ---------------------------------------------------------------------------
// Merkle trees
// ---------------------------------------------------------------------------

/// Domain tag for leaf hashing (RFC 6962-style separation).
pub const MERKLE_LEAF_TAG: &str = "OBSIDIAN/MERKLE/LEAF/v1";
/// Domain tag for internal node hashing.
pub const MERKLE_NODE_TAG: &str = "OBSIDIAN/MERKLE/NODE/v1";

/// Computes a Merkle root over an ordered list of leaf payloads.
///
/// * Empty list → the all-zero hash.
/// * Odd levels promote the final node unchanged (RFC 6962 rule).
///
/// The construction is deterministic and independent of the caller, so any
/// implementation given the same leaves and order produces the same root.
pub fn merkle_root(leaves: &[Vec<u8>]) -> Hash32 {
    if leaves.is_empty() {
        return Hash32::ZERO;
    }
    let mut level: Vec<Hash32> = leaves
        .iter()
        .map(|leaf| Hash32::tagged(MERKLE_LEAF_TAG, &[leaf]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(Hash32::tagged(
                    MERKLE_NODE_TAG,
                    &[&pair[0].0, &pair[1].0],
                ));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// Computes a Merkle inclusion proof for the leaf at `index`.
///
/// Each element is `Some(sibling)` for a normal pair, or `None` when the node
/// at that level was promoted unchanged (odd number of nodes).  The explicit
/// marker keeps verification unambiguous for any leaf count.
pub fn merkle_proof(leaves: &[Vec<u8>], index: usize) -> Option<Vec<Option<Hash32>>> {
    if index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Hash32> = leaves
        .iter()
        .map(|leaf| Hash32::tagged(MERKLE_LEAF_TAG, &[leaf]))
        .collect();
    let mut proof = Vec::new();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            level.get(idx + 1).copied()
        } else {
            Some(level[idx - 1])
        };
        proof.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(Hash32::tagged(MERKLE_NODE_TAG, &[&pair[0].0, &pair[1].0]));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
        idx /= 2;
    }
    Some(proof)
}

/// Verifies a Merkle inclusion proof produced by [`merkle_proof`].
pub fn merkle_verify(
    root: Hash32,
    leaf_payload: &[u8],
    index: usize,
    proof: &[Option<Hash32>],
) -> bool {
    let mut node = Hash32::tagged(MERKLE_LEAF_TAG, &[leaf_payload]);
    let mut idx = index;
    for sibling in proof {
        match sibling {
            None => {
                // The node was promoted unchanged; only valid for an even index.
                if idx % 2 != 0 {
                    return false;
                }
            }
            Some(sibling) => {
                node = if idx % 2 == 0 {
                    Hash32::tagged(MERKLE_NODE_TAG, &[&node.0, &sibling.0])
                } else {
                    Hash32::tagged(MERKLE_NODE_TAG, &[&sibling.0, &node.0])
                };
            }
        }
        idx /= 2;
    }
    node == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_zero() {
        assert_eq!(merkle_root(&[]), Hash32::ZERO);
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let leaves = vec![b"a".to_vec()];
        let leaf = Hash32::tagged(MERKLE_LEAF_TAG, &[b"a"]);
        assert_eq!(merkle_root(&leaves), leaf);
    }

    #[test]
    fn roots_are_order_dependent_and_deterministic() {
        let a = vec![b"a".to_vec(), b"b".to_vec()];
        let b = vec![b"b".to_vec(), b"a".to_vec()];
        assert_ne!(merkle_root(&a), merkle_root(&b));
        assert_eq!(merkle_root(&a), merkle_root(&a));
    }

    #[test]
    fn proofs_verify_for_all_positions() {
        for count in 1..=9usize {
            let leaves: Vec<Vec<u8>> = (0..count).map(|i| vec![i as u8; i + 1]).collect();
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = merkle_proof(&leaves, i).unwrap();
                assert!(
                    merkle_verify(root, leaf, i, &proof),
                    "proof must verify for leaf {} of {}",
                    i,
                    count
                );
                // A tampered leaf payload must not verify.
                let mut bad = leaf.clone();
                bad.push(0);
                assert!(!merkle_verify(root, &bad, i, &proof));
            }
        }
    }

    #[test]
    fn hash_hex_roundtrip() {
        let h = Hash32::tagged("test", &[b"value"]);
        assert_eq!(Hash32::from_hex(&h.to_hex()).unwrap(), h);
        assert!(Hash32::from_hex("zz").is_none());
    }
}
