//! Argon2id (RFC 9106) — memory-hard password and secret hashing.
//!
//! Implements Argon2 with the version-1.3 BlaMka round function, supporting the
//! Argon2d, Argon2i and Argon2id addressing modes.  Lanes are processed
//! sequentially: lanes are independent inside a slice, so this produces
//! byte-identical output to the multi-threaded reference implementation while
//! keeping the code free of threading assumptions.

use crate::blake2b::Blake2b;
use crate::ct::{Zeroize, Zeroizing};

/// Argon2 algorithm variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Type {
    /// Data-dependent addressing.
    D = 0,
    /// Data-independent addressing.
    I = 1,
    /// Hybrid (recommended for password hashing).
    Id = 2,
}

/// Argon2 parameters.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KiB (rounded down internally to a multiple of `4 * lanes`).
    pub memory_kib: u32,
    /// Number of passes over memory (time cost).
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub lanes: u32,
    /// Output length in bytes.
    pub output_len: u32,
    /// Algorithm variant.
    pub variant: Argon2Type,
}

impl Argon2Params {
    /// Obsidian protocol parameters for account passwords:
    /// 64 MiB, 3 passes, 1 lane, 32-byte tag.
    pub const PASSWORD: Argon2Params = Argon2Params {
        memory_kib: 65_536,
        iterations: 3,
        lanes: 1,
        output_len: 32,
        variant: Argon2Type::Id,
    };

    /// Parameters for high-entropy machine-generated credentials
    /// (mining-account recovery codes, API key secrets, invite codes).
    ///
    /// The dominant defence for these is their 160+ bits of uniform entropy;
    /// the KDF only has to make bulk guessing expensive.
    pub const HIGH_ENTROPY_CODE: Argon2Params = Argon2Params {
        memory_kib: 32_768,
        iterations: 2,
        lanes: 1,
        output_len: 32,
        variant: Argon2Type::Id,
    };

    /// Validates the parameter ranges supported by this implementation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.lanes == 0 || self.lanes > 0x00ff_ffff {
            return Err("argon2: lanes out of range");
        }
        if self.iterations == 0 {
            return Err("argon2: iterations must be >= 1");
        }
        if self.output_len < 4 || self.output_len > 1024 {
            return Err("argon2: output length out of range");
        }
        if self.memory_kib < 8 * self.lanes {
            return Err("argon2: memory cost must be >= 8 * lanes KiB");
        }
        Ok(())
    }
}

const ARGON2_VERSION: u32 = 0x13;
const ADDRESSES_IN_BLOCK: u32 = 128;
const SYNC_POINTS: u32 = 4;
const BLOCK_WORDS: usize = 128;

type Block = [u64; BLOCK_WORDS];

#[inline(always)]
fn g_blamka(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    let (va, vb) = (v[a], v[b]);
    v[a] = va
        .wrapping_add(vb)
        .wrapping_add(2u64.wrapping_mul((va & 0xffff_ffff).wrapping_mul(vb & 0xffff_ffff)));
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    let (vc, vd) = (v[c], v[d]);
    v[c] = vc
        .wrapping_add(vd)
        .wrapping_add(2u64.wrapping_mul((vc & 0xffff_ffff).wrapping_mul(vd & 0xffff_ffff)));
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    let (va, vb) = (v[a], v[b]);
    v[a] = va
        .wrapping_add(vb)
        .wrapping_add(2u64.wrapping_mul((va & 0xffff_ffff).wrapping_mul(vb & 0xffff_ffff)));
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    let (vc, vd) = (v[c], v[d]);
    v[c] = vc
        .wrapping_add(vd)
        .wrapping_add(2u64.wrapping_mul((vc & 0xffff_ffff).wrapping_mul(vd & 0xffff_ffff)));
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The Argon2 permutation `P` applied to 16 words.
#[inline(always)]
fn permute(v: &mut [u64; 16]) {
    g_blamka(v, 0, 4, 8, 12);
    g_blamka(v, 1, 5, 9, 13);
    g_blamka(v, 2, 6, 10, 14);
    g_blamka(v, 3, 7, 11, 15);
    g_blamka(v, 0, 5, 10, 15);
    g_blamka(v, 1, 6, 11, 12);
    g_blamka(v, 2, 7, 8, 13);
    g_blamka(v, 3, 4, 9, 14);
}

/// Applies `P` to all rows and then all columns of a block.
fn permute_block(z: &mut Block) {
    for row in 0..8 {
        let mut b = [0u64; 16];
        b.copy_from_slice(&z[row * 16..row * 16 + 16]);
        permute(&mut b);
        z[row * 16..row * 16 + 16].copy_from_slice(&b);
    }
    // Columns: group j consists of the word pairs (2j, 2j+1) taken from each
    // of the eight 16-word rows, i.e. words 2j, 2j+1, 2j+16, 2j+17, ...,
    // 2j+112, 2j+113 (RFC 9106 §3.5, matching the reference implementation).
    for col in 0..8 {
        let mut b = [0u64; 16];
        for row in 0..8 {
            b[row * 2] = z[row * 16 + col * 2];
            b[row * 2 + 1] = z[row * 16 + col * 2 + 1];
        }
        permute(&mut b);
        for row in 0..8 {
            z[row * 16 + col * 2] = b[row * 2];
            z[row * 16 + col * 2 + 1] = b[row * 2 + 1];
        }
    }
}

/// The Argon2 compression function `G(X, Y) = P(X ^ Y) ^ X ^ Y`.
///
/// When `old` is supplied (passes after the first) the previous contents of the
/// destination block are XORed into the result as specified in RFC 9106 §3.5.
fn fill_block(prev: &Block, reference: &Block, old: Option<&Block>, out: &mut Block) {
    let mut r = [0u64; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        r[i] = prev[i] ^ reference[i];
    }
    let mut tmp = r;
    if let Some(old) = old {
        for i in 0..BLOCK_WORDS {
            tmp[i] ^= old[i];
        }
    }
    let mut z = r;
    permute_block(&mut z);
    for i in 0..BLOCK_WORDS {
        out[i] = z[i] ^ tmp[i];
    }
}

/// Computes the next address block for data-independent addressing.
fn next_addresses(zero: &Block, input_block: &mut Block, address_block: &mut Block) {
    input_block[6] += 1;
    let mut first = [0u64; BLOCK_WORDS];
    fill_block(zero, input_block, None, &mut first);
    fill_block(zero, &first, None, address_block);
}

/// Argon2's variable-length hash function `H'` (RFC 9106 §3.3).
fn h_prime(input: &[u8], out_len: usize) -> Vec<u8> {
    if out_len <= 64 {
        let mut h = Blake2b::new(out_len);
        h.update(&(out_len as u32).to_le_bytes());
        h.update(input);
        return h.finalize();
    }
    let r = out_len.div_ceil(32) - 2;
    let mut h = Blake2b::new(64);
    h.update(&(out_len as u32).to_le_bytes());
    h.update(input);
    let mut v = h.finalize();
    let mut out = Vec::with_capacity(out_len);
    out.extend_from_slice(&v[..32]);
    for _ in 1..r {
        v = crate::blake2b::blake2b(&v, 64);
        out.extend_from_slice(&v[..32]);
    }
    let remaining = out_len - 32 * r;
    let last = crate::blake2b::blake2b(&v, remaining);
    out.extend_from_slice(&last);
    out
}

fn block_from_bytes(bytes: &[u8]) -> Block {
    debug_assert_eq!(bytes.len(), 1024);
    let mut b = [0u64; BLOCK_WORDS];
    for (i, word) in b.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *word = u64::from_le_bytes(w);
    }
    b
}

fn block_to_bytes(block: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    for word in block.iter() {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

/// Derives `out_len` bytes with Argon2.
pub fn argon2(
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    params.validate()?;
    if salt.len() < 8 {
        return Err("argon2: salt must be at least 8 bytes");
    }
    let lanes = params.lanes;
    let memory_blocks = (params.memory_kib / (SYNC_POINTS * lanes)) * (SYNC_POINTS * lanes);
    let lane_length = memory_blocks / lanes;
    let segment_length = lane_length / SYNC_POINTS;

    // H0 — pre-hashing digest.
    let mut h0 = Blake2b::new(64);
    h0.update(&lanes.to_le_bytes());
    h0.update(&params.output_len.to_le_bytes());
    h0.update(&params.memory_kib.to_le_bytes());
    h0.update(&params.iterations.to_le_bytes());
    h0.update(&ARGON2_VERSION.to_le_bytes());
    h0.update(&(params.variant as u32).to_le_bytes());
    h0.update(&(password.len() as u32).to_le_bytes());
    h0.update(password);
    h0.update(&(salt.len() as u32).to_le_bytes());
    h0.update(salt);
    let secret = secret.unwrap_or(&[]);
    h0.update(&(secret.len() as u32).to_le_bytes());
    h0.update(secret);
    let ad = associated_data.unwrap_or(&[]);
    h0.update(&(ad.len() as u32).to_le_bytes());
    h0.update(ad);
    let h0 = h0.finalize();

    let mut memory: Vec<Block> = vec![[0u64; BLOCK_WORDS]; memory_blocks as usize];

    // First two blocks of every lane.
    for lane in 0..lanes {
        for index in 0..2u32 {
            let mut input = Vec::with_capacity(h0.len() + 8);
            input.extend_from_slice(&h0);
            input.extend_from_slice(&index.to_le_bytes());
            input.extend_from_slice(&lane.to_le_bytes());
            let bytes = h_prime(&input, 1024);
            memory[(lane * lane_length + index) as usize] = block_from_bytes(&bytes);
        }
    }

    let zero_block = [0u64; BLOCK_WORDS];
    let mut input_block = [0u64; BLOCK_WORDS];
    let mut address_block = [0u64; BLOCK_WORDS];

    for pass in 0..params.iterations {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                let data_independent = match params.variant {
                    Argon2Type::I => true,
                    Argon2Type::D => false,
                    Argon2Type::Id => pass == 0 && slice < 2,
                };
                if data_independent {
                    input_block = [0u64; BLOCK_WORDS];
                    input_block[0] = pass as u64;
                    input_block[1] = lane as u64;
                    input_block[2] = slice as u64;
                    input_block[3] = memory_blocks as u64;
                    input_block[4] = params.iterations as u64;
                    input_block[5] = params.variant as u64;
                    address_block = [0u64; BLOCK_WORDS];
                    next_addresses(&zero_block, &mut input_block, &mut address_block);
                }
                let starting_index = if pass == 0 && slice == 0 { 2u32 } else { 0u32 };
                let mut current_offset =
                    lane * lane_length + slice * segment_length + starting_index;
                let mut prev_offset = if current_offset % lane_length == 0 {
                    current_offset + lane_length - 1
                } else {
                    current_offset - 1
                };
                for index in starting_index..segment_length {
                    if current_offset % lane_length == 1 {
                        prev_offset = current_offset - 1;
                    }
                    let pseudo_random: u64 = if data_independent {
                        if index % ADDRESSES_IN_BLOCK == 0 && index != starting_index {
                            next_addresses(&zero_block, &mut input_block, &mut address_block);
                        }
                        address_block[(index % ADDRESSES_IN_BLOCK) as usize]
                    } else {
                        memory[prev_offset as usize][0]
                    };
                    let j1 = (pseudo_random & 0xffff_ffff) as u32;
                    let j2 = (pseudo_random >> 32) as u32;
                    let ref_lane = if pass == 0 && slice == 0 {
                        lane
                    } else {
                        j2 % lanes
                    };
                    let same_lane = ref_lane == lane;
                    let reference_area_size: u32 = if pass == 0 {
                        if slice == 0 {
                            index - 1
                        } else if same_lane {
                            slice * segment_length + index - 1
                        } else {
                            slice * segment_length - u32::from(index == 0)
                        }
                    } else if same_lane {
                        lane_length - segment_length + index - 1
                    } else {
                        lane_length - segment_length - u32::from(index == 0)
                    };
                    let mut relative = j1 as u64;
                    relative = (relative * relative) >> 32;
                    relative = reference_area_size as u64
                        - 1
                        - ((reference_area_size as u64 * relative) >> 32);
                    let start_position: u32 = if pass == 0 || slice == 3 {
                        0
                    } else {
                        (slice + 1) * segment_length
                    };
                    let ref_index = (start_position + relative as u32) % lane_length;
                    let ref_offset = ref_lane * lane_length + ref_index;

                    let prev = memory[prev_offset as usize];
                    let reference = memory[ref_offset as usize];
                    let old = memory[current_offset as usize];
                    let mut out = [0u64; BLOCK_WORDS];
                    fill_block(&prev, &reference, if pass == 0 { None } else { Some(&old) }, &mut out);
                    memory[current_offset as usize] = out;

                    current_offset += 1;
                    prev_offset += 1;
                }
            }
        }
    }
    input_block.zeroize();
    address_block.zeroize();

    let mut final_block = memory[(lane_length - 1) as usize];
    for lane in 1..lanes {
        let last = memory[(lane * lane_length + lane_length - 1) as usize];
        for i in 0..BLOCK_WORDS {
            final_block[i] ^= last[i];
        }
    }
    let bytes = Zeroizing(block_to_bytes(&final_block));
    let tag = h_prime(&bytes, params.output_len as usize);
    Ok(tag)
}

/// Convenience wrapper for Argon2id.
pub fn argon2id(
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut p = *params;
    p.variant = Argon2Type::Id;
    argon2(&p, password, salt, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn argon2id_rfc9106_test_vector() {
        let params = Argon2Params {
            memory_kib: 32,
            iterations: 3,
            lanes: 4,
            output_len: 32,
            variant: Argon2Type::Id,
        };
        let tag = argon2(
            &params,
            &[0x01u8; 32],
            &[0x02u8; 16],
            Some(&[0x03u8; 8]),
            Some(&[0x04u8; 12]),
        )
        .unwrap();
        assert_eq!(
            hex(&tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn argon2i_rfc9106_test_vector() {
        let params = Argon2Params {
            memory_kib: 32,
            iterations: 3,
            lanes: 4,
            output_len: 32,
            variant: Argon2Type::I,
        };
        let tag = argon2(
            &params,
            &[0x01u8; 32],
            &[0x02u8; 16],
            Some(&[0x03u8; 8]),
            Some(&[0x04u8; 12]),
        )
        .unwrap();
        assert_eq!(
            hex(&tag),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );
    }

    #[test]
    fn argon2d_rfc9106_test_vector() {
        let params = Argon2Params {
            memory_kib: 32,
            iterations: 3,
            lanes: 4,
            output_len: 32,
            variant: Argon2Type::D,
        };
        let tag = argon2(
            &params,
            &[0x01u8; 32],
            &[0x02u8; 16],
            Some(&[0x03u8; 8]),
            Some(&[0x04u8; 12]),
        )
        .unwrap();
        assert_eq!(
            hex(&tag),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );
    }

    #[test]
    fn parameters_are_validated() {
        let bad = Argon2Params {
            memory_kib: 4,
            iterations: 1,
            lanes: 4,
            output_len: 32,
            variant: Argon2Type::Id,
        };
        assert!(bad.validate().is_err());
    }
}
