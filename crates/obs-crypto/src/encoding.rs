//! Deterministic byte/text encodings: hexadecimal and Base32.
//!
//! Only these two encodings are used inside Obsidian Network:
//! * lowercase hex — transaction hashes, block hashes, state roots (display),
//! * lowercase Base32 without padding (RFC 4648 §6) — wallet addresses,
//!   invite codes, recovery codes, API key identifiers.
//!
//! Both are strict: decoding never accepts whitespace, mixed alphabets or
//! non-canonical trailing bits.

/// Encodes bytes as lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes lowercase or uppercase hexadecimal.  Returns `None` on any invalid
/// character or odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes bytes as lowercase Base32 without padding.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for b in bytes {
        buffer = (buffer << 8) | (*b as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }
    out
}

/// Decodes lowercase Base32 without padding.  Rejects uppercase, padding,
/// invalid characters and non-canonical trailing bits.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let value = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | (value as u64);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    // Reject non-canonical encodings: leftover bits must be zero.
    if bits > 0 {
        let leftover = buffer & ((1u64 << bits) - 1);
        if leftover != 0 {
            return None;
        }
    }
    Some(out)
}

/// Encodes a 32-byte value as Base64url without padding (used for HTTP
/// idempotency keys and cursor tokens).
pub fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decodes Base64url without padding.
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data: Vec<u8> = (0..=255u8).collect();
        let encoded = hex_encode(&data);
        assert!(encoded.starts_with("000102"));
        assert_eq!(hex_decode(&encoded).unwrap(), data);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn base32_rfc4648_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_encode(b"fo"), "mzxq");
        assert_eq!(base32_encode(b"foo"), "mzxw6");
        assert_eq!(base32_encode(b"foob"), "mzxw6yq");
        assert_eq!(base32_encode(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let enc = base32_encode(s.as_bytes());
            assert_eq!(base32_decode(&enc).unwrap(), s.as_bytes());
        }
    }

    #[test]
    fn base32_rejects_invalid_input() {
        assert!(base32_decode("MZXW6").is_none(), "uppercase rejected");
        assert!(base32_decode("mzxw6=").is_none(), "padding rejected");
        assert!(base32_decode("mzxw1").is_none(), "invalid alphabet rejected");
        // non-canonical trailing bits
        assert!(base32_decode("mz").is_none());
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"\x00\x01\x02\xfb\xfc\xfd\xfe\xff";
        let enc = base64url_encode(data);
        assert_eq!(base64url_decode(&enc).unwrap(), data.to_vec());
        assert!(base64url_decode("!!!!").is_none());
    }
}
