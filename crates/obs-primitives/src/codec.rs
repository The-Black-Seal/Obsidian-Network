//! Canonical binary serialization.
//!
//! Every consensus-critical structure (blocks, headers, transactions, claims,
//! attestations, P2P messages) is serialized with exactly this codec.  The
//! encoder is deterministic — there is exactly one valid encoding of any value
//! — and the decoder is strict: it rejects trailing bytes, non-minimal varints,
//! out-of-range lengths, invalid booleans and invalid UTF-8.
//!
//! Rules:
//! * integers: little-endian, fixed width (no varints for consensus fields),
//! * lengths/counts: canonical unsigned LEB128 varints,
//! * `Option<T>`: one tag byte `0x00` (none) or `0x01` (some),
//! * byte strings and strings: varint length followed by the bytes,
//! * collections: varint count followed by the items, in order.

use crate::hash::Hash32;
use crate::money::Amount;

/// Maximum size of a single encoded value (8 MiB).
pub const MAX_ENCODED_LEN: usize = 8 * 1024 * 1024;
/// Maximum number of items in a collection.
pub const MAX_COLLECTION_ITEMS: usize = 1_000_000;
/// Maximum length of a string in bytes.
pub const MAX_STRING_LEN: usize = 1024 * 1024;

/// Encoding/decoding errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The input ended before the value was complete.
    UnexpectedEnd,
    /// Bytes remained after decoding the value.
    TrailingBytes(usize),
    /// A varint was not encoded in its shortest form.
    NonCanonicalVarint,
    /// A varint did not terminate within ten bytes.
    VarintTooLong,
    /// A length or count exceeded the configured limit.
    LengthOutOfRange,
    /// An `Option` tag byte was neither 0 nor 1.
    InvalidOptionTag(u8),
    /// A boolean byte was neither 0 nor 1.
    InvalidBool(u8),
    /// A string was not valid UTF-8.
    InvalidUtf8,
    /// A field carried a value that the protocol does not define.
    InvalidValue(&'static str),
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CodecError::UnexpectedEnd => write!(f, "unexpected end of input"),
            CodecError::TrailingBytes(n) => write!(f, "{} trailing bytes after value", n),
            CodecError::NonCanonicalVarint => write!(f, "non-canonical varint encoding"),
            CodecError::VarintTooLong => write!(f, "varint is too long"),
            CodecError::LengthOutOfRange => write!(f, "length or count out of range"),
            CodecError::InvalidOptionTag(t) => write!(f, "invalid option tag {}", t),
            CodecError::InvalidBool(b) => write!(f, "invalid boolean byte {}", b),
            CodecError::InvalidUtf8 => write!(f, "invalid UTF-8 in string"),
            CodecError::InvalidValue(what) => write!(f, "invalid value for {}", what),
        }
    }
}

impl std::error::Error for CodecError {}

/// Types that can be encoded canonically.
pub trait Encode {
    /// Appends the canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>);

    /// Returns the canonical encoding as a new vector.
    fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// Types that can be decoded from their canonical encoding.
pub trait Decode: Sized {
    /// Decodes a value from `decoder`.
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError>;
}

/// A strict, position-tracking decoder.
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder over the given input.
    pub fn new(input: &'a [u8]) -> Decoder<'a> {
        Decoder { input, pos: 0 }
    }

    /// Number of bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Number of bytes remaining.
    pub fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Returns `true` when all input has been consumed.
    pub fn is_finished(&self) -> bool {
        self.pos == self.input.len()
    }

    /// Reads exactly `n` bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.pos + n > self.input.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let slice = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Reads one byte.
    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Reads a boolean (0 or 1 only).
    pub fn read_bool(&mut self) -> Result<bool, CodecError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CodecError::InvalidBool(other)),
        }
    }

    /// Reads a fixed-width little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, CodecError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Reads a fixed-width little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, CodecError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a fixed-width little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, CodecError> {
        let b = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }

    /// Reads a fixed-width little-endian `u128`.
    pub fn read_u128(&mut self) -> Result<u128, CodecError> {
        let b = self.read_bytes(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        Ok(u128::from_le_bytes(arr))
    }

    /// Reads a canonical unsigned LEB128 `u64`.
    pub fn read_varint(&mut self) -> Result<u64, CodecError> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        let start = self.pos;
        loop {
            if shift >= 64 {
                return Err(CodecError::VarintTooLong);
            }
            let byte = self.read_u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        // Canonical form: the encoding must be the shortest possible.
        let encoded_len = self.pos - start;
        let minimal_len = if result == 0 {
            1
        } else {
            ((64 - result.leading_zeros() as usize) + 6) / 7
        };
        if encoded_len != minimal_len {
            return Err(CodecError::NonCanonicalVarint);
        }
        Ok(result)
    }

    /// Reads a length-prefixed byte string with a maximum size.
    pub fn read_byte_string(&mut self, max_len: usize) -> Result<Vec<u8>, CodecError> {
        let len = self.read_varint()? as usize;
        if len > max_len {
            return Err(CodecError::LengthOutOfRange);
        }
        Ok(self.read_bytes(len)?.to_vec())
    }

    /// Reads a length-prefixed UTF-8 string.
    pub fn read_string(&mut self) -> Result<String, CodecError> {
        let bytes = self.read_byte_string(MAX_STRING_LEN)?;
        String::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8)
    }

    /// Reads a length-prefixed sequence of decodable items.
    pub fn read_seq<T: Decode>(&mut self, max_items: usize) -> Result<Vec<T>, CodecError> {
        let count = self.read_varint()? as usize;
        if count > max_items {
            return Err(CodecError::LengthOutOfRange);
        }
        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            out.push(T::decode(self)?);
        }
        Ok(out)
    }

    /// Ensures the decoder consumed the entire input.
    pub fn expect_finished(&self) -> Result<(), CodecError> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes(self.remaining()))
        }
    }
}

/// Decodes a value and rejects trailing bytes.
pub fn decode_exact<T: Decode>(input: &[u8]) -> Result<T, CodecError> {
    let mut decoder = Decoder::new(input);
    let value = T::decode(&mut decoder)?;
    decoder.expect_finished()?;
    Ok(value)
}

// ---------------------------------------------------------------------------
// Primitive implementations
// ---------------------------------------------------------------------------

macro_rules! impl_fixed_int {
    ($ty:ty, $read:ident, $write:ident) => {
        impl Encode for $ty {
            fn encode(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }
        }
        impl Decode for $ty {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
                decoder.$read()
            }
        }
    };
}

impl_fixed_int!(u16, read_u16, to_le_bytes);
impl_fixed_int!(u32, read_u32, to_le_bytes);
impl_fixed_int!(u64, read_u64, to_le_bytes);
impl_fixed_int!(u128, read_u128, to_le_bytes);

impl Encode for u8 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

impl Decode for u8 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        decoder.read_u8()
    }
}

impl Encode for bool {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
}

impl Decode for bool {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        decoder.read_bool()
    }
}

impl Encode for Hash32 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Hash32 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(decoder.read_bytes(32)?);
        Ok(Hash32(arr))
    }
}

impl Encode for Amount {
    fn encode(&self, out: &mut Vec<u8>) {
        // Money is encoded as a 128-bit little-endian integer: fixed width, so
        // the encoding never depends on the magnitude.
        self.0.encode(out);
    }
}

impl Decode for Amount {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Amount(u128::decode(decoder)?))
    }
}

impl Encode for Vec<u8> {
    fn encode(&self, out: &mut Vec<u8>) {
        write_varint(self.len() as u64, out);
        out.extend_from_slice(self);
    }
}

impl Encode for String {
    fn encode(&self, out: &mut Vec<u8>) {
        write_varint(self.len() as u64, out);
        out.extend_from_slice(self.as_bytes());
    }
}

impl Decode for String {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        decoder.read_string()
    }
}

impl Decode for Vec<u8> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        decoder.read_byte_string(MAX_ENCODED_LEN)
    }
}

impl Encode for crate::address::Address {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.version());
        self.network().chain_id.encode(out);
        out.extend_from_slice(self.payload());
    }
}

impl Decode for crate::address::Address {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let version = decoder.read_u8()?;
        if version != crate::address::ADDRESS_VERSION_ED25519_V1 {
            return Err(CodecError::InvalidValue("address version"));
        }
        let chain_id = decoder.read_u32()?;
        let network = crate::network::Network::by_chain_id(chain_id)
            .ok_or(CodecError::InvalidValue("address chain id"))?;
        let mut payload = [0u8; crate::address::ADDRESS_PAYLOAD_LEN];
        payload.copy_from_slice(decoder.read_bytes(crate::address::ADDRESS_PAYLOAD_LEN)?);
        Ok(crate::address::Address::from_parts(network, version, payload))
    }
}

/// A length-prefixed sequence of values.
///
/// `Vec<u8>` is reserved for byte strings (length followed by raw bytes, no
/// per-element framing); `Seq` provides the generic collection encoding used
/// for lists of consensus objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seq<T>(pub Vec<T>);

impl<T> Seq<T> {
    /// Wraps a vector.
    pub fn new(items: Vec<T>) -> Seq<T> {
        Seq(items)
    }

    /// Unwraps the vector.
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> core::ops::Deref for Seq<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<T: Encode> Encode for Seq<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        write_varint(self.0.len() as u64, out);
        for item in &self.0 {
            item.encode(out);
        }
    }
}

impl<T: Decode> Decode for Seq<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Seq(decoder.read_seq::<T>(MAX_COLLECTION_ITEMS)?))
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let mut arr = [0u8; N];
        arr.copy_from_slice(decoder.read_bytes(N)?);
        Ok(arr)
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.encode(out);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        match decoder.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(decoder)?)),
            other => Err(CodecError::InvalidOptionTag(other)),
        }
    }
}

/// Writes a canonical unsigned LEB128 varint.
pub fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_and_canonicality() {
        for v in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            write_varint(v, &mut out);
            let mut d = Decoder::new(&out);
            assert_eq!(d.read_varint().unwrap(), v);
            assert!(d.is_finished());
        }
        // 0x80 0x00 is a non-canonical encoding of zero.
        let mut d = Decoder::new(&[0x80, 0x00]);
        assert_eq!(d.read_varint(), Err(CodecError::NonCanonicalVarint));
        // Unterminated varint.
        let long = vec![0x80u8; 12];
        let mut d = Decoder::new(&long);
        assert!(matches!(d.read_varint(), Err(CodecError::VarintTooLong)));
    }

    #[test]
    fn fixed_ints_are_little_endian() {
        let bytes = 0x0102_0304u32.encoded();
        assert_eq!(bytes, vec![4, 3, 2, 1]);
    }

    #[test]
    fn strictness_checks() {
        assert_eq!(decode_exact::<u8>(&[1, 2]), Err(CodecError::TrailingBytes(1)));
        assert_eq!(decode_exact::<bool>(&[2]), Err(CodecError::InvalidBool(2)));
        assert_eq!(
            decode_exact::<Option<u8>>(&[5]),
            Err(CodecError::InvalidOptionTag(5))
        );
        assert_eq!(
            decode_exact::<String>(&[2, 0xff, 0xfe]),
            Err(CodecError::InvalidUtf8)
        );
        // Oversized length field.
        let mut out = Vec::new();
        write_varint(MAX_STRING_LEN as u64 + 1, &mut out);
        let mut d = Decoder::new(&out);
        assert_eq!(d.read_string(), Err(CodecError::LengthOutOfRange));
    }

    #[test]
    fn collections_and_options_roundtrip() {
        let value = Seq(vec![1u32, 2, 3, 500]);
        let encoded = value.encoded();
        let mut d = Decoder::new(&encoded);
        assert_eq!(d.read_seq::<u32>(10).unwrap(), value.0);
        let some: Option<u64> = Some(9);
        let none: Option<u64> = None;
        assert_eq!(some.encoded(), vec![1, 9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(none.encoded(), vec![0]);
    }

    #[test]
    fn amounts_encode_as_16_bytes() {
        assert_eq!(Amount::from_obs(1).encoded().len(), 16);
        assert_eq!(Amount::ZERO.encoded().len(), 16);
    }

    #[test]
    fn decoding_never_panics_on_garbage() {
        // Deterministic pseudo-random garbage must always produce an error or a
        // value, never a panic.
        let mut state = 12345u64;
        for _ in 0..2000 {
            let len = (state % 64) as usize;
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                input.push((state >> 33) as u8);
            }
            let _ = decode_exact::<Seq<u32>>(&input);
            let _ = decode_exact::<Option<Hash32>>(&input);
            let _ = decode_exact::<String>(&input);
        }
    }
}
