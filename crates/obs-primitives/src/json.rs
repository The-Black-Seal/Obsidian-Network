//! Minimal, strict JSON support.
//!
//! Obsidian APIs exchange JSON, so the network needs a small, auditable
//! implementation.  Design rules:
//!
//! * **No floating point.** JSON numbers must be integers that fit `i128`.
//!   Monetary values are integers in the smallest unit; price-like display
//!   values are strings.  This makes it structurally impossible for a float to
//!   be parsed into a protocol path.
//! * **Strict input.** Trailing content, duplicate object keys, control
//!   characters in strings, `NaN`, `Infinity`, leading `+`, and non-integer
//!   numbers are all rejected.
//! * **Deterministic output.** Serialization is stable; a canonical form with
//!   sorted keys exists for hashing (idempotency keys, request signatures).

use core::fmt;

/// Maximum nesting depth accepted by the parser.
pub const MAX_DEPTH: usize = 64;
/// Maximum size of a JSON document.
pub const MAX_DOCUMENT_LEN: usize = 4 * 1024 * 1024;
/// Maximum number of elements in an array or object.
pub const MAX_ELEMENTS: usize = 100_000;

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// An integer (including negative values).
    Int(i128),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, preserving key order as given (or sorted in canonical form).
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Constructs an object from key/value pairs.
    pub fn obj<I, K>(pairs: I) -> Json
    where
        I: IntoIterator<Item = (K, Json)>,
        K: Into<String>,
    {
        Json::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Looks up a key in an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Returns the string value, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the integer value as `u64` when it is non-negative and in range.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(v) if *v >= 0 && *v <= u64::MAX as i128 => Some(*v as u64),
            _ => None,
        }
    }

    /// Returns the integer value as `i128`.
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Json::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the boolean value.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the array value.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Serializes compactly (keys in their stored order).
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, None, 0);
        out
    }

    /// Serializes with two-space indentation (used in API documentation).
    pub fn to_pretty_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, Some(2), 0);
        out
    }

    /// Serializes with object keys sorted recursively and no whitespace.
    ///
    /// This is the canonical form used whenever a JSON document is hashed or
    /// signed, so that two equivalent documents produce identical bytes.
    pub fn to_canonical_string(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write(&self, out: &mut String, indent: Option<usize>, level: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(v) => out.push_str(&v.to_string()),
            Json::Str(s) => write_escaped(s, out),
            Json::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline_indent(out, indent, level + 1);
                    item.write(out, indent, level + 1);
                }
                newline_indent(out, indent, level);
                out.push(']');
            }
            Json::Object(pairs) => {
                if pairs.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline_indent(out, indent, level + 1);
                    write_escaped(k, out);
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.write(out, indent, level + 1);
                }
                newline_indent(out, indent, level);
                out.push('}');
            }
        }
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Json::Object(pairs) => {
                let mut sorted: Vec<&(String, Json)> = pairs.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                out.push('{');
                for (i, (k, v)) in sorted.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped(k, out);
                    out.push(':');
                    v.write_canonical(out);
                }
                out.push('}');
            }
            other => other.write(out, None, 0),
        }
    }
}

fn newline_indent(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(width) = indent {
        out.push('\n');
        for _ in 0..(width * level) {
            out.push(' ');
        }
    }
}

fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// JSON parsing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// The document ended prematurely.
    UnexpectedEnd,
    /// A character was not valid at this position.
    UnexpectedCharacter(char),
    /// A number was not an integer (floats are rejected by protocol design).
    NonIntegerNumber,
    /// A number did not fit in `i128`.
    NumberOutOfRange,
    /// A string contained an invalid escape sequence.
    BadEscape,
    /// A string contained an unpaired surrogate escape.
    BadSurrogate,
    /// An object contained the same key twice.
    DuplicateKey(String),
    /// Content followed the top-level value.
    TrailingContent,
    /// The document exceeded a size or depth limit.
    LimitExceeded(&'static str),
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::UnexpectedEnd => write!(f, "unexpected end of JSON input"),
            JsonError::UnexpectedCharacter(c) => write!(f, "unexpected character '{}'", c),
            JsonError::NonIntegerNumber => {
                write!(f, "floating-point numbers are not permitted in Obsidian JSON")
            }
            JsonError::NumberOutOfRange => write!(f, "number out of range"),
            JsonError::BadEscape => write!(f, "invalid escape sequence"),
            JsonError::BadSurrogate => write!(f, "invalid unicode escape"),
            JsonError::DuplicateKey(k) => write!(f, "duplicate object key '{}'", k),
            JsonError::TrailingContent => write!(f, "trailing content after JSON value"),
            JsonError::LimitExceeded(what) => write!(f, "JSON {} limit exceeded", what),
        }
    }
}

impl std::error::Error for JsonError {}

/// Parses a JSON document with the strict rules described in the module docs.
pub fn parse(input: &str) -> Result<Json, JsonError> {
    if input.len() > MAX_DOCUMENT_LEN {
        return Err(JsonError::LimitExceeded("document size"));
    }
    let bytes = input.as_bytes();
    let mut parser = Parser {
        input: bytes,
        pos: 0,
        depth: 0,
    };
    parser.skip_whitespace();
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.pos != bytes.len() {
        return Err(JsonError::TrailingContent);
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Result<u8, JsonError> {
        let b = self.peek().ok_or(JsonError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(b)
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), JsonError> {
        let b = self.next()?;
        if b == expected {
            Ok(())
        } else {
            Err(JsonError::UnexpectedCharacter(b as char))
        }
    }

    fn parse_value(&mut self) -> Result<Json, JsonError> {
        if self.depth > MAX_DEPTH {
            return Err(JsonError::LimitExceeded("nesting depth"));
        }
        match self.peek() {
            None => Err(JsonError::UnexpectedEnd),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') => {
                self.parse_literal("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.parse_literal("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.parse_literal("null")?;
                Ok(Json::Null)
            }
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(other) => Err(JsonError::UnexpectedCharacter(other as char)),
        }
    }

    fn parse_literal(&mut self, literal: &str) -> Result<(), JsonError> {
        for expected in literal.bytes() {
            let b = self.next()?;
            if b != expected {
                return Err(JsonError::UnexpectedCharacter(b as char));
            }
        }
        Ok(())
    }

    fn parse_number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == digits_start {
            return Err(JsonError::UnexpectedCharacter(
                self.peek().unwrap_or(b' ') as char,
            ));
        }
        // Reject leading zeros such as 007.
        if self.input[digits_start] == b'0' && self.pos - digits_start > 1 {
            return Err(JsonError::UnexpectedCharacter('0'));
        }
        match self.peek() {
            Some(b'.') | Some(b'e') | Some(b'E') => return Err(JsonError::NonIntegerNumber),
            _ => {}
        }
        let text = core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| JsonError::UnexpectedCharacter('?'))?;
        let value: i128 = text.parse().map_err(|_| JsonError::NumberOutOfRange)?;
        Ok(Json::Int(value))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.next()?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.next()?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if (0xd800..0xdc00).contains(&cp) {
                                // High surrogate: require the matching low one.
                                if self.next()? != b'\\' || self.next()? != b'u' {
                                    return Err(JsonError::BadSurrogate);
                                }
                                let low = self.parse_hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err(JsonError::BadSurrogate);
                                }
                                let combined =
                                    0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                                out.push(
                                    char::from_u32(combined).ok_or(JsonError::BadSurrogate)?,
                                );
                            } else if (0xdc00..0xe000).contains(&cp) {
                                return Err(JsonError::BadSurrogate);
                            } else {
                                out.push(char::from_u32(cp).ok_or(JsonError::BadSurrogate)?);
                            }
                        }
                        _ => return Err(JsonError::BadEscape),
                    }
                }
                b if b < 0x20 => return Err(JsonError::UnexpectedCharacter(b as char)),
                b if b < 0x80 => out.push(b as char),
                _ => {
                    // Multi-byte UTF-8: re-read the sequence.
                    let start = self.pos - 1;
                    let width = match b {
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => return Err(JsonError::UnexpectedCharacter(b as char)),
                    };
                    if start + width > self.input.len() {
                        return Err(JsonError::UnexpectedEnd);
                    }
                    let slice = &self.input[start..start + width];
                    let s = core::str::from_utf8(slice)
                        .map_err(|_| JsonError::UnexpectedCharacter('?'))?;
                    out.push_str(s);
                    self.pos = start + width;
                }
            }
            if out.len() > MAX_DOCUMENT_LEN {
                return Err(JsonError::LimitExceeded("string size"));
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, JsonError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let b = self.next()?;
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => return Err(JsonError::BadEscape),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_array(&mut self) -> Result<Json, JsonError> {
        self.expect(b'[')?;
        self.depth += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value()?);
            if items.len() > MAX_ELEMENTS {
                return Err(JsonError::LimitExceeded("array size"));
            }
            self.skip_whitespace();
            match self.next()? {
                b',' => continue,
                b']' => break,
                other => return Err(JsonError::UnexpectedCharacter(other as char)),
            }
        }
        self.depth -= 1;
        Ok(Json::Array(items))
    }

    fn parse_object(&mut self) -> Result<Json, JsonError> {
        self.expect(b'{')?;
        self.depth += 1;
        let mut pairs: Vec<(String, Json)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Object(pairs));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if pairs.iter().any(|(k, _)| *k == key) {
                return Err(JsonError::DuplicateKey(key));
            }
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.parse_value()?;
            pairs.push((key, value));
            if pairs.len() > MAX_ELEMENTS {
                return Err(JsonError::LimitExceeded("object size"));
            }
            self.skip_whitespace();
            match self.next()? {
                b',' => continue,
                b'}' => break,
                other => return Err(JsonError::UnexpectedCharacter(other as char)),
            }
        }
        self.depth -= 1;
        Ok(Json::Object(pairs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_types() {
        let doc = r#"{"a":1,"b":[true,false,null],"c":"x\ny","d":{"e":-5},"f":[],"g":{}}"#;
        let parsed = parse(doc).unwrap();
        assert_eq!(parsed.get("a").unwrap().as_i128(), Some(1));
        assert_eq!(parsed.get("c").unwrap().as_str(), Some("x\ny"));
        assert_eq!(
            parse(&parsed.to_string()).unwrap(),
            parsed,
            "serialize/parse must round-trip"
        );
    }

    #[test]
    fn floats_are_rejected() {
        assert_eq!(parse("1.5"), Err(JsonError::NonIntegerNumber));
        assert_eq!(parse("1e5"), Err(JsonError::NonIntegerNumber));
        assert_eq!(parse("0.0"), Err(JsonError::NonIntegerNumber));
    }

    #[test]
    fn strictness() {
        assert_eq!(parse(""), Err(JsonError::UnexpectedEnd));
        assert_eq!(parse("{} {}"), Err(JsonError::TrailingContent));
        assert_eq!(parse("\"\\x\""), Err(JsonError::BadEscape));
        assert_eq!(
            parse("{\"a\":1,\"a\":2}"),
            Err(JsonError::DuplicateKey("a".into()))
        );
        assert_eq!(parse("007"), Err(JsonError::UnexpectedCharacter('0')));
        assert_eq!(parse("+1"), Err(JsonError::UnexpectedCharacter('+')));
        assert_eq!(parse("[1,]"), Err(JsonError::UnexpectedCharacter(']')));
        assert_eq!(
            parse("999999999999999999999999999999999999999999"),
            Err(JsonError::NumberOutOfRange)
        );
    }

    #[test]
    fn unicode_escapes() {
        assert_eq!(parse("\"\\u0041\"").unwrap().as_str(), Some("A"));
        assert_eq!(parse("\"\\ud83d\\ude00\"").unwrap().as_str(), Some("😀"));
        assert_eq!(parse("\"héllo\"").unwrap().as_str(), Some("héllo"));
        assert_eq!(parse("\"\\ud83d\""), Err(JsonError::BadSurrogate));
    }

    #[test]
    fn canonical_form_sorts_keys() {
        let a = parse("{\"b\":1,\"a\":2}").unwrap();
        let b = parse("{\"a\":2,\"b\":1}").unwrap();
        assert_eq!(a.to_canonical_string(), b.to_canonical_string());
        assert_ne!(a.to_string(), b.to_string());
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let deep = "[".repeat(MAX_DEPTH + 5);
        assert!(matches!(parse(&deep), Err(JsonError::LimitExceeded(_))));
    }

    #[test]
    fn parsing_garbage_never_panics() {
        let mut state = 987654321u64;
        let alphabet = b"{}[]\":,0123456789.eE+-\\u \n\ttruefalsn";
        for _ in 0..5000 {
            let len = (state % 32) as usize;
            let mut s = String::new();
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                s.push(alphabet[(state >> 33) as usize % alphabet.len()] as char);
            }
            let _ = parse(&s);
        }
    }
}
