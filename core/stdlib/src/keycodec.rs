//! Order-preserving, self-describing key codec — the single encoding behind
//! storage paths, map keys, index buckets, sort prefixes, and compound keys.
//!
//! A key is a byte string built from typed **elements**, each `tag + payload`.
//! The encoding is **order-preserving** (bytewise `memcmp` of two encoded keys
//! equals their logical, element-by-element order), **prefix-scannable** (an
//! ancestor's encoding is a byte-prefix of every descendant's), **self-delimiting**
//! (boundaries are recoverable from the bytes alone — see [`next_element`]), and
//! **canonical** (exactly one encoding per value). It is the FoundationDB tuple
//! layer / Google OrderedCode format, restricted to the element types we need.
//!
//! This is a *consensus-critical* format (encoded paths are hashed into
//! checkpoints), so it is owned here rather than pulled from a crate, and frozen
//! once shipped. See `docs/design/indexed-map-index-system.md` (Part I).
//!
//! Tags (see also the reserved-space map in the design doc):
//! ```text
//!   0x00            terminator / escape sentinel (never a tag)
//!   0x01 bytes   0x02 string   0x05 nested tuple
//!   0x0C – 0x1C   integer (sign + minimal byte-length; 0x14 == zero)
//!   0x26 false   0x27 true   0x28 none   0x29 some
//! ```

use alloc::string::String;
use alloc::vec::Vec;

const TAG_BYTES: u8 = 0x01;
const TAG_STR: u8 = 0x02;
const TAG_TUPLE: u8 = 0x05;
const TAG_INT_ZERO: u8 = 0x14; // 0x14-n .. 0x14 .. 0x14+n
const TAG_INT_MIN: u8 = 0x0C; // 8-byte negative
const TAG_INT_MAX: u8 = 0x1C; // 8-byte positive
// 256-bit sign-magnitude (the `numerics` Integer/Decimal shape). Placed just
// outside the 64-bit int range so the global order is 256neg < 64int < 256pos
// (FDB-bignum-style); within a field the type is fixed, so only one pair appears.
const TAG_NUM_NEG: u8 = 0x0B;
const TAG_NUM_POS: u8 = 0x1D;
const NUM_LEN: usize = 32; // big-endian magnitude width
const TAG_FALSE: u8 = 0x26;
const TAG_TRUE: u8 = 0x27;
const TAG_NONE: u8 = 0x28;
const TAG_SOME: u8 = 0x29;

const TERM: u8 = 0x00; // string/tuple terminator
const ESC: u8 = 0xFF; // escape byte: a real 0x00 in content becomes 0x00 0xFF

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The leading tag isn't valid for the type being decoded.
    UnexpectedTag(u8),
    /// The slice ended mid-element.
    Truncated,
    /// A decoded integer doesn't fit the target type.
    Overflow,
    /// A string element wasn't valid UTF-8.
    Utf8,
    /// A stringly-encoded element decoded as valid UTF-8 but didn't parse back
    /// into its domain type (a `key_element_via_display!` type's `FromStr` failed).
    FromStr,
}

/// A value that encodes to one order-preserving key element and decodes back.
/// `decode_from` consumes exactly one element and returns it plus the unconsumed
/// tail, so a sequence (a path) decodes by repeated calls.
pub trait KeyElement: Sized {
    fn encode_to(&self, out: &mut Vec<u8>);
    fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError>;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }
}

// ── strings / bytes ────────────────────────────────────────────────────────
// `0x00` in content is escaped to `0x00 0xFF`, then the element is `0x00`-
// terminated. The terminator (the minimum byte) sorts below any real content, so
// `"a" < "ab"`; the escape keeps content `0x00`-free so the terminator is
// unambiguous.

fn encode_blob(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    for &b in content {
        out.push(b);
        if b == TERM {
            out.push(ESC);
        }
    }
    out.push(TERM);
}

/// Decode a `0x00`-terminated escaped blob body starting *after* the tag.
/// Returns the unescaped content and the tail after the terminator.
fn decode_blob_body(bytes: &[u8]) -> Result<(Vec<u8>, &[u8]), CodecError> {
    let mut content = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == TERM {
            // Escaped null (`0x00 0xFF`) vs the real terminator (`0x00` then not
            // `0xFF`, or end of slice).
            if bytes.get(i + 1) == Some(&ESC) {
                content.push(TERM);
                i += 2;
            } else {
                return Ok((content, &bytes[i + 1..]));
            }
        } else {
            content.push(b);
            i += 1;
        }
    }
    Err(CodecError::Truncated) // ran off the end without a terminator
}

impl KeyElement for Vec<u8> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_blob(TAG_BYTES, self, out);
    }
    fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        match bytes.first() {
            Some(&TAG_BYTES) => decode_blob_body(&bytes[1..]),
            Some(&t) => Err(CodecError::UnexpectedTag(t)),
            None => Err(CodecError::Truncated),
        }
    }
}

impl KeyElement for String {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_blob(TAG_STR, self.as_bytes(), out);
    }
    fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        match bytes.first() {
            Some(&TAG_STR) => {
                let (content, rest) = decode_blob_body(&bytes[1..])?;
                let s = String::from_utf8(content).map_err(|_| CodecError::Utf8)?;
                Ok((s, rest))
            }
            Some(&t) => Err(CodecError::UnexpectedTag(t)),
            None => Err(CodecError::Truncated),
        }
    }
}

// ── integers ───────────────────────────────────────────────────────────────
// Minimal-length big-endian; the tag carries sign and byte count. Encoding is
// magnitude-based and width-independent, so `5u8` and `5u64` encode identically
// (a field is one type, so the guest decodes into its known width). Negatives are
// stored offset (`v + 256^n - 1`) under a tag below `0x14`, so they sort first.

fn uint_len(v: u64) -> usize {
    if v == 0 {
        0
    } else {
        8 - (v.leading_zeros() / 8) as usize
    }
}

fn encode_uint(v: u64, out: &mut Vec<u8>) {
    let n = uint_len(v);
    out.push(TAG_INT_ZERO + n as u8);
    out.extend_from_slice(&v.to_be_bytes()[8 - n..]);
}

fn encode_int(v: i64, out: &mut Vec<u8>) {
    if v >= 0 {
        encode_uint(v as u64, out);
        return;
    }
    let n = uint_len(v.unsigned_abs()); // minimal bytes for |v| (handles i64::MIN)
    // stored = v + 256^n - 1, always in [0, 256^n); i128 avoids the 256^8 overflow.
    let stored = (v as i128) + (1i128 << (8 * n)) - 1;
    out.push(TAG_INT_ZERO - n as u8);
    out.extend_from_slice(&(stored as u64).to_be_bytes()[8 - n..]);
}

fn read_be(bytes: &[u8], n: usize) -> Result<u64, CodecError> {
    if bytes.len() < n {
        return Err(CodecError::Truncated);
    }
    let mut buf = [0u8; 8];
    buf[8 - n..].copy_from_slice(&bytes[..n]);
    Ok(u64::from_be_bytes(buf))
}

/// Decode an unsigned integer element. Rejects negative-int tags.
fn decode_uint(bytes: &[u8]) -> Result<(u64, &[u8]), CodecError> {
    let tag = *bytes.first().ok_or(CodecError::Truncated)?;
    if !(TAG_INT_ZERO..=TAG_INT_MAX).contains(&tag) {
        return Err(CodecError::UnexpectedTag(tag));
    }
    let n = (tag - TAG_INT_ZERO) as usize;
    let v = read_be(&bytes[1..], n)?;
    Ok((v, &bytes[1 + n..]))
}

/// Decode a signed integer element across the full negative/zero/positive range.
fn decode_int(bytes: &[u8]) -> Result<(i64, &[u8]), CodecError> {
    let tag = *bytes.first().ok_or(CodecError::Truncated)?;
    if !(TAG_INT_MIN..=TAG_INT_MAX).contains(&tag) {
        return Err(CodecError::UnexpectedTag(tag));
    }
    if tag >= TAG_INT_ZERO {
        let n = (tag - TAG_INT_ZERO) as usize;
        let v = read_be(&bytes[1..], n)?;
        let v = i64::try_from(v).map_err(|_| CodecError::Overflow)?;
        Ok((v, &bytes[1 + n..]))
    } else {
        let n = (TAG_INT_ZERO - tag) as usize;
        let stored = read_be(&bytes[1..], n)?;
        // inverse of encode: v = stored - (256^n - 1)
        let v = (stored as i128) - (1i128 << (8 * n)) + 1;
        let v = i64::try_from(v).map_err(|_| CodecError::Overflow)?;
        Ok((v, &bytes[1 + n..]))
    }
}

macro_rules! key_element_uint {
    ($($t:ty),*) => {$(
        impl KeyElement for $t {
            fn encode_to(&self, out: &mut Vec<u8>) { encode_uint(*self as u64, out); }
            fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
                let (v, rest) = decode_uint(bytes)?;
                Ok((<$t>::try_from(v).map_err(|_| CodecError::Overflow)?, rest))
            }
        }
    )*};
}
key_element_uint!(u8, u16, u32, u64);

macro_rules! key_element_int {
    ($($t:ty),*) => {$(
        impl KeyElement for $t {
            fn encode_to(&self, out: &mut Vec<u8>) { encode_int(*self as i64, out); }
            fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
                let (v, rest) = decode_int(bytes)?;
                Ok((<$t>::try_from(v).map_err(|_| CodecError::Overflow)?, rest))
            }
        }
    )*};
}
key_element_int!(i8, i16, i32, i64);

// ── bool / option ──────────────────────────────────────────────────────────

impl KeyElement for bool {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(if *self { TAG_TRUE } else { TAG_FALSE });
    }
    fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        match bytes.first() {
            Some(&TAG_FALSE) => Ok((false, &bytes[1..])),
            Some(&TAG_TRUE) => Ok((true, &bytes[1..])),
            Some(&t) => Err(CodecError::UnexpectedTag(t)),
            None => Err(CodecError::Truncated),
        }
    }
}

impl<T: KeyElement> KeyElement for Option<T> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(TAG_NONE),
            Some(inner) => {
                out.push(TAG_SOME);
                inner.encode_to(out);
            }
        }
    }
    fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
        match bytes.first() {
            Some(&TAG_NONE) => Ok((None, &bytes[1..])),
            Some(&TAG_SOME) => {
                let (inner, rest) = T::decode_from(&bytes[1..])?;
                Ok((Some(inner), rest))
            }
            Some(&t) => Err(CodecError::UnexpectedTag(t)),
            None => Err(CodecError::Truncated),
        }
    }
}

// ── nested tuples (compound keys) ──────────────────────────────────────────
// A compound key is ONE element: `0x05`, the inner elements (each self-
// delimiting), then a `0x00` terminator. Ordered by element sequence, so it sorts
// by the first field, then the second, …

macro_rules! key_element_tuple {
    ($($name:ident),+) => {
        impl<$($name: KeyElement),+> KeyElement for ($($name,)+) {
            fn encode_to(&self, out: &mut Vec<u8>) {
                out.push(TAG_TUPLE);
                #[allow(non_snake_case)]
                let ($($name,)+) = self;
                $($name.encode_to(out);)+
                out.push(TERM);
            }
            fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), CodecError> {
                match bytes.first() {
                    Some(&TAG_TUPLE) => {}
                    Some(&t) => return Err(CodecError::UnexpectedTag(t)),
                    None => return Err(CodecError::Truncated),
                }
                let mut rest = &bytes[1..];
                $(
                    #[allow(non_snake_case)]
                    let $name;
                    ($name, rest) = $name::decode_from(rest)?;
                )+
                match rest.first() {
                    Some(&TERM) => Ok((($($name,)+), &rest[1..])),
                    _ => Err(CodecError::Truncated),
                }
            }
        }
    };
}
key_element_tuple!(A, B);
key_element_tuple!(A, B, C);
key_element_tuple!(A, B, C, D);

// ── 256-bit sign-magnitude integers (numerics Integer/Decimal) ──────────────
// Magnitude is a fixed 32-byte big-endian value built from four little-endian
// u64 limbs (`limbs[0]` least significant). Order-preserving: positives sort by
// magnitude under `TAG_NUM_POS`; negatives are bit-inverted under the lower
// `TAG_NUM_NEG` so a larger magnitude sorts earlier — exactly the int scheme,
// widened to 256 bits. Zero is CANONICAL (always positive) so `+0` and `-0`
// encode identically. `Decimal` reuses this on its raw scaled limbs (fixed scale
// ⇒ raw-magnitude order == value order).

fn limbs_to_be(limbs: [u64; 4]) -> [u8; NUM_LEN] {
    let mut be = [0u8; NUM_LEN];
    be[0..8].copy_from_slice(&limbs[3].to_be_bytes());
    be[8..16].copy_from_slice(&limbs[2].to_be_bytes());
    be[16..24].copy_from_slice(&limbs[1].to_be_bytes());
    be[24..32].copy_from_slice(&limbs[0].to_be_bytes());
    be
}

fn be_to_limbs(be: &[u8]) -> [u64; 4] {
    let limb = |i: usize| {
        let mut a = [0u8; 8];
        a.copy_from_slice(&be[i * 8..i * 8 + 8]);
        u64::from_be_bytes(a)
    };
    // be[0..8] is the most-significant limb (limbs[3]); be[24..32] the least.
    [limb(3), limb(2), limb(1), limb(0)]
}

/// Encode a 256-bit sign-magnitude number order-preservingly (33 bytes).
pub fn encode_int256(out: &mut Vec<u8>, negative: bool, limbs: [u64; 4]) {
    let zero = limbs == [0, 0, 0, 0];
    let be = limbs_to_be(limbs);
    if negative && !zero {
        out.push(TAG_NUM_NEG);
        for b in be {
            out.push(!b); // invert so larger magnitude sorts earlier
        }
    } else {
        out.push(TAG_NUM_POS);
        out.extend_from_slice(&be);
    }
}

/// Decode a 256-bit sign-magnitude number written by [`encode_int256`], returning
/// `(negative, limbs, rest)`. `negative` is always false for zero (canonical).
pub fn decode_int256(bytes: &[u8]) -> Result<(bool, [u64; 4], &[u8]), CodecError> {
    let tag = *bytes.first().ok_or(CodecError::Truncated)?;
    let negative = match tag {
        TAG_NUM_POS => false,
        TAG_NUM_NEG => true,
        other => return Err(CodecError::UnexpectedTag(other)),
    };
    if bytes.len() < 1 + NUM_LEN {
        return Err(CodecError::Truncated);
    }
    let mut be = [0u8; NUM_LEN];
    be.copy_from_slice(&bytes[1..1 + NUM_LEN]);
    if negative {
        for b in be.iter_mut() {
            *b = !*b;
        }
    }
    Ok((negative, be_to_limbs(&be), &bytes[1 + NUM_LEN..]))
}

/// Pack several already-encoded elements into one nested-tuple element, ordered
/// by the sequence of `parts` — the same bytes `(A, B, …)::encode_to` produces,
/// but from parts whose Rust types differ per call (so a uniform, type-erased
/// caller like the index-diff can build an `(sort, pk)` member). Each part MUST be
/// exactly one encoded element; the result decodes via the matching tuple
/// `KeyElement`.
pub fn tuple_from_elements(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(TAG_TUPLE);
    for part in parts {
        out.extend_from_slice(part);
    }
    out.push(TERM);
    out
}

/// Derive [`KeyElement`] for a domain type that is keyed by its canonical string
/// form: it encodes as a string element via `Display` and decodes via `FromStr`.
/// For types (e.g. the built-in `Holder`) whose distinct/ordered string identity
/// is the right key and that already round-trip through `Display`/`FromStr`.
#[macro_export]
macro_rules! key_element_via_display {
    ($ty:ty) => {
        impl $crate::KeyElement for $ty {
            fn encode_to(&self, out: &mut alloc::vec::Vec<u8>) {
                $crate::KeyElement::encode_to(&alloc::string::ToString::to_string(self), out)
            }
            fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), $crate::CodecError> {
                let (s, rest) = <alloc::string::String as $crate::KeyElement>::decode_from(bytes)?;
                let v = <Self as core::str::FromStr>::from_str(&s)
                    .map_err(|_| $crate::CodecError::FromStr)?;
                Ok((v, rest))
            }
        }
    };
}

// ── schema-agnostic helpers (host side) ────────────────────────────────────

/// Split the first complete element off `bytes`, returning `(element, rest)`
/// without knowing its Rust type — what the host needs to extract a child key for
/// `keys()`. Walks by tag: ints have a tag-implied length; strings/bytes/tuples
/// scan to their terminator (recursing into tuples).
pub fn next_element(bytes: &[u8]) -> Result<(&[u8], &[u8]), CodecError> {
    let tag = *bytes.first().ok_or(CodecError::Truncated)?;
    let consumed = match tag {
        TAG_FALSE | TAG_TRUE | TAG_NONE => 1,
        TAG_SOME => 1 + next_element(&bytes[1..])?.0.len(),
        TAG_INT_MIN..=TAG_INT_MAX => 1 + (tag.abs_diff(TAG_INT_ZERO)) as usize,
        TAG_NUM_NEG | TAG_NUM_POS => 1 + NUM_LEN,
        TAG_BYTES | TAG_STR => 1 + blob_body_len(&bytes[1..])?,
        TAG_TUPLE => 1 + tuple_body_len(&bytes[1..])?,
        other => return Err(CodecError::UnexpectedTag(other)),
    };
    if consumed > bytes.len() {
        return Err(CodecError::Truncated);
    }
    Ok((&bytes[..consumed], &bytes[consumed..]))
}

/// Length of an escaped blob body up to and including its terminator.
fn blob_body_len(bytes: &[u8]) -> Result<usize, CodecError> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == TERM {
            if bytes.get(i + 1) == Some(&ESC) {
                i += 2;
            } else {
                return Ok(i + 1);
            }
        } else {
            i += 1;
        }
    }
    Err(CodecError::Truncated)
}

/// Length of a nested-tuple body (inner elements + terminator), after the tag.
fn tuple_body_len(bytes: &[u8]) -> Result<usize, CodecError> {
    let mut consumed = 0;
    loop {
        match bytes.get(consumed) {
            Some(&TERM) => return Ok(consumed + 1),
            Some(_) => consumed += next_element(&bytes[consumed..])?.0.len(),
            None => return Err(CodecError::Truncated),
        }
    }
}

/// A best-effort human-readable rendering of a codec key, for logs/debug ONLY —
/// it is NOT canonical or round-trippable (the bytes are). Segments are joined by
/// `/`; each renders by type: a string as its text, an int as its number, a bool/
/// option by name, a nested tuple as `(a,b,…)`, and raw bytes / anything
/// unrecognized as `0x<hex>`.
pub fn debug_render(mut bytes: &[u8]) -> String {
    let mut out = String::new();
    while !bytes.is_empty() {
        let (elem, rest) = match next_element(bytes) {
            Ok(parts) => parts,
            Err(_) => {
                out.push_str("/<malformed>");
                break;
            }
        };
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&render_element(elem));
        bytes = rest;
    }
    out
}

/// Render one complete element (tag-led) to debug text. Recurses into `some(…)`
/// and tuple members.
fn render_element(elem: &[u8]) -> String {
    match elem.first() {
        Some(&TAG_STR) => match String::decode_from(elem) {
            Ok((s, _)) => s,
            Err(_) => hex(elem),
        },
        Some(&TAG_BYTES) => match <Vec<u8>>::decode_from(elem) {
            Ok((content, _)) => hex(&content),
            Err(_) => hex(elem),
        },
        Some(&TAG_FALSE) => String::from("false"),
        Some(&TAG_TRUE) => String::from("true"),
        Some(&TAG_NONE) => String::from("none"),
        Some(&TAG_SOME) => match next_element(&elem[1..]) {
            Ok((inner, _)) => alloc::format!("some({})", render_element(inner)),
            Err(_) => hex(elem),
        },
        // Signed range covers all but u64 values above `i64::MAX`, which decode
        // unsigned instead — so a `u64` key renders as its true magnitude.
        Some(&t) if (TAG_INT_MIN..=TAG_INT_MAX).contains(&t) => {
            if let Ok((v, _)) = decode_int(elem) {
                alloc::format!("{v}")
            } else if let Ok((v, _)) = decode_uint(elem) {
                alloc::format!("{v}")
            } else {
                hex(elem)
            }
        }
        // 256-bit number: render sign + hex magnitude (no_std has no bigint for
        // decimal). Debug-only, so the exact decimal form isn't needed.
        Some(&TAG_NUM_NEG) | Some(&TAG_NUM_POS) => match decode_int256(elem) {
            Ok((negative, limbs, _)) => {
                let be = limbs_to_be(limbs);
                let sign = if negative { "-" } else { "" };
                alloc::format!("{sign}{}", hex(&be))
            }
            Err(_) => hex(elem),
        },
        Some(&TAG_TUPLE) => {
            let mut parts = Vec::new();
            let mut rest = &elem[1..];
            loop {
                match rest.first() {
                    Some(&TERM) | None => break,
                    Some(_) => match next_element(rest) {
                        Ok((inner, tail)) => {
                            parts.push(render_element(inner));
                            rest = tail;
                        }
                        Err(_) => {
                            parts.push(String::from("<malformed>"));
                            break;
                        }
                    },
                }
            }
            alloc::format!("({})", parts.join(","))
        }
        _ => hex(elem),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    for b in bytes {
        out.push_str(&alloc::format!("{b:02x}"));
    }
    out
}

/// The exclusive upper bound of the range covering every key with `prefix` as a
/// byte-prefix: strip trailing `0xFF`, increment the last remaining byte. `None`
/// means "no upper bound" (the prefix is empty or all `0xFF`), i.e. scan to the
/// end. Subtree of `P` = `[P, strinc(P))`.
pub fn strinc(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut out = prefix.to_vec();
    while let Some(&last) = out.last() {
        if last == 0xFF {
            out.pop();
        } else {
            *out.last_mut().unwrap() = last + 1;
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Tiny deterministic PRNG (reproducible — this is a consensus format).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    fn roundtrip<T: KeyElement + PartialEq + core::fmt::Debug>(v: T) {
        let enc = v.encode();
        let (got, rest) = T::decode_from(&enc).expect("decode");
        assert_eq!(got, v, "roundtrip value");
        assert!(rest.is_empty(), "decode consumed all bytes");
        // next_element agrees on the boundary (schema-agnostic == typed).
        let (elem, tail) = next_element(&enc).expect("next_element");
        assert_eq!(elem, &enc[..], "next_element spans the whole element");
        assert!(tail.is_empty());
    }

    // Assert encoded byte order matches a provided logical order.
    fn assert_ordered<T: KeyElement + Clone>(sorted_ascending: &[T]) {
        let encs: Vec<Vec<u8>> = sorted_ascending.iter().map(|v| v.encode()).collect();
        for w in encs.windows(2) {
            assert!(w[0] < w[1], "encoded order must match logical order");
        }
    }

    #[test]
    fn ints_roundtrip_and_order() {
        let edges = [
            0i64,
            1,
            -1,
            255,
            256,
            -255,
            -256,
            257,
            -257,
            65535,
            65536,
            -65536,
            i32::MAX as i64,
            i32::MIN as i64,
            1 << 40,
            -(1 << 40),
            i64::MAX,
            i64::MIN,
        ];
        for &v in &edges {
            roundtrip(v);
        }
        let mut rng = Lcg(1);
        let mut samples: Vec<i64> = edges.to_vec();
        for _ in 0..5000 {
            let v = rng.next() as i64;
            roundtrip(v);
            samples.push(v);
        }
        samples.sort();
        samples.dedup();
        assert_ordered(&samples);
    }

    #[test]
    fn uints_roundtrip_and_order_full_range() {
        // u64 above i64::MAX must encode positive and order above everything signed.
        let edges = [0u64, 1, 255, 256, u32::MAX as u64, 1 << 63, u64::MAX];
        for &v in &edges {
            roundtrip(v);
        }
        let mut rng = Lcg(7);
        let mut samples = edges.to_vec();
        for _ in 0..5000 {
            let v = rng.next();
            roundtrip(v);
            samples.push(v);
        }
        samples.sort();
        samples.dedup();
        assert_ordered(&samples);
        // narrower types narrow on decode
        roundtrip(200u8);
        roundtrip(40_000u16);
        roundtrip(-100i8);
        assert!(matches!(
            u8::decode_from(&300u16.encode()),
            Err(CodecError::Overflow)
        ));
    }

    #[test]
    fn strings_roundtrip_and_order() {
        let words = [
            "",
            "a",
            "ab",
            "a.b",
            "a-b",
            "a b",
            "b",
            "z",
            "aa",
            "a\u{0}b",
            "a\u{0}",
            "\u{0}",
            "ünîcødé",
            "a\u{0}\u{0}b",
        ];
        for w in &words {
            roundtrip(String::from(*w));
        }
        let mut sorted: Vec<String> = words.iter().map(|s| String::from(*s)).collect();
        sorted.sort();
        sorted.dedup();
        assert_ordered(&sorted);
    }

    #[test]
    fn bool_option_roundtrip_and_order() {
        roundtrip(false);
        roundtrip(true);
        assert_ordered(&[false, true]);
        roundtrip(None::<u64>);
        roundtrip(Some(0u64));
        roundtrip(Some(42u64));
        // none < some(anything); some ordered by inner
        assert_ordered(&[None, Some(0u64), Some(1), Some(u64::MAX)]);
    }

    #[test]
    fn compound_keys_roundtrip_and_order() {
        // (String, u64) — the memberships shape.
        let pairs = [
            (String::from(""), 0u64),
            (String::from("a"), 0),
            (String::from("a"), 5),
            (String::from("a"), 256),
            (String::from("a-b"), 0),
            (String::from("a.b"), 0),
            (String::from("b"), 0),
        ];
        for p in &pairs {
            roundtrip(p.clone());
        }
        let mut sorted = pairs.to_vec();
        sorted.sort();
        assert_ordered(&sorted);

        // Two variable-length strings — the case fixed-width suffix couldn't do.
        let two = [
            (String::from(""), String::from("")),
            (String::from(""), String::from("x")),
            (String::from("a"), String::from("")),
            (String::from("a"), String::from("b")),
            (String::from("a\u{0}"), String::from("b")),
            (String::from("ab"), String::from("")),
        ];
        for p in &two {
            roundtrip(p.clone());
        }
        let mut s2 = two.to_vec();
        s2.sort();
        assert_ordered(&s2);

        // Triple — index member shape (bucket, sort, pk) packed as one nested tuple.
        roundtrip((true, 2016u64, String::from("challenge-1")));
    }

    #[test]
    fn next_element_walks_a_path_sequence() {
        // A top-level path is a concatenation of elements (no wrapper).
        let mut path = Vec::new();
        String::from("memberships").encode_to(&mut path);
        (String::from("agr"), 42u64).encode_to(&mut path);
        true.encode_to(&mut path);

        let (e1, r1) = next_element(&path).unwrap();
        assert_eq!(e1, &String::from("memberships").encode()[..]);
        let (e2, r2) = next_element(r1).unwrap();
        assert_eq!(e2, &(String::from("agr"), 42u64).encode()[..]);
        let (e3, r3) = next_element(r2).unwrap();
        assert_eq!(e3, &true.encode()[..]);
        assert!(r3.is_empty());
    }

    #[test]
    fn int256_roundtrip_and_order() {
        use core::cmp::Ordering;

        // Numeric order of two 256-bit sign-magnitude values (the reference the
        // encoded byte order must match). limbs[3] is most significant; zero is
        // canonical (sign ignored).
        fn mag_cmp(a: [u64; 4], b: [u64; 4]) -> Ordering {
            for i in (0..4).rev() {
                match a[i].cmp(&b[i]) {
                    Ordering::Equal => {}
                    o => return o,
                }
            }
            Ordering::Equal
        }
        fn norm(neg: bool, m: [u64; 4]) -> bool {
            if m == [0, 0, 0, 0] { false } else { neg }
        }
        fn num_cmp(a: (bool, [u64; 4]), b: (bool, [u64; 4])) -> Ordering {
            match (norm(a.0, a.1), norm(b.0, b.1)) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => mag_cmp(a.1, b.1),
                (true, true) => mag_cmp(b.1, a.1), // larger magnitude = more negative = first
            }
        }
        fn enc(neg: bool, m: [u64; 4]) -> Vec<u8> {
            let mut o = Vec::new();
            encode_int256(&mut o, neg, m);
            o
        }

        let edges: &[(bool, [u64; 4])] = &[
            (false, [0, 0, 0, 0]),
            (true, [0, 0, 0, 0]), // -0 canonicalizes to +0
            (false, [1, 0, 0, 0]),
            (true, [1, 0, 0, 0]),
            (false, [0, 0, 0, 1]),
            (true, [0, 0, 0, 1]),
            (false, [u64::MAX, u64::MAX, u64::MAX, u64::MAX]),
            (true, [u64::MAX, u64::MAX, u64::MAX, u64::MAX]),
        ];
        for &(neg, m) in edges {
            let bytes = enc(neg, m);
            let (gneg, gm, rest) = decode_int256(&bytes).unwrap();
            assert!(rest.is_empty());
            assert_eq!((gneg, gm), (norm(neg, m), m), "roundtrip");
            // next_element agrees on the boundary.
            let (e, t) = next_element(&bytes).unwrap();
            assert_eq!(e, &bytes[..]);
            assert!(t.is_empty());
        }
        // +0 and -0 encode identically (canonical zero).
        assert_eq!(enc(false, [0, 0, 0, 0]), enc(true, [0, 0, 0, 0]));

        // Ordering fuzz: encoded bytewise order must equal numeric order.
        let mut rng = Lcg(99);
        let mut samples: Vec<(bool, [u64; 4])> = edges.to_vec();
        for _ in 0..4000 {
            samples.push((rng.next() & 1 == 0, [rng.next(), rng.next(), rng.next(), rng.next()]));
            // also bias toward small magnitudes (where most real balances live)
            samples.push((rng.next() & 1 == 0, [rng.next() & 0xffff, 0, 0, 0]));
        }
        samples.sort_by(|a, b| num_cmp(*a, *b));
        samples.dedup_by(|a, b| num_cmp(*a, *b) == Ordering::Equal);
        let encs: Vec<Vec<u8>> = samples.iter().map(|&(n, m)| enc(n, m)).collect();
        for w in encs.windows(2) {
            assert!(w[0] < w[1], "encoded order must match numeric order");
        }
    }

    #[test]
    fn debug_render_renders_typed_elements() {
        // A mixed path: string segment, (string,int) tuple member, bool, option.
        let mut p = Vec::new();
        String::from("memberships").encode_to(&mut p);
        (String::from("agr"), 42u64).encode_to(&mut p);
        true.encode_to(&mut p);
        Some(7u64).encode_to(&mut p);
        assert_eq!(debug_render(&p), "memberships/(agr,42)/true/some(7)");

        // u64 above i64::MAX renders as its true magnitude (unsigned fallback).
        assert_eq!(
            debug_render(&u64::MAX.encode()),
            alloc::format!("{}", u64::MAX)
        );
        assert_eq!(debug_render(&(-5i64).encode()), "-5");
        assert_eq!(debug_render(&None::<u64>.encode()), "none");
        // raw bytes render as hex of their content.
        assert_eq!(debug_render(&vec![0xde_u8, 0xad].encode()), "0xdead");
    }

    #[test]
    fn strinc_prefix_bounds_the_subtree() {
        // every key with `prefix` is in [prefix, strinc(prefix))
        let prefix = String::from("agr").encode();
        let upper = strinc(&prefix).unwrap();
        let child = {
            let mut p = prefix.clone();
            42u64.encode_to(&mut p);
            p
        };
        assert!(prefix.as_slice() <= child.as_slice() && child.as_slice() < upper.as_slice());
        // a sibling NOT under the prefix is outside the range
        let sibling = String::from("ags").encode();
        assert!(sibling.as_slice() >= upper.as_slice());

        assert_eq!(strinc(&[0x01, 0xFF]), Some(vec![0x02]));
        assert_eq!(strinc(&[0xFF, 0xFF]), None); // unbounded above
        assert_eq!(strinc(&[]), None);
    }

    #[test]
    fn truncated_and_bad_tag_error_not_panic() {
        assert_eq!(u64::decode_from(&[]), Err(CodecError::Truncated));
        assert_eq!(u64::decode_from(&[0x1C, 0x00]), Err(CodecError::Truncated)); // wants 8 bytes
        assert!(matches!(
            String::decode_from(&[0x99]),
            Err(CodecError::UnexpectedTag(0x99))
        ));
        assert_eq!(next_element(&[]), Err(CodecError::Truncated));
    }
}
