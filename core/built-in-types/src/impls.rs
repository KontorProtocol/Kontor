//! Hand-written behavior on the shared numbers/error types — the former
//! `impls.rs` guest-mode bodies, now written ONCE on types this crate owns.
//! The arithmetic delegates to the `kontor:built-in/numbers` host functions
//! through this crate's own generated bindings (on non-wasm targets those
//! stubs are never called — the host uses its own type family and the pure
//! `numerics` crate).

use alloc::string::String;

use crate::kontor;

impl PartialEq for kontor::built_in::error::Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                kontor::built_in::error::Error::Message(msg1),
                kontor::built_in::error::Error::Message(msg2),
            ) => msg1 == msg2,
            (
                kontor::built_in::error::Error::Overflow(msg1),
                kontor::built_in::error::Error::Overflow(msg2),
            ) => msg1 == msg2,
            (
                kontor::built_in::error::Error::DivByZero(msg1),
                kontor::built_in::error::Error::DivByZero(msg2),
            ) => msg1 == msg2,
            (
                kontor::built_in::error::Error::Syntax(msg1),
                kontor::built_in::error::Error::Syntax(msg2),
            ) => msg1 == msg2,
            (
                kontor::built_in::error::Error::Validation(msg1),
                kontor::built_in::error::Error::Validation(msg2),
            ) => msg1 == msg2,
            _ => false,
        }
    }
}

impl Eq for kontor::built_in::error::Error {}

impl kontor::built_in::error::Error {
    pub fn new(message: impl Into<alloc::string::String>) -> Self {
        kontor::built_in::error::Error::Message(message.into())
    }
}

impl From<core::num::ParseIntError> for kontor::built_in::error::Error {
    fn from(err: core::num::ParseIntError) -> Self {
        kontor::built_in::error::Error::Message(alloc::format!("Parse integer error: {:?}", err))
    }
}

impl From<core::num::TryFromIntError> for kontor::built_in::error::Error {
    fn from(err: core::num::TryFromIntError) -> Self {
        kontor::built_in::error::Error::Message(alloc::format!("Try from integer error: {:?}", err))
    }
}

impl From<core::str::Utf8Error> for kontor::built_in::error::Error {
    fn from(err: core::str::Utf8Error) -> Self {
        kontor::built_in::error::Error::Message(alloc::format!("UTF-8 parse error: {:?}", err))
    }
}

impl From<core::char::ParseCharError> for kontor::built_in::error::Error {
    fn from(err: core::char::ParseCharError) -> Self {
        kontor::built_in::error::Error::Message(alloc::format!("Parse char error: {:?}", err))
    }
}

impl kontor::built_in::numbers::Integer {
    pub fn sqrt(
        &self,
    ) -> Result<kontor::built_in::numbers::Integer, kontor::built_in::error::Error> {
        kontor::built_in::numbers::sqrt_integer(*self)
    }
}

impl core::fmt::Display for kontor::built_in::numbers::Integer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = kontor::built_in::numbers::integer_to_string(*self);
        write!(f, "{}", s)
    }
}

impl Default for kontor::built_in::numbers::Integer {
    fn default() -> Self {
        Self {
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            sign: kontor::built_in::numbers::Sign::Plus,
        }
    }
}

impl stdlib::CheckedArithmetics<kontor::built_in::error::Error>
    for kontor::built_in::numbers::Integer
{
    type Output = Self;
    fn add(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::add_integer(self, other)
    }
    fn sub(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::sub_integer(self, other)
    }
    fn mul(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::mul_integer(self, other)
    }
    fn div(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::div_integer(self, other)
    }
}

impl stdlib::CheckedArithmetics<kontor::built_in::error::Error>
    for kontor::built_in::numbers::Decimal
{
    type Output = Self;
    fn add(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::add_decimal(self, other)
    }
    fn sub(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::sub_decimal(self, other)
    }
    fn mul(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::mul_decimal(self, other)
    }
    fn div(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        kontor::built_in::numbers::div_decimal(self, other)
    }
}

impl core::ops::Add for kontor::built_in::numbers::Integer {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        kontor::built_in::numbers::add_integer(self, other).unwrap()
    }
}

impl core::ops::Sub for kontor::built_in::numbers::Integer {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        kontor::built_in::numbers::sub_integer(self, other).unwrap()
    }
}

impl core::ops::Mul for kontor::built_in::numbers::Integer {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        kontor::built_in::numbers::mul_integer(self, rhs).unwrap()
    }
}

impl core::ops::Div for kontor::built_in::numbers::Integer {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        kontor::built_in::numbers::div_integer(self, rhs).unwrap()
    }
}

impl PartialOrd for kontor::built_in::numbers::Integer {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for kontor::built_in::numbers::Integer {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match kontor::built_in::numbers::cmp_integer(*self, *other) {
            kontor::built_in::numbers::Ordering::Less => core::cmp::Ordering::Less,
            kontor::built_in::numbers::Ordering::Equal => core::cmp::Ordering::Equal,
            kontor::built_in::numbers::Ordering::Greater => core::cmp::Ordering::Greater,
        }
    }
}

impl PartialEq for kontor::built_in::numbers::Integer {
    fn eq(&self, other: &Self) -> bool {
        kontor::built_in::numbers::eq_integer(*self, *other)
    }
}

impl Eq for kontor::built_in::numbers::Integer {}

impl From<u64> for kontor::built_in::numbers::Integer {
    fn from(i: u64) -> Self {
        kontor::built_in::numbers::u64_to_integer(i)
    }
}

impl From<u32> for kontor::built_in::numbers::Integer {
    fn from(i: u32) -> Self {
        (i as u64).into()
    }
}

impl From<i64> for kontor::built_in::numbers::Integer {
    fn from(i: i64) -> Self {
        kontor::built_in::numbers::s64_to_integer(i)
    }
}

impl From<i32> for kontor::built_in::numbers::Integer {
    fn from(i: i32) -> Self {
        (i as i64).into()
    }
}

impl From<&str> for kontor::built_in::numbers::Integer {
    fn from(s: &str) -> Self {
        kontor::built_in::numbers::string_to_integer(s).unwrap()
    }
}

impl From<String> for kontor::built_in::numbers::Integer {
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

impl kontor::built_in::numbers::Decimal {
    pub fn log10(
        &self,
    ) -> Result<kontor::built_in::numbers::Decimal, kontor::built_in::error::Error> {
        kontor::built_in::numbers::log10_decimal(*self)
    }
}

impl core::fmt::Display for kontor::built_in::numbers::Decimal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = kontor::built_in::numbers::decimal_to_string(*self);
        write!(f, "{}", s)
    }
}

impl Default for kontor::built_in::numbers::Decimal {
    fn default() -> Self {
        Self {
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            sign: kontor::built_in::numbers::Sign::Plus,
        }
    }
}

impl core::ops::Add for kontor::built_in::numbers::Decimal {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        kontor::built_in::numbers::add_decimal(self, other).unwrap()
    }
}

impl core::ops::Sub for kontor::built_in::numbers::Decimal {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        kontor::built_in::numbers::sub_decimal(self, other).unwrap()
    }
}

impl core::ops::Mul for kontor::built_in::numbers::Decimal {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        kontor::built_in::numbers::mul_decimal(self, rhs).unwrap()
    }
}

impl core::ops::Div for kontor::built_in::numbers::Decimal {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        kontor::built_in::numbers::div_decimal(self, rhs).unwrap()
    }
}

impl PartialOrd for kontor::built_in::numbers::Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for kontor::built_in::numbers::Decimal {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match kontor::built_in::numbers::cmp_decimal(*self, *other) {
            kontor::built_in::numbers::Ordering::Less => core::cmp::Ordering::Less,
            kontor::built_in::numbers::Ordering::Equal => core::cmp::Ordering::Equal,
            kontor::built_in::numbers::Ordering::Greater => core::cmp::Ordering::Greater,
        }
    }
}

impl PartialEq for kontor::built_in::numbers::Decimal {
    fn eq(&self, other: &Self) -> bool {
        kontor::built_in::numbers::eq_decimal(*self, *other).expect("eq_decimal failed")
    }
}

impl Eq for kontor::built_in::numbers::Decimal {}

impl TryFrom<kontor::built_in::numbers::Integer> for kontor::built_in::numbers::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(
        i: kontor::built_in::numbers::Integer,
    ) -> Result<kontor::built_in::numbers::Decimal, Self::Error> {
        kontor::built_in::numbers::integer_to_decimal(i)
    }
}

impl TryFrom<u64> for kontor::built_in::numbers::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: u64) -> Result<Self, Self::Error> {
        kontor::built_in::numbers::u64_to_decimal(i)
    }
}

impl TryFrom<u32> for kontor::built_in::numbers::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: u32) -> Result<Self, Self::Error> {
        (i as u64).try_into()
    }
}

impl TryFrom<i64> for kontor::built_in::numbers::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: i64) -> Result<Self, Self::Error> {
        kontor::built_in::numbers::s64_to_decimal(i)
    }
}

impl TryFrom<i32> for kontor::built_in::numbers::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: i32) -> Result<Self, Self::Error> {
        (i as i64).try_into()
    }
}

impl TryFrom<f64> for kontor::built_in::numbers::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(f: f64) -> Result<Self, Self::Error> {
        kontor::built_in::numbers::f64_to_decimal(f)
    }
}

impl TryFrom<f32> for kontor::built_in::numbers::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(f: f32) -> Result<Self, Self::Error> {
        (f as f64).try_into()
    }
}

impl From<&str> for kontor::built_in::numbers::Decimal {
    fn from(s: &str) -> Self {
        kontor::built_in::numbers::string_to_decimal(s).unwrap()
    }
}

impl From<String> for kontor::built_in::numbers::Decimal {
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

// --- storage-integration impls (moved from the per-contract `contract!` glue;
// stdlib traits on types this crate owns) ---

/// `#[index]` on an Integer/Decimal field buckets by its canonical string
/// (equality partition — order irrelevant).
impl stdlib::IndexKey for kontor::built_in::numbers::Integer {
    fn index_key(&self) -> alloc::vec::Vec<u8> {
        stdlib::KeyElement::encode(&alloc::string::ToString::to_string(self))
    }
}

impl stdlib::IndexKey for kontor::built_in::numbers::Decimal {
    fn index_key(&self) -> alloc::vec::Vec<u8> {
        stdlib::KeyElement::encode(&alloc::string::ToString::to_string(self))
    }
}

/// 256-bit sign-magnitude encoded as order-preserving codec elements so they
/// can be `Map` KEYS or index SORT fields (e.g. ordering by a monetary
/// amount). `Decimal` reuses the integer encoding on its raw scaled limbs
/// (fixed scale ⇒ raw-magnitude order == value order). Distinct from the
/// `IndexKey` (bucket) impls above.
macro_rules! __key_element_num256 {
    ($($ty:path),*) => {$(
        impl stdlib::KeyElement for $ty {
            fn encode_to(&self, out: &mut alloc::vec::Vec<u8>) {
                stdlib::encode_int256(
                    out,
                    matches!(self.sign, kontor::built_in::numbers::Sign::Minus),
                    [self.r0, self.r1, self.r2, self.r3],
                );
            }
            fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), stdlib::CodecError> {
                let (negative, limbs, rest) = stdlib::decode_int256(bytes)?;
                Ok((
                    Self {
                        r0: limbs[0],
                        r1: limbs[1],
                        r2: limbs[2],
                        r3: limbs[3],
                        sign: if negative {
                            kontor::built_in::numbers::Sign::Minus
                        } else {
                            kontor::built_in::numbers::Sign::Plus
                        },
                    },
                    rest,
                ))
            }
        }
    )*};
}
__key_element_num256!(
    kontor::built_in::numbers::Integer,
    kontor::built_in::numbers::Decimal
);

impl<__S: stdlib::ReadStorage + 'static> stdlib::Retrieve<__S>
    for kontor::built_in::numbers::Integer
{
    fn __get(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath) -> Option<Self> {
        stdlib::ReadStorage::__exists(ctx, &path)
            .then(|| kontor::built_in::numbers::IntegerModel::new(ctx.clone(), path).load())
    }
}

impl<__S: stdlib::ReadStorage + 'static> stdlib::Retrieve<__S>
    for kontor::built_in::numbers::Decimal
{
    fn __get(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath) -> Option<Self> {
        stdlib::ReadStorage::__exists(ctx, &path)
            .then(|| kontor::built_in::numbers::DecimalModel::new(ctx.clone(), path).load())
    }
}
