//! The numbers/error family: arithmetic through [`backend`] — the
//! `kontor:built-in/numbers` host functions when compiled to wasm (contracts)
//! and the pure `numerics` crate natively (the indexer and tests) — the same
//! split the old guest/host macro modes encoded, now as one target-cfg'd
//! module instead of two expansion sites.

use alloc::string::String;

use crate::kontor;

/// The arithmetic backend: identical signatures on both targets.
mod backend {
    #[cfg(target_arch = "wasm32")]
    pub use crate::kontor::built_in::numbers::*;

    #[cfg(not(target_arch = "wasm32"))]
    pub use native::*;

    /// Native backend: shape conversions plus delegation to the pure
    /// `numerics` crate (the same math the host functions run — `@kontor/sdk`
    /// shares it too, so semantics are identical byte-for-byte everywhere).
    #[cfg(not(target_arch = "wasm32"))]
    mod native {
        use ::numerics as core_numerics;

        use crate::error::Error;
        use crate::numbers_types::{Decimal, Integer, Ordering, Sign};

        impl From<Sign> for core_numerics::Sign {
            fn from(s: Sign) -> Self {
                match s {
                    Sign::Plus => core_numerics::Sign::Plus,
                    Sign::Minus => core_numerics::Sign::Minus,
                }
            }
        }

        impl From<core_numerics::Sign> for Sign {
            fn from(s: core_numerics::Sign) -> Self {
                match s {
                    core_numerics::Sign::Plus => Sign::Plus,
                    core_numerics::Sign::Minus => Sign::Minus,
                }
            }
        }

        impl From<core_numerics::Ordering> for Ordering {
            fn from(o: core_numerics::Ordering) -> Self {
                match o {
                    core_numerics::Ordering::Less => Ordering::Less,
                    core_numerics::Ordering::Equal => Ordering::Equal,
                    core_numerics::Ordering::Greater => Ordering::Greater,
                }
            }
        }

        impl From<Integer> for core_numerics::Integer {
            fn from(i: Integer) -> Self {
                core_numerics::Integer {
                    r0: i.r0,
                    r1: i.r1,
                    r2: i.r2,
                    r3: i.r3,
                    sign: i.sign.into(),
                }
            }
        }

        impl From<core_numerics::Integer> for Integer {
            fn from(i: core_numerics::Integer) -> Self {
                Integer {
                    r0: i.r0,
                    r1: i.r1,
                    r2: i.r2,
                    r3: i.r3,
                    sign: i.sign.into(),
                }
            }
        }

        impl From<Decimal> for core_numerics::Decimal {
            fn from(d: Decimal) -> Self {
                core_numerics::Decimal {
                    r0: d.r0,
                    r1: d.r1,
                    r2: d.r2,
                    r3: d.r3,
                    sign: d.sign.into(),
                }
            }
        }

        impl From<core_numerics::Decimal> for Decimal {
            fn from(d: core_numerics::Decimal) -> Self {
                Decimal {
                    r0: d.r0,
                    r1: d.r1,
                    r2: d.r2,
                    r3: d.r3,
                    sign: d.sign.into(),
                }
            }
        }

        impl From<core_numerics::Error> for Error {
            fn from(e: core_numerics::Error) -> Self {
                match e {
                    core_numerics::Error::Message(s) => Error::Message(s),
                    core_numerics::Error::Overflow(s) => Error::Overflow(s),
                    core_numerics::Error::DivByZero(s) => Error::DivByZero(s),
                    core_numerics::Error::Syntax(s) => Error::Syntax(s),
                    core_numerics::Error::Validation(s) => Error::Validation(s),
                }
            }
        }

        use alloc::string::{String, ToString};

        macro_rules! bin {
            ($name:ident, $ty:ident, $core_fn:ident) => {
                pub fn $name(a: $ty, b: $ty) -> Result<$ty, Error> {
                    core_numerics::$core_fn(a.into(), b.into())
                        .map(Into::into)
                        .map_err(Into::into)
                }
            };
        }

        bin!(add_integer, Integer, add_integer);
        bin!(sub_integer, Integer, sub_integer);
        bin!(mul_integer, Integer, mul_integer);
        bin!(div_integer, Integer, div_integer);
        bin!(add_decimal, Decimal, add_decimal);
        bin!(sub_decimal, Decimal, sub_decimal);
        bin!(mul_decimal, Decimal, mul_decimal);
        bin!(div_decimal, Decimal, div_decimal);

        pub fn sqrt_integer(i: Integer) -> Result<Integer, Error> {
            core_numerics::sqrt_integer(i.into())
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn log10_decimal(d: Decimal) -> Result<Decimal, Error> {
            core_numerics::log10_decimal(d.into())
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn u64_to_integer(i: u64) -> Integer {
            core_numerics::u64_to_integer(i).into()
        }

        pub fn s64_to_integer(i: i64) -> Integer {
            core_numerics::s64_to_integer(i).into()
        }

        pub fn string_to_integer(s: &str) -> Result<Integer, Error> {
            core_numerics::string_to_integer(s)
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn integer_to_string(i: Integer) -> String {
            core_numerics::integer_to_string(i.into())
        }

        pub fn eq_integer(a: Integer, b: Integer) -> bool {
            core_numerics::eq_integer(a.into(), b.into())
        }

        pub fn cmp_integer(a: Integer, b: Integer) -> Ordering {
            core_numerics::cmp_integer(a.into(), b.into()).into()
        }

        pub fn integer_to_decimal(i: Integer) -> Result<Decimal, Error> {
            core_numerics::integer_to_decimal(i.into())
                .map(Into::into)
                .map_err(Into::into)
        }

        // Not called by the shared impls today, but part of the backend's
        // complete numbers surface (mirrors the host-function set).
        #[allow(dead_code)]
        pub fn decimal_to_integer(d: Decimal) -> Result<Integer, Error> {
            core_numerics::decimal_to_integer(d.into())
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn u64_to_decimal(i: u64) -> Result<Decimal, Error> {
            core_numerics::u64_to_decimal(i)
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn s64_to_decimal(i: i64) -> Result<Decimal, Error> {
            core_numerics::s64_to_decimal(i)
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn f64_to_decimal(f: f64) -> Result<Decimal, Error> {
            core_numerics::f64_to_decimal(f)
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn string_to_decimal(s: &str) -> Result<Decimal, Error> {
            core_numerics::string_to_decimal(s)
                .map(Into::into)
                .map_err(Into::into)
        }

        pub fn decimal_to_string(d: Decimal) -> String {
            core_numerics::decimal_to_string(d.into())
        }

        pub fn eq_decimal(a: Decimal, b: Decimal) -> Result<bool, Error> {
            core_numerics::eq_decimal(a.into(), b.into()).map_err(Into::into)
        }

        pub fn cmp_decimal(a: Decimal, b: Decimal) -> Ordering {
            core_numerics::cmp_decimal(a.into(), b.into()).into()
        }

        // silence unused-import when only some wrappers are exercised
        #[allow(unused_imports)]
        use ToString as _;
    }
}

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

impl kontor::built_in::numbers_types::Integer {
    pub fn sqrt(
        &self,
    ) -> Result<kontor::built_in::numbers_types::Integer, kontor::built_in::error::Error> {
        backend::sqrt_integer(*self)
    }
}

impl core::fmt::Display for kontor::built_in::numbers_types::Integer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = backend::integer_to_string(*self);
        write!(f, "{}", s)
    }
}

impl Default for kontor::built_in::numbers_types::Integer {
    fn default() -> Self {
        Self {
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            sign: kontor::built_in::numbers_types::Sign::Plus,
        }
    }
}

impl stdlib::CheckedArithmetics<kontor::built_in::error::Error>
    for kontor::built_in::numbers_types::Integer
{
    type Output = Self;
    fn add(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::add_integer(self, other)
    }
    fn sub(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::sub_integer(self, other)
    }
    fn mul(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::mul_integer(self, other)
    }
    fn div(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::div_integer(self, other)
    }
}

impl stdlib::CheckedArithmetics<kontor::built_in::error::Error>
    for kontor::built_in::numbers_types::Decimal
{
    type Output = Self;
    fn add(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::add_decimal(self, other)
    }
    fn sub(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::sub_decimal(self, other)
    }
    fn mul(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::mul_decimal(self, other)
    }
    fn div(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
        backend::div_decimal(self, other)
    }
}

impl core::ops::Add for kontor::built_in::numbers_types::Integer {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        backend::add_integer(self, other).unwrap()
    }
}

impl core::ops::Sub for kontor::built_in::numbers_types::Integer {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        backend::sub_integer(self, other).unwrap()
    }
}

impl core::ops::Mul for kontor::built_in::numbers_types::Integer {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        backend::mul_integer(self, rhs).unwrap()
    }
}

impl core::ops::Div for kontor::built_in::numbers_types::Integer {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        backend::div_integer(self, rhs).unwrap()
    }
}

impl PartialOrd for kontor::built_in::numbers_types::Integer {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for kontor::built_in::numbers_types::Integer {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match backend::cmp_integer(*self, *other) {
            kontor::built_in::numbers_types::Ordering::Less => core::cmp::Ordering::Less,
            kontor::built_in::numbers_types::Ordering::Equal => core::cmp::Ordering::Equal,
            kontor::built_in::numbers_types::Ordering::Greater => core::cmp::Ordering::Greater,
        }
    }
}

impl PartialEq for kontor::built_in::numbers_types::Integer {
    fn eq(&self, other: &Self) -> bool {
        backend::eq_integer(*self, *other)
    }
}

impl Eq for kontor::built_in::numbers_types::Integer {}

impl From<u64> for kontor::built_in::numbers_types::Integer {
    fn from(i: u64) -> Self {
        backend::u64_to_integer(i)
    }
}

impl From<u32> for kontor::built_in::numbers_types::Integer {
    fn from(i: u32) -> Self {
        (i as u64).into()
    }
}

impl From<i64> for kontor::built_in::numbers_types::Integer {
    fn from(i: i64) -> Self {
        backend::s64_to_integer(i)
    }
}

impl From<i32> for kontor::built_in::numbers_types::Integer {
    fn from(i: i32) -> Self {
        (i as i64).into()
    }
}

impl From<&str> for kontor::built_in::numbers_types::Integer {
    fn from(s: &str) -> Self {
        backend::string_to_integer(s).unwrap()
    }
}

impl From<String> for kontor::built_in::numbers_types::Integer {
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

impl kontor::built_in::numbers_types::Decimal {
    pub fn log10(
        &self,
    ) -> Result<kontor::built_in::numbers_types::Decimal, kontor::built_in::error::Error> {
        backend::log10_decimal(*self)
    }
}

impl core::fmt::Display for kontor::built_in::numbers_types::Decimal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = backend::decimal_to_string(*self);
        write!(f, "{}", s)
    }
}

impl Default for kontor::built_in::numbers_types::Decimal {
    fn default() -> Self {
        Self {
            r0: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            sign: kontor::built_in::numbers_types::Sign::Plus,
        }
    }
}

impl core::ops::Add for kontor::built_in::numbers_types::Decimal {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        backend::add_decimal(self, other).unwrap()
    }
}

impl core::ops::Sub for kontor::built_in::numbers_types::Decimal {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        backend::sub_decimal(self, other).unwrap()
    }
}

impl core::ops::Mul for kontor::built_in::numbers_types::Decimal {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        backend::mul_decimal(self, rhs).unwrap()
    }
}

impl core::ops::Div for kontor::built_in::numbers_types::Decimal {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        backend::div_decimal(self, rhs).unwrap()
    }
}

impl PartialOrd for kontor::built_in::numbers_types::Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for kontor::built_in::numbers_types::Decimal {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match backend::cmp_decimal(*self, *other) {
            kontor::built_in::numbers_types::Ordering::Less => core::cmp::Ordering::Less,
            kontor::built_in::numbers_types::Ordering::Equal => core::cmp::Ordering::Equal,
            kontor::built_in::numbers_types::Ordering::Greater => core::cmp::Ordering::Greater,
        }
    }
}

impl PartialEq for kontor::built_in::numbers_types::Decimal {
    fn eq(&self, other: &Self) -> bool {
        backend::eq_decimal(*self, *other).expect("eq_decimal failed")
    }
}

impl Eq for kontor::built_in::numbers_types::Decimal {}

impl TryFrom<kontor::built_in::numbers_types::Integer>
    for kontor::built_in::numbers_types::Decimal
{
    type Error = kontor::built_in::error::Error;
    fn try_from(
        i: kontor::built_in::numbers_types::Integer,
    ) -> Result<kontor::built_in::numbers_types::Decimal, Self::Error> {
        backend::integer_to_decimal(i)
    }
}

impl TryFrom<u64> for kontor::built_in::numbers_types::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: u64) -> Result<Self, Self::Error> {
        backend::u64_to_decimal(i)
    }
}

impl TryFrom<u32> for kontor::built_in::numbers_types::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: u32) -> Result<Self, Self::Error> {
        (i as u64).try_into()
    }
}

impl TryFrom<i64> for kontor::built_in::numbers_types::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: i64) -> Result<Self, Self::Error> {
        backend::s64_to_decimal(i)
    }
}

impl TryFrom<i32> for kontor::built_in::numbers_types::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(i: i32) -> Result<Self, Self::Error> {
        (i as i64).try_into()
    }
}

impl TryFrom<f64> for kontor::built_in::numbers_types::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(f: f64) -> Result<Self, Self::Error> {
        backend::f64_to_decimal(f)
    }
}

impl TryFrom<f32> for kontor::built_in::numbers_types::Decimal {
    type Error = kontor::built_in::error::Error;
    fn try_from(f: f32) -> Result<Self, Self::Error> {
        (f as f64).try_into()
    }
}

impl From<&str> for kontor::built_in::numbers_types::Decimal {
    fn from(s: &str) -> Self {
        backend::string_to_decimal(s).unwrap()
    }
}

impl From<String> for kontor::built_in::numbers_types::Decimal {
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

// --- storage-integration impls (moved from the per-contract `contract!` glue;
// stdlib traits on types this crate owns) ---

/// `#[index]` on an Integer/Decimal field buckets by its canonical string
/// (equality partition — order irrelevant).
impl stdlib::IndexKey for kontor::built_in::numbers_types::Integer {
    fn index_key(&self) -> alloc::vec::Vec<u8> {
        stdlib::KeyElement::encode(&alloc::string::ToString::to_string(self))
    }
}

impl stdlib::IndexKey for kontor::built_in::numbers_types::Decimal {
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
                    matches!(self.sign, kontor::built_in::numbers_types::Sign::Minus),
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
                            kontor::built_in::numbers_types::Sign::Minus
                        } else {
                            kontor::built_in::numbers_types::Sign::Plus
                        },
                    },
                    rest,
                ))
            }
        }
    )*};
}
__key_element_num256!(
    kontor::built_in::numbers_types::Integer,
    kontor::built_in::numbers_types::Decimal
);

impl<__S: stdlib::ReadStorage + 'static> stdlib::Retrieve<__S>
    for kontor::built_in::numbers_types::Integer
{
    fn __get(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath) -> Option<Self> {
        stdlib::ReadStorage::__exists(ctx, &path)
            .then(|| kontor::built_in::numbers_types::IntegerModel::new(ctx.clone(), path).load())
    }
}

impl<__S: stdlib::ReadStorage + 'static> stdlib::Retrieve<__S>
    for kontor::built_in::numbers_types::Decimal
{
    fn __get(ctx: &alloc::rc::Rc<__S>, path: stdlib::KeyPath) -> Option<Self> {
        stdlib::ReadStorage::__exists(ctx, &path)
            .then(|| kontor::built_in::numbers_types::DecimalModel::new(ctx.clone(), path).load())
    }
}
