use darling::FromMeta;
use proc_macro2::TokenStream;
use quote::quote;

#[derive(FromMeta)]
pub struct Config {
    host: Option<bool>,
}

pub fn generate(config: Config) -> TokenStream {
    let host = config.host.unwrap_or_default();
    let numerics_mod_name = if host {
        quote! { numerics }
    } else {
        quote! { kontor::built_in::numbers }
    };

    quote! {
        #[automatically_derived]
        impl std::fmt::Display for kontor::built_in::foreign::ContractAddress {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}_{}_{}", self.name, self.height, self.tx_index)
            }
        }

        #[automatically_derived]
        impl std::str::FromStr for kontor::built_in::foreign::ContractAddress {
            type Err = String;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                let parts: Vec<&str> = s.split('_').collect();
                if parts.len() != 3 {
                    return Err(format!("expected 3 parts separated by '_', got: {s}"));
                }
                let name = parts[0].to_string();
                let height = parts[1]
                    .parse::<u64>()
                    .map_err(|e| format!("invalid height: {e}"))?;
                let tx_index = parts[2]
                    .parse::<u64>()
                    .map_err(|e| format!("invalid tx_index: {e}"))?;

                Ok(kontor::built_in::foreign::ContractAddress {
                    name,
                    height,
                    tx_index,
                })
            }
        }

        #[automatically_derived]
        impl PartialEq for kontor::built_in::foreign::ContractAddress {
            fn eq(&self, other: &Self) -> bool {
                self.name == other.name && self.height == other.height && self.tx_index == other.tx_index
            }
        }

        #[automatically_derived]
        impl Eq for kontor::built_in::foreign::ContractAddress {}

        #[automatically_derived]
        impl PartialEq for kontor::built_in::error::Error {
            fn eq(&self, other: &Self) -> bool {
                match (self, other) {
                    (kontor::built_in::error::Error::Message(msg1), kontor::built_in::error::Error::Message(msg2)) => msg1 == msg2,
                    (kontor::built_in::error::Error::Overflow(msg1), kontor::built_in::error::Error::Overflow(msg2)) => msg1 == msg2,
                    (kontor::built_in::error::Error::DivByZero(msg1), kontor::built_in::error::Error::DivByZero(msg2)) => msg1 == msg2,
                    _ => false,
                }
            }
        }

        #[automatically_derived]
        impl Eq for kontor::built_in::error::Error {}

        #[automatically_derived]
        impl kontor::built_in::error::Error {
            pub fn new(message: impl Into<String>) -> Self {
                kontor::built_in::error::Error::Message(message.into())
            }
        }

        #[automatically_derived]
        impl From<core::num::ParseIntError> for kontor::built_in::error::Error {
            fn from(err: core::num::ParseIntError) -> Self {
                kontor::built_in::error::Error::Message(format!("Parse integer error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl From<core::num::TryFromIntError> for kontor::built_in::error::Error {
            fn from(err: core::num::TryFromIntError) -> Self {
                kontor::built_in::error::Error::Message(format!("Try from integer error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl From<core::str::Utf8Error> for kontor::built_in::error::Error {
            fn from(err: core::str::Utf8Error) -> Self {
                kontor::built_in::error::Error::Message(format!("UTF-8 parse error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl From<core::char::ParseCharError> for kontor::built_in::error::Error {
            fn from(err: core::char::ParseCharError) -> Self {
                kontor::built_in::error::Error::Message(format!("Parse char error: {:?}", err))
            }
        }

        #[automatically_derived]
        impl kontor::built_in::numbers::Integer {
            pub fn sqrt(&self) -> Result<kontor::built_in::numbers::Integer, kontor::built_in::error::Error> {
                #numerics_mod_name::sqrt_integer(*self)
            }
        }

        #[automatically_derived]
        impl std::fmt::Display for kontor::built_in::numbers::Integer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let s = #numerics_mod_name::integer_to_string(*self);
                write!(f, "{}", s)
            }
        }

        #[automatically_derived]
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

        #[automatically_derived]
        impl CheckedArithmetics<kontor::built_in::error::Error> for kontor::built_in::numbers::Integer {
            type Output = Self;
            fn add(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::add_integer(self, other)
            }
            fn sub(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::sub_integer(self, other)
            }
            fn mul(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::mul_integer(self, other)
            }
            fn div(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::div_integer(self, other)
            }
        }

        #[automatically_derived]
        impl CheckedArithmetics<kontor::built_in::error::Error> for kontor::built_in::numbers::Decimal {
            type Output = Self;
            fn add(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::add_decimal(self, other)
            }
            fn sub(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::sub_decimal(self, other)
            }
            fn mul(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::mul_decimal(self, other)
            }
            fn div(self, other: Self) -> Result<Self::Output, kontor::built_in::error::Error> {
                #numerics_mod_name::div_decimal(self, other)
            }
        }

        #[automatically_derived]
        impl std::ops::Add for kontor::built_in::numbers::Integer {
            type Output = Self;

            fn add(self, other: Self) -> Self::Output {
                #numerics_mod_name::add_integer(self, other).unwrap()
            }
        }

        #[automatically_derived]
        impl std::ops::Sub for kontor::built_in::numbers::Integer {
            type Output = Self;

            fn sub(self, other: Self) -> Self::Output {
                #numerics_mod_name::sub_integer(self, other).unwrap()
            }
        }

        #[automatically_derived]
        impl std::ops::Mul for kontor::built_in::numbers::Integer {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self {
                #numerics_mod_name::mul_integer(self, rhs).unwrap()
            }
        }

        #[automatically_derived]
        impl std::ops::Div for kontor::built_in::numbers::Integer {
            type Output = Self;

            fn div(self, rhs: Self) -> Self {
                #numerics_mod_name::div_integer(self, rhs).unwrap()
            }
        }

        #[automatically_derived]
        impl PartialOrd for kontor::built_in::numbers::Integer {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        #[automatically_derived]
        impl Ord for kontor::built_in::numbers::Integer {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                match #numerics_mod_name::cmp_integer(*self, *other) {
                    kontor::built_in::numbers::Ordering::Less => std::cmp::Ordering::Less,
                    kontor::built_in::numbers::Ordering::Equal => std::cmp::Ordering::Equal,
                    kontor::built_in::numbers::Ordering::Greater => std::cmp::Ordering::Greater,
                }
            }
        }

        #[automatically_derived]
        impl PartialEq for kontor::built_in::numbers::Integer {
            fn eq(&self, other: &Self) -> bool {
                #numerics_mod_name::eq_integer(*self, *other)
            }
        }

        #[automatically_derived]
        impl Eq for kontor::built_in::numbers::Integer {}

        #[automatically_derived]
        impl From<u64> for kontor::built_in::numbers::Integer {
            fn from(i: u64) -> Self {
                #numerics_mod_name::u64_to_integer(i)
            }
        }

        #[automatically_derived]
        impl From<u32> for kontor::built_in::numbers::Integer {
            fn from(i: u32) -> Self {
                (i as u64).into()
            }
        }

        #[automatically_derived]
        impl From<i64> for kontor::built_in::numbers::Integer {
            fn from(i: i64) -> Self {
                #numerics_mod_name::s64_to_integer(i)
            }
        }

        #[automatically_derived]
        impl From<i32> for kontor::built_in::numbers::Integer {
            fn from(i: i32) -> Self {
                (i as i64).into()
            }
        }

        #[automatically_derived]
        impl From<&str> for kontor::built_in::numbers::Integer {
            fn from(s: &str) -> Self {
                #numerics_mod_name::string_to_integer(s).unwrap()
            }
        }

        #[automatically_derived]
        impl From<String> for kontor::built_in::numbers::Integer {
            fn from(s: String) -> Self {
                s.as_str().into()
            }
        }

        #[automatically_derived]
        impl kontor::built_in::numbers::Decimal {
            pub fn log10(&self) -> Result<kontor::built_in::numbers::Decimal, kontor::built_in::error::Error> {
                #numerics_mod_name::log10_decimal(*self)
            }
        }


        #[automatically_derived]
        impl std::fmt::Display for kontor::built_in::numbers::Decimal {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let s = #numerics_mod_name::decimal_to_string(*self);
                write!(f, "{}", s)
            }
        }

        #[automatically_derived]
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

        #[automatically_derived]
        impl std::ops::Add for kontor::built_in::numbers::Decimal {
            type Output = Self;

            fn add(self, other: Self) -> Self::Output {
                #numerics_mod_name::add_decimal(self, other).unwrap()
            }
        }

        #[automatically_derived]
        impl std::ops::Sub for kontor::built_in::numbers::Decimal {
            type Output = Self;

            fn sub(self, other: Self) -> Self::Output {
                #numerics_mod_name::sub_decimal(self, other).unwrap()
            }
        }

        #[automatically_derived]
        impl std::ops::Mul for kontor::built_in::numbers::Decimal {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self {
                #numerics_mod_name::mul_decimal(self, rhs).unwrap()
            }
        }

        #[automatically_derived]
        impl std::ops::Div for kontor::built_in::numbers::Decimal {
            type Output = Self;

            fn div(self, rhs: Self) -> Self {
                #numerics_mod_name::div_decimal(self, rhs).unwrap()
            }
        }


        #[automatically_derived]
        impl PartialOrd for kontor::built_in::numbers::Decimal {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        #[automatically_derived]
        impl Ord for kontor::built_in::numbers::Decimal {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                match #numerics_mod_name::cmp_decimal(*self, *other) {
                    kontor::built_in::numbers::Ordering::Less => std::cmp::Ordering::Less,
                    kontor::built_in::numbers::Ordering::Equal => std::cmp::Ordering::Equal,
                    kontor::built_in::numbers::Ordering::Greater => std::cmp::Ordering::Greater,
                }
            }
        }

        #[automatically_derived]
        impl PartialEq for kontor::built_in::numbers::Decimal {
            fn eq(&self, other: &Self) -> bool {
                #numerics_mod_name::eq_decimal(*self, *other)
            }
        }

        #[automatically_derived]
        impl Eq for kontor::built_in::numbers::Decimal {}

        #[automatically_derived]
        impl From<kontor::built_in::numbers::Integer> for kontor::built_in::numbers::Decimal {
            fn from(i: kontor::built_in::numbers::Integer) -> kontor::built_in::numbers::Decimal {
                #numerics_mod_name::integer_to_decimal(i)
            }
        }

        impl From<u64> for kontor::built_in::numbers::Decimal {
            fn from(i: u64) -> Self {
                #numerics_mod_name::u64_to_decimal(i)
            }
        }

        impl From<u32> for kontor::built_in::numbers::Decimal {
            fn from(i: u32) -> Self {
                (i as u64).into()
            }
        }

        impl From<i64> for kontor::built_in::numbers::Decimal {
            fn from(i: i64) -> Self {
                #numerics_mod_name::s64_to_decimal(i)
            }
        }

        impl From<i32> for kontor::built_in::numbers::Decimal {
            fn from(i: i32) -> Self {
                (i as i64).into()
            }
        }

        impl From<f64> for kontor::built_in::numbers::Decimal {
            fn from(f: f64) -> Self {
                #numerics_mod_name::f64_to_decimal(f)
            }
        }

        impl From<f32> for kontor::built_in::numbers::Decimal {
            fn from(f: f32) -> Self {
                (f as f64).into()
            }
        }

        impl From<&str> for kontor::built_in::numbers::Decimal {
            fn from(s: &str) -> Self {
                #numerics_mod_name::string_to_decimal(s).unwrap()
            }
        }

        impl From<String> for kontor::built_in::numbers::Decimal {
            fn from(s: String) -> Self {
                s.as_str().into()
            }
        }
    }
}
