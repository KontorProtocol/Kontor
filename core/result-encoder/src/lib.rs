//! Node-owned core Wasm formatter. Source reads are imports implemented by Wasm
//! accessors over the contract memory, never native host calls or lifted values.
#[cfg(target_arch = "wasm32")]
use core::arch::wasm32::unreachable;

use std::cell::{Cell, RefCell};
use std::fmt::Write;

thread_local! {
    static OUTPUT: RefCell<String> = const { RefCell::new(String::new()) };
    static RESULT_KIND: Cell<u32> = const { Cell::new(u32::MAX) };
    static RAW: Cell<bool> = const { Cell::new(false) };
    static SCRATCH: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "source")]
unsafe extern "C" {
    fn byte(address: u32) -> u32;
    fn pages() -> u32;
}

#[cfg(target_arch = "wasm32")]
fn invalid() -> ! {
    unreachable()
}

#[cfg(not(target_arch = "wasm32"))]
fn invalid() -> ! {
    panic!("invalid canonical result")
}

fn checked(condition: bool) {
    if !condition {
        invalid();
    }
}

fn scalar(value: u32) -> char {
    char::from_u32(value).unwrap_or_else(|| invalid())
}

fn write_char(output: &mut String, value: char) {
    // Match WAVE's character spelling, including control characters and
    // combining marks. Rust's Unicode tables live in the encoder's own memory.
    match value {
        '\\' => output.push_str("\\\\"),
        '\"' => output.push_str("\\\""),
        '\'' => output.push_str("\\'"),
        '\t' => output.push_str("\\t"),
        '\r' => output.push_str("\\r"),
        '\n' => output.push_str("\\n"),
        ' '..='~' => output.push(value),
        ch if ch.is_control() => write!(output, "{}", ch.escape_unicode()).unwrap(),
        ch => write!(output, "{}", ch.escape_debug()).unwrap(),
    }
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "begin"))]
pub extern "C" fn begin(kind: u32, raw: u32) {
    RESULT_KIND.set(kind);
    RAW.set(raw != 0);
    OUTPUT.with_borrow_mut(String::clear);
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "expect-kind"))]
pub extern "C" fn expect_kind(kind: u32) {
    checked(RESULT_KIND.get() == kind);
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "scratch"))]
pub extern "C" fn scratch(bytes: u32) -> usize {
    SCRATCH.with_borrow_mut(|buffer| {
        buffer.resize((bytes as usize).div_ceil(8), 0);
        buffer.as_mut_ptr() as usize
    })
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "punctuation"))]
pub extern "C" fn punctuation(value: u32) {
    checked(value < 128);
    OUTPUT.with_borrow_mut(|output| output.push(value as u8 as char));
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "unsigned"))]
pub extern "C" fn unsigned(value: u64) {
    OUTPUT.with_borrow_mut(|output| write!(output, "{value}").unwrap());
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "signed"))]
pub extern "C" fn signed(value: i64) {
    OUTPUT.with_borrow_mut(|output| write!(output, "{value}").unwrap());
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "boolean"))]
pub extern "C" fn boolean(value: u32) {
    // Canonical lifting treats every nonzero integer as true.
    OUTPUT.with_borrow_mut(|output| output.push_str(if value == 0 { "false" } else { "true" }));
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "character"))]
pub extern "C" fn character(value: u32) {
    OUTPUT.with_borrow_mut(|output| {
        output.push('\'');
        write_char(output, scalar(value));
        output.push('\'');
    });
}

#[cfg(target_arch = "wasm32")]
fn read(address: u32) -> u8 {
    // The imported Wasm load traps on an invalid address before returning.
    unsafe { byte(address) as u8 }
}

#[cfg(target_arch = "wasm32")]
fn range(ptr: u32, len: u64) {
    checked(u64::from(ptr) + len <= u64::from(unsafe { pages() }) * 65536);
}

#[cfg(target_arch = "wasm32")]
fn utf8(ptr: u32, len: u32, mut emit: impl FnMut(char)) {
    range(ptr, u64::from(len));
    let mut position = 0;
    while position < len {
        let first = read(ptr + position);
        if first.is_ascii() {
            emit(char::from(first));
            position += 1;
            continue;
        }
        let width = match first {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => invalid(),
        };
        checked(width <= len - position);
        let mut bytes = [0; 4];
        bytes[0] = first;
        for index in 1..width {
            bytes[index as usize] = read(ptr + position + index);
        }
        let text = std::str::from_utf8(&bytes[..width as usize]).unwrap_or_else(|_| invalid());
        emit(text.chars().next().unwrap());
        position += width;
    }
}

#[cfg(target_arch = "wasm32")]
#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "string"))]
pub extern "C" fn string(ptr: u32, len: u32, encoding: u32, raw: u32) {
    let raw = if raw == 2 { u32::from(RAW.get()) } else { raw };
    OUTPUT.with_borrow_mut(|output| {
        if raw == 0 {
            output.push('"');
        }
        let mut emit = |ch| {
            if raw != 0 {
                output.push(ch);
            } else {
                write_char(output, ch);
            }
        };
        match encoding {
            0 => utf8(ptr, len, &mut emit),
            1 | 2 => {
                checked(ptr % 2 == 0);
                if encoding == 2 && len & 0x80000000 == 0 {
                    range(ptr, u64::from(len));
                    for i in 0..len {
                        emit(char::from(read(ptr + i)));
                    }
                } else {
                    let len = if encoding == 2 { len & 0x7fffffff } else { len };
                    range(ptr, u64::from(len) * 2);
                    let units = (0..len).map(|i| {
                        let address = ptr + i * 2;
                        u16::from_le_bytes([read(address), read(address + 1)])
                    });
                    for ch in char::decode_utf16(units) {
                        emit(ch.unwrap_or_else(|_| invalid()));
                    }
                }
            }
            _ => invalid(),
        }
        if raw == 0 {
            output.push('"');
        }
    });
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "output-pointer"))]
pub extern "C" fn output_pointer() -> usize {
    OUTPUT.with_borrow(|output| output.as_ptr() as usize)
}

#[cfg_attr(target_arch = "wasm32", unsafe(export_name = "output-length"))]
pub extern "C" fn output_length() -> usize {
    OUTPUT.with_borrow(String::len)
}

#[cfg(test)]
mod tests {
    use super::{OUTPUT, begin, character, signed, unsigned, write_char};
    use wasm_wave::value::Value;

    #[test]
    fn character_spelling_matches_wave_for_every_scalar() {
        for ch in (0..=0x10ffff).filter_map(char::from_u32) {
            let mut actual = String::from("\"");
            write_char(&mut actual, ch);
            actual.push('"');
            assert_eq!(
                actual,
                wasm_wave::to_string(&Value::from(ch.to_string())).unwrap()
            );
        }
    }

    #[test]
    fn scalar_boundaries() {
        begin(0, 0);
        signed(i64::MIN);
        unsigned(u64::MAX);
        character('🦀' as u32);
        OUTPUT
            .with_borrow(|value| assert_eq!(value, "-922337203685477580818446744073709551615'🦀'"));
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod memory;
#[cfg(not(target_arch = "wasm32"))]
mod prepare;
#[cfg(not(target_arch = "wasm32"))]
mod walker;

pub const ENCODER_IMPORT: &str = "kontor-result-encoder";
pub const OUTPUT_IMPORT: &str = "kontor-result-output";
pub const PRIVATE_PREFIX: &str = "kontor-encoded-";

#[cfg(not(target_arch = "wasm32"))]
pub use prepare::encode as prepare_component;

#[cfg(not(target_arch = "wasm32"))]
pub fn encoder_module() -> anyhow::Result<Vec<u8>> {
    memory::inject(include_bytes!("../binaries/encoder.wasm"))
}

#[cfg(not(target_arch = "wasm32"))]
mod asynchronous;

#[cfg(not(target_arch = "wasm32"))]
mod kinds;
