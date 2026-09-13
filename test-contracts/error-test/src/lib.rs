#![no_std]
contract!(name = "error_test");

use alloc::vec;
use built_in_types::kontor::built_in::context_types::HolderRef;
use built_in_types::numbers_types::Integer;
use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct ErrorTestStorage {
    marker: u64,
    numbers: Map<u64, Integer>,
    records: Map<u64, Record>,
    unsigned: Map<u64, u64>,
    signed: Map<u64, i64>,
    small_unsigned: Map<u64, u32>,
    small_signed: Map<u64, i32>,
    flags: Map<u64, bool>,
    strings: Map<u64, String>,
    bytes: Map<u64, Vec<u8>>,
    holders: Map<u64, Holder>,
}

#[derive(Clone, Storage)]
struct Record {
    value: u64,
}

impl Guest for ErrorTest {
    fn init(ctx: &ProcContext) -> Contract {
        ErrorTestStorage::default().init(ctx);
        ctx.contract()
    }

    fn succeed(_ctx: &ViewContext) -> u64 {
        42
    }

    fn contract_error(_ctx: &ViewContext) -> Result<u64, Error> {
        Err(Error::Message("deliberate error".into()))
    }

    fn trap_div_zero(_ctx: &ProcContext) {
        let x: u64 = 1;
        let y: u64 = 0;
        #[allow(unconditional_panic)]
        let _ = x / y;
    }

    fn trap_panic(_ctx: &ProcContext) {
        panic!("deliberate contract panic");
    }

    fn storage_state(ctx: &ViewContext) -> Vec<u64> {
        let model = ctx.model();
        vec![
            model.marker(),
            model.numbers().keys().count() as u64,
            model.records().keys().count() as u64,
            (model.unsigned().keys().count()
                + model.signed().keys().count()
                + model.small_unsigned().keys().count()
                + model.small_signed().keys().count()
                + model.flags().keys().count()
                + model.strings().keys().count()
                + model.bytes().keys().count()
                + model.holders().keys().count()) as u64,
        ]
    }

    fn invalid_storage_read(ctx: &ProcContext, case: u32, scan: bool) {
        let model = ctx.model();
        model.set_marker(1);
        match case {
            0 | 1 => {
                let path = model.numbers().base_path.push_element(&0u64);
                // Valid host writes, incompatible numeric layout: a byte-list
                // length without its payload, or an invalid numeric type tag.
                if case == 0 {
                    ctx.storage().set_u64(&path, 128);
                } else {
                    ctx.storage().set_list_u8(&path, &[0xff]);
                }
                if scan {
                    let _ = model.numbers().entries().next();
                } else {
                    let _ = model.numbers().get(&0);
                }
            }
            2 => {
                ctx.storage().set_u64(
                    &model.small_unsigned().base_path.push_element(&0u64),
                    u64::from(u32::MAX) + 1,
                );
                if scan {
                    let _ = model.small_unsigned().entries().next();
                } else {
                    let _ = model.small_unsigned().get(&0);
                }
            }
            3 | 4 => {
                let value = if case == 3 {
                    i64::from(i32::MIN) - 1
                } else {
                    i64::from(i32::MAX) + 1
                };
                ctx.storage()
                    .set_s64(&model.small_signed().base_path.push_element(&0u64), value);
                if scan {
                    let _ = model.small_signed().entries().next();
                } else {
                    let _ = model.small_signed().get(&0);
                }
            }
            5 => {
                ctx.storage()
                    .set_u64(&model.flags().base_path.push_element(&0u64), 2);
                if scan {
                    let _ = model.flags().entries().next();
                } else {
                    let _ = model.flags().get(&0);
                }
            }
            6 => {
                // A byte-list is a length followed by bytes. Reading it as u64
                // consumes the length but leaves the payload trailing.
                ctx.storage()
                    .set_list_u8(&model.unsigned().base_path.push_element(&0u64), &[42]);
                if scan {
                    let _ = model.unsigned().entries().next();
                } else {
                    let _ = model.unsigned().get(&0);
                }
            }
            7 => {
                ctx.storage()
                    .set_list_u8(&model.strings().base_path.push_element(&0u64), &[0xff]);
                if scan {
                    let _ = model.strings().entries().next();
                } else {
                    let _ = model.strings().get(&0);
                }
            }
            8 => {
                ctx.storage().set_str(
                    &model.holders().base_path.push_element(&0u64),
                    "invalid-holder",
                );
                if scan {
                    let _ = model.holders().entries().next();
                } else {
                    let _ = model.holders().get(&0);
                }
            }
            _ => panic!("unknown test case"),
        }
    }

    fn primitive_entries(ctx: &ProcContext) {
        let model = ctx.model();
        macro_rules! check {
            ($field:ident, $values:expr) => {{
                let values = $values;
                for (key, value) in values.iter().enumerate() {
                    model.$field().set(&(key as u64), value.clone());
                }
                let expected: Vec<_> = values
                    .into_iter()
                    .enumerate()
                    .map(|(key, value)| (key as u64, value))
                    .collect();
                assert_eq!(model.$field().entries().collect::<Vec<_>>(), expected);
                for (key, value) in &expected {
                    assert_eq!(model.$field().get(key).as_ref(), Some(value));
                }
                assert_eq!(
                    model.$field().range(..).rev().entries().collect::<Vec<_>>(),
                    expected.into_iter().rev().collect::<Vec<_>>()
                );
            }};
        }
        check!(unsigned, [0u64, 127, 128, u64::MAX]);
        check!(signed, [i64::MIN, -1, 0, i64::MAX]);
        check!(small_unsigned, [0u32, u32::MAX]);
        check!(small_signed, [i32::MIN, 0, i32::MAX]);
        check!(flags, [false, true]);
        check!(
            strings,
            [String::new(), String::from("a\0b"), String::from("雪")]
        );
        check!(bytes, [vec![], vec![0, 128, 255]]);
        let holder = Holder::from_ref(&HolderRef::Core).unwrap();
        model.holders().set(&0, holder.clone());
        assert!(model.holders().get(&0) == Some(holder.clone()));
        assert!(model.holders().entries().collect::<Vec<_>>() == vec![(0, holder)]);
    }

    fn scan_compound(ctx: &ProcContext, descending: bool) {
        let model = ctx.model();
        model.set_marker(1);
        model.records().set(&0, Record { value: 42 });
        // Bypass the typed map API to exercise the untrusted host boundary.
        let _ = ctx
            .storage()
            .get_storage_rows(&model.records().base_path, None, None, descending)
            .next_u64();
    }

    fn trap_out_of_fuel(_ctx: &ProcContext) {
        #[allow(clippy::empty_loop)]
        loop {}
    }

    fn host_error(_ctx: &ProcContext) {
        let _result = testing::host_error();
    }

    fn host_panic(_ctx: &ProcContext) {
        let _result = testing::host_panic();
    }
}
