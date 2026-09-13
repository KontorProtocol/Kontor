#![no_std]
contract!(name = "error_test");

use alloc::vec;
use built_in_types::numbers_types::Integer;
use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct ErrorTestStorage {
    marker: u64,
    numbers: Map<u64, Integer>,
    records: Map<u64, Record>,
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
        ]
    }

    fn trap_scalar_decode(ctx: &ProcContext, malformed_frame: bool) {
        let model = ctx.model();
        model.set_marker(1);
        let path = model.numbers().base_path.push_element(&0u64);
        // Both writes are valid host operations, but deliberately violate the
        // guest's numeric layout. 128 frames a byte-list length with no payload.
        if malformed_frame {
            ctx.storage().set_u64(&path, 128);
        } else {
            ctx.storage().set_list_u8(&path, &[0xff]);
        }
        let _ = model.numbers().entries().next();
    }

    fn scan_compound(ctx: &ProcContext, descending: bool) {
        let model = ctx.model();
        model.set_marker(1);
        model.records().set(&0, Record { value: 42 });
        // Bypass the typed map API to exercise the untrusted host boundary.
        let _ = ctx
            .storage()
            .get_storage_rows(&model.records().base_path, None, None, descending)
            .next();
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
