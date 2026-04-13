#![no_std]
contract!(name = "error_test");

use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct ErrorTestStorage {}

impl Guest for ErrorTest {
    fn init(ctx: &ProcContext) {
        ErrorTestStorage {}.init(ctx);
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

    fn trap_out_of_fuel(_ctx: &ProcContext) {
        #[allow(clippy::empty_loop)]
        loop {}
    }

    fn host_error(_ctx: &ProcContext) {
        // Calls a host function that always returns Err (simulates infrastructure failure)
        let _result = testing::host_error();
    }

    fn host_panic_nan(_ctx: &ProcContext) {
        // f64::NAN converted to Decimal triggers panic in host numerics code
        let _decimal = numbers::f64_to_decimal(f64::NAN);
    }
}
