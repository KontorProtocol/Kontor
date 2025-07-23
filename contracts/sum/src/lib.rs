macros::contract!(name = "sum");

impl Guest for Sum {
    fn init(_: &ProcContext) {}

    fn sum(_: &ProcContext, args: SumArgs) -> SumReturn {
        SumReturn {
            value: args.x + args.y,
        }
    }
}

export!(Sum);
