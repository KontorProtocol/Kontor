use testlib::*;

const WIT: &str = r#"package root:component;

world root {
  import kontor:built-in/context;
  import kontor:built-in/error;
  import kontor:built-in/numbers;
  use kontor:built-in/context.{view-context, proc-context, signer};
  use kontor:built-in/error.{error};
  use kontor:built-in/numbers.{integer, decimal};

  export init: func(ctx: borrow<proc-context>);
  export mint: func(ctx: borrow<proc-context>, n: integer);
  export mint-checked: func(ctx: borrow<proc-context>, n: integer) -> result<_, error>;
  export transfer: func(ctx: borrow<proc-context>, to: string, n: integer) -> result<_, error>;
  export balance: func(ctx: borrow<view-context>, acc: string) -> option<integer>;
  export balance-log10: func(ctx: borrow<view-context>, acc: string) -> result<option<decimal>, error>;
}
"#;

async fn run_test(runtime: &mut Runtime) -> Result<()> {
    let alice = runtime.identity().await?;
    let token = runtime.publish(&alice, "token").await?;
    let wit = runtime.wit(&token).await?;
    assert_eq!(WIT, wit);
    Ok(())
}

#[runtime(contracts_dir = "../../test-contracts")]
async fn test_get_wit_from_api() -> Result<()> {
    run_test(runtime).await
}

#[runtime(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_get_wit_from_api_regtest() -> Result<()> {
    run_test(runtime).await
}
