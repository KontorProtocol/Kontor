use indexer::runtime::token;
use testlib::*;

const WIT: &str = r#"package root:component;

world root {
  import kontor:built-in/context;
  import kontor:built-in/error;
  import kontor:built-in/numbers;
  use kontor:built-in/context.{view-context, proc-context, signer};
  use kontor:built-in/error.{error};
  use kontor:built-in/numbers.{decimal};

  record balance {
    key: string,
    value: decimal,
  }

  export mint: func(ctx: borrow<proc-context>, n: decimal) -> result<_, error>;
  export burn: func(ctx: borrow<proc-context>, n: decimal) -> result<_, error>;
  export transfer: func(ctx: borrow<proc-context>, to: string, n: decimal) -> result<_, error>;
  export balance: func(ctx: borrow<view-context>, acc: string) -> option<decimal>;
  export balances: func(ctx: borrow<view-context>) -> list<balance>;
  export total-supply: func(ctx: borrow<view-context>) -> decimal;
}
"#;

async fn run_test(runtime: &mut Runtime) -> Result<()> {
    let wit = runtime.wit(&token::address()).await?;
    assert_eq!(WIT, wit);
    Ok(())
}

#[testlib::test(contracts_dir = "test-contracts")]
async fn test_get_wit_from_api() -> Result<()> {
    run_test(runtime).await
}

#[testlib::test(contracts_dir = "test-contracts", mode = "regtest")]
async fn test_get_wit_from_api_regtest() -> Result<()> {
    run_test(runtime).await
}
