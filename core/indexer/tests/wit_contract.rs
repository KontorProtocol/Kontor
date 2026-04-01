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
    acc: string,
    amt: decimal,
  }

  record transfer {
    src: string,
    dst: string,
    amt: decimal,
  }

  record burn {
    src: string,
    amt: decimal,
  }

  record mint {
    dst: string,
    amt: decimal,
  }

  export mint: async func(ctx: borrow<proc-context>, amt: decimal) -> result<mint, error>;
  export burn: async func(ctx: borrow<proc-context>, amt: decimal) -> result<burn, error>;
  export transfer: async func(ctx: borrow<proc-context>, dst: string, amt: decimal) -> result<transfer, error>;
  export balance: async func(ctx: borrow<view-context>, acc: string) -> option<decimal>;
  export balances: async func(ctx: borrow<view-context>) -> list<balance>;
  export total-supply: async func(ctx: borrow<view-context>) -> decimal;
  export attach: async func(ctx: borrow<proc-context>, vout: u64, amt: decimal) -> result<transfer, error>;
  export detach: async func(ctx: borrow<proc-context>) -> result<transfer, error>;
}
"#;

#[testlib::test(contracts_dir = "../../test-contracts", shared)]
async fn test_get_wit_from_api() -> Result<()> {
    let wit = runtime.wit(&token::address()).await?;
    assert_eq!(WIT, wit);
    Ok(())
}
