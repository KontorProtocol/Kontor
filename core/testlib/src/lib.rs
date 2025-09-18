use std::{env::current_dir, path::Path};

use bon::Builder;
// Re-export the actual types from indexer  
use indexer::runtime::wit::kontor::built_in::{
    error::Error as WitError,
    foreign::ContractAddress as WitContractAddress,
    numbers::{Decimal as WitDecimal, Integer as WitInteger, Sign},
};

// We can't implement traits on foreign types, so use the raw types directly
pub type Error = WitError;
pub type ContractAddress = WitContractAddress;
pub type Integer = WitInteger;
pub type Decimal = WitDecimal;

// Conversion traits for test code
// We can't implement From on foreign types, so we provide our own trait

/// Trait for converting values to Integer in tests
pub trait IntoInteger {
    fn into_integer(self) -> Integer;
}

impl IntoInteger for u64 {
    fn into_integer(self) -> Integer {
        int(self)
    }
}

impl IntoInteger for i64 {
    fn into_integer(self) -> Integer {
        int_from_i64(self)
    }
}

impl IntoInteger for i32 {
    fn into_integer(self) -> Integer {
        int_from_i64(self as i64)
    }
}

impl IntoInteger for &str {
    fn into_integer(self) -> Integer {
        int_from_str(self)
    }
}

impl IntoInteger for String {
    fn into_integer(self) -> Integer {
        int_from_str(&self)
    }
}

/// Trait for converting values to Decimal in tests
pub trait IntoDecimal {
    fn into_decimal(self) -> Decimal;
}

impl IntoDecimal for f64 {
    fn into_decimal(self) -> Decimal {
        decimal_from_f64(self)
    }
}

impl IntoDecimal for f32 {
    fn into_decimal(self) -> Decimal {
        decimal_from_f64(self as f64)
    }
}

impl IntoDecimal for &str {
    fn into_decimal(self) -> Decimal {
        decimal_from_str(self)
    }
}

impl IntoDecimal for Integer {
    fn into_decimal(self) -> Decimal {
        indexer::runtime::numerics::integer_to_decimal(self).expect("Integer to decimal")
    }
}

// Helper to create Integer from u64
pub fn int(n: u64) -> Integer {
    Integer {
        r0: n,
        r1: 0,
        r2: 0,
        r3: 0,
        sign: Sign::Plus,
    }
}

// Helper to format Integer for Wave string interface
pub fn int_str(n: u64) -> String {
    format!("{{r0: {}, r1: 0, r2: 0, r3: 0, sign: plus}}", n)
}

// Helper functions for creating Integers from different types
pub fn int_from_i64(n: i64) -> Integer {
    if n >= 0 {
        int(n as u64)
    } else {
        Integer {
            r0: (-n) as u64,
            r1: 0,
            r2: 0,
            r3: 0,
            sign: Sign::Minus,
        }
    }
}

pub fn int_from_str(s: &str) -> Integer {
    if let Ok(n) = s.parse::<i64>() {
        int_from_i64(n)
    } else {
        int(0)
    }
}

// Helper functions for Decimal
pub fn decimal_from_f64(f: f64) -> Decimal {
    let is_negative = f < 0.0;
    let abs_val = f.abs();
    let whole = abs_val as u64;
    
    Decimal {
        r0: whole,
        r1: 0,
        r2: 0,
        r3: 0,
        sign: if is_negative { Sign::Minus } else { Sign::Plus },
    }
}

pub fn decimal_from_int(i: Integer) -> Decimal {
    indexer::runtime::numerics::integer_to_decimal(i).expect("Integer to decimal conversion")
}

pub fn decimal_from_str(s: &str) -> Decimal {
    if let Ok(f) = s.parse::<f64>() {
        decimal_from_f64(f)
    } else {
        decimal_from_f64(0.0)
    }
}

// Arithmetic operations as functions (can't implement traits on foreign types)
pub fn int_add(a: Integer, b: Integer) -> Integer {
    indexer::runtime::numerics::add_integer(a, b).expect("Integer addition")
}

pub fn int_sub(a: Integer, b: Integer) -> Integer {
    indexer::runtime::numerics::sub_integer(a, b).expect("Integer subtraction")
}

pub fn int_mul(a: Integer, b: Integer) -> Integer {
    indexer::runtime::numerics::mul_integer(a, b).expect("Integer multiplication")
}

pub fn int_div(a: Integer, b: Integer) -> Integer {
    indexer::runtime::numerics::div_integer(a, b).expect("Integer division")
}

pub fn decimal_add(a: Decimal, b: Decimal) -> Decimal {
    indexer::runtime::numerics::add_decimal(a, b).expect("Decimal addition")
}

pub fn decimal_sub(a: Decimal, b: Decimal) -> Decimal {
    indexer::runtime::numerics::sub_decimal(a, b).expect("Decimal subtraction")
}

pub fn decimal_mul(a: Decimal, b: Decimal) -> Decimal {
    indexer::runtime::numerics::mul_decimal(a, b).expect("Decimal multiplication")
}

pub fn decimal_div(a: Decimal, b: Decimal) -> Decimal {
    indexer::runtime::numerics::div_decimal(a, b).expect("Decimal division")
}

// Helper functions for comparison
pub fn int_eq(a: &Integer, b: &Integer) -> bool {
    a.r0 == b.r0 && 
    a.r1 == b.r1 && 
    a.r2 == b.r2 && 
    a.r3 == b.r3 && 
    a.sign == b.sign
}

pub fn decimal_eq(a: &Decimal, b: &Decimal) -> bool {
    a.r0 == b.r0 && 
    a.r1 == b.r1 && 
    a.r2 == b.r2 && 
    a.r3 == b.r3 && 
    a.sign == b.sign
}

use indexer::{
    config::Config,
    database::{queries::insert_block, types::BlockRow},
    runtime::{
        ComponentCache, Runtime as IndexerRuntime, Storage, load_contracts, load_native_contracts,
    },
    test_utils::{new_mock_block_hash, new_test_db},
};
use libsql::Connection;
pub use macros::{import_test as import, interface_test as interface};

use anyhow::anyhow;
pub use anyhow::{Error as AnyhowError, Result};
use tokio::{fs::File, io::AsyncReadExt, task};

async fn find_first_file_with_extension(dir: &Path, extension: &str) -> Option<String> {
    let pattern = format!("{}/*.{}", dir.display(), extension.trim_start_matches('.'));

    task::spawn_blocking(move || {
        glob::glob(&pattern)
            .expect("Invalid glob pattern")
            .filter_map(Result::ok)
            .find(|path| path.is_file())
            .and_then(|path| path.file_name().map(|s| s.to_string_lossy().into_owned()))
    })
    .await
    .unwrap_or_default()
}

async fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;
    Ok(buffer)
}

async fn read_wasm_file(cd: &Path) -> Result<Vec<u8>> {
    let release_dir = cd.join("target/wasm32-unknown-unknown/release");
    let ext = ".wasm.br";
    let file_name = find_first_file_with_extension(&release_dir, ext)
        .await
        .ok_or(anyhow!(
            "Could not find file with extension: {}@{:?}",
            ext,
            release_dir
        ))?;
    read_file(&release_dir.join(file_name)).await
}

pub async fn contract_bytes() -> Result<Vec<u8>> {
    let mut cd = current_dir()?;
    cd.pop();
    read_wasm_file(&cd).await
}

pub async fn dep_contract_bytes(dir_name: &str) -> Result<Vec<u8>> {
    let mut cd = current_dir()?;
    cd.pop();
    cd.pop();
    read_wasm_file(&cd.join(dir_name)).await
}

#[derive(Clone)]
pub struct CallContext {
    height: i64,
    tx_id: i64,
}

#[derive(Default, Builder)]
pub struct RuntimeConfig<'a> {
    call_context: Option<CallContext>,
    contracts: Option<&'a [(&'a str, &'a [u8])]>,
}

impl RuntimeConfig<'_> {
    pub fn get_call_context(&self) -> CallContext {
        self.call_context.clone().unwrap_or(CallContext {
            height: 1,
            tx_id: 1,
        })
    }
}

pub struct Runtime {
    pub runtime: IndexerRuntime,
}

impl Runtime {
    async fn make_storage(call_context: CallContext, conn: Connection) -> Result<Storage> {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(call_context.height)
                .hash(new_mock_block_hash(call_context.height as u32))
                .build(),
        )
        .await?;
        Ok(Storage::builder()
            .height(call_context.height)
            .tx_id(call_context.tx_id)
            .conn(conn)
            .build())
    }

    pub async fn new(config: RuntimeConfig<'_>) -> Result<Self> {
        let na = "n/a".to_string();
        let (_, writer, _test_db_dir) = new_test_db(&Config {
            bitcoin_rpc_url: na.clone(),
            bitcoin_rpc_user: na.clone(),
            bitcoin_rpc_password: na.clone(),
            zmq_address: na,
            api_port: 0,
            data_dir: "will be set".into(),
            starting_block_height: 1,
        })
        .await?;
        let conn = writer.connection();
        let storage = Runtime::make_storage(config.get_call_context(), conn).await?;
        let component_cache: ComponentCache = ComponentCache::new();
        let runtime = IndexerRuntime::new(storage, component_cache).await?;
        if let Some(contracts) = config.contracts {
            load_contracts(&runtime, contracts).await?;
        } else {
            load_native_contracts(&runtime).await?;
        }
        Ok(Self { runtime })
    }

    pub async fn set_call_context(&mut self, context: CallContext) -> Result<()> {
        self.runtime
            .set_storage(Runtime::make_storage(context, self.runtime.get_storage_conn()).await?);
        Ok(())
    }

    pub async fn execute(
        &self,
        signer: Option<&str>,
        addr: &ContractAddress,
        expr: &str,
    ) -> Result<String, AnyhowError> {
        self.runtime
            .execute(signer.map(|s| s.to_string()), addr, expr.to_string())
            .await
    }

    pub async fn execute_owned(
        &self,
        signer: Option<&str>,
        addr: ContractAddress,
        expr: String,
    ) -> Result<String, AnyhowError> {
        self.runtime
            .execute(signer.map(|s| s.to_string()), &addr, expr)
            .await
    }
}

/// Load additional token instances for AMM tests that need multiple token contracts
pub async fn load_amm_test_tokens(runtime: &Runtime) -> Result<()> {
    use indexer::{
        database::{
            queries::{contract_has_state, insert_contract},
            types::ContractRow,
        },
        runtime::ContractAddress,
    };

    const TOKEN: &[u8] =
        include_bytes!("../../../contracts/target/wasm32-unknown-unknown/release/token.wasm.br");

    let conn = runtime.runtime.get_storage_conn();
    let height = 0;

    // Create token instances at tx_index 1 and 2 for AMM tests
    for tx_index in [1, 2] {
        let contract_id = insert_contract(
            &conn,
            ContractRow::builder()
                .height(height)
                .tx_index(tx_index)
                .name("token".to_string())
                .bytes(TOKEN.to_vec())
                .build(),
        )
        .await?;

        if !contract_has_state(&conn, contract_id).await? {
            runtime
                .runtime
                .execute(
                    Some("kontor".to_string()),
                    &ContractAddress {
                        name: "token".to_string(),
                        height,
                        tx_index,
                    },
                    "init()".to_string(),
                )
                .await?;
        }
    }

    Ok(())
}
