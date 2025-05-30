use std::env;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const SQLEAN_CRYPTO_EXTENSION: &[u8] =
    include_bytes!("../../sqlean-0.27.2/macos-arm64/crypto.dylib");

pub const CREATE_BLOCKS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY,
        hash TEXT NOT NULL
    )";

fn get_sqlean_ext_path(module: &str) -> String {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let platform = match (os, arch) {
        ("macos", "aarch64") => "macos-arm64",
        ("macos", "x86_64") => "macos-x86",
        ("linux", "x86_64") => "linux-x86",
        ("linux", "aarch64") => "linux-arm64",
        _ => panic!("Unsupported platform or architecture"),
    };

    let extension = if os == "macos" { "dylib" } else { "so" };

    format!("sqlean-0.27.2/{}/{}.{}", platform, module, extension)
}

pub async fn initialize_database(conn: &libsql::Connection) -> Result<(), libsql::Error> {
    conn.execute(CREATE_BLOCKS_TABLE, ()).await?;
    conn.query("PRAGMA journal_mode = WAL;", ()).await?;
    conn.query("PRAGMA synchronous = NORMAL;", ()).await?;
    conn.load_extension_enable()?;
    conn.load_extension(get_sqlean_ext_path("crypto"), None)?;
    Ok(())
}
