use std::hint::black_box;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use libsql::Connection;
use serde_json::json;

use super::{get_results_paginated, get_transactions_paginated, rollback_to_height};
use crate::database::connection::new_connection;
use crate::database::types::{ResultQuery, TransactionQuery};
use crate::runtime::ContractAddress;
use crate::test_utils::new_test_db;

struct IndexCase {
    name: &'static str,
    probe: &'static str,
}

const CASES: &[IndexCase] = &[
    IndexCase {
        name: "idx_transactions_height",
        probe: "SELECT id FROM transactions WHERE height = 1000 ORDER BY id DESC LIMIT 21",
    },
    IndexCase {
        name: "idx_contract_results_height",
        probe: "SELECT id FROM contract_results WHERE height = 1000 ORDER BY id DESC LIMIT 21",
    },
    IndexCase {
        name: "idx_contracts_height",
        probe: "SELECT rowid FROM contracts WHERE height = 991",
    },
    IndexCase {
        name: "idx_contract_provenance_height",
        probe: "SELECT rowid FROM contract_provenance WHERE height = 991",
    },
    IndexCase {
        name: "idx_signers_height",
        probe: "SELECT rowid FROM signers WHERE height = {recent_height}",
    },
    IndexCase {
        name: "idx_x_only_pubkeys_height",
        probe: "SELECT rowid FROM x_only_pubkeys WHERE height = {recent_height}",
    },
    IndexCase {
        name: "idx_bls_keys_height",
        probe: "SELECT rowid FROM bls_keys WHERE height = {recent_height}",
    },
    IndexCase {
        name: "idx_nonces_height",
        probe: "SELECT rowid FROM nonces WHERE height = 1000",
    },
    IndexCase {
        name: "idx_bls_keys_pubkey",
        probe: "SELECT signer_id FROM bls_keys WHERE bls_pubkey = CAST(printf('%096x', 42) AS BLOB) ORDER BY height DESC LIMIT 1",
    },
    IndexCase {
        name: "idx_contract_results_contract",
        probe: "SELECT id FROM contract_results WHERE contract_id = 42 ORDER BY id DESC LIMIT 21",
    },
    IndexCase {
        name: "idx_contract_results_signer",
        probe: "SELECT id FROM contract_results WHERE signer_id = 42 ORDER BY id DESC LIMIT 21",
    },
    IndexCase {
        name: "idx_contracts_signer",
        probe: "SELECT id FROM contracts WHERE signer_id = 42 ORDER BY id DESC LIMIT 21",
    },
    IndexCase {
        name: "idx_contract_state_tx",
        probe: "SELECT rowid FROM contract_state WHERE tx_id = 42",
    },
    IndexCase {
        name: "idx_contract_results_payer",
        probe: "SELECT rowid FROM contract_results WHERE payer_signer_id = {recent_height}",
    },
];

async fn used_bytes(conn: &Connection) -> Result<i64> {
    let mut values = Vec::new();
    for pragma in ["page_count", "freelist_count", "page_size"] {
        let row = conn
            .query(&format!("PRAGMA {pragma}"), ())
            .await?
            .next()
            .await?
            .unwrap();
        values.push(row.get::<i64>(0)?);
    }
    Ok((values[0] - values[1]) * values[2])
}

async fn plan(conn: &Connection, sql: &str) -> Result<Vec<String>> {
    let mut rows = conn.query(&format!("EXPLAIN QUERY PLAN {sql}"), ()).await?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        result.push(row.get(3)?);
    }
    Ok(result)
}

async fn query_once(conn: &Connection, sql: &str) -> Result<usize> {
    let mut rows = conn.query(sql, ()).await?;
    let mut count = 0;
    while let Some(row) = rows.next().await? {
        black_box(row.get::<i64>(0)?);
        count += 1;
    }
    Ok(count)
}

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

async fn query_us(conn: &Connection, sql: &str) -> Result<(f64, usize)> {
    let expected = query_once(conn, sql).await?;
    let mut samples = Vec::new();
    for trial in 0..12 {
        let start = Instant::now();
        for _ in 0..16 {
            ensure!(query_once(conn, sql).await? == expected);
        }
        if trial >= 3 {
            samples.push(start.elapsed().as_secs_f64() * 1e6 / 16.0);
        }
    }
    Ok((median(samples), expected))
}

async fn exact_count(conn: &Connection, sql: &str) -> Result<i64> {
    conn.query(sql, ())
        .await?
        .next()
        .await?
        .context("count row")?
        .get(0)
        .map_err(Into::into)
}

#[tokio::test]
#[ignore = "count measurements, run explicitly in release mode with --nocapture"]
async fn benchmark_pagination_counts() -> Result<()> {
    let count: u64 = std::env::var("KONTOR_BENCH_ROWS")
        .unwrap_or_else(|_| "100000".into())
        .parse()?;
    ensure!(count >= 100000 && count.is_multiple_of(100));
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    populate(&conn, count).await?;

    let midpoint = count / 2;
    for (case, from, id, predicate) in [
        ("transactions_all", "transactions t", "t.id", String::new()),
        (
            "transactions_cursor",
            "transactions t",
            "t.id",
            format!("WHERE t.id < {midpoint}"),
        ),
        (
            "transactions_height",
            "transactions t",
            "t.id",
            "WHERE t.height = 1000".into(),
        ),
        ("blocks_all", "blocks b", "b.height", String::new()),
        ("contracts_all", "contracts c", "c.id", String::new()),
        (
            "contracts_signer",
            "contracts c",
            "c.id",
            "WHERE c.signer_id = 42".into(),
        ),
    ] {
        let old = format!("SELECT COUNT(DISTINCT {id}) FROM {from} {predicate}");
        let new = format!("SELECT COUNT(*) FROM {from} {predicate}");
        let matches = exact_count(&conn, &old).await?;
        ensure!(exact_count(&conn, &new).await? == matches);
        for (variant, sql) in [("distinct", old), ("rows", new)] {
            let (us, _) = query_us(&conn, &sql).await?;
            println!(
                "COUNT_BENCH {}",
                json!({"rows":count,"case":case,"variant":variant,"matches":matches,"us":us,"sql":sql,"plan":plan(&conn,&sql).await?})
            );
        }
    }

    let joined = "contract_results r LEFT JOIN transactions t ON r.tx_id = t.id JOIN contracts c ON r.contract_id = c.id";
    let count_from = "contract_results r JOIN contracts c ON r.contract_id = c.id";
    for (case, predicate) in [
        ("results_all", String::new()),
        ("results_cursor", format!("WHERE r.id < {midpoint}")),
        ("results_contract", "WHERE r.contract_id = 42".into()),
        ("results_signer", "WHERE r.signer_id = 42".into()),
        ("results_height", "WHERE r.height = 1000".into()),
        ("results_func", "WHERE r.func = 'bench'".into()),
        (
            "results_combined",
            "WHERE r.contract_id = 42 AND r.height >= 411 AND r.func = 'bench' AND r.id > 4125"
                .into(),
        ),
    ] {
        let variants = [
            (
                "distinct_joined",
                format!("SELECT COUNT(DISTINCT r.id) FROM {joined} {predicate}"),
            ),
            (
                "rows_joined",
                format!("SELECT COUNT(*) FROM {joined} {predicate}"),
            ),
            (
                "rows_required_join",
                format!("SELECT COUNT(*) FROM {count_from} {predicate}"),
            ),
        ];
        let matches = exact_count(&conn, &variants[0].1).await?;
        for (variant, sql) in variants {
            ensure!(exact_count(&conn, &sql).await? == matches);
            let (us, _) = query_us(&conn, &sql).await?;
            println!(
                "COUNT_BENCH {}",
                json!({"rows":count,"case":case,"variant":variant,"matches":matches,"us":us,"sql":sql,"plan":plan(&conn,&sql).await?})
            );
        }
    }
    Ok(())
}

const API_CASES: &[&str] = &[
    "transactions_page",
    "transactions_counted",
    "transactions_contract",
    "transactions_signer",
    "results_contract",
    "results_signer",
];

async fn api_once(conn: &Connection, case: &str) -> Result<usize> {
    let contract = ContractAddress {
        name: "bench42".into(),
        height: 411,
        tx_index: 0,
    };
    if case.starts_with("results_") {
        let mut query = ResultQuery::builder().limit(20).build();
        match case {
            "results_contract" => query.contract = Some(contract),
            "results_signer" => query.signer_id = Some(42),
            _ => unreachable!(),
        }
        let (rows, meta) = get_results_paginated(conn, query).await?;
        black_box(meta);
        Ok(black_box(rows).len())
    } else {
        let mut query = TransactionQuery::builder().limit(20).build();
        match case {
            "transactions_page" => {}
            "transactions_counted" => query.count = true,
            "transactions_contract" => query.contract = Some(contract),
            "transactions_signer" => query.signer_id = Some(42),
            _ => unreachable!(),
        }
        let (rows, meta) = get_transactions_paginated(conn, query).await?;
        black_box(meta);
        Ok(black_box(rows).len())
    }
}

async fn api_us(conn: &Connection, case: &str) -> Result<f64> {
    let expected = api_once(conn, case).await?;
    let mut samples = Vec::new();
    for trial in 0..12 {
        let start = Instant::now();
        for _ in 0..8 {
            ensure!(api_once(conn, case).await? == expected);
        }
        if trial >= 3 {
            samples.push(start.elapsed().as_secs_f64() * 1e6 / 8.0);
        }
    }
    Ok(median(samples))
}

async fn rollback_us(conn: &Connection, blocks: u64) -> Result<f64> {
    let mut samples = Vec::new();
    for trial in 0..7 {
        conn.execute("SAVEPOINT measure", ()).await?;
        let start = Instant::now();
        ensure!(rollback_to_height(conn, blocks - 6).await? == 6);
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        conn.execute_batch("ROLLBACK TO measure; RELEASE measure;")
            .await?;
        if trial >= 2 {
            samples.push(elapsed);
        }
    }
    Ok(median(samples))
}

async fn populate(conn: &Connection, count: u64) -> Result<()> {
    let blocks = count / 10;
    conn.execute_batch(&format!(r#"
        BEGIN;
        CREATE TEMP TABLE bench_seq (n INTEGER PRIMARY KEY);
        INSERT INTO bench_seq WITH RECURSIVE seq(n) AS (
            VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n < {count}
        ) SELECT n FROM seq;
        INSERT INTO blocks SELECT n, printf('%064x', n), 1 FROM bench_seq WHERE n <= {blocks};
        INSERT INTO signers SELECT n, CASE WHEN n <= {blocks}/2 THEN 1 ELSE n END
            FROM bench_seq WHERE n <= {blocks};
        INSERT INTO x_only_pubkeys SELECT id, printf('%064x', id), height FROM signers;
        INSERT INTO bls_keys SELECT id, CAST(printf('%096x', id) AS BLOB), height FROM signers;
        INSERT INTO contracts (id,name,height,tx_index,size,bytes,signer_id)
            SELECT n, printf('bench%d',n), 1+(n-1)*10, 0, 0, X'', n+1
            FROM bench_seq WHERE n <= {count}/100;
        INSERT INTO contract_provenance (contract_id,author_signer_id,height,tx_index,provenance)
            SELECT id, signer_id, height, 0, X'' FROM contracts;
        INSERT INTO transactions (id,txid,height,confirmed_height,tx_index)
            SELECT n, printf('%064x', n), 1+(n-1)/10, 1+(n-1)/10, (n-1)%10 FROM bench_seq;
        INSERT INTO contract_results (contract_id,func,height,tx_id,input_index,op_index,result_index,gas,size,value,signer_id,payer_signer_id)
            SELECT 1+(n-1)/100, 'bench', 1+(n-1)/10, n, 0, 0, 0, 10, 2, '[]',
                CASE WHEN 1+(n-1)/10 > {blocks}/2 THEN 1+(n-1)/10 ELSE 1+(n-1)%({blocks}/2) END, 1
            FROM bench_seq;
        INSERT INTO nonces SELECT DISTINCT signer_id, height, height FROM contract_results;
        INSERT INTO contract_state (contract_id,height,tx_id,size,path,value,depositor,deposited_gas)
            SELECT contract_id, height, tx_id, 64, CAST(printf('key%d',tx_id) AS BLOB), zeroblob(64), signer_id, 80
            FROM contract_results;
        COMMIT;
    "#)).await?;
    ensure!(
        conn.query("PRAGMA foreign_key_check", ())
            .await?
            .next()
            .await?
            .is_none()
    );
    Ok(())
}

async fn writes_us(conn: &Connection, count: u64) -> Result<f64> {
    let height = count / 10 + 1;
    let sql = format!(
        r#"
        INSERT INTO blocks VALUES ({height}, printf('%064x', {height}), 1);
        INSERT INTO signers VALUES ({height}, {height});
        INSERT INTO x_only_pubkeys VALUES ({height}, printf('%064x', {height}), {height});
        INSERT INTO bls_keys VALUES ({height}, CAST(printf('%096x', {height}) AS BLOB), {height});
        INSERT INTO nonces VALUES ({height}, 50, {height});
        INSERT INTO contracts (id,name,height,tx_index,size,bytes,signer_id)
            VALUES ({count}, 'new', {height}, 0, 0, X'', {height});
        INSERT INTO contract_provenance (contract_id,author_signer_id,height,tx_index,provenance)
            VALUES ({count}, {height}, {height}, 0, X'');
        INSERT INTO transactions (id,txid,height,confirmed_height,tx_index)
            SELECT {count}+n, printf('%064x', {count}+n), {height}, {height}, n-1 FROM bench_seq WHERE n <= 50;
        INSERT INTO contract_results (contract_id,func,height,tx_id,input_index,op_index,result_index,gas,size,value,signer_id,payer_signer_id)
            SELECT 1, 'bench', {height}, {count}+n, 0, 0, 0, 10, 2, '[]', {height}, 1 FROM bench_seq WHERE n <= 50;
        INSERT INTO contract_state (contract_id,height,tx_id,size,path,value,depositor,deposited_gas)
            SELECT 1, {height}, {count}+n, 64, CAST(printf('new%d',n) AS BLOB), zeroblob(64), {height}, 80
            FROM bench_seq WHERE n <= 50;
    "#
    );
    let mut samples = Vec::new();
    for trial in 0..12 {
        conn.execute("SAVEPOINT measure", ()).await?;
        let start = Instant::now();
        conn.execute_batch(&sql).await?;
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        conn.execute_batch("ROLLBACK TO measure; RELEASE measure;")
            .await?;
        if trial >= 3 {
            samples.push(elapsed);
        }
    }
    Ok(median(samples))
}

#[tokio::test]
#[ignore = "query/index measurements, run explicitly in release mode with --nocapture"]
async fn benchmark_query_indexes() -> Result<()> {
    let count: u64 = std::env::var("KONTOR_BENCH_ROWS")
        .unwrap_or_else(|_| "100000".into())
        .parse()?;
    ensure!(count >= 100000 && count.is_multiple_of(100));
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    // Use the production definitions, then remove them to reconstruct the baseline.
    let mut definitions = Vec::new();
    for case in CASES {
        let row = conn
            .query(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
                [case.name],
            )
            .await?
            .next()
            .await?
            .context("benchmark index missing from schema")?;
        definitions.push(row.get::<String>(0)?);
        drop(row);
        conn.execute(&format!("DROP INDEX {}", case.name), ())
            .await?;
    }
    populate(&conn, count).await?;
    let base_bytes = used_bytes(&conn).await?;
    let base_rollback = rollback_us(&conn, count / 10).await?;
    let base_writes = writes_us(&conn, count).await?;
    let mut base_api = Vec::new();
    for case in API_CASES {
        base_api.push(api_us(&conn, case).await?);
    }
    for (case, definition) in CASES.iter().zip(&definitions) {
        let probe = case
            .probe
            .replace("{recent_height}", &(count / 10 - 1).to_string());
        let before_plan = plan(&conn, &probe).await?;
        let (before, rows) = query_us(&conn, &probe).await?;
        let size = used_bytes(&conn).await?;
        conn.execute(definition, ()).await?;
        let bytes = used_bytes(&conn).await? - size;
        let after_plan = plan(&conn, &probe).await?;
        let (after, after_rows) = query_us(&conn, &probe).await?;
        ensure!(rows == after_rows);
        println!(
            "INDEX_BENCH {}",
            json!({"rows":count,"index":case.name,"query":probe,"before_us":before,"after_us":after,"bytes":bytes,"matches":rows,"before_plan":before_plan,"after_plan":after_plan})
        );
        conn.execute(&format!("DROP INDEX {}", case.name), ())
            .await?;
    }
    for definition in &definitions {
        conn.execute(definition, ()).await?;
    }
    let indexed_rollback = rollback_us(&conn, count / 10).await?;
    let indexed_writes = writes_us(&conn, count).await?;
    for (case, before) in API_CASES.iter().zip(base_api) {
        let after = api_us(&conn, case).await?;
        println!(
            "API_BENCH {}",
            json!({"rows":count,"query":case,"before_us":before,"after_us":after})
        );
    }
    println!(
        "ROLLBACK_PLAN {}",
        json!(plan(&conn, "DELETE FROM blocks WHERE height > 100").await?)
    );
    println!(
        "INDEX_BENCH {}",
        json!({"rows":count,"group":"all","baseline_bytes":base_bytes,"indexed_bytes":used_bytes(&conn).await?,"rollback_before_us":base_rollback,"rollback_after_us":indexed_rollback,"writes_before_us":base_writes,"writes_after_us":indexed_writes})
    );
    Ok(())
}

#[tokio::test]
async fn existing_database_gains_indexes_without_changing_rollback() -> Result<()> {
    let (_reader, writer, (temp, name)) = new_test_db().await?;
    let conn = writer.connection();
    populate(&conn, 2000).await?;
    let checkpoint: String = conn
        .query("SELECT hash FROM checkpoints WHERE height = 194", ())
        .await?
        .next()
        .await?
        .context("checkpoint")?
        .get(0)?;
    for case in CASES {
        conn.execute(&format!("DROP INDEX {}", case.name), ())
            .await?;
    }
    let reopened = new_connection(temp.path(), &name).await?;
    for case in CASES {
        let probe = case.probe.replace("{recent_height}", "199");
        let steps = plan(&reopened, &probe).await?;
        ensure!(
            steps.iter().any(|step| step.contains(case.name)),
            "{}: {steps:?}",
            case.name
        );
    }
    let before: i64 = reopened
        .query("SELECT COUNT(*) FROM transactions", ())
        .await?
        .next()
        .await?
        .context("count")?
        .get(0)?;
    ensure!(before == 2000);
    ensure!(rollback_to_height(&reopened, 194).await? == 6);
    for table in ["transactions", "contract_results", "contract_state"] {
        let count: i64 = reopened
            .query(&format!("SELECT COUNT(*) FROM {table}"), ())
            .await?
            .next()
            .await?
            .context("count")?
            .get(0)?;
        ensure!(count == 1940, "{table}: {count}");
    }
    let after: String = reopened
        .query(
            "SELECT hash FROM checkpoints ORDER BY height DESC LIMIT 1",
            (),
        )
        .await?
        .next()
        .await?
        .context("checkpoint")?
        .get(0)?;
    ensure!(after == checkpoint);
    ensure!(
        reopened
            .query("PRAGMA foreign_key_check", ())
            .await?
            .next()
            .await?
            .is_none()
    );
    Ok(())
}
