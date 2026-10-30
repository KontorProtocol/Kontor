"""Closed data shapes for the regtest-only correctness smoke."""

from fractions import Fraction
import re

from workload_fixture import FixtureError, exact_fields, hex_string, unsigned


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def string(value, where):
    require(isinstance(value, str), f"{where}: expected string")


def text(value, where):
    string(value, where)
    require(bool(value), f"{where}: empty string")


def boolean(value, where):
    require(type(value) is bool, f"{where}: expected boolean")


def u64(value, where):
    return unsigned(value, 64, where)


def u32(value, where):
    return unsigned(value, 32, where)


def digest(value, where):
    return hex_string(value, 32, where)


def commit(value, where):
    return hex_string(value, 20, where)


def bytes_hex(value, where):
    string(value, where)
    require(re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None, f"{where}: invalid hex bytes")


def money(value, where):
    string(value, where)
    require(
        re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{0,17}[1-9])?", value) is not None,
        f"{where}: expected canonical nonnegative decimal, at most 18 places",
    )
    amount = Fraction(value)
    require(amount * 10**18 <= 2**256 - 1, f"{where}: Decimal magnitude overflow")
    return amount


def literal(expected):
    def validate(value, where):
        require(type(value) is type(expected) and value == expected, f"{where}: expected {expected!r}")
    return validate


def choice(*values):
    def validate(value, where):
        require(isinstance(value, str) and value in values, f"{where}: unsupported value")
    return validate


def nullable(check):
    def validate(value, where):
        if value is not None:
            check(value, where)
    return validate


def record(**fields):
    def validate(value, where):
        exact_fields(value, fields, where)
        for name, check in fields.items():
            check(value[name], f"{where}.{name}")
    return validate


def array(check, length=None):
    def validate(value, where):
        require(isinstance(value, list), f"{where}: expected array")
        if length is not None:
            require(len(value) == length, f"{where}: expected {length} elements")
        for index, item in enumerate(value):
            check(item, f"{where}[{index}]")
    return validate


FILE = record(path=text, sha256=digest)
SOURCE = record(
    kontor_commit=commit, rustc_verbose=text, target=text,
    profile=choice("dev", "release"), features=array(text), core_lockfile=FILE,
    wasmtime_revision=literal("0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7"),
    engine=literal("pulley"), pulley_stack_bytes=literal(524288),
    native_fiber_bytes=literal(2097152),
)
ARTIFACT = record(id=text, compressed=FILE, raw_sha256=digest, addresses=array(text))
SNAPSHOT = record(
    database=FILE, schema_sha256=digest, anchor_height=u64, anchor_hash=digest,
    checkpoint=text, prune_watermark=u64, reset_report=FILE,
)
OPERATION = record(
    txid=digest, tx_index=u32, input_index=u32, op_index=u32,
    contract=text, expression=text, gas_limit=literal(100000),
)
INPUT = record(
    raw_block=FILE, height=u64, block_hash=digest, previous_hash=digest,
    raw_txids=array(digest), kontor_txids=array(digest),
    kontor_input_count=literal(1), operation_count=literal(3),
    payer_x_only_pubkey=digest, operations=array(OPERATION, 3),
    bitcoin_validation=record(
        network=literal("regtest"), bitcoind_version=text,
        accepted_block_hash=digest, record=FILE,
    ),
)
EXECUTION_FIELDS = dict(
    executor=literal("RuntimeExecutor"), component_cache=literal("cold"),
    network=literal("regtest"), prune_enabled=literal(True), retain_blocks=literal(6),
    starting_block_height=u64,
    gas_to_fuel_multiplier=literal(1000), execution_price=literal("0.000000001"),
    storage_gas_per_byte=literal(1), lifecycle_parameters=FILE,
    independent_resets=literal(2), timing_claim=literal("none"),
)
EXECUTION = record(**EXECUTION_FIELDS)
EXECUTION_V2 = record(**EXECUTION_FIELDS, effective_retain_blocks=literal(7))
DECISION = record(
    consensus_height=u64, certificate_hex=literal(""), value_kind=literal("block"),
    block_height=u64, block_hash=digest, certified_txs=literal(None),
)
MANIFEST_FIELDS = dict(
    kind=literal("smoke"),
    case_id=literal("paid-success-failure-success-v1"),
    funding_seed_hex=lambda value, where: hex_string(value, 64, where),
    source=SOURCE, artifacts=array(ARTIFACT), snapshot=SNAPSHOT, input=INPUT,
    expected_report=FILE, numeric_check=FILE, decision=DECISION,
)
MANIFEST = record(**MANIFEST_FIELDS, schema_version=literal(1), execution=EXECUTION)
MANIFEST_V2 = record(**MANIFEST_FIELDS, schema_version=literal(2), execution=EXECUTION_V2)
STATUS = choice("Ok", "ContractErr", "OutOfFuel", "Trap", "Other")
RECEIPT = record(
    id=u64, height=u64, tx_index=nullable(u32), input_index=nullable(u32),
    op_index=nullable(u32), result_index=u32, func=text, gas=u64, status=STATUS,
    value=nullable(string), contract=text, txid=nullable(digest), signer_id=u64,
    payer_signer_id=nullable(u64),
)
USAGE = record(
    height=u64, tx_index=nullable(u32), txid=nullable(digest), user_fuel=u64,
    system_fuel=u64, deposit_fuel=u64, kind=choice("transaction", "block"),
)
ACCOUNT = record(balance=money, floor=money)
VIEW = record(address=text, storage_state=array(u64, 4))
VERSION = record(
    contract=text, path_hex=bytes_hex, height=u64, value_hex=bytes_hex,
    deleted=boolean, depositor=nullable(u64), deposited_gas=nullable(u64),
)
REPORT = record(
    schema_version=literal(1), height=u64, block_hash=digest, checkpoint=text,
    prune_watermark=u64, receipts=array(RECEIPT), usage=array(USAGE),
    accounts=record(
        payer=ACCOUNT, burner=ACCOUNT, core=ACCOUNT, ordering_pool=ACCOUNT,
        storage_pool=ACCOUNT, total_supply=ACCOUNT,
    ),
    contract_views=record(A=VIEW, B=VIEW), state_versions=array(VERSION),
    table_counts=array(record(table=text, rows=u64)),
)
NUMERIC_OPERATION = record(
    txid=digest, tx_index=u32, input_index=u32, op_index=u32, contract=text,
    expression=text, status=STATUS, value=nullable(string), gas=u64,
    user_fuel=u64, system_fuel=u64, deposit_fuel=u64, reserved_deposit_gas=u64,
    payer_before=money, payer_after=money, burner_before=money, burner_after=money,
    floor_before=money, floor_after=money, execution_fee=money,
    error_message=nullable(string), storage_state=array(u64, 4),
)
NUMERIC_CHECK = record(
    schema_version=literal(1), snapshot_sha256=digest, raw_block_sha256=digest,
    source_commit=commit, operations=array(NUMERIC_OPERATION, 3),
)


def sorted_unique(values, where):
    require(values == sorted(set(values)), f"{where}: expected sorted unique entries")


def effective_retention(manifest):
    execution = manifest["execution"]
    return (execution["effective_retain_blocks"] if manifest["schema_version"] == 2
            else execution["retain_blocks"])


def validate_manifest(manifest):
    check = MANIFEST_V2 if isinstance(manifest, dict) and manifest.get("schema_version") == 2 else MANIFEST
    check(manifest, "manifest")
    source, snapshot, block = manifest["source"], manifest["snapshot"], manifest["input"]
    sorted_unique(source["features"], "source.features")
    sorted_unique([item["id"] for item in manifest["artifacts"]], "artifacts")
    require({item["id"] for item in manifest["artifacts"]}
            == {"error_test", "filestorage", "nft", "staking", "system", "token"},
            "artifacts: incomplete native and smoke contract inventory")
    addresses = []
    for artifact in manifest["artifacts"]:
        sorted_unique(artifact["addresses"], f"artifact {artifact['id']} addresses")
        require(bool(artifact["addresses"]), "artifact without a contract address")
        addresses.extend(artifact["addresses"])
    require(len(addresses) == len(set(addresses)), "duplicate artifact contract address")
    require(block["height"] == snapshot["anchor_height"] + 1, "block does not follow snapshot")
    require(0 < manifest["execution"]["starting_block_height"] <= snapshot["anchor_height"], "invalid indexed history start")
    require(block["previous_hash"] == snapshot["anchor_hash"], "block parent differs from snapshot")
    require(block["bitcoin_validation"]["accepted_block_hash"] == block["block_hash"], "validated block differs")
    require(snapshot["prune_watermark"] < block["height"] - effective_retention(manifest), "no new pruning band")
    decision = manifest["decision"]
    require(decision["consensus_height"] > 0, "consensus height must be positive")
    require(decision["block_height"] == block["height"] and decision["block_hash"] == block["block_hash"], "decision block differs")
    raw_txids = block["raw_txids"]
    require(len(raw_txids) >= 3 and len(set(raw_txids)) == len(raw_txids), "raw block needs distinct coinbase, commit and reveal")
    first, middle, last = block["operations"]
    require(block["kontor_txids"] == [first["txid"]], "smoke requires one relevant reveal")
    require(first["contract"] == last["contract"] != middle["contract"], "expected contract order A/B/A")
    require(first["contract"] in addresses and middle["contract"] in addresses, "operation artifact missing")
    user_artifact = next(item for item in manifest["artifacts"] if item["id"] == "error_test")
    require(set(user_artifact["addresses"]) == {first["contract"], middle["contract"]}, "smoke instances do not share the error_test artifact")
    expressions = ["write-result-payload(1)", "scan-compound(false)", "write-result-payload(2)"]
    for index, operation in enumerate(block["operations"]):
        require(operation["expression"] == expressions[index] and operation["op_index"] == index, "operation order or expression differs")
        require(all(operation[key] == first[key] for key in ("txid", "tx_index", "input_index")), "operations must share one reveal input")
        position = operation["tx_index"]
        require(0 < position < len(raw_txids) and raw_txids[position] == operation["txid"], "original Bitcoin transaction index differs")
    return manifest


def validate_report(report):
    REPORT(report, "report")
    receipts = report["receipts"]
    sorted_unique([item["id"] for item in receipts], "receipt IDs")
    require(all(item["height"] == report["height"] for item in receipts), "receipt outside report height")
    sorted_unique([item["table"] for item in report["table_counts"]], "table counts")
    require(bool(report["table_counts"]), "missing persistent table inventory")
    require(report["accounts"]["total_supply"]["floor"] == "0", "total supply cannot have a floor")
    for account in report["accounts"].values():
        require(Fraction(account["balance"]) >= Fraction(account["floor"]), "account balance below collateral floor")
    usage = report["usage"]
    require(all(item["height"] == report["height"] for item in usage), "usage outside report height")
    transactions = [item for item in usage if item["kind"] == "transaction"]
    blocks = [item for item in usage if item["kind"] == "block"]
    require(usage == transactions + blocks and len(blocks) <= 1, "usage ordering or duplicate block usage")
    require(all(item["txid"] is not None and item["tx_index"] is not None for item in transactions), "transaction usage lacks identity")
    sorted_unique([item["tx_index"] for item in transactions], "transaction usage positions")
    require(len({item["txid"] for item in transactions}) == len(transactions), "duplicate transaction usage")
    for block in blocks:
        require(block["txid"] is None and block["tx_index"] is None and block["user_fuel"] == block["deposit_fuel"] == 0, "invalid maintenance usage")
    keys = []
    for version in report["state_versions"]:
        require((version["depositor"] is None) == (version["deposited_gas"] is None), "partial deposit identity")
        require(version["height"] <= report["height"], "future state version")
        keys.append((version["contract"], version["path_hex"], version["height"]))
    sorted_unique(keys, "state versions")
    return report
