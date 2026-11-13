# Kontor Indexer API

## HTTP

Base URL: `/api`

Request and response types are defined in Typescript [here](sdk/src/bindings.d.ts).

All responses are wrapped in the `ResultResponse<T>` type. If a response is an error then the `ErrorResponse` type is returned.

### Root

#### GET `/`

Returns indexer status, current height, version and availability.

Response: `Info`


### Blocks

#### GET `/blocks`

Query Parameters (`BlockQuery`):
- `cursor?: number` – cursor-based pagination
- `offset?: number` – offset-based pagination (mutually exclusive with cursor)
- `limit?: number` (default: implementation-defined)
- `order?: "asc" | "desc"` (default: desc)
- `relevant?: boolean` – only blocks containing indexed transactions

Response: `PaginatedResponse<BlockRow>`


#### GET `/blocks/latest`

Latest indexed block.

Response: `BlockRow`


#### GET `/blocks/:height_or_hash`

Path Param: `height_or_hash` – block height (as number string) or block hash (hex)

Response: `BlockRow`  

`404` if not found


#### GET `/blocks/:height/transactions`

Path Param: `height` – block height

Response: `PaginatedResponse<TransactionRow>`


### Transactions

#### GET `/transactions`

Query Parameters (`TransactionQuery`):
- same pagination fields as `BlockQuery`
- `height?: number`
- `contract?: string` – filter by contract address

Response: `PaginatedResponse<TransactionRow>`


#### GET `/transactions/:txid`

Response: `TransactionRow`  

`404` if not indexed


#### GET `/transactions/:txid/inspect`

Parses the transaction and returns every detected op with its execution result (if any).

Response: `OpWithResult[]`


#### POST `/transactions/inspect`

Inspects an arbitrary transaction hex (does *not* need to be indexed).

Request Body: `TransactionHex`

Response: `OpWithResult[]`


#### POST `/transactions/simulate`

Simulates the execution of a transaction's operations. Useful for testing transaction before broadcasting.

Request Body: `TransactionHex`

Response: `OpWithResult[]`


### Compose Helpers

#### POST `/transactions/compose`

Full compose (commit + reveal) in one call.

Request Body: `ComposeQuery`

Response: `ComposeOutputs`


#### POST `/transactions/compose/commit`

Only the commit phase (for 2-step reveals).

Request Body: `ComposeQuery`

Response: `CommitOutputs`


#### POST `/transactions/compose/reveal`

Only the reveal phase (when you already have a commit).

Request Body: `RevealQuery`

Response: `RevealOutputs`


### Contracts

#### GET `/contracts`

List all deployed contracts.

Response: `ContractListRow[]`


#### GET `/contracts/:address`

Path Param: `address` – contract address (as string)

Response: `ContractResponse`

`404` if contract not found  

`503` if indexer runtime is not available


#### POST `/contracts/:address`

Execute a read-only view expression against the contract state.

Path Param: `address` – contract address  

Request Body: `ViewExpr`

Response: `ViewResult`

`503` if indexer runtime is not available


### Results (Contract Execution Results)

#### GET `/results`

Query Parameters (`ResultQuery`):
- same pagination fields as others
- `height?`: number
- `start_height?`: number (mutually exclusive with height)
- `contract?`: string
- `func?`: string (requires contract)

Response: `PaginatedResponse<ResultRow>`


#### GET `/results/:id`

Path Param: `id` – txid_inputIndex_opIndex (e.g. a94a8f..._0_0)

Response: `ResultRow | null`


## WebSocket

Base URL: `/ws`

Upon connection, the client will be subscribed to indexer events (see `WsResponse`).

Request: `WsRequest`

Response: `WsResponse`

## Relay and reconciliation

`POST /api/transactions/broadcast` and `POST /api/transactions/reconcile` accept
`{"transactions": ["<signed transaction hex>", "<signed child hex>"]}` in dependency
order. The broadcast route observes the exact bytes first, skips already observed
transactions, relays the remainder, then observes the full package again. The
reconcile route only observes and never publishes. All transaction hex is parsed
before any relay occurs. Malformed input returns HTTP 400.

Both return the usual `result` envelope containing:

```json
{
  "result": {
    "outcome": "partial",
    "transactions": [
      { "txid": "...", "wtxid": "...", "status": "accepted", "reason": null },
      { "txid": "...", "wtxid": "...", "status": "unknown", "reason": "not_observed: ..." }
    ]
  }
}
```

Entries retain request order and bind both transaction and witness identity.
Outcome is `accepted` when all exact transactions are observed, `partial` when
some are, or `unknown` when none are. Partial/unknown outcomes are successful HTTP
reports, not a claim that publication failed. A differing witness is reported as
`unknown` with a `conflicting_witness` reason. A lost HTTP response is also uncertain.
Callers must not free funding merely because a transaction is unobserved or a relay
was rejected. These observations are not confirmation, Kontor execution receipts,
or finality. Exact retry is safe to request, but may still be rejected by Bitcoin.

Fresh lookup bypasses the node's transaction cache. Confirmed transaction lookup
requires Bitcoin Core's `txindex=1`; an unavailable lookup stays unknown. This
prelaunch change replaces the old broadcast `{ txid }` response. The SDK retains
signed submission recovery and funding ownership across uncertain outcomes.
