# Kontor Indexer API

## HTTP

Base URL: `/api`

Request and response types are defined in Typescript [here](kontor-ts/src/bindings.d.ts).

All responses are wrapped in the `ResultResponse<T>` type. If a response is an error then the `ErrorResponse` type is returned.

### Root

#### GET `/`

Returns indexer status, current height, version and availability.

Response: `Info`


#### GET `/stop`

Gracefully shuts down the indexer (cancels the main task). Returns the same info as `/`.

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
