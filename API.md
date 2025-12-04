# Kontor Indexer API

Base URL: `/api` (unless otherwise specified)

All endpoints return JSON.  
All paginated responses use the generic `PaginatedResponse<T>` shape.

## Root

### GET /
**Response**: `Info`

Returns indexer status, current height, version and availability.

### GET /stop
**Response**: `Info`

Gracefully shuts down the indexer (cancels the main task). Returns the same info as `/`.

## Blocks

### GET /blocks
**Query Parameters** (`BlockQuery`):
- `cursor?: number` – cursor-based pagination
- `offset?: number` – offset-based pagination (mutually exclusive with cursor)
- `limit?: number` (default: implementation-defined)
- `order?: "asc" | "desc"` (default: desc)
- `relevant?: boolean` – only blocks containing indexed transactions

**Response**: `PaginatedResponse<BlockRow>`

### GET /blocks/latest
**Response**: `BlockRow`

Latest indexed block.

### GET /blocks/:height_or_hash
**Path Param**: `height_or_hash` – block height (as number string) or block hash (hex)

**Response**: `BlockRow`  
**404** if not found

### GET /blocks/:height/transactions
**Path Param**: `height` – block height

**Response**: `PaginatedResponse<TransactionRow>`

## Transactions

### GET /transactions
**Query Parameters** (`TransactionQuery`):
- same pagination fields as `BlockQuery`
- `height?: number`
- `contract?: string` – filter by contract address

**Response**: `PaginatedResponse<TransactionRow>`

### GET /transactions/:txid
**Response**: `TransactionRow`  
**404** if not indexed

### GET /transactions/:txid/inspect
Parses the transaction and returns every detected op with its execution result (if any).

**Response**: `OpWithResult[]`

### POST /transactions/inspect
**Request Body**: `{ "hex": string }`

Inspects an arbitrary transaction hex (does **not** need to be indexed).

**Response**: `OpWithResult[]`

## Compose Helpers

### POST /transactions/compose
**Request Body**: `ComposeQuery`

**Response**: `ComposeOutputs`

Full compose (commit + reveal) in one call.

### POST /transactions/compose/commit
**Request Body**: `ComposeQuery`

**Response**: `CommitOutputs`

Only the commit phase (for 2-step reveals).

### POST /transactions/compose/reveal
**Request Body**: `RevealQuery`

**Response**: `RevealOutputs`

Only the reveal phase (when you already have a commit).

> Note: `instructions` length is limited to 400 KiB.

## Contracts

### GET /contracts
**Response**: `ContractListRow[]`

List all deployed contracts.

### GET /contracts/:address
**Path Param**: `address` – contract address (as string)

**Response**: `ContractResponse` → `{ wit: string }`  
**404** if contract not found  
**503** if indexer runtime is not available

### POST /contracts/:address
**Path Param**: `address` – contract address  
**Request Body**: `{ "expr": string }`

Execute a read-only view expression against the contract state.

**Response**: `ViewResult`
