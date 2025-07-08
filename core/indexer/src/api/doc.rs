use utoipa::OpenApi;

use crate::{
    api::{compose, handlers, json_types},
    bitcoin_client, database,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::get_block,
        handlers::get_block_latest,
        handlers::get_transaction,
        handlers::get_transactions_root,
        handlers::get_transactions_for_block,
        handlers::test_mempool_accept,
        handlers::get_compose,
        handlers::get_compose_commit,
        handlers::get_compose_reveal,
    ),
    components(
        schemas(
            database::types::BlockRow,
            database::types::TransactionRow,
            database::types::TransactionListResponse,
            database::types::PaginationMeta,
            database::types::TransactionQuery,
            bitcoin_client::types::TestMempoolAcceptResult,
            bitcoin_client::types::TestMempoolAcceptResultFees,
            compose::ComposeQuery,
            compose::ComposeOutputs,
            compose::CommitOutputs,
            compose::RevealQuery,
            compose::RevealOutputs,
            compose::TapLeafScript,
            handlers::TxsQuery,
            json_types::JsonTransaction,
            json_types::JsonTxIn,
            json_types::JsonTxOut,
            json_types::JsonOutPoint,
        )
    ),
    tags(
        (name = "Kontor", description = "Kontor Indexer API")
    )
)]
pub struct ApiDoc;
