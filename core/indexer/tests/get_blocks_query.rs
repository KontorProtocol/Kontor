use anyhow::Result;
use indexer::{
    database::{
        queries::{get_blocks_paginated, insert_block, insert_processed_block},
        types::{BlockQuery, BlockRow},
    },
    test_utils::{new_mock_block_hash, new_test_db},
};

#[tokio::test]
async fn test_get_blocks_query() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(100)
            .hash(new_mock_block_hash(100))
            .build(),
    )
    .await?;

    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(101)
            .hash(new_mock_block_hash(101))
            .build(),
    )
    .await?;

    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(102)
            .hash(new_mock_block_hash(102))
            .build(),
    )
    .await?;

    insert_block(
        &conn,
        BlockRow::builder()
            .height(103)
            .hash(new_mock_block_hash(103))
            .build(),
    )
    .await?;

    let (blocks, meta) =
        get_blocks_paginated(&conn, BlockQuery::builder().limit(1).build()).await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 102);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(blocks[0].height));
    assert_eq!(meta.total_count, 3);

    let (blocks, meta) = get_blocks_paginated(
        &conn,
        BlockQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 101);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(blocks[0].height));

    let (blocks, meta) = get_blocks_paginated(
        &conn,
        BlockQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 100);
    assert!(!meta.has_more);
    assert!(meta.next_cursor.is_none());

    Ok(())
}
