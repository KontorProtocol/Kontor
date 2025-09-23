use anyhow::Result;

#[tokio::test]
async fn test_spawn_traps_panic() -> Result<()> {
    let r = tokio::spawn(async {
        panic!("test");
    })
    .await;
    assert!(r.is_err());
    Ok(())
}
