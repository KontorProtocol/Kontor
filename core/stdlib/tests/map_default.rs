use stdlib::Map;

#[test]
fn map_empty_and_default_are_empty() {
    let m1: Map<String, u64> = Map::empty();
    assert!(m1.entries.is_empty());

    let m2: Map<String, u64> = Default::default();
    assert!(m2.entries.is_empty());
}


