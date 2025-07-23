use stdlib::DotPathBuf;

#[test]
fn test_from_str() {
    let path: DotPathBuf = "a.b.c".parse().unwrap();
    assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);
    assert_eq!(path.to_string(), "a.b.c");

    let path: DotPathBuf = "a..b".parse().unwrap();
    assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b"]);
    assert_eq!(path.to_string(), "a.b");

    let path: DotPathBuf = "a.b.c.".parse().unwrap();
    assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);
    assert_eq!(path.to_string(), "a.b.c");

    let path: DotPathBuf = ".a.b.c.".parse().unwrap();
    assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);
    assert_eq!(path.to_string(), "a.b.c");

    let path: DotPathBuf = "".parse().unwrap();
    assert_eq!(path.segments().collect::<Vec<_>>(), vec![] as Vec<&str>);
    assert_eq!(path.to_string(), "");
}

#[test]
fn test_push_pop() {
    let path = DotPathBuf::new();
    let path = path.push("a").push("b").push("c");
    assert_eq!(path.to_string(), "a.b.c");
    assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);

    let path = path.push(""); // Empty segment ignored
    assert_eq!(path.to_string(), "a.b.c");

    let (path, popped) = path.pop();
    assert_eq!(popped, Some("c".to_string()));
    assert_eq!(path.to_string(), "a.b");

    let (path, popped) = path.pop();
    assert_eq!(popped, Some("b".to_string()));

    let (path, popped) = path.pop();
    assert_eq!(popped, Some("a".to_string()));

    let (path, popped) = path.pop();
    assert_eq!(popped, None);
    assert_eq!(path.to_string(), "");
}

#[test]
fn test_conversions() {
    let path_buf: DotPathBuf = "x.y.z".parse().unwrap();
    let s: String = path_buf.into();
    assert_eq!(s, "x.y.z");
}

#[test]
fn test_equality() {
    let path1: DotPathBuf = "a.b.c".parse().unwrap();
    let path2: DotPathBuf = "a.b.c".parse().unwrap();
    assert_eq!(path1, path2);

    let path3: DotPathBuf = "x.y.z".parse().unwrap();
    assert_ne!(path1, path3);
}

#[test]
fn test_new() {
    let path = DotPathBuf::new();
    assert_eq!(path.segments().collect::<Vec<_>>(), vec![] as Vec<&str>);
    assert_eq!(path.to_string(), "");
}
