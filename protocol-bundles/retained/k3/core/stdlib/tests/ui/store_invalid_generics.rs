use stdlib::Store;

#[derive(Store)]
struct Test<'a> {
    s: &'a str,
}

#[derive(Store)]
struct Test1<T> {
    s: T,
}
