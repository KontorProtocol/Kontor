use stdlib::Store;

#[derive(Store)]
enum Invalid {
    Multi(u64, u64),
}
