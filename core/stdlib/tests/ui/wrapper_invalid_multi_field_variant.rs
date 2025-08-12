use stdlib::Wrapper;

#[derive(Wrapper)]
enum Invalid {
    Multi(u64, u64),
}
