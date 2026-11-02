use stdlib::Model;

#[derive(Model)]
enum Invalid {
    Multi(u64, u64),
}
