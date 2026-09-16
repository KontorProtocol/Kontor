use stdlib::Store;
enum Error {
    Message(String),
    Overflow,
}
#[automatically_derived]
impl<__S: stdlib::WriteStorage + stdlib::ReadStorage + ?Sized> stdlib::Store<__S>
for Error {
    const STORES_ROOT: bool = false;
    fn __set(ctx: &alloc::rc::Rc<__S>, base_path: stdlib::KeyPath, value: Error) {
        stdlib::WriteStorage::__delete(ctx, &base_path);
        match value {
            Error::Message(inner) => {
                stdlib::Store::__set_variant_payload(
                    ctx,
                    base_path.push_interned(0u8),
                    inner,
                );
            }
            Error::Overflow => {
                stdlib::WriteStorage::__set_void(ctx, &base_path.push_interned(1u8))
            }
        }
    }
}
