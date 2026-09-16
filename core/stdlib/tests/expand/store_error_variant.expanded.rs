use stdlib::Store;
enum Error {
    Message(String),
    Overflow,
}
#[automatically_derived]
impl<__S: stdlib::WriteStorage + stdlib::ReadStorage + ?Sized> stdlib::Store<__S>
for Error {
    fn __set(ctx: &alloc::rc::Rc<__S>, base_path: stdlib::KeyPath, value: Error) {
        stdlib::WriteStorage::__delete(ctx, &base_path);
        match value {
            Error::Message(inner) => {
                stdlib::WriteStorage::__set_u64(ctx, &base_path, u64::from(0u8));
                stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), inner);
            }
            Error::Overflow => {
                stdlib::WriteStorage::__set_u64(ctx, &base_path, u64::from(1u8))
            }
        }
    }
}
