use crate::DotPathBuf;

pub trait FromString {
    fn from_string(s: String) -> Self;
}

pub trait Store<T>: Clone {
    fn __set(ctx: &T, base_path: DotPathBuf, value: Self);
}

pub trait Retrieve<T>: Clone {
    fn __get(ctx: &T, base_path: DotPathBuf) -> Option<Self>;
}
