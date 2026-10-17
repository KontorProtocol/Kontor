extern crate alloc;
use stdlib::Model;
mod error {
    pub type Error = String;
}
pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}
pub enum OpModel<__S> {
    Id,
    Sum(__OperandModelFor<__S>),
    Mul(__OperandModelFor<__S>),
    Div(__OperandModelFor<__S>),
    #[doc(hidden)]
    __Phantom(core::marker::PhantomData<__S>, core::convert::Infallible),
}
#[doc(hidden)]
pub type __OpModelFor<__S> = OpModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> OpModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let variant = stdlib::ReadStorage::__get_keys::<
            stdlib::Interned,
        >(&ctx, &base_path)
            .next();
        variant
            .map(|stdlib::Interned(__idx)| match __idx {
                0u8 => OpModel::Id,
                1u8 => {
                    OpModel::Sum(
                        __OperandModelFor::<
                            __S,
                        >::new(ctx.clone(), base_path.push_interned(1u8)),
                    )
                }
                2u8 => {
                    OpModel::Mul(
                        __OperandModelFor::<
                            __S,
                        >::new(ctx.clone(), base_path.push_interned(2u8)),
                    )
                }
                3u8 => {
                    OpModel::Div(
                        __OperandModelFor::<
                            __S,
                        >::new(ctx.clone(), base_path.push_interned(3u8)),
                    )
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Invalid enum storage tag"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Op {
        match self {
            OpModel::Id => Op::Id,
            OpModel::Sum(inner) => Op::Sum(inner.load()),
            OpModel::Mul(inner) => Op::Mul(inner.load()),
            OpModel::Div(inner) => Op::Div(inner.load()),
            Self::__Phantom(_, i) => match *i {}
        }
    }
    pub fn with_index(
        self,
        _index_root: stdlib::KeyPath,
        _index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        alloc::vec::Vec::new()
    }
}
pub enum OpWriteModel<__S: stdlib::HasViewStorage> {
    Id,
    Sum(__OperandWriteModelFor<__S>),
    Mul(__OperandWriteModelFor<__S>),
    Div(__OperandWriteModelFor<__S>),
    #[doc(hidden)]
    __Phantom(core::marker::PhantomData<__S>, core::convert::Infallible),
}
#[doc(hidden)]
pub type __OpWriteModelFor<__S> = OpWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> OpWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let variant = stdlib::ReadStorage::__get_keys::<
            stdlib::Interned,
        >(&ctx, &base_path)
            .next();
        variant
            .map(|stdlib::Interned(__idx)| match __idx {
                0u8 => OpWriteModel::Id,
                1u8 => {
                    OpWriteModel::Sum(
                        __OperandWriteModelFor::<
                            __S,
                        >::new(ctx.clone(), base_path.push_interned(1u8)),
                    )
                }
                2u8 => {
                    OpWriteModel::Mul(
                        __OperandWriteModelFor::<
                            __S,
                        >::new(ctx.clone(), base_path.push_interned(2u8)),
                    )
                }
                3u8 => {
                    OpWriteModel::Div(
                        __OperandWriteModelFor::<
                            __S,
                        >::new(ctx.clone(), base_path.push_interned(3u8)),
                    )
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Invalid enum storage tag"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Op {
        match self {
            OpWriteModel::Id => Op::Id,
            OpWriteModel::Sum(inner) => Op::Sum(inner.load()),
            OpWriteModel::Mul(inner) => Op::Mul(inner.load()),
            OpWriteModel::Div(inner) => Op::Div(inner.load()),
            Self::__Phantom(_, i) => match *i {}
        }
    }
    pub fn with_index(
        self,
        _index_root: stdlib::KeyPath,
        _index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        alloc::vec::Vec::new()
    }
}
struct Operand {
    y: u64,
}
#[automatically_derived]
impl ::core::clone::Clone for Operand {
    #[inline]
    fn clone(&self) -> Operand {
        Operand {
            y: ::core::clone::Clone::clone(&self.y),
        }
    }
}
pub struct OperandModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __OperandModelFor<__S> = OperandModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> OperandModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
    }
    pub fn y(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
pub struct OperandWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: OperandModel<__S::View>,
}
#[doc(hidden)]
pub type __OperandWriteModelFor<__S> = OperandWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> OperandWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: OperandModel::new(alloc::rc::Rc::new(view_storage), base_path.clone()),
        }
    }
    pub fn with_index(
        mut self,
        index_root: stdlib::KeyPath,
        index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self.index_binding = Some((index_root, index_key));
        self
    }
    pub fn y(&self) -> u64 {
        stdlib::ReadStorage::__get(&self.ctx, self.base_path.push_interned(0u8)).unwrap()
    }
    pub fn set_y(&self, value: u64) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn update_y(&self, f: impl Fn(u64) -> u64) {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone());
        stdlib::WriteStorage::__set(&self.ctx, path, new);
    }
    pub fn try_update_y(
        &self,
        f: impl Fn(u64) -> Result<u64, crate::error::Error>,
    ) -> Result<(), crate::error::Error> {
        let path = self.base_path.push_interned(0u8);
        let old: u64 = stdlib::ReadStorage::__get(&self.ctx, path.clone()).unwrap();
        let new = f(old.clone())?;
        stdlib::WriteStorage::__set(&self.ctx, path, new);
        Ok(())
    }
    pub fn load(&self) -> Operand {
        Operand { y: self.y() }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for OperandWriteModel<__S> {
    type Target = OperandModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
