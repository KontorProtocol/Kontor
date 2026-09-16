use stdlib::Model;
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
