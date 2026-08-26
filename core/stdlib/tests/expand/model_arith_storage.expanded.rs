use stdlib::Model;
struct ArithStorage {
    pub last_op: Option<Op>,
}
pub struct ArithStorageModel<__S> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
}
#[doc(hidden)]
pub type __ArithStorageModelFor<__S> = ArithStorageModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> ArithStorageModel<__S> {
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
    pub fn last_op(&self) -> Option<__OpModelFor<__S>> {
        let base_path = self.base_path.push_interned(0u8);
        if stdlib::ReadStorage::__extend_path_with_match(
                &self.ctx,
                &base_path,
                &[stdlib::string_element("none")],
            )
            .is_some()
        {
            None
        } else {
            Some(__OpModelFor::<__S>::new(self.ctx.clone(), base_path.push("some")))
        }
    }
    pub fn load(&self) -> ArithStorage {
        ArithStorage {
            last_op: self.last_op().map(|p| p.load()),
        }
    }
}
pub struct ArithStorageWriteModel<__S: stdlib::HasViewStorage> {
    pub base_path: stdlib::KeyPath,
    ctx: alloc::rc::Rc<__S>,
    index_binding: Option<(stdlib::KeyPath, alloc::vec::Vec<u8>)>,
    model: ArithStorageModel<__S::View>,
}
#[doc(hidden)]
pub type __ArithStorageWriteModelFor<__S> = ArithStorageWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> ArithStorageWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let view_storage = stdlib::HasViewStorage::view_storage(&*ctx);
        Self {
            base_path: base_path.clone(),
            ctx,
            index_binding: None,
            model: ArithStorageModel::new(
                alloc::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
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
    pub fn last_op(&self) -> Option<__OpWriteModelFor<__S>> {
        let base_path = self.base_path.push_interned(0u8);
        if stdlib::ReadStorage::__extend_path_with_match(
                &self.ctx,
                &base_path,
                &[stdlib::string_element("none")],
            )
            .is_some()
        {
            None
        } else {
            Some(__OpWriteModelFor::<__S>::new(self.ctx.clone(), base_path.push("some")))
        }
    }
    pub fn set_last_op(&self, value: Option<Op>) {
        stdlib::WriteStorage::__set(&self.ctx, self.base_path.push_interned(0u8), value);
    }
    pub fn load(&self) -> ArithStorage {
        ArithStorage {
            last_op: self.last_op().map(|p| p.load()),
        }
    }
}
impl<__S: stdlib::HasViewStorage> core::ops::Deref for ArithStorageWriteModel<__S> {
    type Target = ArithStorageModel<__S::View>;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
