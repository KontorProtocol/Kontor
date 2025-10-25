use stdlib::Model;
struct FibValue {
    pub value: u64,
}
pub struct FibValueModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
impl FibValueModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn value(&self) -> u64 {
        self.ctx.__get(self.base_path.push("value")).unwrap()
    }
    pub fn load(&self) -> FibValue {
        FibValue { value: self.value() }
    }
}
pub struct FibValueWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
    model: FibValueModel,
}
impl FibValueWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: FibValueModel::new(std::rc::Rc::new(view_storage), base_path.clone()),
        }
    }
    pub fn value(&self) -> u64 {
        self.ctx.__get(self.base_path.push("value")).unwrap()
    }
    pub fn set_value(&self, value: u64) {
        self.ctx.__set(self.base_path.push("value"), value);
    }
    pub fn load(&self) -> FibValue {
        FibValue { value: self.value() }
    }
}
impl std::ops::Deref for FibValueWriteModel {
    type Target = FibValueModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}
pub struct FibStorageModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
impl FibStorageModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        Self {
            base_path: base_path.clone(),
            ctx,
        }
    }
    pub fn cache(&self) -> FibStorageCacheModel {
        FibStorageCacheModel {
            base_path: self.base_path.push("cache"),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> FibStorage {
        FibStorage {
            cache: self.cache().load(),
        }
    }
}
pub struct FibStorageCacheModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ViewStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for FibStorageCacheModel {
    #[inline]
    fn clone(&self) -> FibStorageCacheModel {
        FibStorageCacheModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl FibStorageCacheModel {
    pub fn get(&self, key: impl ToString) -> Option<FibValueModel> {
        let base_path = self.base_path.push(key.to_string());
        self.ctx
            .__exists(&base_path)
            .then(|| FibValueModel::new(self.ctx.clone(), base_path))
    }
    pub fn load(&self) -> Map<u64, FibValue> {
        Map::new(&[])
    }
    pub fn keys<'a, T: ToString + FromString + Clone + 'a>(
        &'a self,
    ) -> impl Iterator<Item = T> + 'a {
        self.ctx.__get_keys(&self.base_path)
    }
}
pub struct FibStorageWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
    model: FibStorageModel,
}
impl FibStorageWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        let view_storage = ctx.view_storage();
        Self {
            base_path: base_path.clone(),
            ctx,
            model: FibStorageModel::new(
                std::rc::Rc::new(view_storage),
                base_path.clone(),
            ),
        }
    }
    pub fn cache(&self) -> FibStorageCacheWriteModel {
        FibStorageCacheWriteModel {
            base_path: self.base_path.push("cache"),
            ctx: self.ctx.clone(),
        }
    }
    pub fn load(&self) -> FibStorage {
        FibStorage {
            cache: self.cache().load(),
        }
    }
}
impl std::ops::Deref for FibStorageWriteModel {
    type Target = FibStorageModel;
    fn deref(&self) -> &Self::Target {
        &self.model
    }
}
pub struct FibStorageCacheWriteModel {
    pub base_path: stdlib::DotPathBuf,
    ctx: std::rc::Rc<crate::context::ProcStorage>,
}
#[automatically_derived]
impl ::core::clone::Clone for FibStorageCacheWriteModel {
    #[inline]
    fn clone(&self) -> FibStorageCacheWriteModel {
        FibStorageCacheWriteModel {
            base_path: ::core::clone::Clone::clone(&self.base_path),
            ctx: ::core::clone::Clone::clone(&self.ctx),
        }
    }
}
impl FibStorageCacheWriteModel {
    pub fn get(&self, key: impl ToString) -> Option<FibValueWriteModel> {
        let base_path = self.base_path.push(key.to_string());
        self.ctx
            .__exists(&base_path)
            .then(|| FibValueWriteModel::new(self.ctx.clone(), base_path))
    }
    pub fn set(&self, key: u64, value: FibValue) {
        self.ctx.__set(self.base_path.push(key.to_string()), value)
    }
    pub fn load(&self) -> Map<u64, FibValue> {
        Map::new(&[])
    }
    pub fn keys<'a, T: ToString + FromString + Clone + 'a>(
        &'a self,
    ) -> impl Iterator<Item = T> + 'a {
        self.ctx.__get_keys(&self.base_path)
    }
}
