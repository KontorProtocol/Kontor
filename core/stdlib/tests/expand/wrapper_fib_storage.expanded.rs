use stdlib::Wrapper;
struct FibValue {
    pub value: u64,
}
pub struct FibValueWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for FibValueWrapper {
    #[inline]
    fn clone(&self) -> FibValueWrapper {
        FibValueWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
impl FibValueWrapper {
    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        Self { base_path }
    }
    pub fn value(&self, ctx: &impl stdlib::ReadContext) -> u64 {
        ctx.__get(self.base_path.push("value")).unwrap()
    }
    pub fn set_value(&self, ctx: &impl stdlib::WriteContext, value: u64) {
        ctx.__set(self.base_path.push("value"), value);
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> FibValue {
        FibValue { value: self.value(ctx) }
    }
}
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}
pub struct FibStorageWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for FibStorageWrapper {
    #[inline]
    fn clone(&self) -> FibStorageWrapper {
        FibStorageWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
impl FibStorageWrapper {
    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        Self { base_path }
    }
    pub fn cache(&self) -> FibStorageCacheWrapper {
        FibStorageCacheWrapper {
            base_path: self.base_path.push("cache"),
        }
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> FibStorage {
        FibStorage {
            cache: self.cache().load(ctx),
        }
    }
}
pub struct FibStorageCacheWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for FibStorageCacheWrapper {
    #[inline]
    fn clone(&self) -> FibStorageCacheWrapper {
        FibStorageCacheWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
impl FibStorageCacheWrapper {
    pub fn get(
        &self,
        ctx: &impl stdlib::ReadContext,
        key: impl ToString,
    ) -> Option<FibValueWrapper> {
        let base_path = self.base_path.push(key.to_string());
        ctx.__exists(&base_path).then(|| FibValueWrapper::new(ctx, base_path))
    }
    pub fn set(&self, ctx: &impl stdlib::WriteContext, key: u64, value: FibValue) {
        ctx.__set(self.base_path.push(key.to_string()), value)
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> Map<u64, FibValue> {
        Map::new(&[])
    }
    pub fn keys<'a, T: ToString + FromString + Clone + 'a>(
        &'a self,
        ctx: &'a impl ReadContext,
    ) -> impl Iterator<Item = T> + 'a {
        ctx.__get_keys(&self.base_path)
    }
}
