use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

use wasmtime::component::{
    Accessor, ComponentNamedList, Lift, Linker as WasmtimeLinker,
    LinkerInstance as WasmtimeLinkerInstance, Lower, ResourceType,
};
use wasmtime::{AsContextMut, Engine, Error, Result, StoreContextMut};

use super::Lowering;
use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;

type Charge<T> = fn(StoreContextMut<'_, T>, u64) -> Result<()>;

pub(crate) fn charge(mut store: StoreContextMut<'_, Runtime>, bytes: u64) -> Result<()> {
    if bytes != 0 {
        Fuel::LoweringBytes(bytes)
            .consume_with_store(&mut store)
            .map_err(Error::from_anyhow)?;
    }
    Ok(())
}

/// Registration through this linker always reserves variable return work.
/// The callback keeps bindgen's generic Store data parameter intact.
pub struct Linker<T: 'static> {
    inner: WasmtimeLinker<T>,
    charge: Charge<T>,
}

impl Linker<Runtime> {
    pub fn new(engine: &Engine) -> Self {
        Self {
            inner: WasmtimeLinker::new(engine),
            charge,
        }
    }
}

impl<T: 'static> Linker<T> {
    pub fn allow_shadowing(&mut self, allow: bool) -> &mut Self {
        self.inner.allow_shadowing(allow);
        self
    }

    pub fn root(&mut self) -> LinkerInstance<'_, T> {
        LinkerInstance {
            inner: self.inner.root(),
            charge: self.charge,
        }
    }

    pub fn instance(&mut self, name: &str) -> Result<LinkerInstance<'_, T>> {
        Ok(LinkerInstance {
            inner: self.inner.instance(name)?,
            charge: self.charge,
        })
    }
}

impl<T: 'static> Clone for Linker<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            charge: self.charge,
        }
    }
}

// Read-only Wasmtime APIs remain available for instantiation. No DerefMut:
// accidentally passing this to an unmetered registration helper must not compile.
// LinkerInstance has no Deref for the same reason.
impl<T: 'static> Deref for Linker<T> {
    type Target = WasmtimeLinker<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct LinkerInstance<'a, T: 'static> {
    inner: WasmtimeLinkerInstance<'a, T>,
    charge: Charge<T>,
}

impl<T: 'static> LinkerInstance<'_, T> {
    pub fn func_wrap<Params, Return, F>(&mut self, name: &str, f: F) -> Result<()>
    where
        F: Fn(StoreContextMut<'_, T>, Params) -> Result<Return> + Send + Sync + 'static,
        Params: ComponentNamedList + Lift + 'static,
        Return: ComponentNamedList + Lower + Lowering + 'static,
    {
        let charge = self.charge;
        self.inner.func_wrap(name, move |mut store, params| {
            let value = f(store.as_context_mut(), params)?;
            charge(store, value.lowering_bytes().map_err(Error::from_anyhow)?)?;
            Ok(value)
        })
    }

    pub fn func_wrap_async<Params, Return, F>(&mut self, name: &str, f: F) -> Result<()>
    where
        T: Send,
        F: Fn(
                StoreContextMut<'_, T>,
                Params,
            ) -> Box<dyn Future<Output = Result<Return>> + Send + '_>
            + Send
            + Sync
            + 'static,
        Params: ComponentNamedList + Lift + Send + 'static,
        Return: ComponentNamedList + Lower + Lowering + 'static,
    {
        let charge = self.charge;
        let f = Arc::new(f);
        self.inner.func_wrap_async(name, move |mut store, params| {
            let f = f.clone();
            Box::new(async move {
                let value = Box::into_pin(f(store.as_context_mut(), params)).await?;
                charge(store, value.lowering_bytes().map_err(Error::from_anyhow)?)?;
                Ok(value)
            })
        })
    }

    pub fn func_wrap_concurrent<Params, Return, F>(&mut self, name: &str, f: F) -> Result<()>
    where
        F: Fn(&Accessor<T>, Params) -> Pin<Box<dyn Future<Output = Result<Return>> + Send + '_>>
            + Send
            + Sync
            + 'static,
        Params: ComponentNamedList + Lift + 'static,
        Return: ComponentNamedList + Lower + Lowering + 'static,
    {
        let charge = self.charge;
        self.inner
            .func_wrap_concurrent(name, move |accessor, params| {
                let future = f(accessor, params);
                Box::pin(async move {
                    let value = future.await?;
                    let bytes = value.lowering_bytes().map_err(Error::from_anyhow)?;
                    accessor.with(|mut access| charge(access.as_context_mut(), bytes))?;
                    Ok(value)
                })
            })
    }

    pub fn resource_concurrent<F>(&mut self, name: &str, ty: ResourceType, dtor: F) -> Result<()>
    where
        T: Send,
        F: Fn(&Accessor<T>, u32) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>
            + Send
            + Sync
            + 'static,
    {
        self.inner.resource_concurrent(name, ty, dtor)
    }
}

/// bindgen's supported crate override routes generated registrations through
/// the same wrapper as handwritten imports, leaving Wasmtime's ABI types intact.
pub mod bindings {
    pub use wasmtime::*;

    pub mod component {
        pub use wasmtime::component::*;

        pub use super::super::{Linker, LinkerInstance};
    }
}
