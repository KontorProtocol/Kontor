use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::Keys;
use crate::runtime::wit::kontor::built_in;

impl built_in::context::HostKeys for Runtime {
    async fn drop(&mut self, rep: Resource<Keys>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostKeysWithStore<T> for Runtime {
    async fn next(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<Keys>,
    ) -> Result<Option<Vec<u8>>> {
        accessor.get().clone()._next(&mut accessor, self_).await
    }
}
