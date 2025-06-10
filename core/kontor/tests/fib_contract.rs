use std::future::Future;
use std::path::Path;

use anyhow::Result;
use tokio::fs::read;
use wasmtime::{
    Engine, Store, StoreContextMut,
    component::{
        Component, Linker, Resource, ResourceTable, ResourceType, Type, Val,
        wasm_wave::parser::Parser as WaveParser,
    },
};

type MzeroFn = fn() -> u64;
type MappendFn = fn(u64, u64) -> u64;

fn mzero_for_add() -> u64 {
    0
}

fn mappend_for_add(a: u64, b: u64) -> u64 {
    a + b
}

fn mzero_for_mul() -> u64 {
    1
}

fn mappend_for_mul(a: u64, b: u64) -> u64 {
    a * b
}
struct MyMonoidHostRep {
    mzero_operation: MzeroFn,
    mappend_operation: MappendFn,
}

impl MyMonoidHostRep {
    fn new(address: u64) -> Result<Self> {
        match address {
            0 => Ok(MyMonoidHostRep {
                mzero_operation: mzero_for_add,
                mappend_operation: mappend_for_add,
            }),
            1 => Ok(MyMonoidHostRep {
                mzero_operation: mzero_for_mul,
                mappend_operation: mappend_for_mul,
            }),
            _ => Err(anyhow::anyhow!(
                "Invalid address: {} provided to monoid constructor. Expected 0 (add) or 1 (mul).",
                address
            )),
        }
    }
}
struct HostCtx {
    table: ResourceTable,
}

// Destructor for the resource, called by Wasmtime's internal resource management.
// This is distinct from `host_monoid_drop` (which is called by Wasm's `[resource-drop]monoid` export).
// This destructor is invoked by Wasmtime when it needs to drop its own tracking of a resource handle.
fn monoid_linker_destructor<'a>(
    mut store: StoreContextMut<'a, HostCtx>,
    handle: u32, // Wasmtime provides the u32 handle of the resource to drop
) -> Box<dyn Future<Output = Result<()>> + Send + 'a> {
    Box::new(async move {
        println!(
            "Host: Linker's resource destructor called for handle {}.",
            handle
        );
        // Attempt to remove the resource from the table using the handle.
        // `Resource::new_own` takes ownership of the handle, which is appropriate here
        // as Wasmtime is telling us it's done with this handle.
        let resource_to_delete = Resource::<MyMonoidHostRep>::new_own(handle);
        match store.data_mut().table.delete(resource_to_delete) {
            Ok(_deleted_host_rep) => {
                println!(
                    "Host: Successfully deleted resource with handle {} from table via linker destructor.",
                    handle
                );
                Ok(())
            }
            Err(e) => {
                // This error case (Trap::ResourceNotDynamic) might mean the resource was already dropped
                // (e.g., by the guest calling [resource-drop] which then called host_monoid_drop).
                // Or, the handle was invalid for other reasons.
                // Depending on desired semantics, this might not be a fatal error for the *linker destructor*.
                eprintln!(
                    "Host: Error in linker destructor for handle {}: {:?}. This might be okay if already dropped by guest.",
                    handle, e
                );
                // We might choose to return Ok(()) here if an error (like already dropped) is acceptable.
                // For now, let's propagate the error to see its nature during testing.
                Err(anyhow::Error::from(e))
            }
        }
    })
}

impl HostCtx {
    fn new() -> Self {
        Self {
            table: ResourceTable::new(),
        }
    }
}

fn host_monoid_constructor<'a>(
    mut store_context: wasmtime::StoreContextMut<'a, HostCtx>,
    (address,): (u64,),
) -> Box<dyn Future<Output = Result<(Resource<MyMonoidHostRep>,), anyhow::Error>> + Send + 'a> {
    Box::new(async move {
        println!("Host: monoid.new(address: {}) called from Wasm", address);
        match MyMonoidHostRep::new(address) {
            Ok(monoid_rep) => store_context
                .data_mut()
                .table
                .push(monoid_rep)
                .map(|r| (r,))
                .map_err(Into::into),
            Err(e) => Err(e),
        }
    })
}

fn host_monoid_mappend<'a>(
    store_context: wasmtime::StoreContextMut<'a, HostCtx>,
    args: (Resource<MyMonoidHostRep>, u64, u64),
) -> Box<dyn Future<Output = Result<(u64,), anyhow::Error>> + Send + 'a> {
    Box::new(async move {
        let (self_handle, x, y) = args;
        let monoid_rep = store_context.data().table.get(&self_handle)?;

        println!(
            "Host: monoid.mappend({:?}, {}, {}) called from Wasm. Dispatching to stored operation.",
            self_handle, x, y
        );

        let result = (monoid_rep.mappend_operation)(x, y);
        Ok((result,))
    })
}

fn host_monoid_mzero<'a>(
    store_context: wasmtime::StoreContextMut<'a, HostCtx>,
    (self_handle,): (Resource<MyMonoidHostRep>,),
) -> Box<dyn Future<Output = Result<(u64,), anyhow::Error>> + Send + 'a> {
    Box::new(async move {
        let monoid_rep = store_context.data().table.get(&self_handle)?;
        println!(
            "Host: monoid.mzero({:?}) called from Wasm. Dispatching to stored mzero_operation.",
            self_handle
        );
        let result = (monoid_rep.mzero_operation)();
        Ok((result,))
    })
}

fn host_monoid_drop<'a>(
    mut store_context: wasmtime::StoreContextMut<'a, HostCtx>,
    (resource,): (Resource<MyMonoidHostRep>,),
) -> Box<dyn Future<Output = Result<((),), anyhow::Error>> + Send + 'a> {
    Box::new(async move {
        // Get the handle for logging before `resource` is moved.
        // Note: Resource<T>::handle() is not directly available in this version or context.
        // We will log the debug representation of the resource which typically includes the handle.
        let resource_dbg_for_log = format!("{:?}", resource);
        println!(
            "Host: [resource-drop]monoid called for {}",
            resource_dbg_for_log
        );

        match store_context.data_mut().table.delete(resource) {
            Ok(_deleted_host_rep) => Ok(((),)),
            Err(e) => {
                eprintln!(
                    "Host: Error in [resource-drop]monoid for {}: {:?}",
                    resource_dbg_for_log, e
                );
                Err(anyhow::Error::from(e))
            }
        }
    })
}

fn default_val_for_type(ty: &Type) -> Val {
    match ty {
        Type::Bool => Val::Bool(false),
        Type::S8 => Val::S8(0),
        Type::U8 => Val::U8(0),
        Type::S16 => Val::S16(0),
        Type::U16 => Val::U16(0),
        Type::S32 => Val::S32(0),
        Type::U32 => Val::U32(0),
        Type::S64 => Val::S64(0),
        Type::U64 => Val::U64(0),
        Type::Float32 => Val::Float32(0.0),
        Type::Float64 => Val::Float64(0.0),
        Type::Char => Val::Char(' '),
        Type::String => Val::String("".to_string()),
        Type::List(_) => Val::List(Vec::new()),
        Type::Record(record_ty) => {
            let fields = record_ty
                .fields()
                .map(|field| {
                    let field_val = default_val_for_type(&field.ty);
                    (field.name.to_string(), field_val)
                })
                .collect::<Vec<_>>();
            Val::Record(fields)
        }
        Type::Tuple(tuple_ty) => {
            let fields = tuple_ty
                .types()
                .map(|ty| default_val_for_type(&ty))
                .collect::<Vec<_>>();
            Val::Tuple(fields)
        }
        Type::Variant(variant_ty) => {
            let first_case = variant_ty
                .cases()
                .next()
                .expect("Variant must have at least one case");
            let payload = first_case.ty.map(|ty| Box::new(default_val_for_type(&ty)));
            Val::Variant(first_case.name.to_string(), payload)
        }
        Type::Enum(enum_ty) => {
            let first_case = enum_ty
                .names()
                .next()
                .expect("Enum must have at least one case");
            Val::Enum(first_case.to_string())
        }
        Type::Option(_) => Val::Option(None),
        Type::Result(result_ty) => {
            if let Some(ty) = result_ty.ok() {
                Val::Result(Ok(Some(Box::new(default_val_for_type(&ty)))))
            } else if let Some(ty) = result_ty.err() {
                Val::Result(Err(Some(Box::new(default_val_for_type(&ty)))))
            } else {
                Val::Result(Ok(None))
            }
        }
        Type::Flags(_) => Val::Flags(Vec::new()),
        Type::Own(_) => panic!("Cannot create a default Own value without a resource context"),
        Type::Borrow(_) => {
            panic!("Cannot create a default Borrow value without a resource context")
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_fib_contract() -> Result<()> {
    let mut config = wasmtime::Config::new();
    config.async_support(true);
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    let host_ctx = HostCtx::new();
    let mut store = Store::new(&engine, host_ctx);

    let mut linker = Linker::<HostCtx>::new(&engine);

    linker.root().resource_async(
        "monoid",
        ResourceType::host::<MyMonoidHostRep>(),
        monoid_linker_destructor,
    )?;

    linker
        .root()
        .func_wrap_async("[constructor]monoid", host_monoid_constructor)?;

    linker
        .root()
        .func_wrap_async("[method]monoid.mzero", host_monoid_mzero)?;

    linker
        .root()
        .func_wrap_async("[method]monoid.mappend", host_monoid_mappend)?;

    // Link [resource-drop]monoid. This is crucial.
    // This is the function the Wasm guest calls to signal it's done with a resource instance.
    // Our implementation (`host_monoid_drop`) will remove it from the ResourceTable.
    linker
        .root()
        .func_wrap_async("[resource-drop]monoid", host_monoid_drop)?;

    let n = 8;
    let s = format!("fib({})", n);
    let call = WaveParser::new(&s).parse_raw_func_call()?;

    let path = Path::new("../target/wasm32-unknown-unknown/debug/fib.wasm");
    let wasm = read(path).await?;
    let component = Component::from_binary(&engine, &wasm)?;
    let instance = linker.instantiate_async(&mut store, &component).await?;

    let func = instance
        .get_func(&mut store, call.name())
        .expect("fib should exist in instance");
    let params = call.to_wasm_params(func.params(&store).iter().map(|(_, t)| t))?;
    let mut results = func
        .results(&store)
        .iter()
        .map(default_val_for_type)
        .collect::<Vec<_>>();
    func.call_async(&mut store, &params, &mut results).await?;
    assert_eq!(results[0], Val::U64(21));

    Ok(())
}
