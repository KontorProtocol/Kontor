use anyhow::{Context, Result, anyhow};
use serde::de::{DeserializeSeed, EnumAccess, SeqAccess, VariantAccess, Visitor};

use crate::database::queries::get_contract_address_from_id;

use super::*;

impl Runtime {
    /// Execute a `BinaryCall` (contract_id + function_index + postcard args bytes).
    ///
    /// The complicated part here is decoding `args` into `wasmtime::component::Val`s *without*
    /// having any Rust type information for the contract's interface at compile-time.
    /// We use the component's runtime type information (`wasmtime::component::Type`) to drive a
    /// type-directed postcard deserializer.
    pub async fn execute_binary(
        &mut self,
        signer: Option<&Signer>,
        contract_id: u32,
        function_index: u16,
        args: &[u8],
    ) -> Result<String> {
        let contract_id = i64::from(contract_id);
        let contract_address = get_contract_address_from_id(&self.storage.conn, contract_id)
            .await?
            .ok_or_else(|| anyhow!("Contract not found (id={})", contract_id))?;

        let func_name = self
            .resolve_binary_export_name(contract_id, function_index)
            .await?;

        tracing::info!(
            "Executing contract_id={} ({}) with function_index={} ({}) with tx context {:?}",
            contract_id,
            contract_address,
            function_index,
            func_name,
            self.tx_context()
        );

        let (
            mut store,
            contract_id,
            func_name,
            is_fallback,
            params,
            mut results,
            func,
            is_proc,
            starting_fuel,
        ) = self
            .prepare_call_binary(
                contract_id,
                &contract_address,
                signer,
                &func_name,
                args,
                true,
                self.fuel_limit(),
            )
            .await?;

        OptionFuture::from(
            self.gauge
                .as_ref()
                .map(|g| g.set_starting_fuel(starting_fuel)),
        )
        .await;

        let (result, results, mut store) = tokio::spawn(async move {
            (
                func.call_async(&mut store, &params, &mut results).await,
                results,
                store,
            )
        })
        .await
        .expect("Failed to join execution");

        let mut result = self.handle_call(is_fallback, result, results).await;

        OptionFuture::from(
            self.gauge
                .as_ref()
                .map(|g| g.set_ending_fuel(store.get_fuel().unwrap())),
        )
        .await;

        if is_proc {
            let signer = signer.expect("Signer should be available in proc");
            result = self
                .handle_procedure(
                    signer,
                    contract_id,
                    &contract_address,
                    &func_name,
                    true,
                    starting_fuel,
                    &mut store,
                    result,
                )
                .await;
        }

        result
    }

    async fn prepare_call_binary(
        &self,
        contract_id: i64,
        _contract_address: &ContractAddress,
        signer: Option<&Signer>,
        func_name: &str,
        args: &[u8],
        is_top_level: bool,
        fuel: Option<u64>,
    ) -> Result<(
        Store<Runtime>,
        i64,
        String,
        bool,
        Vec<Val>,
        Vec<Val>,
        Func,
        bool,
        u64,
    )> {
        let component = self.load_component(contract_id).await?;
        let mut fuel_limit = fuel.unwrap_or(self.fuel_limit_for_non_procs());
        let mut store = self.make_store(fuel_limit)?;
        let instance = self
            .linker
            .instantiate_async(&mut store, &component)
            .await?;

        let func = instance
            .get_func(&mut store, func_name)
            .ok_or_else(|| anyhow!("Unknown export function: {}", func_name))?;

        // Binary calls are not routed through fallback.
        let is_fallback = false;

        let component_func = func.ty(&store);
        let func_params = component_func.params();
        let func_param_types = func_params.map(|(_, t)| t).collect::<Vec<_>>();
        let (func_ctx_param_type, func_param_types) = func_param_types
            .split_first()
            .ok_or(anyhow!("Context/signer parameter not found"))?;

        let mut params = decode_postcard_args_tuple(func_param_types, args)
            .with_context(|| format!("Failed to decode binary args for {}()", func_name))?;

        let resource_type = match func_ctx_param_type {
            wasmtime::component::Type::Borrow(t) => Ok(*t),
            _ => Err(anyhow!("Unsupported context type")),
        }?;

        // Same "contract id signer" invariant as the WAVE execution path.
        if let Some(Signer::ContractId { id, .. }) = signer
            && self.stack.peek().await != Some(*id)
        {
            return Err(anyhow!("Invalid contract id signer"));
        }

        let mut is_proc = false;
        {
            let mut table = self.table.lock().await;
            match (resource_type, signer) {
                (t, Some(Signer::Core(signer)))
                    if t.eq(&wasmtime::component::ResourceType::host::<CoreContext>()) =>
                {
                    is_proc = true;
                    fuel_limit = self.fuel_limit_for_non_procs();
                    store
                        .set_fuel(fuel_limit)
                        .expect("Failed to set fuel for core context procedure");
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(CoreContext {
                                    signer: *signer.clone(),
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                (t, _) if t.eq(&wasmtime::component::ResourceType::host::<ViewContext>()) => params
                    .insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ViewContext { contract_id })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    ),
                (t, Some(signer))
                    if t.eq(&wasmtime::component::ResourceType::host::<ProcContext>()) =>
                {
                    is_proc = true;
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(ProcContext {
                                    signer: signer.clone(),
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                (t, signer) if t.eq(&wasmtime::component::ResourceType::host::<FallContext>()) => {
                    is_proc = signer.is_some();
                    params.insert(
                        0,
                        wasmtime::component::Val::Resource(
                            table
                                .push(FallContext {
                                    signer: signer.cloned(),
                                    contract_id,
                                })?
                                .try_into_resource_any(&mut store)?,
                        ),
                    )
                }
                (t, signer) => {
                    return Err(anyhow!(
                        "Unsupported context/signer type: {:?} {:?}",
                        t,
                        signer
                    ));
                }
            }
        }

        if is_proc && fuel.is_none() {
            return Err(anyhow!("Missing fuel for procedure"));
        }

        let results = component_func
            .results()
            .map(default_val_for_type)
            .collect::<Vec<_>>();

        if is_proc
            && is_top_level
            && let Some(signer) = signer
            && !signer.is_core()
        {
            Box::pin({
                let mut runtime = self.clone();
                async move {
                    token::api::hold(
                        &mut runtime,
                        &Signer::Core(Box::new(signer.clone())),
                        Decimal::from(fuel_limit)
                            .div(Decimal::from(self.gas_to_fuel_multiplier))
                            .expect("Failed to convert fuel limit into gas limit")
                            .mul(self.gas_to_token_multiplier)
                            .expect("Failed to convert gas limit into token limit"),
                    )
                    .await
                }
            })
            .await
            .expect("Failed to escrow gas")
            .map_err(|e| {
                anyhow!(
                    "Signer {:?} does not have enough token to cover gas limit: {}",
                    signer,
                    e
                )
            })?;
        }

        self.stack.push(contract_id).await?;
        self.storage.savepoint().await?;
        self.file_ledger.clear_dirty().await;

        Ok((
            store,
            contract_id,
            func_name.to_string(),
            is_fallback,
            params,
            results,
            func,
            is_proc,
            fuel_limit,
        ))
    }

    /// Map `function_index` -> export name for `BinaryCall`s.
    ///
    /// We intentionally derive this from the contract's embedded WIT world (via `wit-component`)
    /// so that all indexers compute the same mapping deterministically from on-chain contract bytes.
    async fn resolve_binary_export_name(
        &self,
        contract_id: i64,
        function_index: u16,
    ) -> Result<String> {
        let component_bytes = self.storage.component_bytes(contract_id).await?;

        let decoded = wit_component::decode(&component_bytes)
            .context("Failed to decode component WIT metadata")?;

        let (resolve, world_id) = match decoded {
            wit_component::DecodedWasm::Component(resolve, world) => (resolve, world),
            wit_component::DecodedWasm::WitPackage(..) => {
                return Err(anyhow!(
                    "Contract bytes decoded as a WIT package, not a component"
                ));
            }
        };

        let world = &resolve.worlds[world_id];

        // BinaryCall supports both proc-context and view-context exports.
        //
        // IMPORTANT: Keep proc indices stable by listing proc exports first.
        let mut proc_exports = Vec::new();
        let mut view_exports = Vec::new();
        for (key, item) in world.exports.iter() {
            match item {
                wit_parser::WorldItem::Function(func) => {
                    let wit_parser::WorldKey::Name(export_name) = key else {
                        continue;
                    };
                    if export_name == "init" {
                        continue;
                    }
                    if is_proc_context_export(&resolve, func) {
                        proc_exports.push(export_name.clone());
                    } else if is_view_context_export(&resolve, func) {
                        view_exports.push(export_name.clone());
                    }
                }
                wit_parser::WorldItem::Interface { id, .. } => {
                    let iface = &resolve.interfaces[*id];
                    for (func_name, func) in iface.functions.iter() {
                        if func_name == "init" {
                            continue;
                        }
                        if is_proc_context_export(&resolve, func) {
                            proc_exports.push(func_name.clone());
                        } else if is_view_context_export(&resolve, func) {
                            view_exports.push(func_name.clone());
                        }
                    }
                }
                _ => continue,
            }
        }

        let idx = usize::from(function_index);
        if let Some(name) = proc_exports.get(idx) {
            return Ok(name.clone());
        }
        let view_idx = idx.saturating_sub(proc_exports.len());
        view_exports.get(view_idx).cloned().ok_or_else(|| {
            anyhow!(
                "function_index {} out of bounds ({} proc exports, {} view exports) for contract_id={}",
                function_index,
                proc_exports.len(),
                view_exports.len(),
                contract_id
            )
        })
    }
}

fn is_proc_context_export(resolve: &wit_parser::Resolve, func: &wit_parser::Function) -> bool {
    let Some((_, first_param_ty)) = func.params.first() else {
        return false;
    };

    // In WIT, `borrow<proc-context>` is represented as a handle type whose referent is the
    // `proc-context` resource imported from `kontor:built-in/context`.
    let wit_parser::Type::Id(handle_id) = first_param_ty else {
        return false;
    };

    let handle_def = &resolve.types[*handle_id];
    let wit_parser::TypeDefKind::Handle(wit_parser::Handle::Borrow(ctx_id)) = &handle_def.kind
    else {
        return false;
    };

    is_named_resource_type(resolve, *ctx_id, "proc-context")
}

fn is_view_context_export(resolve: &wit_parser::Resolve, func: &wit_parser::Function) -> bool {
    let Some((_, first_param_ty)) = func.params.first() else {
        return false;
    };

    // In WIT, `borrow<view-context>` is represented as a handle type whose referent is the
    // `view-context` resource imported from `kontor:built-in/context`.
    let wit_parser::Type::Id(handle_id) = first_param_ty else {
        return false;
    };

    let handle_def = &resolve.types[*handle_id];
    let wit_parser::TypeDefKind::Handle(wit_parser::Handle::Borrow(ctx_id)) = &handle_def.kind
    else {
        return false;
    };

    is_named_resource_type(resolve, *ctx_id, "view-context")
}

/// Resolve whether a `TypeId` refers to a resource named `expected_name`.
///
/// Why this helper exists:
/// - For some decoded components, `TypeDef.name` for imported resources can be `None`, even though
///   the type is still reachable via an interface's exported `types` map.
/// - The indexer must still reliably recognize `proc-context` and `view-context` to build a stable
///   `function_index` mapping for `BinaryCall`.
fn is_named_resource_type(
    resolve: &wit_parser::Resolve,
    ty: wit_parser::TypeId,
    expected_name: &str,
) -> bool {
    // Follow `type` aliases until reaching the underlying resource.
    let mut visited = Vec::new();
    let mut cur = ty;
    for _ in 0..64 {
        visited.push(cur);
        let def = &resolve.types[cur];
        match &def.kind {
            wit_parser::TypeDefKind::Resource => break,
            wit_parser::TypeDefKind::Type(wit_parser::Type::Id(next)) => {
                cur = *next;
            }
            _ => return false,
        }
    }

    let Some(last) = visited.last().copied() else {
        return false;
    };
    if !matches!(resolve.types[last].kind, wit_parser::TypeDefKind::Resource) {
        return false;
    }

    if visited
        .iter()
        .any(|id| resolve.types[*id].name.as_deref() == Some(expected_name))
    {
        return true;
    }

    // Fallback: search interface type exports (in case the type itself is anonymous).
    for (_id, iface) in resolve.interfaces.iter() {
        if iface
            .types
            .get(expected_name)
            .is_some_and(|id| visited.contains(id))
        {
            return true;
        }
    }

    false
}

/// Decode postcard `args` bytes as a tuple of values matching `param_types`.
///
/// This expects `args` to be encoded as `postcard::to_allocvec(&(arg0, arg1, ...))` in signer tooling.
fn decode_postcard_args_tuple(
    param_types: &[wasmtime::component::Type],
    args: &[u8],
) -> Result<Vec<Val>> {
    let mut deserializer = postcard::Deserializer::from_bytes(args);
    let vals = ArgsTupleSeed { param_types }.deserialize(&mut deserializer)?;
    let remaining = deserializer.finalize()?;
    if !remaining.is_empty() {
        return Err(anyhow!(
            "Extra trailing bytes in postcard args ({} bytes)",
            remaining.len()
        ));
    }
    Ok(vals)
}

struct ArgsTupleSeed<'a> {
    param_types: &'a [wasmtime::component::Type],
}

impl<'de> DeserializeSeed<'de> for ArgsTupleSeed<'_> {
    type Value = Vec<Val>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_tuple(
            self.param_types.len(),
            ArgsTupleVisitor {
                param_types: self.param_types,
            },
        )
    }
}

struct ArgsTupleVisitor<'a> {
    param_types: &'a [wasmtime::component::Type],
}

impl<'de> Visitor<'de> for ArgsTupleVisitor<'_> {
    type Value = Vec<Val>;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "a tuple of {} args", self.param_types.len())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(self.param_types.len());
        for ty in self.param_types {
            let v = seq
                .next_element_seed(ValSeed { ty })?
                .ok_or_else(|| serde::de::Error::invalid_length(out.len(), &self))?;
            out.push(v);
        }

        Ok(out)
    }
}

struct ValSeed<'a> {
    ty: &'a wasmtime::component::Type,
}

impl<'de> DeserializeSeed<'de> for ValSeed<'_> {
    type Value = Val;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match self.ty {
            wasmtime::component::Type::Bool => bool::deserialize(deserializer).map(Val::Bool),
            wasmtime::component::Type::S8 => i8::deserialize(deserializer).map(Val::S8),
            wasmtime::component::Type::U8 => u8::deserialize(deserializer).map(Val::U8),
            wasmtime::component::Type::S16 => i16::deserialize(deserializer).map(Val::S16),
            wasmtime::component::Type::U16 => u16::deserialize(deserializer).map(Val::U16),
            wasmtime::component::Type::S32 => i32::deserialize(deserializer).map(Val::S32),
            wasmtime::component::Type::U32 => u32::deserialize(deserializer).map(Val::U32),
            wasmtime::component::Type::S64 => i64::deserialize(deserializer).map(Val::S64),
            wasmtime::component::Type::U64 => u64::deserialize(deserializer).map(Val::U64),
            wasmtime::component::Type::Float32 => f32::deserialize(deserializer).map(Val::Float32),
            wasmtime::component::Type::Float64 => f64::deserialize(deserializer).map(Val::Float64),
            wasmtime::component::Type::Char => char::deserialize(deserializer).map(Val::Char),
            wasmtime::component::Type::String => String::deserialize(deserializer).map(Val::String),

            wasmtime::component::Type::List(list) => {
                let elem_ty = list.ty();
                deserializer.deserialize_seq(ListVisitor { elem_ty })
            }
            wasmtime::component::Type::Record(record) => {
                let fields = record
                    .fields()
                    .map(|f| (f.name.to_string(), f.ty))
                    .collect::<Vec<_>>();
                deserializer.deserialize_tuple(fields.len(), RecordVisitor { fields })
            }
            wasmtime::component::Type::Tuple(tuple) => {
                let types = tuple.types().collect::<Vec<_>>();
                deserializer.deserialize_tuple(types.len(), TupleVisitor { types })
            }
            wasmtime::component::Type::Variant(variant) => {
                let cases = variant
                    .cases()
                    .map(|c| (c.name.to_string(), c.ty))
                    .collect::<Vec<_>>();
                deserializer.deserialize_enum("variant", &[], VariantVisitor { cases })
            }
            wasmtime::component::Type::Enum(enum_ty) => {
                let names = enum_ty.names().map(|s| s.to_string()).collect::<Vec<_>>();
                deserializer.deserialize_enum("enum", &[], EnumVisitor { names })
            }
            wasmtime::component::Type::Option(opt) => {
                let elem_ty = opt.ty();
                deserializer.deserialize_option(OptionVisitor { elem_ty })
            }
            wasmtime::component::Type::Result(res) => {
                let ok_ty = res.ok();
                let err_ty = res.err();
                deserializer.deserialize_enum("result", &[], ResultVisitor { ok_ty, err_ty })
            }
            wasmtime::component::Type::Flags(flags) => {
                // Encode flags as one-or-more u32 bitsets (matching canonical ABI flattening).
                let names = flags.names().map(|s| s.to_string()).collect::<Vec<_>>();
                let u32_count = names.len().div_ceil(32);
                let chunks = if u32_count <= 1 {
                    vec![u32::deserialize(deserializer)?]
                } else {
                    Vec::<u32>::deserialize(deserializer)?
                };
                Ok(Val::Flags(decode_flag_names(&names, &chunks)))
            }

            // These exist in the component model, but are not currently supported as on-chain
            // BinaryCall argument types in Kontor.
            wasmtime::component::Type::Own(_)
            | wasmtime::component::Type::Borrow(_)
            | wasmtime::component::Type::Future(_)
            | wasmtime::component::Type::Stream(_)
            | wasmtime::component::Type::ErrorContext => Err(serde::de::Error::custom(format!(
                "unsupported BinaryCall arg type: {:?}",
                self.ty
            ))),
        }
    }
}

fn decode_flag_names(names: &[String], chunks: &[u32]) -> Vec<String> {
    let mut out = Vec::new();
    for (chunk_idx, chunk) in chunks.iter().copied().enumerate() {
        for bit in 0..32 {
            let flag_idx = (chunk_idx * 32) + bit;
            if flag_idx >= names.len() {
                break;
            }
            if (chunk & (1u32 << bit)) != 0 {
                out.push(names[flag_idx].clone());
            }
        }
    }
    out
}

struct ListVisitor {
    elem_ty: wasmtime::component::Type,
}

impl<'de> Visitor<'de> for ListVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "a list")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(ValSeed { ty: &self.elem_ty })? {
            out.push(v);
        }
        Ok(Val::List(out))
    }
}

struct RecordVisitor {
    fields: Vec<(String, wasmtime::component::Type)>,
}

impl<'de> Visitor<'de> for RecordVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "a record with {} fields", self.fields.len())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(self.fields.len());
        for (name, ty) in self.fields.iter() {
            let v = seq
                .next_element_seed(ValSeed { ty })?
                .ok_or_else(|| serde::de::Error::invalid_length(out.len(), &self))?;
            out.push((name.clone(), v));
        }
        Ok(Val::Record(out))
    }
}

struct TupleVisitor {
    types: Vec<wasmtime::component::Type>,
}

impl<'de> Visitor<'de> for TupleVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "a tuple of {} elements", self.types.len())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(self.types.len());
        for ty in self.types.iter() {
            let v = seq
                .next_element_seed(ValSeed { ty })?
                .ok_or_else(|| serde::de::Error::invalid_length(out.len(), &self))?;
            out.push(v);
        }
        Ok(Val::Tuple(out))
    }
}

struct U32Seed;

impl<'de> DeserializeSeed<'de> for U32Seed {
    type Value = u32;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer)
    }
}

struct VariantVisitor {
    cases: Vec<(String, Option<wasmtime::component::Type>)>,
}

impl<'de> Visitor<'de> for VariantVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "a variant")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (idx, variant) = data.variant_seed(U32Seed)?;
        let idx = usize::try_from(idx).map_err(|_| serde::de::Error::custom("variant idx OOB"))?;
        let (name, payload_ty) = self
            .cases
            .get(idx)
            .ok_or_else(|| serde::de::Error::custom("invalid variant index"))?;

        let payload = match payload_ty {
            Some(ty) => Some(Box::new(variant.newtype_variant_seed(ValSeed { ty })?)),
            None => {
                variant.unit_variant()?;
                None
            }
        };

        Ok(Val::Variant(name.clone(), payload))
    }
}

struct EnumVisitor {
    names: Vec<String>,
}

impl<'de> Visitor<'de> for EnumVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "an enum")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (idx, variant) = data.variant_seed(U32Seed)?;
        variant.unit_variant()?;
        let idx = usize::try_from(idx).map_err(|_| serde::de::Error::custom("enum idx OOB"))?;
        let name = self
            .names
            .get(idx)
            .ok_or_else(|| serde::de::Error::custom("invalid enum index"))?;
        Ok(Val::Enum(name.clone()))
    }
}

struct OptionVisitor {
    elem_ty: wasmtime::component::Type,
}

impl<'de> Visitor<'de> for OptionVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "an option")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Val::Option(None))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = ValSeed { ty: &self.elem_ty }.deserialize(deserializer)?;
        Ok(Val::Option(Some(Box::new(inner))))
    }
}

struct ResultVisitor {
    ok_ty: Option<wasmtime::component::Type>,
    err_ty: Option<wasmtime::component::Type>,
}

impl<'de> Visitor<'de> for ResultVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "a result")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (idx, variant) = data.variant_seed(U32Seed)?;
        match idx {
            0 => {
                let payload = match self.ok_ty {
                    Some(ty) => Some(Box::new(variant.newtype_variant_seed(ValSeed { ty: &ty })?)),
                    None => {
                        variant.unit_variant()?;
                        None
                    }
                };
                Ok(Val::Result(Ok(payload)))
            }
            1 => {
                let payload = match self.err_ty {
                    Some(ty) => Some(Box::new(variant.newtype_variant_seed(ValSeed { ty: &ty })?)),
                    None => {
                        variant.unit_variant()?;
                        None
                    }
                };
                Ok(Val::Result(Err(payload)))
            }
            _ => Err(serde::de::Error::custom("invalid result variant index")),
        }
    }
}
