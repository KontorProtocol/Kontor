use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use wasm_encoder::{
    Alias, CanonicalFunctionSection, CanonicalOption, Component, ComponentAliasSection,
    ComponentExportKind, ComponentExportSection, ComponentImportSection, ComponentSection,
    ComponentTypeRef, ComponentTypeSection, ComponentValType, CoreTypeSection, EntityType,
    ExportKind, InstanceSection, MemoryType, ModuleArg, ModuleType, PrimitiveValType, RawSection,
    ValType,
    reencode::{ReencodeComponent, RoundtripReencoder},
};
use wasmparser::{
    CanonicalFunction, CanonicalOption as ParsedCanonicalOption, ComponentAlias,
    ComponentExternalKind, ComponentFuncType, ComponentType, ComponentTypeRef as ParsedTypeRef,
    ComponentValType as ParsedValType, ExternalKind, Parser, Payload,
};
use wit_component::DecodedWasm;
use wit_parser::{Function, Resolve, WorldId, WorldItem, WorldKey, abi::WasmType};

use super::asynchronous;
use super::kinds::{Kinds, check_generation_budget};
use super::walker;
use super::{ENCODER_IMPORT, OUTPUT_IMPORT, PRIVATE_PREFIX};

#[derive(Default)]
struct Counts {
    modules: u32,
    instances: u32,
    core_types: u32,
    core_funcs: u32,
    memories: u32,
    types: u32,
    funcs: u32,
}

#[derive(Clone)]
struct Lift {
    func: u32,
    ty: u32,
    options: Vec<CanonicalOption>,
}

struct Assembly {
    component: Component,
    counts: Counts,
}

impl Assembly {
    fn result_sink(
        &mut self,
        encoders: &mut BTreeMap<u32, (u32, u32)>,
        memory: u32,
        encoder: u32,
        output: u32,
    ) -> Result<(u32, u32)> {
        if let Some(pair) = encoders.get(&memory) {
            return Ok(*pair);
        }
        let reader = wat::parse_str(
            r#"(module (import "env" "memory" (memory 0)) (export "memory" (memory 0))
            (func (export "byte") (param i32) (result i32) local.get 0 i32.load8_u)
            (func (export "pages") (result i32) memory.size))"#,
        )?;
        let reader = self.core_module(&reader);
        let source = self.exports(&[("memory", ExportKind::Memory, memory)]);
        let reader = self.instantiate(reader, &[("env", source)]);
        let encoder_instance = self.instantiate(encoder, &[("source", reader)]);
        let output_memory = self.alias(encoder_instance, ExportKind::Memory, "memory");
        let mut canonical = CanonicalFunctionSection::new();
        canonical.lower(output, [CanonicalOption::Memory(output_memory)]);
        let sink = self.counts.core_funcs;
        self.counts.core_funcs += 1;
        self.section(&canonical);
        let pair = (encoder_instance, sink);
        encoders.insert(memory, pair);
        Ok(pair)
    }

    fn section(&mut self, section: &impl ComponentSection) {
        self.component.section(section);
    }

    fn core_module(&mut self, bytes: &[u8]) -> u32 {
        let index = self.counts.modules;
        self.counts.modules += 1;
        self.section(&RawSection { id: 1, data: bytes });
        index
    }

    fn exports(&mut self, items: &[(&str, ExportKind, u32)]) -> u32 {
        let index = self.counts.instances;
        self.counts.instances += 1;
        let mut section = InstanceSection::new();
        section.export_items(items.iter().copied());
        self.section(&section);
        index
    }

    fn instantiate(&mut self, module: u32, args: &[(&str, u32)]) -> u32 {
        let index = self.counts.instances;
        self.counts.instances += 1;
        let mut section = InstanceSection::new();
        section.instantiate(
            module,
            args.iter()
                .map(|(name, index)| (*name, ModuleArg::Instance(*index))),
        );
        self.section(&section);
        index
    }

    fn alias(&mut self, instance: u32, kind: ExportKind, name: &str) -> u32 {
        let counter = match kind {
            ExportKind::Func => &mut self.counts.core_funcs,
            ExportKind::Memory => &mut self.counts.memories,
            _ => unreachable!(),
        };
        let index = *counter;
        *counter += 1;
        let mut section = ComponentAliasSection::new();
        section.alias(Alias::CoreInstanceExport {
            instance,
            kind,
            name,
        });
        self.section(&section);
        index
    }

    fn encoder_import(&mut self) -> u32 {
        let mut module = ModuleType::new();
        module.import(
            "source",
            "memory",
            EntityType::Memory(MemoryType {
                minimum: 0,
                maximum: None,
                memory64: false,
                shared: false,
                page_size_log2: None,
            }),
        );
        module.ty().function([], [ValType::I32]);
        module.ty().function([ValType::I32], [ValType::I32]);
        module.import("source", "pages", EntityType::Function(0));
        module.import("source", "byte", EntityType::Function(1));
        for (name, params, results) in [
            ("begin", vec![ValType::I32; 2], vec![]),
            ("expect-kind", vec![ValType::I32], vec![]),
            ("scratch", vec![ValType::I32], vec![ValType::I32]),
            ("punctuation", vec![ValType::I32], vec![]),
            ("unsigned", vec![ValType::I64], vec![]),
            ("signed", vec![ValType::I64], vec![]),
            ("boolean", vec![ValType::I32], vec![]),
            ("character", vec![ValType::I32], vec![]),
            ("string", vec![ValType::I32; 4], vec![]),
            ("output-pointer", vec![], vec![ValType::I32]),
            ("output-length", vec![], vec![ValType::I32]),
        ] {
            let index = module.type_count();
            module.ty().function(params, results);
            module.export(name, EntityType::Function(index));
        }
        module.export(
            "memory",
            EntityType::Memory(MemoryType {
                minimum: 0,
                maximum: None,
                memory64: false,
                shared: false,
                page_size_log2: None,
            }),
        );
        let mut types = CoreTypeSection::new();
        types.ty().module(&module);
        self.section(&types);
        let mut imports = ComponentImportSection::new();
        imports.import(
            ENCODER_IMPORT,
            ComponentTypeRef::Module(self.counts.core_types),
        );
        self.counts.core_types += 1;
        self.section(&imports);
        let index = self.counts.modules;
        self.counts.modules += 1;
        index
    }

    fn output_import(&mut self) -> u32 {
        let mut types = ComponentTypeSection::new();
        let bytes = self.counts.types;
        types.defined_type().list(PrimitiveValType::U8);
        types
            .function()
            .params([("bytes", ComponentValType::Type(bytes))])
            .result(None);
        self.counts.types += 2;
        self.section(&types);
        let mut imports = ComponentImportSection::new();
        imports.import(OUTPUT_IMPORT, ComponentTypeRef::Func(bytes + 1));
        self.section(&imports);
        let index = self.counts.funcs;
        self.counts.funcs += 1;
        index
    }
}

pub fn encode(bytes: &[u8]) -> Result<Vec<u8>> {
    let DecodedWasm::Component(resolve, world) = wit_component::decode(bytes)? else {
        bail!("expected a component");
    };
    check_generation_budget(&resolve, result_functions(&resolve, world))?;
    encode_inner(bytes, &resolve, world, None)
}

struct Task {
    function: String,
    memory: Option<u32>,
    encoding: u32,
}

fn result_key(result: Option<ParsedValType>) -> (u8, u32) {
    match result {
        None => (0, 0),
        Some(ParsedValType::Primitive(ty)) => (1, ty as u32),
        Some(ParsedValType::Type(index)) => (2, index),
    }
}

fn result_functions(resolve: &Resolve, world: WorldId) -> impl Iterator<Item = &Function> {
    resolve.worlds[world]
        .exports
        .iter()
        .filter_map(|(key, item)| match (key, item) {
            (WorldKey::Name(name), WorldItem::Function(function)) if name != "init" => {
                Some(function)
            }
            _ => None,
        })
}

fn encode_inner(
    bytes: &[u8],
    resolve: &Resolve,
    world: WorldId,
    tasks: Option<Vec<Task>>,
) -> Result<Vec<u8>> {
    let mut assembly = Assembly {
        component: Component::new(),
        counts: Counts::default(),
    };
    let mut functions = BTreeMap::<u32, ComponentFuncType<'_>>::new();
    let mut lifts = BTreeMap::new();
    let mut exports = BTreeMap::new();
    let mut raw_tasks = Vec::new();
    let mut memory_origins = BTreeMap::new();
    let mut memory_aliases = BTreeMap::new();
    let mut depth = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        if matches!(payload, Payload::Version { .. }) {
            depth += 1;
            continue;
        }
        if matches!(payload, Payload::End(_)) {
            depth -= 1;
            continue;
        }
        if depth != 1 {
            continue;
        }
        if let Some((id, range)) = payload.as_section() {
            assembly.section(&RawSection {
                id,
                data: &bytes[range.start as usize..range.end as usize],
            });
        }
        let c = &mut assembly.counts;
        match payload {
            Payload::ModuleSection { .. } => c.modules += 1,
            Payload::InstanceSection(section) => c.instances += section.count(),
            Payload::CoreTypeSection(section) => c.core_types += section.count(),
            Payload::ComponentTypeSection(section) => {
                for ty in section {
                    if let ComponentType::Func(ty) = ty? {
                        functions.insert(c.types, ty);
                    }
                    c.types += 1;
                }
            }
            Payload::ComponentImportSection(section) => {
                for import in section {
                    match import?.ty {
                        ParsedTypeRef::Func(_) => c.funcs += 1,
                        ParsedTypeRef::Module(_) => c.modules += 1,
                        ParsedTypeRef::Type(_) => c.types += 1,
                        _ => {}
                    }
                }
            }
            Payload::ComponentAliasSection(section) => {
                for alias in section {
                    match alias? {
                        ComponentAlias::CoreInstanceExport {
                            kind: ExternalKind::Func,
                            ..
                        } => c.core_funcs += 1,
                        ComponentAlias::CoreInstanceExport {
                            kind: ExternalKind::Memory,
                            instance_index,
                            name,
                        } => {
                            let original = *memory_origins
                                .entry((instance_index, name.to_owned()))
                                .or_insert(c.memories);
                            memory_aliases.insert(c.memories, original);
                            c.memories += 1;
                        }
                        ComponentAlias::InstanceExport {
                            kind: ComponentExternalKind::Func,
                            ..
                        } => c.funcs += 1,
                        ComponentAlias::InstanceExport {
                            kind: ComponentExternalKind::Type,
                            ..
                        } => c.types += 1,
                        _ => {}
                    }
                }
            }
            Payload::ComponentCanonicalSection(section) => {
                for function in section {
                    match function? {
                        CanonicalFunction::Lift {
                            core_func_index,
                            type_index,
                            options,
                        } => {
                            lifts.insert(
                                c.funcs,
                                Lift {
                                    func: core_func_index,
                                    ty: type_index,
                                    options: options
                                        .iter()
                                        .map(|option| RoundtripReencoder.canonical_option(*option))
                                        .collect::<Result<Vec<_>, _>>()?,
                                },
                            );
                            c.funcs += 1;
                        }
                        CanonicalFunction::TaskReturn { result, options } => {
                            raw_tasks.push((c.core_funcs, result, options));
                            c.core_funcs += 1;
                        }
                        _ => c.core_funcs += 1,
                    }
                }
            }
            Payload::ComponentExportSection(section) => {
                for export in section {
                    let export = export?;
                    if export.kind == ComponentExternalKind::Func {
                        exports.insert(export.name.name.to_owned(), export.index);
                        if let Some(lift) = lifts.get(&export.index) {
                            lifts.insert(c.funcs, lift.clone());
                        }
                        c.funcs += 1;
                    }
                    if export.kind == ComponentExternalKind::Type {
                        c.types += 1;
                    }
                }
            }
            _ => {}
        }
    }
    if tasks.is_none() && !raw_tasks.is_empty() {
        let mut selected = Vec::new();
        let mut signatures = Vec::new();
        let mut by_result = BTreeMap::new();
        for function in result_functions(resolve, world) {
            let lift = lifts
                .get(exports.get(&function.name).context("export index")?)
                .context("canonical export")?;
            by_result
                .entry(result_key(
                    functions.get(&lift.ty).context("function type")?.result,
                ))
                .or_insert(function);
        }
        for (index, result, options) in &raw_tasks {
            let Some(function) = by_result.get(&result_key(*result)) else {
                continue;
            };
            let memory = options.iter().find_map(|o| {
                if let ParsedCanonicalOption::Memory(i) = o {
                    Some(*i)
                } else {
                    None
                }
            });
            let encoding = if options.contains(&ParsedCanonicalOption::UTF16) {
                1
            } else if options.contains(&ParsedCanonicalOption::CompactUTF16) {
                2
            } else {
                0
            };
            selected.push(Task {
                function: function.name.clone(),
                memory: memory.map(|i| memory_aliases.get(&i).copied().unwrap_or(i)),
                encoding,
            });
            signatures.push((
                *index,
                walker::flattened(resolve, function.result).unwrap_or_else(|| vec![WasmType::I32]),
            ));
        }
        let task_functions = selected.iter().filter_map(|task| {
            match &resolve.worlds[world].exports[&WorldKey::Name(task.function.clone())] {
                WorldItem::Function(function) => Some(function),
                _ => None,
            }
        });
        check_generation_budget(
            resolve,
            result_functions(resolve, world).chain(task_functions),
        )?;
        if !selected.is_empty() {
            return encode_inner(
                &asynchronous::redirect(bytes, &signatures)?,
                resolve,
                world,
                Some(selected),
            );
        }
    }
    let mut kinds = Kinds::default();
    if assembly.counts.memories == 0 {
        let module =
            assembly.core_module(&wat::parse_str("(module (memory (export \"memory\") 0))")?);
        let instance = assembly.instantiate(module, &[]);
        assembly.alias(instance, ExportKind::Memory, "memory");
    }
    let original_memory = Some(0);
    let encoder = assembly.encoder_import();
    let output = assembly.output_import();
    let mut encoders = BTreeMap::new();
    for (key, item) in &resolve.worlds[world].exports {
        let (WorldKey::Name(name), WorldItem::Function(function)) = (key, item) else {
            continue;
        };
        ensure!(
            !name.starts_with(PRIVATE_PREFIX),
            "reserved execution export name"
        );
        if name == "init" {
            continue;
        }
        let lift = lifts
            .get(exports.get(name).context("export index")?)
            .context("export must be a canonical lift")?;

        let memory = lift.options.iter().find_map(|o| {
            if let CanonicalOption::Memory(i) = o {
                Some(*i)
            } else {
                None
            }
        });
        // Even scalar-only exports share the module's memory with other exports.
        let memory = memory.or(original_memory).context("result memory")?;
        let memory = memory_aliases.get(&memory).copied().unwrap_or(memory);
        let (encoder_instance, sink) =
            assembly.result_sink(&mut encoders, memory, encoder, output)?;
        let options = &lift.options;
        let cleanup = options.iter().find_map(|o| {
            if let CanonicalOption::PostReturn(i) = o {
                Some(*i)
            } else {
                None
            }
        });
        let encoding = if options.contains(&CanonicalOption::UTF16) {
            1
        } else if options.contains(&CanonicalOption::CompactUTF16) {
            2
        } else {
            0
        };
        let kind = kinds.get(resolve, function.result)?;
        let module = walker::module(
            resolve,
            function,
            encoding,
            cleanup.is_some(),
            options.contains(&CanonicalOption::Async),
            options
                .iter()
                .any(|o| matches!(o, CanonicalOption::Callback(_))),
            kind,
        )?;
        let module = assembly.core_module(&module);
        let mut bindings = vec![
            ("memory", ExportKind::Memory, memory),
            ("run", ExportKind::Func, lift.func),
            ("output", ExportKind::Func, sink),
        ];
        if let Some(cleanup) = cleanup {
            bindings.push(("cleanup", ExportKind::Func, cleanup));
        }
        let environment = assembly.exports(&bindings);
        let instance = assembly.instantiate(
            module,
            &[("env", environment), ("encoder", encoder_instance)],
        );
        let run = assembly.alias(instance, ExportKind::Func, "run");
        let original_type = functions.get(&lift.ty).context("export function type")?;
        let mut types = ComponentTypeSection::new();
        types
            .function()
            .async_(original_type.async_)
            .params(
                original_type
                    .params
                    .iter()
                    .map(|(name, ty)| (*name, RoundtripReencoder.component_val_type(*ty))),
            )
            .result(None);
        let ty = assembly.counts.types;
        assembly.counts.types += 1;
        assembly.section(&types);
        let mut canonical = CanonicalFunctionSection::new();
        let mut options = options
            .iter()
            .filter(|o| !matches!(o, CanonicalOption::PostReturn(_)))
            .cloned()
            .collect::<Vec<_>>();
        if cleanup.is_some() {
            options.push(CanonicalOption::PostReturn(assembly.alias(
                instance,
                ExportKind::Func,
                "post-return",
            )));
        }
        canonical.lift(run, ty, options);
        let function = assembly.counts.funcs;
        assembly.counts.funcs += 1;
        assembly.section(&canonical);
        let mut exports = ComponentExportSection::new();
        exports.export(
            format!("{PRIVATE_PREFIX}{name}"),
            ComponentExportKind::Func,
            function,
            None,
        );
        assembly.section(&exports);
        assembly.counts.funcs += 1;
    }
    if let Some(tasks) = tasks {
        let mut bindings = vec![("table", ExportKind::Table, 0)];
        let mut fixup = format!(
            "(module (import \"env\" \"table\" (table {} funcref))",
            tasks.len()
        );
        let mut names = Vec::new();
        for (index, task) in tasks.iter().enumerate() {
            let WorldItem::Function(function) =
                &resolve.worlds[world].exports[&WorldKey::Name(task.function.clone())]
            else {
                bail!("task return export");
            };
            let memory = task.memory.unwrap_or(0);
            let (encoder_instance, sink) =
                assembly.result_sink(&mut encoders, memory, encoder, output)?;
            let mut canonical = CanonicalFunctionSection::new();
            // Erase only the result type. Wasmtime must still enforce the
            // original memory identity and string encoding on task.return.
            let mut options = vec![match task.encoding {
                1 => CanonicalOption::UTF16,
                2 => CanonicalOption::CompactUTF16,
                _ => CanonicalOption::UTF8,
            }];
            if let Some(memory) = task.memory {
                options.push(CanonicalOption::Memory(memory));
            }
            canonical.task_return(None, options);
            let done = assembly.counts.core_funcs;
            assembly.counts.core_funcs += 1;
            assembly.section(&canonical);
            let module = walker::task_return(
                resolve,
                function.result,
                task.encoding,
                kinds.get(resolve, function.result)?,
            )?;
            let module = assembly.core_module(&module);
            let environment = assembly.exports(&[
                ("memory", ExportKind::Memory, memory),
                ("output", ExportKind::Func, sink),
                ("done", ExportKind::Func, done),
            ]);
            let instance = assembly.instantiate(
                module,
                &[("env", environment), ("encoder", encoder_instance)],
            );
            let run = assembly.alias(instance, ExportKind::Func, "run");
            names.push((format!("return-{index}"), run));
            let params = walker::flattened(resolve, function.result)
                .unwrap_or_else(|| vec![WasmType::I32])
                .iter()
                .map(|ty| format!("(param {})", walker::wasm_type(ty)))
                .collect::<String>();
            fixup.push_str(&format!(
                "(import \"env\" \"return-{index}\" (func $f{index} {params}))"
            ));
        }
        fixup.push_str("(elem (i32.const 0) func");
        for index in 0..tasks.len() {
            fixup.push_str(&format!(" $f{index}"));
        }
        fixup.push_str("))");
        bindings.extend(
            names
                .iter()
                .map(|(name, func)| (name.as_str(), ExportKind::Func, *func)),
        );
        let environment = assembly.exports(&bindings);
        let module = assembly.core_module(&wat::parse_str(fixup)?);
        assembly.instantiate(module, &[("env", environment)]);
    }
    Ok(assembly.component.finish())
}
