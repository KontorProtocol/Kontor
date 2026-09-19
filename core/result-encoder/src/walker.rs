use std::collections::HashMap;
use std::fmt::Write;

use anyhow::{Context, Result, bail, ensure};
use wasm_wave::lex::Keyword;
use wit_parser::{
    Function, Int, Resolve, SizeAlign, Type, TypeDefKind,
    abi::{AbiVariant, FlatTypes, WasmType},
};

const PREAMBLE: &str = r#"
(import "env" "memory" (memory 0))
(import "env" "output" (func $output (param i32 i32)))
(import "encoder" "memory" (memory 0))
(import "encoder" "begin" (func $begin (param i32 i32)))
(import "encoder" "punctuation" (func $byte (param i32)))
(import "encoder" "unsigned" (func $unsigned (param i64)))
(import "encoder" "signed" (func $signed (param i64)))
(import "encoder" "boolean" (func $boolean (param i32)))
(import "encoder" "character" (func $character (param i32)))
(import "encoder" "string" (func $string (param i32 i32 i32 i32)))
(import "encoder" "output-pointer" (func $pointer (result i32)))
(import "encoder" "output-length" (func $length (result i32)))
"#;
const RANGE: &str = r#"
(global $depth (mut i32) (i32.const -1))
(func $range0 (param $ptr i32) (param $len i64) (param $align i32)
  local.get $ptr local.get $align i32.const 1 i32.sub i32.and
  if unreachable end
  local.get $ptr i64.extend_i32_u local.get $len i64.add
  memory.size i64.extend_i32_u i64.const 65536 i64.mul i64.gt_u
  if unreachable end)
"#;

struct Walker<'a> {
    resolve: &'a Resolve,
    sizes: SizeAlign,
    encoding: u32,
    functions: Vec<String>,
    cache: HashMap<(Type, u32), usize>,
}

fn literal(body: &mut String, text: &str) {
    for byte in text.bytes() {
        writeln!(body, "i32.const {byte} call $byte").unwrap();
    }
}

fn label(body: &mut String, name: &str) {
    if Keyword::decode(name).is_some() {
        literal(body, "%");
    }
    literal(body, name);
}

pub(super) fn wasm_type(ty: &WasmType) -> &'static str {
    match ty {
        WasmType::I32 | WasmType::Pointer | WasmType::Length => "i32",
        WasmType::I64 | WasmType::PointerOrI64 => "i64",
        WasmType::F32 => "f32",
        WasmType::F64 => "f64",
    }
}

impl Walker<'_> {
    fn unalias(&self, mut ty: Type) -> Type {
        while let Type::Id(id) = ty {
            if let TypeDefKind::Type(inner) = self.resolve.types[id].kind {
                ty = inner;
            } else {
                break;
            }
        }
        ty
    }

    fn integer(body: &mut String, ty: Type, memory: Option<u32>) -> bool {
        if let Some(memory) = memory {
            let (load, render) = match ty {
                Type::U8 => ("i32.load8_u", "i64.extend_i32_u call $unsigned"),
                Type::U16 => ("i32.load16_u", "i64.extend_i32_u call $unsigned"),
                Type::U32 => ("i32.load", "i64.extend_i32_u call $unsigned"),
                Type::U64 => ("i64.load", "call $unsigned"),
                Type::S8 => ("i32.load8_s", "i64.extend_i32_s call $signed"),
                Type::S16 => ("i32.load16_s", "i64.extend_i32_s call $signed"),
                Type::S32 => ("i32.load", "i64.extend_i32_s call $signed"),
                Type::S64 => ("i64.load", "call $signed"),
                Type::Bool => ("i32.load8_u", "call $boolean"),
                Type::Char => ("i32.load", "call $character"),
                _ => return false,
            };
            writeln!(body, "local.get $p {load} {memory} {render}").unwrap();
        } else {
            let render = match ty {
                Type::U8 => "i32.const 255 i32.and i64.extend_i32_u call $unsigned",
                Type::U16 => "i32.const 65535 i32.and i64.extend_i32_u call $unsigned",
                Type::U32 => "i64.extend_i32_u call $unsigned",
                Type::U64 => "call $unsigned",
                Type::S8 => "i32.extend8_s i64.extend_i32_s call $signed",
                Type::S16 => "i32.extend16_s i64.extend_i32_s call $signed",
                Type::S32 => "i64.extend_i32_s call $signed",
                Type::S64 => "call $signed",
                Type::Bool => "call $boolean",
                Type::Char => "call $character",
                _ => return false,
            };
            writeln!(body, "local.get $result {render}").unwrap();
        }
        true
    }

    fn cases(
        &mut self,
        body: &mut String,
        cases: &[(String, Option<Type>)],
        memory: bool,
        depth: usize,
        escape_names: bool,
        memory_id: u32,
    ) -> Result<()> {
        let tag = match cases.len() {
            0..=256 => Int::U8,
            257..=65536 => Int::U16,
            _ => Int::U32,
        };
        let load = match tag {
            Int::U8 => "i32.load8_u",
            Int::U16 => "i32.load16_u",
            _ => "i32.load",
        };
        if memory {
            writeln!(body, "local.get $p {load} {memory_id} local.set $tag")?;
        } else {
            body.push_str("local.get $result local.set $tag\n");
        }
        writeln!(
            body,
            "local.get $tag i32.const {} i32.ge_u if unreachable end",
            cases.len()
        )?;
        let offset = self
            .sizes
            .payload_offset(tag, cases.iter().map(|c| c.1.as_ref()))
            .size_wasm32();
        // A balanced branch tree bounds dispatch by log(case count), avoiding
        // charging a late enum case for a linear scan through every alternative.
        self.case_tree(
            body,
            cases,
            0,
            offset,
            memory,
            depth,
            escape_names,
            memory_id,
        )
    }

    fn case_tree(
        &mut self,
        body: &mut String,
        cases: &[(String, Option<Type>)],
        start: usize,
        offset: usize,
        memory: bool,
        depth: usize,
        escape_names: bool,
        memory_id: u32,
    ) -> Result<()> {
        if cases.len() == 1 {
            let (name, ty) = &cases[0];
            if escape_names {
                label(body, name);
            } else {
                literal(body, name);
            }
            if let Some(ty) = ty {
                ensure!(memory, "payload cannot use scalar result ABI");
                literal(body, "(");
                let child = self.walk(*ty, depth + 1, memory_id)?;
                writeln!(
                    body,
                    "local.get $p i32.const {offset} i32.add call $v{child}"
                )?;
                literal(body, ")");
            }
        } else if !cases.is_empty() {
            let mid = cases.len() / 2;
            writeln!(body, "local.get $tag i32.const {} i32.lt_u if", start + mid)?;
            self.case_tree(
                body,
                &cases[..mid],
                start,
                offset,
                memory,
                depth,
                escape_names,
                memory_id,
            )?;
            body.push_str("else\n");
            self.case_tree(
                body,
                &cases[mid..],
                start + mid,
                offset,
                memory,
                depth,
                escape_names,
                memory_id,
            )?;
            body.push_str("end\n");
        }
        Ok(())
    }

    fn flat(&mut self, ty: Type, body: &mut String, depth: usize) -> Result<()> {
        ensure!(depth <= 64, "result type is too deep");
        let ty = self.unalias(ty);
        if Self::integer(body, ty, None) {
            return Ok(());
        }
        let Type::Id(id) = ty else {
            bail!("unsupported scalar result type {ty:?}");
        };
        match &self.resolve.types[id].kind {
            TypeDefKind::Record(record) => {
                ensure!(record.fields.len() == 1, "unexpected scalar record ABI");
                literal(body, "{");
                literal(body, &record.fields[0].name);
                literal(body, ": ");
                self.flat(record.fields[0].ty, body, depth + 1)?;
                literal(body, "}");
            }
            TypeDefKind::Enum(enumeration) => self.cases(
                body,
                &enumeration
                    .cases
                    .iter()
                    .map(|c| (c.name.clone(), None))
                    .collect::<Vec<_>>(),
                false,
                depth,
                true,
                0,
            )?,
            TypeDefKind::Variant(variant) => self.cases(
                body,
                &variant
                    .cases
                    .iter()
                    .map(|c| (c.name.clone(), c.ty))
                    .collect::<Vec<_>>(),
                false,
                depth,
                true,
                0,
            )?,
            TypeDefKind::Result(result) => self.cases(
                body,
                &[("ok".into(), result.ok), ("err".into(), result.err)],
                false,
                depth,
                false,
                0,
            )?,
            _ => bail!("unsupported scalar result ABI"),
        }
        Ok(())
    }

    fn walk(&mut self, ty: Type, depth: usize, memory_id: u32) -> Result<usize> {
        ensure!(depth <= 256, "result type is too deep");
        let ty = self.unalias(ty);
        if let Some(index) = self.cache.get(&(ty, memory_id)) {
            return Ok(*index);
        }
        let index = self.functions.len();
        self.functions.push(String::new());
        self.cache.insert((ty, memory_id), index);
        let size = self.sizes.size(&ty).size_wasm32();
        let align = self.sizes.align(&ty).align_wasm32();
        let mut body = format!(
            "global.get $depth i32.const 1 i32.add global.set $depth global.get $depth i32.const 64 i32.gt_u if unreachable end\nlocal.get $p i64.const {size} i32.const {align} call $range{memory_id}\n"
        );
        if Self::integer(&mut body, ty, Some(memory_id)) {
        } else {
            match ty {
                Type::String => writeln!(
                    body,
                    "local.get $p i32.load {memory_id} local.get $p i32.load {memory_id} offset=4 i32.const {} i32.const 0 call $string",
                    self.encoding
                )?,
                Type::Id(id) => {
                    match self.resolve.types[id].kind.clone() {
                        TypeDefKind::Record(record) => {
                            literal(&mut body, "{");
                            let offsets = self
                                .sizes
                                .field_offsets(record.fields.iter().map(|f| &f.ty));
                            for (field, (offset, ty)) in record.fields.iter().zip(offsets) {
                                let offset = offset.size_wasm32();
                                let optional = matches!(self.unalias(*ty), Type::Id(id) if matches!(self.resolve.types[id].kind, TypeDefKind::Option(_)));
                                if optional {
                                    body.push_str("global.get $depth i32.const 64 i32.ge_u if unreachable end\n");
                                    writeln!(
                                        body,
                                        "local.get $p i32.load8_u {memory_id} offset={offset} if"
                                    )?;
                                }
                                body.push_str("local.get $fields if\n");
                                literal(&mut body, ", ");
                                body.push_str("end i32.const 1 local.set $fields\n");
                                literal(&mut body, &field.name);
                                literal(&mut body, ": ");
                                let child = self.walk(*ty, depth + 1, memory_id)?;
                                writeln!(
                                    body,
                                    "local.get $p i32.const {offset} i32.add call $v{child}"
                                )?;
                                if optional {
                                    body.push_str("end\n");
                                }
                            }
                            body.push_str("local.get $fields i32.eqz if\n");
                            literal(&mut body, ":");
                            body.push_str("end\n");
                            literal(&mut body, "}");
                        }
                        TypeDefKind::List(ty) => {
                            let stride = self.sizes.size(&ty).size_wasm32();
                            let align = self.sizes.align(&ty).align_wasm32();
                            let child = self.walk(ty, depth + 1, 0)?;
                            writeln!(
                                body,
                                "local.get $p i32.load {memory_id} local.set $ptr\nlocal.get $p i32.load {memory_id} offset=4 local.set $len"
                            )?;
                            writeln!(
                                body,
                                "local.get $ptr local.get $len i64.extend_i32_u i64.const {stride} i64.mul i32.const {align} call $range0"
                            )?;
                            literal(&mut body, "[");
                            body.push_str("block $end loop $next local.get $i local.get $len i32.ge_u br_if $end local.get $i if\n");
                            literal(&mut body, ", ");
                            body.push_str("end\n");
                            writeln!(
                                body,
                                "local.get $ptr local.get $i i32.const {stride} i32.mul i32.add call $v{child}\nlocal.get $i i32.const 1 i32.add local.set $i br $next end end"
                            )?;
                            literal(&mut body, "]");
                        }
                        TypeDefKind::Option(ty) => self.cases(
                            &mut body,
                            &[("none".into(), None), ("some".into(), Some(ty))],
                            true,
                            depth,
                            false,
                            memory_id,
                        )?,
                        TypeDefKind::Result(result) => self.cases(
                            &mut body,
                            &[("ok".into(), result.ok), ("err".into(), result.err)],
                            true,
                            depth,
                            false,
                            memory_id,
                        )?,
                        TypeDefKind::Variant(variant) => self.cases(
                            &mut body,
                            &variant
                                .cases
                                .iter()
                                .map(|c| (c.name.clone(), c.ty))
                                .collect::<Vec<_>>(),
                            true,
                            depth,
                            true,
                            memory_id,
                        )?,
                        TypeDefKind::Enum(enumeration) => self.cases(
                            &mut body,
                            &enumeration
                                .cases
                                .iter()
                                .map(|c| (c.name.clone(), None))
                                .collect::<Vec<_>>(),
                            true,
                            depth,
                            true,
                            memory_id,
                        )?,
                        _ => bail!("unsupported result type {:?}", self.resolve.types[id].kind),
                    }
                }
                _ => bail!("unsupported result type {ty:?}"),
            }
        }
        body.push_str(" global.get $depth i32.const 1 i32.sub global.set $depth");
        self.functions[index] = format!(
            "(func $v{index} (param $p i32) (local $ptr i32) (local $len i32) (local $i i32) (local $tag i32) (local $fields i32) {body})"
        );
        Ok(index)
    }
}

pub fn module(
    resolve: &Resolve,
    function: &Function,
    encoding: u32,
    cleanup: bool,
    async_: bool,
    callback: bool,
    kind: u32,
) -> Result<Vec<u8>> {
    let mut sizes = SizeAlign::default();
    sizes.fill(resolve)?;
    let mut walker = Walker {
        resolve,
        sizes,
        encoding,
        functions: Vec::new(),
        cache: HashMap::new(),
    };
    let abi = if async_ {
        if callback {
            AbiVariant::GuestExportAsync
        } else {
            AbiVariant::GuestExportAsyncStackful
        }
    } else {
        AbiVariant::GuestExport
    };
    let signature = resolve.wasm_signature(abi, function);
    let params = signature
        .params
        .iter()
        .map(|ty| format!("(param {})", wasm_type(ty)))
        .collect::<String>();
    let results = signature
        .results
        .iter()
        .map(|ty| format!("(result {})", wasm_type(ty)))
        .collect::<String>();
    let mut code =
        format!("(module {PREAMBLE} (import \"env\" \"run\" (func $run {params} {results}))");
    if cleanup {
        write!(
            code,
            "(import \"env\" \"cleanup\" (func $cleanup {}))",
            signature
                .results
                .iter()
                .map(|ty| format!("(param {})", wasm_type(ty)))
                .collect::<String>()
        )?;
    }
    if cleanup && let Some(ty) = signature.results.first() {
        let ty = wasm_type(ty);
        write!(code, "(global $return (mut {ty}) ({ty}.const 0))")?;
    }
    code.push_str(RANGE);
    code.push_str(
        &RANGE
            .replace("(global $depth (mut i32) (i32.const -1))", "")
            .replace("$range0", "$range1")
            .replace("memory.size", "memory.size 1"),
    );
    let mut body = format!(
        "i32.const {kind} i32.const {} call $begin\n",
        u32::from(function.name == "fallback")
    );
    for index in 0..signature.params.len() {
        writeln!(body, "local.get {index}")?;
    }
    body.push_str("call $run\n");
    if async_ {
        write!(code, "(func (export \"run\") {params} {results} {body}))")?;
        return Ok(wat::parse_str(&code)?);
    }
    let mut local = String::new();
    if let Some(ty) = signature.results.first() {
        local = format!("(local $result {})", wasm_type(ty));
        body.push_str("local.set $result\n");
        if cleanup {
            body.push_str("local.get $result global.set $return\n");
        }
    }
    if let Some(result) = function.result {
        if signature.retptr {
            if function.name == "fallback" {
                body.push_str("local.get $result i64.const 8 i32.const 4 call $range0\n");
                writeln!(
                    body,
                    "local.get $result i32.load local.get $result i32.load offset=4 i32.const {encoding} i32.const 1 call $string"
                )?;
            } else {
                let root = walker.walk(result, 0, 0)?;
                writeln!(body, "local.get $result call $v{root}")?;
            }
        } else {
            walker.flat(result, &mut body, 0)?;
        }
    }
    body.push_str("call $pointer call $length call $output\n");
    if cleanup {
        code.push_str("(func (export \"post-return\") ");
        if !signature.results.is_empty() {
            code.push_str("global.get $return ");
        }
        code.push_str("call $cleanup)");
    }
    code.push_str(&walker.functions.join("\n"));
    write!(
        code,
        "(func (export \"run\") {params} {local} (local $tag i32) {body}))"
    )?;
    Ok(wat::parse_str(&code)?)
}

pub(super) fn flattened(resolve: &Resolve, ty: Option<Type>) -> Option<Vec<WasmType>> {
    let mut storage = [WasmType::I32; 16];
    let mut flat = FlatTypes::new(&mut storage);
    if let Some(ty) = ty
        && !resolve.push_flat(&ty, &mut flat)
    {
        return None;
    }
    Some(flat.to_vec())
}

fn load_flat(body: &mut String, index: usize, flat: &[WasmType], ty: WasmType) {
    writeln!(body, "local.get {index}").unwrap();
    match (wasm_type(&flat[index]), wasm_type(&ty)) {
        ("i64", "i32") => body.push_str("i32.wrap_i64\n"),
        ("i32", "i64") => body.push_str("i64.extend_i32_u\n"),
        _ => {}
    }
}

impl Walker<'_> {
    fn store_flat(
        &self,
        body: &mut String,
        address: usize,
        index: usize,
        flat: &[WasmType],
        ty: WasmType,
        store: &str,
        boolean: bool,
    ) {
        writeln!(body, "local.get $scratch i32.const {address} i32.add").unwrap();
        load_flat(body, index, flat, ty);
        if boolean {
            body.push_str("i32.eqz i32.eqz\n");
        }
        writeln!(body, "{store} 1").unwrap();
    }

    fn lower_flat(
        &self,
        ty: Type,
        address: usize,
        cursor: &mut usize,
        flat: &[WasmType],
        body: &mut String,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth <= 256, "result type is too deep");
        let ty = self.unalias(ty);
        let scalar = match ty {
            Type::Bool | Type::U8 | Type::S8 => Some((WasmType::I32, "i32.store8")),
            Type::U16 | Type::S16 => Some((WasmType::I32, "i32.store16")),
            Type::U32 | Type::S32 | Type::Char => Some((WasmType::I32, "i32.store")),
            Type::U64 | Type::S64 => Some((WasmType::I64, "i64.store")),
            _ => None,
        };
        if let Some((core_type, store)) = scalar {
            self.store_flat(
                body,
                address,
                *cursor,
                flat,
                core_type,
                store,
                ty == Type::Bool,
            );
            *cursor += 1;
            return Ok(());
        }
        if ty == Type::String
            || matches!(ty, Type::Id(id) if matches!(self.resolve.types[id].kind, TypeDefKind::List(_)))
        {
            for offset in [0, 4] {
                self.store_flat(
                    body,
                    address + offset,
                    *cursor,
                    flat,
                    WasmType::I32,
                    "i32.store",
                    false,
                );
                *cursor += 1;
            }
            return Ok(());
        }
        let Type::Id(id) = ty else {
            bail!("unsupported flat result type");
        };
        let cases = match &self.resolve.types[id].kind {
            TypeDefKind::Record(record) => {
                for (offset, ty) in self
                    .sizes
                    .field_offsets(record.fields.iter().map(|f| &f.ty))
                {
                    self.lower_flat(
                        *ty,
                        address + offset.size_wasm32(),
                        cursor,
                        flat,
                        body,
                        depth + 1,
                    )?;
                }
                return Ok(());
            }
            TypeDefKind::Variant(v) => v.cases.iter().map(|c| c.ty).collect::<Vec<_>>(),
            TypeDefKind::Enum(v) => vec![None; v.cases.len()],
            TypeDefKind::Option(ty) => vec![None, Some(*ty)],
            TypeDefKind::Result(r) => vec![r.ok, r.err],
            _ => bail!("unsupported flat result layout"),
        };
        let tag = match cases.len() {
            0..=256 => Int::U8,
            257..=65536 => Int::U16,
            _ => Int::U32,
        };
        let store = match tag {
            Int::U8 => "i32.store8",
            Int::U16 => "i32.store16",
            _ => "i32.store",
        };
        load_flat(body, *cursor, flat, WasmType::I32);
        writeln!(
            body,
            "i32.const {} i32.ge_u if unreachable end",
            cases.len()
        )?;
        self.store_flat(body, address, *cursor, flat, WasmType::I32, store, false);
        let payload = self
            .sizes
            .payload_offset(tag, cases.iter().map(Option::as_ref))
            .size_wasm32();
        self.lower_cases(&cases, 0, address + payload, *cursor, flat, body, depth)?;
        *cursor += flattened(self.resolve, Some(ty))
            .context("subtype exceeds flat result capacity")?
            .len();
        Ok(())
    }

    fn lower_cases(
        &self,
        cases: &[Option<Type>],
        first: usize,
        address: usize,
        tag: usize,
        flat: &[WasmType],
        body: &mut String,
        depth: usize,
    ) -> Result<()> {
        if cases.len() == 1 {
            if let Some(ty) = cases[0] {
                self.lower_flat(ty, address, &mut (tag + 1), flat, body, depth + 1)?;
            }
        } else if !cases.is_empty() {
            let mid = cases.len() / 2;
            load_flat(body, tag, flat, WasmType::I32);
            writeln!(body, "i32.const {} i32.lt_u if", first + mid)?;
            self.lower_cases(&cases[..mid], first, address, tag, flat, body, depth)?;
            body.push_str("else\n");
            self.lower_cases(&cases[mid..], first + mid, address, tag, flat, body, depth)?;
            body.push_str("end\n");
        }
        Ok(())
    }
}

pub(super) fn task_return(
    resolve: &Resolve,
    ty: Option<Type>,
    encoding: u32,
    kind: u32,
) -> Result<Vec<u8>> {
    let mut sizes = SizeAlign::default();
    sizes.fill(resolve)?;
    let mut walker = Walker {
        resolve,
        sizes,
        encoding,
        functions: Vec::new(),
        cache: HashMap::new(),
    };
    let flat = flattened(resolve, ty);
    let signature = flat.clone().unwrap_or_else(|| vec![WasmType::I32]);
    let params = signature
        .iter()
        .map(|ty| format!("(param {})", wasm_type(ty)))
        .collect::<String>();
    let mut code = format!(
        r#"(module {PREAMBLE}
        (import "env" "done" (func $done))
        (import "encoder" "expect-kind" (func $expect (param i32)))
        (import "encoder" "scratch" (func $scratch (param i32) (result i32)))
        {RANGE} {}"#,
        RANGE
            .replace("(global $depth (mut i32) (i32.const -1))", "")
            .replace("$range0", "$range1")
            .replace("memory.size", "memory.size 1")
    );
    let mut body = format!("i32.const {kind} call $expect\n");
    if let Some(ty) = ty {
        let memory = if let Some(flat) = &flat {
            let size = walker.sizes.size(&ty).size_wasm32();
            writeln!(body, "i32.const {size} call $scratch local.set $scratch")?;
            walker.lower_flat(ty, 0, &mut 0, flat, &mut body, 0)?;
            1
        } else {
            0
        };
        let pointer = if memory == 1 {
            "local.get $scratch"
        } else {
            "local.get 0"
        };
        if walker.unalias(ty) == Type::String {
            writeln!(
                body,
                "{pointer} i32.load {memory} {pointer} i32.load {memory} offset=4 i32.const {encoding} i32.const 2 call $string"
            )?;
        } else {
            let root = walker.walk(ty, 0, memory)?;
            writeln!(body, "{pointer} call $v{root}")?;
        }
    }
    body.push_str("call $pointer call $length call $output call $done\n");
    code.push_str(&walker.functions.join("\n"));
    write!(
        code,
        "(func (export \"run\") {params} (local $scratch i32) {body}))"
    )?;
    Ok(wat::parse_str(&code)?)
}
