use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::Write;

use anyhow::Result;
use wasm_encoder::{
    Alias, Component, ComponentAliasSection, ExportKind, InstanceSection, ModuleArg, RawSection,
    reencode::{Error, Reencode, ReencodeComponent},
};
use wasmparser::Parser;
use wit_parser::abi::WasmType;

use super::walker::wasm_type;

struct Redirect {
    functions: BTreeMap<u32, u32>,
    depth: u32,
}

impl Reencode for Redirect {
    type Error = Infallible;
    fn function_index(&mut self, index: u32) -> Result<u32, Error<Self::Error>> {
        Ok(if self.depth == 0 {
            self.functions
                .get(&index)
                .copied()
                .unwrap_or(index + self.functions.len() as u32)
        } else {
            index
        })
    }
    fn table_index(&mut self, index: u32) -> Result<u32, Error<Self::Error>> {
        Ok(index + u32::from(self.depth == 0))
    }
}

impl ReencodeComponent for Redirect {
    fn push_depth(&mut self) {
        self.depth += 1;
    }
    fn pop_depth(&mut self) {
        self.depth -= 1;
    }
    fn module_index(&mut self, index: u32) -> u32 {
        index + u32::from(self.depth == 0)
    }
    fn instance_index(&mut self, index: u32) -> u32 {
        index + u32::from(self.depth == 0)
    }
    fn outer_module_index(&mut self, count: u32, index: u32) -> u32 {
        index + u32::from(count == self.depth)
    }
    fn parse_component_submodule(
        &mut self,
        component: &mut Component,
        _: Parser,
        module: &[u8],
    ) -> Result<(), Error<Self::Error>> {
        // Core module indices are a separate namespace. The injected forwarding
        // functions replace their component-level bindings, not their code.
        component.section(&RawSection {
            id: 1,
            data: module,
        });
        Ok(())
    }
}

pub(super) fn redirect(bytes: &[u8], functions: &[(u32, Vec<WasmType>)]) -> Result<Vec<u8>> {
    let mut component = Component::new();
    let mut module = format!(
        "(module (table (export \"returns\") {} funcref)",
        functions.len()
    );
    for (index, (_, signature)) in functions.iter().enumerate() {
        let params = signature
            .iter()
            .map(|ty| format!("(param {})", wasm_type(ty)))
            .collect::<String>();
        write!(
            module,
            "(type $t{index} (func {params})) (func (export \"return-{index}\") {params}"
        )?;
        for param in 0..signature.len() {
            write!(module, "local.get {param} ")?;
        }
        write!(module, "i32.const {index} call_indirect (type $t{index}))")?;
    }
    module.push(')');
    let module = wat::parse_str(&module)?;
    component.section(&RawSection {
        id: 1,
        data: &module,
    });
    let mut instances = InstanceSection::new();
    instances.instantiate(0, [] as [(&str, ModuleArg); 0]);
    component.section(&instances);
    let mut aliases = ComponentAliasSection::new();
    aliases.alias(Alias::CoreInstanceExport {
        instance: 0,
        kind: ExportKind::Table,
        name: "returns",
    });
    for index in 0..functions.len() {
        aliases.alias(Alias::CoreInstanceExport {
            instance: 0,
            kind: ExportKind::Func,
            name: &format!("return-{index}"),
        });
    }
    component.section(&aliases);
    Redirect {
        functions: functions
            .iter()
            .enumerate()
            .map(|(index, (original, _))| (*original, index as u32))
            .collect(),
        depth: 0,
    }
    .parse_component(&mut component, Parser::new(0), bytes)?;
    Ok(component.finish())
}
