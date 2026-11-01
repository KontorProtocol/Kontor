use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use wasmtime::component::{
    Type, Val,
    wasm_wave::{
        ast::{Node, NodeType},
        untyped::UntypedFuncCall,
    },
};
use wasmtime::{Store, Trap};

use super::MAX_EXPR_DEPTH;
use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::lowering::Lowering;

#[cfg(test)]
mod tests;

pub(super) fn params(
    call: &UntypedFuncCall<'_>,
    types: impl Iterator<Item = Type>,
    store: &mut Store<Runtime>,
) -> Result<Vec<Val>> {
    ArgumentBuilder {
        source: call.source(),
        store,
        lowering_fuel: 0,
    }
    .build(call.params_node(), types)
}

// Construction already bounds every visited value and schema field. Reuse those
// visits to price the later dynamic lowering, including empty payloads, without
// an additional unmetered tree walk. Only a completed build reserves lowering.
struct ArgumentBuilder<'a> {
    source: &'a str,
    store: &'a mut Store<Runtime>,
    lowering_fuel: u64,
}

impl ArgumentBuilder<'_> {
    fn build(
        mut self,
        node: Option<&Node>,
        mut types: impl Iterator<Item = Type>,
    ) -> Result<Vec<Val>> {
        let Some(node) = node else {
            ensure!(types.next().is_none(), "missing required parameters");
            return Ok(Vec::new());
        };
        let mut values = Vec::new();
        for node in node.as_tuple()? {
            let Some(ty) = types.next() else {
                bail!("too many parameters");
            };
            values.push(self.value(node, &ty, 0)?);
        }
        for ty in types {
            self.charge_value()?;
            ensure!(matches!(ty, Type::Option(_)), "missing required parameter");
            values.push(Val::Option(None));
        }
        Fuel::LoweringValues(self.lowering_fuel).consume_with_store(self.store)?;
        Ok(values)
    }

    fn charge_value(&mut self) -> Result<()> {
        self.charge_construction(Fuel::WaveValue)
    }

    fn charge_field(&mut self, name: &str) -> Result<()> {
        self.charge_construction(Fuel::WaveTypeField(name.len() as u64))
    }

    fn charge_construction(&mut self, fuel: Fuel) -> Result<()> {
        fuel.consume_with_store(&mut *self.store)?;
        self.add_lowering_cost(fuel.cost())
    }

    fn add_lowering_cost(&mut self, fuel: u64) -> Result<()> {
        self.lowering_fuel = self
            .lowering_fuel
            .checked_add(fuel)
            .ok_or(Trap::OutOfFuel)?;
        Ok(())
    }

    // Keep WAVE's grammar and scalar decoding. Construct containers here so omitted
    // fields are charged before allocation, without Val::make_record's repeated
    // field searches and recursive revalidation of already typed children.
    fn value(&mut self, node: &Node, ty: &Type, depth: usize) -> Result<Val> {
        ensure!(depth <= MAX_EXPR_DEPTH, "WAVE value nesting is too deep");
        self.charge_value()?;
        let value = match ty {
            Type::List(list) => {
                let ty = list.ty();
                let mut values = Vec::new();
                for node in node.as_list()? {
                    values.push(self.value(node, &ty, depth + 1)?);
                }
                Val::List(values)
            }
            Type::Record(record) => {
                // WAVE accepts unordered fields; its parser rejects duplicates. Raw
                // syntax, including unknown fields, is covered by WaveInputBytes.
                let supplied = node.as_record(self.source)?.collect::<BTreeMap<_, _>>();
                let mut fields = Vec::new();
                for field in record.fields() {
                    self.charge_field(field.name)?;
                    let val = if let Some(node) = supplied.get(field.name) {
                        self.value(node, &field.ty, depth + 1)?
                    } else {
                        self.charge_value()?;
                        ensure!(
                            matches!(field.ty, Type::Option(_)),
                            "missing field: {}",
                            field.name
                        );
                        Val::Option(None)
                    };
                    fields.push((field.name.to_owned(), val));
                }
                Val::Record(fields)
            }
            Type::Tuple(tuple) => {
                let nodes = node.as_tuple()?;
                let types = tuple.types();
                ensure!(nodes.len() == types.len(), "wrong number of tuple elements");
                let mut values = Vec::new();
                for (node, ty) in nodes.zip(types) {
                    values.push(self.value(node, &ty, depth + 1)?);
                }
                Val::Tuple(values)
            }
            Type::Variant(variant) => {
                let (name, node) = node.as_variant(self.source)?;
                let mut selected = None;
                for case in variant.cases() {
                    self.charge_field(case.name)?;
                    if case.name == name {
                        selected = Some(case.ty);
                        break;
                    }
                }
                let Some(ty) = selected else {
                    bail!("unknown variant case: {name}")
                };
                Val::Variant(name.to_owned(), self.payload(node, ty, depth + 1)?)
            }
            Type::Enum(enumeration) => {
                let name = node.as_enum(self.source)?;
                let mut found = false;
                for candidate in enumeration.names() {
                    self.charge_field(candidate)?;
                    if candidate == name {
                        found = true;
                        break;
                    }
                }
                ensure!(found, "unknown enum case: {name}");
                Val::Enum(name.to_owned())
            }
            Type::Option(option) => {
                let ty = option.ty();
                let val = match node.ty() {
                    NodeType::OptionNone => None,
                    NodeType::OptionSome => self.payload(node.as_option()?, Some(ty), depth + 1)?,
                    _ => {
                        ensure!(flattenable(&ty), "expected an explicit option");
                        Some(Box::new(self.value(node, &ty, depth + 1)?))
                    }
                };
                Val::Option(val)
            }
            Type::Result(result) => {
                let val = match node.ty() {
                    NodeType::ResultOk | NodeType::ResultErr => match node.as_result()? {
                        Ok(node) => Ok(self.payload(node, result.ok(), depth + 1)?),
                        Err(node) => Err(self.payload(node, result.err(), depth + 1)?),
                    },
                    _ => {
                        let Some(ty) = result.ok() else {
                            bail!("expected an explicit result")
                        };
                        ensure!(flattenable(&ty), "expected an explicit result");
                        Ok(Some(Box::new(self.value(node, &ty, depth + 1)?)))
                    }
                };
                Val::Result(val)
            }
            Type::Flags(flags) => {
                // Validate membership once instead of scanning the schema for every
                // supplied flag. Both the schema and supplied names can be large.
                let mut names = BTreeSet::new();
                for name in flags.names() {
                    self.charge_field(name)?;
                    names.insert(name);
                }
                let mut values = Vec::new();
                for name in node.as_flags(self.source)? {
                    self.charge_value()?;
                    self.add_lowering_cost(name.len() as u64)?;
                    ensure!(names.contains(name), "unknown flag: {name}");
                    values.push(name.to_owned());
                }
                Val::Flags(values)
            }
            // No compound value may fall through to the unbounded stock builder.
            Type::Bool
            | Type::S8
            | Type::U8
            | Type::S16
            | Type::U16
            | Type::S32
            | Type::U32
            | Type::S64
            | Type::U64
            | Type::Float32
            | Type::Float64
            | Type::Char
            | Type::String => node.to_wasm_value(ty, self.source)?,
            _ => bail!("unsupported WAVE parameter type"),
        };
        if let Val::String(text) = &value {
            self.add_lowering_cost(text.lowering_bytes()?)?;
        }
        Ok(value)
    }

    fn payload(
        &mut self,
        node: Option<&Node>,
        ty: Option<Type>,
        depth: usize,
    ) -> Result<Option<Box<Val>>> {
        match (node, ty) {
            (Some(node), Some(ty)) => Ok(Some(Box::new(self.value(node, &ty, depth)?))),
            (None, None) => Ok(None),
            _ => bail!("variant payload does not match its type"),
        }
    }
}

fn flattenable(ty: &Type) -> bool {
    !matches!(ty, Type::Option(_) | Type::Result(_))
}
