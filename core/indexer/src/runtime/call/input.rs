use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use wasmtime::Store;
use wasmtime::component::{
    Type, Val,
    wasm_wave::{
        ast::{Node, NodeType},
        untyped::UntypedFuncCall,
    },
};

use super::MAX_EXPR_DEPTH;
use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;

#[cfg(test)]
mod tests;

pub(super) fn params(
    call: &UntypedFuncCall<'_>,
    mut types: impl Iterator<Item = Type>,
    store: &mut Store<Runtime>,
) -> Result<Vec<Val>> {
    let Some(node) = call.params_node() else {
        ensure!(types.next().is_none(), "missing required parameters");
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for node in node.as_tuple()? {
        let Some(ty) = types.next() else {
            bail!("too many parameters");
        };
        values.push(value(node, &ty, call.source(), store, 0)?);
    }
    for ty in types {
        Fuel::WaveValue.consume_with_store(store)?;
        ensure!(matches!(ty, Type::Option(_)), "missing required parameter");
        values.push(Val::Option(None));
    }
    Ok(values)
}

// Keep WAVE's grammar and scalar decoding. Construct containers here so omitted
// fields are charged before allocation, without Val::make_record's repeated
// field searches and recursive revalidation of already typed children.
fn value(
    node: &Node,
    ty: &Type,
    source: &str,
    store: &mut Store<Runtime>,
    depth: usize,
) -> Result<Val> {
    ensure!(depth <= MAX_EXPR_DEPTH, "WAVE value nesting is too deep");
    Fuel::WaveValue.consume_with_store(store)?;
    Ok(match ty {
        Type::List(list) => {
            let ty = list.ty();
            let mut values = Vec::new();
            for node in node.as_list()? {
                values.push(value(node, &ty, source, store, depth + 1)?);
            }
            Val::List(values)
        }
        Type::Record(record) => {
            // WAVE accepts unordered fields; its parser rejects duplicates. Raw
            // syntax, including unknown fields, is covered by WaveInputBytes.
            let supplied = node.as_record(source)?.collect::<BTreeMap<_, _>>();
            let mut fields = Vec::new();
            for field in record.fields() {
                Fuel::WaveTypeField(field.name.len() as u64).consume_with_store(store)?;
                let val = if let Some(node) = supplied.get(field.name) {
                    value(node, &field.ty, source, store, depth + 1)?
                } else {
                    Fuel::WaveValue.consume_with_store(store)?;
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
                values.push(value(node, &ty, source, store, depth + 1)?);
            }
            Val::Tuple(values)
        }
        Type::Variant(variant) => {
            let (name, node) = node.as_variant(source)?;
            let mut selected = None;
            for case in variant.cases() {
                Fuel::WaveTypeField(case.name.len() as u64).consume_with_store(store)?;
                if case.name == name {
                    selected = Some(case.ty);
                    break;
                }
            }
            let Some(ty) = selected else {
                bail!("unknown variant case: {name}")
            };
            Val::Variant(
                name.to_owned(),
                payload(node, ty, source, store, depth + 1)?,
            )
        }
        Type::Enum(enumeration) => {
            let name = node.as_enum(source)?;
            let mut found = false;
            for candidate in enumeration.names() {
                Fuel::WaveTypeField(candidate.len() as u64).consume_with_store(store)?;
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
                NodeType::OptionSome => {
                    payload(node.as_option()?, Some(ty), source, store, depth + 1)?
                }
                _ => {
                    ensure!(flattenable(&ty), "expected an explicit option");
                    Some(Box::new(value(node, &ty, source, store, depth + 1)?))
                }
            };
            Val::Option(val)
        }
        Type::Result(result) => {
            let val = match node.ty() {
                NodeType::ResultOk | NodeType::ResultErr => match node.as_result()? {
                    Ok(node) => Ok(payload(node, result.ok(), source, store, depth + 1)?),
                    Err(node) => Err(payload(node, result.err(), source, store, depth + 1)?),
                },
                _ => {
                    let Some(ty) = result.ok() else {
                        bail!("expected an explicit result")
                    };
                    ensure!(flattenable(&ty), "expected an explicit result");
                    Ok(Some(Box::new(value(node, &ty, source, store, depth + 1)?)))
                }
            };
            Val::Result(val)
        }
        Type::Flags(flags) => {
            // Validate membership once instead of scanning the schema for every
            // supplied flag. Both the schema and supplied names can be large.
            let mut names = BTreeSet::new();
            for name in flags.names() {
                Fuel::WaveTypeField(name.len() as u64).consume_with_store(store)?;
                names.insert(name);
            }
            let mut values = Vec::new();
            for name in node.as_flags(source)? {
                Fuel::WaveValue.consume_with_store(store)?;
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
        | Type::String => node.to_wasm_value(ty, source)?,
        _ => bail!("unsupported WAVE parameter type"),
    })
}

fn payload(
    node: Option<&Node>,
    ty: Option<Type>,
    source: &str,
    store: &mut Store<Runtime>,
    depth: usize,
) -> Result<Option<Box<Val>>> {
    match (node, ty) {
        (Some(node), Some(ty)) => Ok(Some(Box::new(value(node, &ty, source, store, depth)?))),
        (None, None) => Ok(None),
        _ => bail!("variant payload does not match its type"),
    }
}

fn flattenable(ty: &Type) -> bool {
    !matches!(ty, Type::Option(_) | Type::Result(_))
}
