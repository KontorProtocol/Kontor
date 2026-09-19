use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;

use anyhow::{Result, anyhow, ensure};
use wit_parser::{Function, Resolve, Type, TypeDefKind};

#[derive(Default)]
pub(super) struct Kinds {
    types: HashMap<Type, u32>,
    shapes: BTreeMap<String, u32>,
}

impl Kinds {
    pub(super) fn get(&mut self, resolve: &Resolve, ty: Option<Type>) -> Result<u32> {
        match ty {
            None => Ok(0),
            Some(ty) => self.intern(resolve, ty, 0),
        }
    }

    fn intern(&mut self, resolve: &Resolve, ty: Type, depth: usize) -> Result<u32> {
        ensure!(depth <= 256, "result type is too deep");
        if let Some(id) = self.types.get(&ty) {
            return Ok(*id);
        }
        let shape = if let Type::Id(id) = ty {
            match &resolve.types[id].kind {
                TypeDefKind::Type(inner) => {
                    let value = self.intern(resolve, *inner, depth)?;
                    self.types.insert(ty, value);
                    return Ok(value);
                }
                TypeDefKind::Record(record) => {
                    let mut key = String::from("record:");
                    for field in &record.fields {
                        write!(
                            key,
                            "{:?}:{};",
                            field.name,
                            self.intern(resolve, field.ty, depth + 1)?
                        )?;
                    }
                    key
                }
                TypeDefKind::Variant(variant) => {
                    let mut key = String::from("variant:");
                    for case in &variant.cases {
                        write!(
                            key,
                            "{:?}:{};",
                            case.name,
                            case.ty
                                .map(|ty| self.intern(resolve, ty, depth + 1))
                                .transpose()?
                                .unwrap_or(0)
                        )?;
                    }
                    key
                }
                TypeDefKind::Enum(enumeration) => format!(
                    "enum:{:?}",
                    enumeration
                        .cases
                        .iter()
                        .map(|c| &c.name)
                        .collect::<Vec<_>>()
                ),
                TypeDefKind::List(inner) => {
                    format!("list:{}", self.intern(resolve, *inner, depth + 1)?)
                }
                TypeDefKind::Option(inner) => {
                    format!("option:{}", self.intern(resolve, *inner, depth + 1)?)
                }
                TypeDefKind::Result(result) => format!(
                    "result:{},{}",
                    result
                        .ok
                        .map(|ty| self.intern(resolve, ty, depth + 1))
                        .transpose()?
                        .unwrap_or(0),
                    result
                        .err
                        .map(|ty| self.intern(resolve, ty, depth + 1))
                        .transpose()?
                        .unwrap_or(0)
                ),
                other => format!("{other:?}"),
            }
        } else {
            format!("{ty:?}")
        };
        let next = self.shapes.len() as u32 + 1;
        let kind = *self.shapes.entry(shape).or_insert(next);
        self.types.insert(ty, kind);
        Ok(kind)
    }
}

// Walkers are specialized per export. Bound aggregate expansion before emitting
// WAT so many exports sharing one wide record cannot multiply compilation work
// without limit. Cache each type within an export to account for generated
// functions rather than exponentially expanding a shared type graph.
pub(super) fn check_generation_budget<'a>(
    resolve: &Resolve,
    functions: impl IntoIterator<Item = &'a Function>,
) -> Result<()> {
    let mut remaining = 64 * 1024usize;
    let mut charge = |units: usize| -> Result<()> {
        remaining = remaining
            .checked_sub(units)
            .ok_or_else(|| anyhow!("result encoder schema budget exceeded"))?;
        Ok(())
    };
    for function in functions {
        charge(1)?;
        let mut seen = HashSet::new();
        let mut pending = function.result.map(|ty| vec![(ty, 0)]).unwrap_or_default();
        while let Some((ty, depth)) = pending.pop() {
            ensure!(depth <= 256, "result type is too deep");
            if !seen.insert(ty) {
                continue;
            }
            charge(1)?;
            let Type::Id(id) = ty else {
                continue;
            };
            match &resolve.types[id].kind {
                TypeDefKind::Record(record) => {
                    for field in &record.fields {
                        charge(1 + field.name.len())?;
                        pending.push((field.ty, depth + 1));
                    }
                }
                TypeDefKind::Variant(variant) => {
                    for case in &variant.cases {
                        charge(1 + case.name.len())?;
                        if let Some(ty) = case.ty {
                            pending.push((ty, depth + 1));
                        }
                    }
                }
                TypeDefKind::Enum(enumeration) => {
                    for case in &enumeration.cases {
                        charge(1 + case.name.len())?;
                    }
                }
                TypeDefKind::Type(inner)
                | TypeDefKind::List(inner)
                | TypeDefKind::Option(inner) => pending.push((*inner, depth + 1)),
                TypeDefKind::Result(result) => {
                    for ty in [result.ok, result.err].into_iter().flatten() {
                        pending.push((ty, depth + 1));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
