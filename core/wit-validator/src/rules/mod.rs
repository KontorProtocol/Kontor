//! Validation rules for Kontor WIT files.
//!
//! See rules.md for the full specification.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Location, ValidationError};
use crate::types::{self, BUILTIN_TYPES, ERROR_TYPE_NAME};
use wit_parser::{Handle, Resolve, Type, TypeDefKind, TypeId, WorldItem, WorldKey};

/// Run all validation rules and collect errors.
pub fn validate_all(resolve: &Resolve) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    errors.extend(validate_function_signatures(resolve));
    errors.extend(validate_required_exports(resolve));
    errors.extend(validate_type_definitions(resolve));
    errors.extend(validate_cycles(resolve));

    errors
}

fn validate_required_exports(resolve: &Resolve) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for (_world_id, world) in resolve.worlds.iter() {
        // Skip the built-in world
        if world.name == "built-in" {
            continue;
        }

        let has_init = world.exports.iter().any(|(key, item)| {
            matches!((key, item), (WorldKey::Name(name), WorldItem::Function(_)) if name == "init")
        });

        if !has_init {
            errors.push(ValidationError::new(
                "contract must export an init function",
                Location::type_def(&world.name),
            ));
        }
    }

    errors
}

fn validate_function_signatures(resolve: &Resolve) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for (_world_id, world) in resolve.worlds.iter() {
        for (key, item) in world.exports.iter() {
            if let (WorldKey::Name(name), WorldItem::Function(func)) = (key, item) {
                // Special handling for init and fallback
                if name == "init" {
                    errors.extend(validate_init_function(resolve, func));
                    continue;
                }
                if name == "fallback" {
                    errors.extend(validate_fallback_function(resolve, func));
                    continue;
                }

                if !func.kind.is_async() {
                    errors.push(ValidationError::new(
                        "exported functions must be async",
                        Location::function(name),
                    ));
                }

                if func.params.is_empty() {
                    errors.push(ValidationError::new(
                        "function must have a context parameter as its first argument",
                        Location::function(name),
                    ));
                    continue;
                }

                let (param_name, param_type) = &func.params[0];

                match get_borrowed_type_name(resolve, param_type) {
                    Some(context_name) => {
                        if !types::is_context_type(&context_name) {
                            errors.push(ValidationError::new(
                                format!(
                                    "first parameter must be a borrow of a valid context type \
                                     (proc-context, view-context, core-context, or fall-context), \
                                     found '{}'",
                                    context_name
                                ),
                                Location::parameter(name, param_name),
                            ));
                        }
                    }
                    None => {
                        errors.push(ValidationError::new(
                            "first parameter must be a borrow of a context type \
                             (e.g., `ctx: borrow<proc-context>`)",
                            Location::parameter(name, param_name),
                        ));
                    }
                }

                for (param_name, param_type) in func.params.iter().skip(1) {
                    errors.extend(validate_type_in_context(
                        resolve,
                        param_type,
                        TypeContext::FunctionParam,
                        &Location::parameter(name, param_name),
                    ));
                }

                if let Some(result_type) = &func.result {
                    errors.extend(validate_type_in_context(
                        resolve,
                        result_type,
                        TypeContext::FunctionReturn,
                        &Location::return_type(name),
                    ));
                }
            }
        }
    }

    errors
}

/// Validate the `init` function signature.
/// Must be: `async func(ctx: borrow<proc-context>)`
fn validate_init_function(resolve: &Resolve, func: &wit_parser::Function) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let name = "init";

    if !func.kind.is_async() {
        errors.push(ValidationError::new(
            "init must be async",
            Location::function(name),
        ));
    }

    if func.params.len() != 1 {
        errors.push(ValidationError::new(
            "init must have exactly one parameter: ctx: borrow<proc-context>",
            Location::function(name),
        ));
    } else {
        let (param_name, param_type) = &func.params[0];
        match get_borrowed_type_name(resolve, param_type) {
            Some(context_name) if context_name == "proc-context" => {}
            _ => {
                errors.push(ValidationError::new(
                    "init parameter must be borrow<proc-context>",
                    Location::parameter(name, param_name),
                ));
            }
        }
    }

    if func.result.is_some() {
        errors.push(ValidationError::new(
            "init must not have a return type",
            Location::return_type(name),
        ));
    }

    errors
}

/// Validate the `fallback` function signature.
/// Must be: `async func(ctx: borrow<fall-context>, expr: string) -> string`
fn validate_fallback_function(
    resolve: &Resolve,
    func: &wit_parser::Function,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let name = "fallback";

    if !func.kind.is_async() {
        errors.push(ValidationError::new(
            "fallback must be async",
            Location::function(name),
        ));
    }

    if func.params.len() != 2 {
        errors.push(ValidationError::new(
            "fallback must have exactly two parameters: ctx: borrow<fall-context>, expr: string",
            Location::function(name),
        ));
    } else {
        // Check first param: ctx: borrow<fall-context>
        let (param_name, param_type) = &func.params[0];
        match get_borrowed_type_name(resolve, param_type) {
            Some(context_name) if context_name == "fall-context" => {}
            _ => {
                errors.push(ValidationError::new(
                    "fallback first parameter must be borrow<fall-context>",
                    Location::parameter(name, param_name),
                ));
            }
        }

        // Check second param: expr: string
        let (param_name, param_type) = &func.params[1];
        if !matches!(param_type, Type::String) {
            errors.push(ValidationError::new(
                "fallback second parameter must be string",
                Location::parameter(name, param_name),
            ));
        }
    }

    // Check return type: string
    match &func.result {
        Some(Type::String) => {}
        Some(_) => {
            errors.push(ValidationError::new(
                "fallback must return string",
                Location::return_type(name),
            ));
        }
        None => {
            errors.push(ValidationError::new(
                "fallback must return string",
                Location::return_type(name),
            ));
        }
    }

    errors
}

fn validate_type_definitions(resolve: &Resolve) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for (_id, type_def) in resolve.types.iter() {
        if let Some(name) = &type_def.name {
            if BUILTIN_TYPES.contains(&name.as_str()) {
                continue;
            }

            match &type_def.kind {
                TypeDefKind::Record(record) => {
                    if record.fields.is_empty() {
                        errors.push(ValidationError::new(
                            "record must have at least one field",
                            Location::type_def(name),
                        ));
                    }

                    for field in &record.fields {
                        errors.extend(validate_type_in_context(
                            resolve,
                            &field.ty,
                            TypeContext::RecordField,
                            &Location::field(name, &field.name),
                        ));
                    }
                }

                TypeDefKind::Variant(variant) => {
                    for case in &variant.cases {
                        if let Some(payload_type) = &case.ty {
                            if is_inline_record(resolve, payload_type) {
                                errors.push(ValidationError::new(
                                    "variant case payload cannot be an inline record; \
                                     define a named record type instead",
                                    Location::variant_case(name, &case.name),
                                ));
                            }

                            errors.extend(validate_type_in_context(
                                resolve,
                                payload_type,
                                TypeContext::VariantPayload,
                                &Location::variant_case(name, &case.name),
                            ));
                        }
                    }
                }

                TypeDefKind::Flags(_) => {
                    errors.push(ValidationError::new(
                        "flags types are not supported",
                        Location::type_def(name),
                    ));
                }

                TypeDefKind::Enum(_) => {}

                _ => {}
            }
        }
    }

    errors
}

fn validate_cycles(resolve: &Resolve) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    let mut deps: BTreeMap<TypeId, Vec<TypeId>> = BTreeMap::new();

    for (id, type_def) in resolve.types.iter() {
        if let Some(name) = &type_def.name
            && BUILTIN_TYPES.contains(&name.as_str())
        {
            continue;
        }

        let mut type_deps = Vec::new();
        collect_type_dependencies(resolve, &type_def.kind, &mut type_deps);
        deps.insert(id, type_deps);
    }

    let mut visited = BTreeSet::new();
    let mut in_stack = BTreeSet::new();

    for id in deps.keys() {
        if !visited.contains(id)
            && let Some(cycle_id) = detect_cycle(*id, &deps, &mut visited, &mut in_stack)
            && let Some(name) = &resolve.types[cycle_id].name
        {
            errors.push(ValidationError::new(
                "cyclic type reference detected",
                Location::type_def(name),
            ));
        }
    }

    errors
}

fn collect_type_dependencies(resolve: &Resolve, kind: &TypeDefKind, deps: &mut Vec<TypeId>) {
    match kind {
        TypeDefKind::Record(record) => {
            for field in &record.fields {
                collect_type_refs(resolve, &field.ty, deps);
            }
        }
        TypeDefKind::Variant(variant) => {
            for case in &variant.cases {
                if let Some(ty) = &case.ty {
                    collect_type_refs(resolve, ty, deps);
                }
            }
        }
        TypeDefKind::Option(inner) | TypeDefKind::List(inner) => {
            collect_type_refs(resolve, inner, deps);
        }
        TypeDefKind::Result(result) => {
            if let Some(ok) = &result.ok {
                collect_type_refs(resolve, ok, deps);
            }
            if let Some(err) = &result.err {
                collect_type_refs(resolve, err, deps);
            }
        }
        TypeDefKind::Type(inner) => {
            collect_type_refs(resolve, inner, deps);
        }
        _ => {}
    }
}

fn collect_type_refs(resolve: &Resolve, ty: &Type, deps: &mut Vec<TypeId>) {
    if let Type::Id(id) = ty {
        if let Some(name) = &resolve.types[*id].name
            && BUILTIN_TYPES.contains(&name.as_str())
        {
            return;
        }
        deps.push(*id);
    }
}

fn detect_cycle(
    id: TypeId,
    deps: &BTreeMap<TypeId, Vec<TypeId>>,
    visited: &mut BTreeSet<TypeId>,
    in_stack: &mut BTreeSet<TypeId>,
) -> Option<TypeId> {
    visited.insert(id);
    in_stack.insert(id);

    if let Some(neighbors) = deps.get(&id) {
        for &neighbor in neighbors {
            if !visited.contains(&neighbor) {
                if let Some(cycle_id) = detect_cycle(neighbor, deps, visited, in_stack) {
                    return Some(cycle_id);
                }
            } else if in_stack.contains(&neighbor) {
                return Some(neighbor);
            }
        }
    }

    in_stack.remove(&id);
    None
}

#[derive(Clone, Copy, PartialEq)]
enum TypeContext {
    FunctionParam,
    FunctionReturn,
    RecordField,
    VariantPayload,
}

fn validate_type_in_context(
    resolve: &Resolve,
    ty: &Type,
    ctx: TypeContext,
    location: &Location,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    match ty {
        Type::Char => {
            errors.push(ValidationError::new(
                "char type is not supported",
                location.clone(),
            ));
        }
        Type::F32 | Type::F64 => {
            errors.push(ValidationError::new(
                "floating point types are not supported",
                location.clone(),
            ));
        }
        Type::U8 => {
            errors.push(ValidationError::new(
                "u8 type is only allowed as list<u8>",
                location.clone(),
            ));
        }
        Type::U16 | Type::U32 | Type::S8 | Type::S16 | Type::S32 => {
            errors.push(ValidationError::new(
                "8/16/32-bit integer types are not supported; use s64 or u64",
                location.clone(),
            ));
        }

        Type::Id(id) => {
            let type_def = &resolve.types[*id];

            match &type_def.kind {
                TypeDefKind::Result(result) => {
                    if ctx != TypeContext::FunctionReturn {
                        errors.push(ValidationError::new(
                            "result type can only be used as a function return type",
                            location.clone(),
                        ));
                    }

                    if let Some(err_type) = &result.err {
                        if !is_error_type(resolve, err_type) {
                            errors.push(ValidationError::new(
                                format!(
                                    "result error type must be 'error', found '{}'",
                                    type_name(resolve, err_type)
                                ),
                                location.clone(),
                            ));
                        }
                    } else {
                        errors.push(ValidationError::new(
                            "result type must have an error type (use result<T, error>)",
                            location.clone(),
                        ));
                    }

                    if let Some(ok_type) = &result.ok
                        && is_result_type(resolve, ok_type)
                    {
                        errors.push(ValidationError::new(
                            "nested result types are not allowed",
                            location.clone(),
                        ));
                    }

                    if let Some(ok) = &result.ok {
                        errors.extend(validate_type_in_context(
                            resolve,
                            ok,
                            TypeContext::FunctionReturn,
                            location,
                        ));
                    }
                }

                TypeDefKind::List(inner) => {
                    if !matches!(inner, Type::U8)
                        && (ctx == TypeContext::RecordField || ctx == TypeContext::VariantPayload)
                    {
                        errors.push(ValidationError::new(
                            "list<T> (where T is not u8) can only be used in function signatures, \
                                 not in record fields or variant payloads",
                            location.clone(),
                        ));
                    }

                    if is_list_type(resolve, inner) {
                        errors.push(ValidationError::new(
                            "nested list types are not allowed",
                            location.clone(),
                        ));
                    }

                    if !matches!(inner, Type::U8) {
                        errors.extend(validate_type_in_context(resolve, inner, ctx, location));
                    }
                }

                TypeDefKind::Option(inner) => {
                    if is_option_type(resolve, inner) {
                        errors.push(ValidationError::new(
                            "nested option types are not allowed",
                            location.clone(),
                        ));
                    }

                    errors.extend(validate_type_in_context(resolve, inner, ctx, location));
                }

                TypeDefKind::Handle(Handle::Own(_)) => {
                    errors.push(ValidationError::new(
                        "own<T> handles are not supported; use borrow<T>",
                        location.clone(),
                    ));
                }

                TypeDefKind::Future(_) => {
                    errors.push(ValidationError::new(
                        "future types are not supported",
                        location.clone(),
                    ));
                }

                TypeDefKind::Stream(_) => {
                    errors.push(ValidationError::new(
                        "stream types are not supported",
                        location.clone(),
                    ));
                }

                TypeDefKind::Tuple(_) => {
                    errors.push(ValidationError::new(
                        "tuple types are not supported; use a named record instead",
                        location.clone(),
                    ));
                }

                TypeDefKind::Type(inner) => {
                    errors.extend(validate_type_in_context(resolve, inner, ctx, location));
                }

                _ => {}
            }
        }

        _ => {}
    }

    errors
}

fn get_borrowed_type_name(resolve: &Resolve, ty: &Type) -> Option<String> {
    if let Type::Id(id) = ty {
        let type_def = &resolve.types[*id];
        if let TypeDefKind::Handle(Handle::Borrow(resource_id)) = &type_def.kind {
            let resource_def = &resolve.types[*resource_id];
            return resource_def.name.clone();
        }
    }
    None
}

fn is_inline_record(resolve: &Resolve, ty: &Type) -> bool {
    if let Type::Id(id) = ty {
        let type_def = &resolve.types[*id];
        if type_def.name.is_none() {
            return matches!(type_def.kind, TypeDefKind::Record(_));
        }
    }
    false
}

fn is_error_type(resolve: &Resolve, ty: &Type) -> bool {
    if let Type::Id(id) = ty
        && let Some(name) = &resolve.types[*id].name
    {
        return name == ERROR_TYPE_NAME;
    }
    false
}

fn is_result_type(resolve: &Resolve, ty: &Type) -> bool {
    if let Type::Id(id) = ty {
        return matches!(resolve.types[*id].kind, TypeDefKind::Result(_));
    }
    false
}

fn is_list_type(resolve: &Resolve, ty: &Type) -> bool {
    if let Type::Id(id) = ty {
        return matches!(resolve.types[*id].kind, TypeDefKind::List(_));
    }
    false
}

fn is_option_type(resolve: &Resolve, ty: &Type) -> bool {
    if let Type::Id(id) = ty {
        return matches!(resolve.types[*id].kind, TypeDefKind::Option(_));
    }
    false
}

fn type_name(resolve: &Resolve, ty: &Type) -> String {
    match ty {
        Type::Bool => String::from("bool"),
        Type::U8 => String::from("u8"),
        Type::U16 => String::from("u16"),
        Type::U32 => String::from("u32"),
        Type::U64 => String::from("u64"),
        Type::S8 => String::from("s8"),
        Type::S16 => String::from("s16"),
        Type::S32 => String::from("s32"),
        Type::S64 => String::from("s64"),
        Type::F32 => String::from("f32"),
        Type::F64 => String::from("f64"),
        Type::Char => String::from("char"),
        Type::String => String::from("string"),
        Type::ErrorContext => String::from("error-context"),
        Type::Id(id) => resolve.types[*id]
            .name
            .clone()
            .unwrap_or_else(|| String::from("<anonymous>")),
    }
}
