use alloc::{format, vec::Vec};
use wit_parser::{Function, Handle, Resolve, Type, TypeDefKind, TypeOwner, WorldItem};

use crate::ValidationError;

pub struct PaginationShape {
    pub request_index: usize,
    pub page: Type,
    pub item: Type,
    pub fallible: bool,
}

pub fn underlying(resolve: &Resolve, mut ty: Type) -> Type {
    for _ in 0..=resolve.types.len() {
        if let Type::Id(id) = ty
            && let TypeDefKind::Type(inner) = resolve.types[id].kind
        {
            ty = inner;
            continue;
        }
        break;
    }
    ty
}

pub fn is_builtin(resolve: &Resolve, ty: Type, interface: &str, name: &str) -> bool {
    let Type::Id(id) = underlying(resolve, ty) else {
        return false;
    };
    let def = &resolve.types[id];
    let TypeOwner::Interface(owner) = def.owner else {
        return false;
    };
    let iface = &resolve.interfaces[owner];
    def.name.as_deref() == Some(name)
        && iface.name.as_deref() == Some(interface)
        && iface.package.is_some_and(|id| {
            let package = &resolve.packages[id].name;
            package.namespace == "kontor" && package.name == "built-in"
        })
}

pub fn shape(
    resolve: &Resolve,
    function: &Function,
) -> Result<Option<PaginationShape>, ValidationError> {
    let requests: Vec<_> = function
        .params
        .iter()
        .enumerate()
        .filter(|(_, param)| is_builtin(resolve, param.ty, "pagination", "cursor-request"))
        .map(|(index, _)| index)
        .collect();
    if requests.is_empty() {
        return Ok(None);
    }
    let error = |message: &str| {
        ValidationError::new(
            format!("paginated view '{}': {message}", function.name),
            function.span,
        )
    };
    if requests.len() != 1 || requests[0] != function.params.len() - 1 {
        return Err(error(
            "exactly one cursor-request is required, as the last parameter",
        ));
    }
    let view = function.params.first().is_some_and(|param| {
        let Type::Id(id) = underlying(resolve, param.ty) else {
            return false;
        };
        matches!(resolve.types[id].kind, TypeDefKind::Handle(Handle::Borrow(id))
            if is_builtin(resolve, Type::Id(id), "context", "view-context"))
    });
    if !view {
        return Err(error(
            "cursor-request is only allowed on a view-context function",
        ));
    }
    let Some(mut page) = function.result.map(|ty| underlying(resolve, ty)) else {
        return Err(error(
            "must return a record or a result containing a record",
        ));
    };
    let mut fallible = false;
    if let Type::Id(id) = page
        && let TypeDefKind::Result(result) = &resolve.types[id].kind
    {
        if !result
            .err
            .is_some_and(|ty| is_builtin(resolve, ty, "error", "error"))
        {
            return Err(error("result must use the built-in error type"));
        }
        page = result
            .ok
            .map(|ty| underlying(resolve, ty))
            .ok_or_else(|| error("result must contain a success record"))?;
        fallible = true;
    }
    let Type::Id(id) = page else {
        return Err(error("must return a record"));
    };
    let TypeDefKind::Record(record) = &resolve.types[id].kind else {
        return Err(error("must return a record"));
    };
    let item = record
        .fields
        .iter()
        .find(|field| field.name == "items")
        .and_then(|field| {
            let Type::Id(id) = underlying(resolve, field.ty) else {
                return None;
            };
            match resolve.types[id].kind {
                TypeDefKind::List(item) => Some(item),
                _ => None,
            }
        })
        .ok_or_else(|| error("return record must contain an 'items' list"))?;
    let next = record.fields.iter().find(|field| field.name == "next").is_some_and(|field| {
        let Type::Id(id) = underlying(resolve, field.ty) else { return false };
        matches!(resolve.types[id].kind, TypeDefKind::Option(inner) if underlying(resolve, inner) == Type::String)
    });
    if !next {
        return Err(error("return record must contain 'next: option<string>'"));
    }
    Ok(Some(PaginationShape {
        request_index: requests[0],
        page,
        item,
        fallible,
    }))
}

pub fn validate(resolve: &Resolve) -> Vec<ValidationError> {
    resolve
        .worlds
        .iter()
        .flat_map(|(_, world)| world.exports.values())
        .filter_map(|item| {
            let WorldItem::Function(function) = item else {
                return None;
            };
            shape(resolve, function).err()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Validator;

    fn wit(context: &str, params: &str, result: &str, fields: &str) -> alloc::string::String {
        format!(
            r#"package test:pagination;
world root {{
 include kontor:built-in/built-in;
 use kontor:built-in/context.{{proc-context, view-context, contract}};
 use kontor:built-in/pagination.{{cursor-request}};
 use kontor:built-in/error.{{error}};
 type request-alias = cursor-request;
 type cursor = option<string>;
 type entries = list<u64>;
 record response {{ {fields} }}
 type reply = result<response, error>;
 export init: async func(ctx: borrow<proc-context>) -> contract;
 export entries: async func(ctx: borrow<{context}>, {params}) -> {result};
}}"#
        )
    }

    #[test]
    fn explicit_type_survives_aliases_and_filters() {
        let text = wit(
            "view-context",
            "filter: string, pagination: request-alias",
            "reply",
            "items: entries, next: cursor, total: u64",
        );
        let (validation, resolve) = Validator::validate_str(&text).unwrap();
        assert!(validation.is_valid(), "{validation}");
        let world = resolve
            .worlds
            .iter()
            .find(|(_, w)| w.name == "root")
            .unwrap()
            .1;
        let function = world
            .exports
            .values()
            .find_map(|item| match item {
                WorldItem::Function(f) if f.name == "entries" => Some(f),
                _ => None,
            })
            .unwrap();
        let shape = shape(&resolve, function).unwrap().unwrap();
        assert_eq!(shape.request_index, 2);
        assert_eq!(shape.item, Type::U64);
        assert!(shape.fallible);
    }

    #[test]
    fn rejects_invalid_opt_ins() {
        for (context, params, result, fields, expected) in [
            (
                "proc-context",
                "pagination: cursor-request",
                "response",
                "items: entries, next: cursor",
                "only allowed on a view",
            ),
            (
                "view-context",
                "a: cursor-request, b: cursor-request",
                "response",
                "items: entries, next: cursor",
                "exactly one",
            ),
            (
                "view-context",
                "pagination: cursor-request, filter: string",
                "response",
                "items: entries, next: cursor",
                "last parameter",
            ),
            (
                "view-context",
                "pagination: cursor-request",
                "u64",
                "items: entries, next: cursor",
                "must return a record",
            ),
            (
                "view-context",
                "pagination: cursor-request",
                "result<response>",
                "items: entries, next: cursor",
                "built-in error type",
            ),
            (
                "view-context",
                "pagination: cursor-request",
                "response",
                "items: u64, next: cursor",
                "'items' list",
            ),
            (
                "view-context",
                "pagination: cursor-request",
                "response",
                "items: entries, next: option<u64>",
                "next: option<string>",
            ),
        ] {
            let (validation, _) =
                Validator::validate_str(&wit(context, params, result, fields)).unwrap();
            assert!(
                validation
                    .errors
                    .iter()
                    .any(|e| e.message.contains(expected)),
                "{validation}"
            );
        }
    }

    #[test]
    fn identical_record_name_and_fields_do_not_opt_in() {
        let text = wit(
            "view-context",
            "pagination: cursor-request",
            "response",
            "items: entries, next: cursor",
        )
        .replace(
            "use kontor:built-in/pagination.{cursor-request};",
            "record cursor-request { after: option<string>, limit: option<u64> }",
        );
        let (validation, resolve) = Validator::validate_str(&text).unwrap();
        assert!(validation.is_valid(), "{validation}");
        for (_, world) in resolve.worlds.iter() {
            for item in world.exports.values() {
                if let WorldItem::Function(function) = item {
                    assert!(shape(&resolve, function).unwrap().is_none());
                }
            }
        }
    }

    #[test]
    fn structural_lookalikes_do_not_opt_in() {
        let text = wit(
            "view-context",
            "after: option<string>, limit: u64",
            "response",
            "items: entries, next: cursor",
        );
        let (validation, resolve) = Validator::validate_str(&text).unwrap();
        assert!(validation.is_valid(), "{validation}");
        for (_, world) in resolve.worlds.iter() {
            for item in world.exports.values() {
                if let WorldItem::Function(function) = item {
                    assert!(shape(&resolve, function).unwrap().is_none());
                }
            }
        }
    }
}
