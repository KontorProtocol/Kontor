use wasmtime::component::{Type, Val};

use crate::runtime::kontor::built_in::context::OutPoint;

pub fn default_val_for_type(ty: Type) -> Val {
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
                    let field_val = default_val_for_type(field.ty);
                    (field.name.to_string(), field_val)
                })
                .collect::<Vec<_>>();
            Val::Record(fields)
        }
        Type::Tuple(tuple_ty) => {
            let fields = tuple_ty
                .types()
                .map(default_val_for_type)
                .collect::<Vec<_>>();
            Val::Tuple(fields)
        }
        Type::Variant(variant_ty) => {
            let first_case = variant_ty
                .cases()
                .next()
                .expect("Variant must have at least one case");
            let payload = first_case.ty.map(|ty| Box::new(default_val_for_type(ty)));
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
                Val::Result(Ok(Some(Box::new(default_val_for_type(ty)))))
            } else if let Some(ty) = result_ty.err() {
                Val::Result(Err(Some(Box::new(default_val_for_type(ty)))))
            } else {
                Val::Result(Ok(None))
            }
        }
        Type::Flags(_) => Val::Flags(Vec::new()),
        Type::Own(_) => panic!("Cannot create a default Own value without a resource context"),
        Type::Borrow(_) => {
            panic!("Cannot create a default Borrow value without a resource context")
        }
        _ => {
            panic!("Unknnown type encountered")
        }
    }
}

impl From<bitcoin::OutPoint> for OutPoint {
    fn from(value: bitcoin::OutPoint) -> Self {
        Self {
            txid: value.txid.to_string(),
            vout: value.vout as u64,
        }
    }
}
