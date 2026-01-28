use anyhow::Result;
use serde::Deserialize;
use serde::de::{DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use std::fmt;
use wasmtime::component::types::{Enum, Record, Variant};
use wasmtime::component::{Type, Val};

pub fn decode_postcard_args(arg_types: &[Type], bytes: &[u8]) -> Result<Vec<Val>> {
    let mut de = postcard::Deserializer::from_bytes(bytes);
    let args = ArgsSeed { arg_types }.deserialize(&mut de)?;
    Ok(args)
}

struct ArgsSeed<'a> {
    arg_types: &'a [Type],
}

impl<'de, 'a> DeserializeSeed<'de> for ArgsSeed<'a> {
    type Value = Vec<Val>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(ArgsVisitor {
            arg_types: self.arg_types,
        })
    }
}

struct ArgsVisitor<'a> {
    arg_types: &'a [Type],
}

impl<'de, 'a> Visitor<'de> for ArgsVisitor<'a> {
    type Value = Vec<Val>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a sequence of {} arguments", self.arg_types.len())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(self.arg_types.len());
        for ty in self.arg_types {
            let v = seq
                .next_element_seed(ValSeed { ty })?
                .ok_or_else(|| serde::de::Error::custom("missing argument"))?;
            out.push(v);
        }

        // Reject trailing args.
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("too many arguments"));
        }

        Ok(out)
    }
}

struct ValSeed<'a> {
    ty: &'a Type,
}

impl<'de, 'a> DeserializeSeed<'de> for ValSeed<'a> {
    type Value = Val;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match self.ty {
            Type::Bool => Ok(Val::Bool(bool::deserialize(deserializer)?)),
            Type::S8 => Ok(Val::S8(i8::deserialize(deserializer)?)),
            Type::U8 => Ok(Val::U8(u8::deserialize(deserializer)?)),
            Type::S16 => Ok(Val::S16(i16::deserialize(deserializer)?)),
            Type::U16 => Ok(Val::U16(u16::deserialize(deserializer)?)),
            Type::S32 => Ok(Val::S32(i32::deserialize(deserializer)?)),
            Type::U32 => Ok(Val::U32(u32::deserialize(deserializer)?)),
            Type::S64 => Ok(Val::S64(i64::deserialize(deserializer)?)),
            Type::U64 => Ok(Val::U64(u64::deserialize(deserializer)?)),
            Type::Float32 => Ok(Val::Float32(f32::deserialize(deserializer)?)),
            Type::Float64 => Ok(Val::Float64(f64::deserialize(deserializer)?)),
            Type::Char => Ok(Val::Char(char::deserialize(deserializer)?)),
            Type::String => Ok(Val::String(String::deserialize(deserializer)?)),
            Type::List(list_ty) => deserializer
                .deserialize_seq(ListVisitor { elem: list_ty.ty() })
                .map(Val::List),
            Type::Tuple(tuple_ty) => {
                let elem_types = tuple_ty.types().collect::<Vec<_>>();
                deserializer
                    .deserialize_seq(TupleVisitor { elem_types })
                    .map(Val::Tuple)
            }
            Type::Record(record_ty) => deserializer.deserialize_any(RecordVisitor {
                record_ty: record_ty.clone(),
            }),
            Type::Enum(enum_ty) => deserializer.deserialize_enum(
                "enum",
                &[],
                EnumVisitor {
                    enum_ty: enum_ty.clone(),
                },
            ),
            Type::Variant(variant_ty) => deserializer.deserialize_enum(
                "variant",
                &[],
                VariantVisitor {
                    variant_ty: variant_ty.clone(),
                },
            ),
            Type::Option(opt_ty) => deserializer.deserialize_option(OptionVisitor {
                inner_ty: opt_ty.ty(),
            }),
            Type::Result(result_ty) => deserializer.deserialize_enum(
                "result",
                &[],
                ResultVisitor {
                    ok_ty: result_ty.ok(),
                    err_ty: result_ty.err(),
                },
            ),
            Type::Flags(_) => {
                // Flags are encoded as a list of flag names.
                let flags = Vec::<String>::deserialize(deserializer)?;
                Ok(Val::Flags(flags))
            }
            Type::Own(_) | Type::Borrow(_) => Err(serde::de::Error::custom(
                "resource values are not supported in BinaryCall args",
            )),
            other => Err(serde::de::Error::custom(format!(
                "unsupported WIT type in BinaryCall args: {other:?}"
            ))),
        }
    }
}

struct ListVisitor {
    elem: Type,
}

impl<'de> Visitor<'de> for ListVisitor {
    type Value = Vec<Val>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a list")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(ValSeed { ty: &self.elem })? {
            out.push(v);
        }
        Ok(out)
    }
}

struct TupleVisitor {
    elem_types: Vec<Type>,
}

impl<'de> Visitor<'de> for TupleVisitor {
    type Value = Vec<Val>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a tuple")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(self.elem_types.len());
        for ty in &self.elem_types {
            let v = seq
                .next_element_seed(ValSeed { ty })?
                .ok_or_else(|| serde::de::Error::custom("missing tuple element"))?;
            out.push(v);
        }
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("too many tuple elements"));
        }
        Ok(out)
    }
}

struct RecordVisitor {
    record_ty: Record,
}

impl<'de> Visitor<'de> for RecordVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a record")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let fields = self
            .record_ty
            .fields()
            .map(|f| (f.name.to_string(), f.ty))
            .collect::<Vec<_>>();

        let mut out = Vec::with_capacity(fields.len());
        for (name, ty) in fields {
            let v = seq
                .next_element_seed(ValSeed { ty: &ty })?
                .ok_or_else(|| serde::de::Error::custom("missing record field"))?;
            out.push((name, v));
        }
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("too many record fields"));
        }
        Ok(Val::Record(out))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        // Postcard encodes structs/records as sequences; reject map encoding.
        while map.next_entry::<String, serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "record map encoding not supported (expected sequence/tuple encoding)",
            ));
        }
        Err(serde::de::Error::custom(
            "record map encoding not supported (expected sequence/tuple encoding)",
        ))
    }
}

struct EnumVisitor {
    enum_ty: Enum,
}

impl<'de> Visitor<'de> for EnumVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "an enum")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (name, variant) = data.variant_seed(VariantNameSeed {
            names: self.enum_ty.names().map(|n: &str| n.to_string()).collect(),
        })?;
        variant.unit_variant()?;
        Ok(Val::Enum(name))
    }
}

struct VariantVisitor {
    variant_ty: Variant,
}

impl<'de> Visitor<'de> for VariantVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a variant")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let case_names = self
            .variant_ty
            .cases()
            .map(|c| c.name.to_string())
            .collect::<Vec<_>>();

        let (case_name, variant) = data.variant_seed(VariantNameSeed { names: case_names })?;

        let case = self
            .variant_ty
            .cases()
            .find(|c| c.name == case_name)
            .ok_or_else(|| serde::de::Error::custom("unknown variant case"))?;

        let payload = if let Some(ty) = case.ty {
            let v = variant.newtype_variant_seed(ValSeed { ty: &ty })?;
            Some(Box::new(v))
        } else {
            variant.unit_variant()?;
            None
        };

        Ok(Val::Variant(case_name, payload))
    }
}

struct OptionVisitor {
    inner_ty: Type,
}

impl<'de> Visitor<'de> for OptionVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        let ty = self.inner_ty;
        let inner = ValSeed { ty: &ty }.deserialize(deserializer)?;
        Ok(Val::Option(Some(Box::new(inner))))
    }
}

struct ResultVisitor {
    ok_ty: Option<Type>,
    err_ty: Option<Type>,
}

impl<'de> Visitor<'de> for ResultVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a result")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (name, variant) = data.variant_seed(VariantNameSeed {
            names: vec!["Ok".to_string(), "Err".to_string()],
        })?;
        match name.as_str() {
            "Ok" => {
                if let Some(ty) = self.ok_ty {
                    let v = variant.newtype_variant_seed(ValSeed { ty: &ty })?;
                    Ok(Val::Result(Ok(Some(Box::new(v)))))
                } else {
                    variant.unit_variant()?;
                    Ok(Val::Result(Ok(None)))
                }
            }
            "Err" => {
                if let Some(ty) = self.err_ty {
                    let v = variant.newtype_variant_seed(ValSeed { ty: &ty })?;
                    Ok(Val::Result(Err(Some(Box::new(v)))))
                } else {
                    variant.unit_variant()?;
                    Ok(Val::Result(Err(None)))
                }
            }
            _ => Err(serde::de::Error::custom("invalid result variant")),
        }
    }
}

struct VariantNameSeed {
    names: Vec<String>,
}

impl<'de> DeserializeSeed<'de> for VariantNameSeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(VariantIdVisitor { names: self.names })
    }
}

struct VariantIdVisitor {
    names: Vec<String>,
}

impl<'de> Visitor<'de> for VariantIdVisitor {
    type Value = String;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a variant identifier")
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_u64(u64::from(v))
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_u64(u64::from(v))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_u64(u64::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let idx = usize::try_from(v).map_err(|_| E::custom("variant index overflow"))?;
        self.names
            .get(idx)
            .cloned()
            .ok_or_else(|| E::custom("variant index out of range"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if self.names.iter().any(|n| n == v) {
            Ok(v.to_string())
        } else {
            Err(E::custom("unknown variant name"))
        }
    }
}
