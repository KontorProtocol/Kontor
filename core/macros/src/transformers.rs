use anyhow::{anyhow, bail};
use heck::ToUpperCamelCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Ident, PathArguments, Type as SynType, TypePath};
use wit_parser::{Handle, Resolve, Type as WitType, TypeDefKind};

pub fn wit_type_to_unwrap_expr(
    resolve: &Resolve,
    ty: &WitType,
    value: TokenStream,
) -> anyhow::Result<TokenStream> {
    match ty {
        WitType::U64 => Ok(quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_u64(&#value) }),
        WitType::S64 => Ok(quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_s64(&#value) }),
        WitType::String => {
            Ok(quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_string(&#value).into_owned() })
        }
        WitType::Id(id) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => wit_type_to_unwrap_expr(resolve, inner, value),
                TypeDefKind::Option(inner) => {
                    let inner_unwrap =
                        wit_type_to_unwrap_expr(resolve, inner, quote! { v.into_owned() })?;
                    Ok(
                        quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_option(&#value).map(|v| #inner_unwrap) },
                    )
                }
                TypeDefKind::List(inner) => {
                    let inner_unwrap =
                        wit_type_to_unwrap_expr(resolve, inner, quote! { v.into_owned() })?;
                    Ok(
                        quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_list(&#value).map(|v| #inner_unwrap).collect() },
                    )
                }
                TypeDefKind::Result(result) => {
                    let ok_unwrap = match result.ok {
                        Some(ok_ty) => {
                            let unwrap_expr = wit_type_to_unwrap_expr(
                                resolve,
                                &ok_ty,
                                quote! { v.unwrap().into_owned() },
                            )?;
                            quote! {
                                |v| #unwrap_expr
                            }
                        }
                        None => quote! { |_| () },
                    };
                    let err_unwrap = match result.err {
                        Some(err_ty) => {
                            let unwrap_expr = wit_type_to_unwrap_expr(
                                resolve,
                                &err_ty,
                                quote! { e.unwrap().into_owned() },
                            )?;
                            quote! {
                                |e| #unwrap_expr
                            }
                        }
                        None => quote! { |_| () },
                    };
                    Ok(quote! {
                        stdlib::wasm_wave::wasm::WasmValue::unwrap_result(&#value).map(#ok_unwrap).map_err(#err_unwrap)
                    })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    Ok(quote! { #value.into() })
                }
                TypeDefKind::Handle(Handle::Own(resource_id)) => {
                    // For owned resource handles, we need to create the resource from the handle
                    let resource_def = &resolve.types[*resource_id];
                    let resource_name = resource_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed resource types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&resource_name, Span::call_site());
                    // The handle is returned as a u32 from the runtime
                    Ok(quote! { #ident::from_handle(stdlib::wasm_wave::wasm::WasmValue::unwrap_u32(&#value)) })
                }
                TypeDefKind::Handle(Handle::Borrow(_)) => {
                    // Borrowed handles shouldn't appear as return types in our use case
                    bail!("Borrowed resource handles cannot be used as return types")
                }
                TypeDefKind::Tuple(tuple) => {
                    // Build per-element unwrap blocks that pull from a single iterator
                    let element_exprs = tuple
                        .types
                        .iter()
                        .map(|elt_ty| {
                            let inner = wit_type_to_unwrap_expr(
                                resolve,
                                elt_ty,
                                quote! { __v } // we'll bind __v to each element's Value
                            )?;
                            Ok(quote! {{
                                let __v = __iter.next()
                                    .expect("tuple length mismatch")
                                    .into_owned();
                                #inner
                            }})
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;

                    // 1-tuple requires a trailing comma to be a tuple in Rust
                    if tuple.types.len() == 1 {
                        Ok(quote! {{
                            let mut __iter =
                                stdlib::wasm_wave::wasm::WasmValue::unwrap_tuple(&#value);
                            (#(#element_exprs),*,)
                        }})
                    } else {
                        Ok(quote! {{
                            let mut __iter =
                                stdlib::wasm_wave::wasm::WasmValue::unwrap_tuple(&#value);
                            (#(#element_exprs),*)
                        }})
                    }
                }
                _ => bail!("Unsupported WIT type definition kind: {:?}", ty_def.kind),
            }
        }
        _ => bail!("Unsupported WIT type: {:?}", ty),
    }
}

pub fn wit_type_to_rust_type(
    resolve: &Resolve,
    ty: &WitType,
    use_str: bool,
) -> anyhow::Result<TokenStream> {
    match (ty, use_str) {
        (WitType::U64, _) => Ok(quote! { u64 }),
        (WitType::S64, _) => Ok(quote! { i64 }),
        (WitType::String, false) => Ok(quote! { String }),
        (WitType::String, true) => Ok(quote! { &str }),
        (WitType::Id(id), _) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => Ok(wit_type_to_rust_type(resolve, inner, use_str)?),
                TypeDefKind::Option(inner) => {
                    let inner_ty = wit_type_to_rust_type(resolve, inner, use_str)?;
                    Ok(quote! { Option<#inner_ty> })
                }
                TypeDefKind::List(inner) => {
                    let inner_ty = wit_type_to_rust_type(resolve, inner, use_str)?;
                    Ok(quote! { Vec<#inner_ty> })
                }
                TypeDefKind::Result(result) => {
                    let ok_ty = match result.ok {
                        Some(ty) => wit_type_to_rust_type(resolve, &ty, use_str)?,
                        None => quote! { () },
                    };
                    let err_ty = match result.err {
                        Some(ty) => wit_type_to_rust_type(resolve, &ty, use_str)?,
                        None => quote! { () },
                    };
                    Ok(quote! { Result<#ok_ty, #err_ty> })
                }
                TypeDefKind::Handle(Handle::Borrow(resource_id)) => {
                    let resource_def = &resolve.types[*resource_id];
                    let resource_name = resource_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed resource types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&resource_name, Span::call_site());
                    Ok(quote! { &context::#ident })
                }
                TypeDefKind::Handle(Handle::Own(resource_id)) => {
                    // Owned resource handle - these are move-only types
                    let resource_def = &resolve.types[*resource_id];
                    let resource_name = resource_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed resource types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&resource_name, Span::call_site());
                    Ok(quote! { #ident })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    let name = ty_def
                        .name
                        .as_ref()
                        .ok_or_else(|| anyhow!("Unnamed types are not supported"))?
                        .to_upper_camel_case();
                    let ident = Ident::new(&name, Span::call_site());
                    Ok(quote! { #ident })
                }
                TypeDefKind::Tuple(tuple) => {
                    // Handle tuples by recursively converting each element
                    let elements = tuple.types.iter().map(|ty| {
                        wit_type_to_rust_type(resolve, ty, use_str)
                    }).collect::<Result<Vec<_>, _>>()?;
                    Ok(quote! { (#(#elements),*) })
                }
                _ => bail!("Unsupported type definition kind: {:?}", ty_def.kind),
            }
        }
        // Note: Tuples are handled through TypeDefKind::Tuple in Type::Id case above
        _ => bail!("Unsupported WIT type: {:?}", ty),
    }
}

pub fn wit_type_to_wave_type(resolve: &Resolve, ty: &WitType) -> anyhow::Result<TokenStream> {
    match ty {
        WitType::U64 => Ok(quote! { stdlib::wasm_wave::value::Type::U64 }),
        WitType::S64 => Ok(quote! { stdlib::wasm_wave::value::Type::S64 }),
        WitType::String => Ok(quote! { stdlib::wasm_wave::value::Type::STRING }),
        WitType::Id(id) => {
            let ty_def = &resolve.types[*id];
            match &ty_def.kind {
                TypeDefKind::Type(inner) => wit_type_to_wave_type(resolve, inner),
                TypeDefKind::Option(inner) => {
                    let inner_ty = wit_type_to_wave_type(resolve, inner)?;
                    Ok(quote! { 
                        {
                            let __inner_ty = #inner_ty;
                            stdlib::wasm_wave::value::Type::option(__inner_ty)
                        }
                    })
                }
                TypeDefKind::List(inner) => {
                    let inner_ty = wit_type_to_wave_type(resolve, inner)?;
                    Ok(quote! { 
                        {
                            let __inner_ty = #inner_ty;
                            stdlib::wasm_wave::value::Type::list(__inner_ty)
                        }
                    })
                }
                TypeDefKind::Result(result) => {
                    let ok_ty = match result.ok {
                        Some(ty) => {
                            let value_type_ = wit_type_to_wave_type(resolve, &ty)?;
                            quote! { 
                                {
                                    let __ok_inner = #value_type_;
                                    Some(__ok_inner)
                                }
                            }
                        }
                        None => quote! { None },
                    };
                    let err_ty = match result.err {
                        Some(ty) => {
                            let value_type_ = wit_type_to_wave_type(resolve, &ty)?;
                            quote! { 
                                {
                                    let __err_inner = #value_type_;
                                    Some(__err_inner)
                                }
                            }
                        }
                        None => quote! { None },
                    };
                    Ok(quote! { 
                        {
                            let __ok_ty = #ok_ty;
                            let __err_ty = #err_ty;
                            stdlib::wasm_wave::value::Type::result(__ok_ty, __err_ty)
                        }
                    })
                }
                TypeDefKind::Record(_) | TypeDefKind::Enum(_) | TypeDefKind::Variant(_) => {
                    let name = ty_def.name.as_ref().ok_or_else(|| anyhow::anyhow!("Unnamed return types are not supported"))?.to_upper_camel_case();
                    let ident = Ident::new(&name, Span::call_site());
                    Ok(quote! { <#ident>::wave_type() })
                }
                TypeDefKind::Handle(Handle::Own(_)) | TypeDefKind::Handle(Handle::Borrow(_)) => {
                    Ok(quote! { stdlib::wasm_wave::value::Type::U32 })
                }
                TypeDefKind::Tuple(tuple) => {
                    let mut elem_bindings = Vec::new();
                    let mut elem_pushes = Vec::new();
                    for (i, t) in tuple.types.iter().enumerate() {
                        let elem_ty = wit_type_to_wave_type(resolve, t)?;
                        let var = Ident::new(&format!("__elem{}", i), Span::call_site());
                        elem_bindings.push(quote! { let #var = #elem_ty; });
                        elem_pushes.push(quote! { __tuple_vec.push(#var); });
                    }
                    Ok(quote! {
                        {
                            #(#elem_bindings)*
                            let mut __tuple_vec = Vec::new();
                            #(#elem_pushes)*
                            stdlib::wasm_wave::value::Type::tuple(__tuple_vec).unwrap()
                        }
                    })
                }
                _ => bail!("Unsupported return type kind: {:?}", ty_def.kind),
            }
        }
        _ => bail!("Unsupported return type: {:?}", ty),
    }
}

pub fn syn_type_to_wave_type(ty: &SynType) -> syn::Result<TokenStream> {
    // Handle tuple types
    if let SynType::Tuple(tup) = ty {
        if tup.elems.is_empty() {
            return Ok(quote! {
                stdlib::wasm_wave::value::Type::tuple(Vec::new()).unwrap()
            });
        }
        
        let elem_vars = tup.elems.iter().enumerate().map(|(i, _)| {
            let var_name = format!("__syn_elem_type_{}", i);
            Ident::new(&var_name, Span::call_site())
        }).collect::<Vec<_>>();
        
        let elem_types = tup.elems
            .iter()
            .map(syn_type_to_wave_type)
            .collect::<syn::Result<Vec<_>>>()?;
        
        let elem_bindings = elem_vars.iter().zip(elem_types.iter()).map(|(var, ty)| {
            quote! { let #var = #ty; }
        });
        
        let elem_pushes = elem_vars.iter().map(|var| {
            quote! { __syn_tuple_vec.push(#var); }
        });
        
        return Ok(quote! {
            {
                #(#elem_bindings)*
                let mut __syn_tuple_vec = Vec::new();
                #(#elem_pushes)*
                stdlib::wasm_wave::value::Type::tuple(__syn_tuple_vec).unwrap()
            }
        });
    }

    if let SynType::Path(TypePath { qself: None, path }) = ty {
        if let Some(segment) = &path.segments.last() {
            if segment.arguments == PathArguments::None {
                match segment.ident.to_string().as_str() {
                    "u64" => return Ok(quote! { stdlib::wasm_wave::value::Type::U64 }),
                    "i64" => return Ok(quote! { stdlib::wasm_wave::value::Type::S64 }),
                    "String" => return Ok(quote! { stdlib::wasm_wave::value::Type::STRING }),
                    "bool" => return Ok(quote! { stdlib::wasm_wave::value::Type::BOOL }),
                    _ => (),
                }
            }
        }
    }

    Ok(quote! { #ty::wave_type() })
}

pub fn syn_type_to_unwrap_expr(ty: &SynType, value: TokenStream) -> syn::Result<TokenStream> {
    if let SynType::Path(TypePath { qself: None, path }) = ty {
        if let Some(segment) = &path.segments.last() {
            if segment.arguments == PathArguments::None {
                let ident = segment.ident.to_string();
                match ident.as_str() {
                    "u64" => {
                        return Ok(
                            quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_u64(&#value.into_owned()) },
                        );
                    }
                    "i64" => {
                        return Ok(
                            quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_s64(&#value.into_owned()) },
                        );
                    }
                    "String" => {
                        return Ok(
                            quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_string(&#value.into_owned()).into_owned() },
                        );
                    }
                    "bool" => {
                        return Ok(
                            quote! { stdlib::wasm_wave::wasm::WasmValue::unwrap_bool(&#value.into_owned()) },
                        );
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(quote! { #value.into_owned().into() })
}
