use darling::FromMeta;
use heck::ToPascalCase;
use proc_macro2::TokenStream;
use quote::quote;
use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use syn::Ident;
use wit_parser::TypeDefKind;

#[derive(FromMeta)]
pub struct Config {
    name: String,
    world: Option<String>,
    path: Option<String>,
}

pub fn generate(config: Config) -> TokenStream {
    let world = config.world.unwrap_or("contract".to_string());
    let path = config.path.unwrap_or("wit".to_string());
    let name = Ident::from_string(&config.name.to_pascal_case()).unwrap();
    
    // Parse WIT file to extract resource definitions
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or(".".to_string());
    let wit_path = PathBuf::from(&manifest_dir).join(&path);
    
    let (resource_types, _records_with_resources, with_clause) = parse_wit_resources(&wit_path, &world)
        .unwrap_or_else(|e| {
            panic!("Failed to parse WIT resources: {}. This is required for proper resource handling.", e);
        });
    
    // Register resources with the registry
    if !resource_types.is_empty() {
        crate::registry::set_resources(&manifest_dir, resource_types.clone());
    }
    
    // Since wit-bindgen handles resources natively, we don't need to generate wrappers
    // Just let wit-bindgen do its work
    
    quote! {
        wit_bindgen::generate!({
            world: #world,
            path: #path,
            generate_all,
            // Don't add derives to resources - they don't support them
            // additional_derives: [stdlib::Storage, stdlib::Wavey],
            #with_clause
        });

        // Don't import types - let each contract import what it needs
        // This avoids conflicts with wit-bindgen generated types

        fn make_keys_iterator<T: FromString>(keys: crate::kontor::built_in::context::Keys) -> impl Iterator<Item = T> {
            struct KeysIterator<T: FromString> {
                keys: crate::kontor::built_in::context::Keys,
                _phantom: std::marker::PhantomData<T>,
            }

            impl<T: FromString> Iterator for KeysIterator<T> {
                type Item = T;
                fn next(&mut self) -> Option<Self::Item> {
                    self.keys.next().map(|s| T::from_string(s))
                }
            }

            KeysIterator {
                keys,
                _phantom: std::marker::PhantomData,
            }
        }

        #[automatically_derived]
        impl ReadContext for crate::kontor::built_in::context::ViewContext {
            fn __get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __get_bool(&self, path: &str) -> Option<bool> {
                self.get_bool(path)
            }

            fn __get_void(&self, path: &str) -> Option<()> {
                if self.is_void(path) {
                    Some(())
                } else {
                    None
                }
            }

            fn __get_keys<'a, T: ToString + FromString + Clone + 'a>(&self, path: &'a str) -> impl Iterator<Item = T> + 'a {
                make_keys_iterator(self.get_keys(path))
            }

            fn __exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn __is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn __matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl ReadContext for crate::kontor::built_in::context::ProcContext {
            fn __get_str(&self, path: &str) -> Option<String> {
                self.get_str(path)
            }

            fn __get_u64(&self, path: &str) -> Option<u64> {
                self.get_u64(path)
            }

            fn __get_s64(&self, path: &str) -> Option<i64> {
                self.get_s64(path)
            }

            fn __get_bool(&self, path: &str) -> Option<bool> {
                self.get_bool(path)
            }

            fn __get_void(&self, path: &str) -> Option<()> {
                if self.is_void(path) {
                    Some(())
                } else {
                    None
                }
            }

            fn __get_keys<'a, T: ToString + FromString + Clone + 'a>(&self, path: &'a str) -> impl Iterator<Item = T> + 'a{
                make_keys_iterator(self.get_keys(path))
            }

            fn __exists(&self, path: &str) -> bool {
                self.exists(path)
            }

            fn __is_void(&self, path: &str) -> bool {
                self.is_void(path)
            }

            fn __matching_path(&self, regexp: &str) -> Option<String> {
                self.matching_path(regexp)
            }

            fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T> {
                T::__get(self, path)
            }
        }

        #[automatically_derived]
        impl WriteContext for crate::kontor::built_in::context::ProcContext {
            fn __set_str(&self, path: &str, value: &str) {
                self.set_str(path, value)
            }

            fn __set_u64(&self, path: &str, value: u64) {
                self.set_u64(path, value)
            }

            fn __set_s64(&self, path: &str, value: i64) {
                self.set_s64(path, value)
            }

            fn __set_bool(&self, path: &str, value: bool) {
                self.set_bool(path, value)
            }

            fn __set_void(&self, path: &str) {
                self.set_void(path)
            }

            fn __set<T: stdlib::Store>(&self, path: DotPathBuf, value: T) {
                T::__set(self, path, value)
            }

            fn __delete_matching_paths(&self, regexp: &str) -> u64 {
                self.delete_matching_paths(regexp)
            }
        }

        #[automatically_derived]
        impl ReadWriteContext for crate::kontor::built_in::context::ProcContext {}

        // Generate implementations for built-in types
        impls!();
        
        // Integer is a record type, store each field directly
        impl stdlib::Store for crate::kontor::built_in::numbers::Integer {
            fn __set(ctx: &impl stdlib::WriteContext, path: stdlib::DotPathBuf, value: Self) {
                // Store each field of the Integer record
                ctx.__set_u64(&format!("{}.r0", path), value.r0);
                ctx.__set_u64(&format!("{}.r1", path), value.r1);
                ctx.__set_u64(&format!("{}.r2", path), value.r2);
                ctx.__set_u64(&format!("{}.r3", path), value.r3);
                // Store sign as u64: 0 = plus, 1 = minus
                let sign_val = match value.sign {
                    crate::kontor::built_in::numbers::Sign::Plus => 0u64,
                    crate::kontor::built_in::numbers::Sign::Minus => 1u64,
                };
                ctx.__set_u64(&format!("{}.sign", path), sign_val);
            }
        }

        impl stdlib::Retrieve for crate::kontor::built_in::numbers::Integer {
            fn __get(ctx: &impl stdlib::ReadContext, path: stdlib::DotPathBuf) -> Option<Self> {
                // Retrieve each field of the Integer record
                let r0 = ctx.__get_u64(&format!("{}.r0", path))?;
                let r1 = ctx.__get_u64(&format!("{}.r1", path))?;
                let r2 = ctx.__get_u64(&format!("{}.r2", path))?;
                let r3 = ctx.__get_u64(&format!("{}.r3", path))?;
                let sign_val = ctx.__get_u64(&format!("{}.sign", path))?;
                let sign = match sign_val {
                    0 => crate::kontor::built_in::numbers::Sign::Plus,
                    1 => crate::kontor::built_in::numbers::Sign::Minus,
                    _ => return None, // Invalid sign value
                };
                Some(crate::kontor::built_in::numbers::Integer { r0, r1, r2, r3, sign })
            }
        }

        impl Default for crate::kontor::built_in::numbers::Integer {
            fn default() -> Self {
                crate::kontor::built_in::numbers::Integer {
                    r0: 0,
                    r1: 0,
                    r2: 0,
                    r3: 0,
                    sign: crate::kontor::built_in::numbers::Sign::Plus,
                }
            }
        }

        // Decimal is also a record type, store each field directly
        impl stdlib::Store for crate::kontor::built_in::numbers::Decimal {
            fn __set(ctx: &impl stdlib::WriteContext, path: stdlib::DotPathBuf, value: Self) {
                ctx.__set_u64(&format!("{}.r0", path), value.r0);
                ctx.__set_u64(&format!("{}.r1", path), value.r1);
                ctx.__set_u64(&format!("{}.r2", path), value.r2);
                ctx.__set_u64(&format!("{}.r3", path), value.r3);
                let sign_val = match value.sign {
                    crate::kontor::built_in::numbers::Sign::Plus => 0u64,
                    crate::kontor::built_in::numbers::Sign::Minus => 1u64,
                };
                ctx.__set_u64(&format!("{}.sign", path), sign_val);
            }
        }

        impl stdlib::Retrieve for crate::kontor::built_in::numbers::Decimal {
            fn __get(ctx: &impl stdlib::ReadContext, path: stdlib::DotPathBuf) -> Option<Self> {
                let r0 = ctx.__get_u64(&format!("{}.r0", path))?;
                let r1 = ctx.__get_u64(&format!("{}.r1", path))?;
                let r2 = ctx.__get_u64(&format!("{}.r2", path))?;
                let r3 = ctx.__get_u64(&format!("{}.r3", path))?;
                let sign_val = ctx.__get_u64(&format!("{}.sign", path))?;
                let sign = match sign_val {
                    0 => crate::kontor::built_in::numbers::Sign::Plus,
                    1 => crate::kontor::built_in::numbers::Sign::Minus,
                    _ => return None,
                };
                Some(crate::kontor::built_in::numbers::Decimal { r0, r1, r2, r3, sign })
            }
        }

        impl Default for crate::kontor::built_in::numbers::Decimal {
            fn default() -> Self {
                crate::kontor::built_in::numbers::Decimal {
                    r0: 0,
                    r1: 0,
                    r2: 0,
                    r3: 0,
                    sign: crate::kontor::built_in::numbers::Sign::Plus,
                }
            }
        }
        
        impl stdlib::Store for crate::kontor::built_in::foreign::ContractAddress {
            fn __set(ctx: &impl stdlib::WriteContext, path: stdlib::DotPathBuf, value: Self) {
                // Store as JSON or similar serialized format
                let serialized = format!("{}:{}:{}", value.name, value.height, value.tx_index);
                ctx.__set_str(&path, &serialized);
            }
        }

        impl stdlib::Retrieve for crate::kontor::built_in::foreign::ContractAddress {
            fn __get(ctx: &impl stdlib::ReadContext, path: stdlib::DotPathBuf) -> Option<Self> {
                ctx.__get_str(&path).and_then(|s| {
                    let parts: Vec<&str> = s.split(':').collect();
                    if parts.len() == 3 {
                        Some(crate::kontor::built_in::foreign::ContractAddress {
                            name: parts[0].to_string(),
                            height: parts[1].parse().ok()?,
                            tx_index: parts[2].parse().ok()?,
                        })
                    } else {
                        None
                    }
                })
            }
        }

        // Contract implementation struct
        struct #name;
        
        // Export the implementation
        export!(#name);
    }
}

fn parse_wit_resources(wit_path: &PathBuf, world_name: &str) -> Result<(HashSet<String>, HashSet<String>, TokenStream), anyhow::Error> {
    use wit_parser::*;
    
    let mut resources = HashSet::new();
    let mut records_with_resources = HashSet::new();
    let mut resource_infos = HashMap::new();
    let mut with_items = Vec::new();
    
    // Find all .wit files in the directory
    let wit_dir = wit_path.parent().unwrap_or(wit_path.as_path());
    let mut paths = Vec::new();
    
    if wit_path.is_dir() {
        for entry in std::fs::read_dir(wit_path)? {
            let entry = entry?;
            if entry.path().extension().map_or(false, |ext| ext == "wit") {
                paths.push(entry.path());
            }
        }
    } else if wit_path.exists() && wit_path.extension().map_or(false, |ext| ext == "wit") {
        paths.push(wit_path.clone());
    }
    
    // Also check for contract.wit in the directory
    let contract_wit = wit_dir.join("contract.wit");
    if contract_wit.exists() && !paths.contains(&contract_wit) {
        paths.push(contract_wit);
    }
    
    if paths.is_empty() {
        return Ok((resources, records_with_resources, TokenStream::new()));
    }
    
    // Parse WIT files - use push_dir to handle deps properly
    let mut resolve = Resolve::new();
    if wit_path.is_dir() {
        resolve.push_dir(wit_path)?;
    } else if let Some(parent) = wit_path.parent() {
        resolve.push_dir(parent)?;
    } else {
        for path in &paths {
            resolve.push_file(path)?;
        }
    }
    
    // Find the target world
    let world_id = resolve.worlds.iter()
        .find(|(_, w)| w.name == world_name)
        .map(|(id, _)| id)
        .ok_or_else(|| anyhow::anyhow!("World '{}' not found", world_name))?;
    
    let world = &resolve.worlds[world_id];
    
    // Collect resources from imports and exports
    for (_, item) in &world.imports {
        collect_resources_from_item(item, &resolve, &mut resources, &mut records_with_resources);
        collect_resource_info(item, &resolve, &mut resource_infos);
    }
    
    for (_, item) in &world.exports {
        collect_resources_from_item(item, &resolve, &mut resources, &mut records_with_resources);
        collect_resource_info(item, &resolve, &mut resource_infos);
    }
    
    // Register detailed resource information
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or(".".to_string());
    for (_name, info) in resource_infos {
        crate::registry::register_resource(&manifest_dir, info);
    }
    
    // Generate with clause for wit_bindgen
    // Note: Resources are handled differently by wit-bindgen, we don't need to wrap them
    if !records_with_resources.is_empty() {
        for rec in &records_with_resources {
            let rec_snake = to_snake_case(rec);
            with_items.push(quote! { #rec_snake: "super::#rec" });
        }
    }
    
    let with_clause = if !with_items.is_empty() {
        quote! { with: { #(#with_items),* } }
    } else {
        TokenStream::new()
    };
    
    Ok((resources, records_with_resources, with_clause))
}

fn collect_resources_from_item(
    item: &wit_parser::WorldItem,
    resolve: &wit_parser::Resolve,
    resources: &mut HashSet<String>,
    records_with_resources: &mut HashSet<String>,
) {
    use wit_parser::*;
    
    match item {
        WorldItem::Interface { id: iface_id, .. } => {
            let iface = &resolve.interfaces[*iface_id];
            for (name, type_id) in &iface.types {
                let typedef = &resolve.types[*type_id];
                match &typedef.kind {
                    TypeDefKind::Resource => {
                        resources.insert(to_pascal_case(name));
                    }
                    TypeDefKind::Record(record) => {
                        if record_contains_resources(&record, iface, resolve) {
                            records_with_resources.insert(to_pascal_case(name));
                        }
                    }
                    _ => {}
                }
            }
        }
        WorldItem::Function(_) => {}
        WorldItem::Type(type_id) => {
            let typedef = &resolve.types[*type_id];
            match &typedef.kind {
                TypeDefKind::Resource => {
                    resources.insert(to_pascal_case(&typedef.name.as_ref().unwrap()));
                }
                TypeDefKind::Record(record) => {
                    let owner = &typedef.owner;
                    match owner {
                        TypeOwner::Interface(iface_id) => {
                            let iface = &resolve.interfaces[*iface_id];
                            if record_contains_resources(&record, iface, resolve) {
                                records_with_resources.insert(to_pascal_case(&typedef.name.as_ref().unwrap()));
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
}

fn collect_resource_info(
    item: &wit_parser::WorldItem,
    resolve: &wit_parser::Resolve,
    resource_infos: &mut HashMap<String, crate::registry::ResourceInfo>,
) {
    use wit_parser::*;
    use crate::registry::{ResourceInfo, ResourceMethod};
    
    match item {
        WorldItem::Interface { id: iface_id, .. } => {
            let iface = &resolve.interfaces[*iface_id];
            
            // Find all resources in this interface
            for (name, type_id) in &iface.types {
                let typedef = &resolve.types[*type_id];
                if let TypeDefKind::Resource = &typedef.kind {
                    let pascal_name = to_pascal_case(name);
                    let mut methods = Vec::new();
                    let mut has_constructor = false;
                    
                    // Find all functions that operate on this resource
                    for (func_name, func) in &iface.functions {
                        // Check if function is a constructor
                        if *func_name == format!("[constructor]{}", name) {
                            has_constructor = true;
                            continue;
                        }
                        
                        // Check if function is a method or static method on this resource
                        if func_name.starts_with(&format!("[method]{}-", name)) {
                            let method_name = func_name.trim_start_matches(&format!("[method]{}-", name));
                            methods.push(ResourceMethod {
                                name: method_name.to_string(),
                                is_static: false,
                                consumes_self: true, // For now assume all methods consume self
                                params: func.params.iter().map(|(pname, _)| pname.clone()).collect(),
                                return_type: format_function_return(&func.result),
                            });
                        } else if func_name.starts_with(&format!("[static]{}-", name)) {
                            let method_name = func_name.trim_start_matches(&format!("[static]{}-", name));
                            methods.push(ResourceMethod {
                                name: method_name.to_string(),
                                is_static: true,
                                consumes_self: false,
                                params: func.params.iter().map(|(pname, _)| pname.clone()).collect(),
                                return_type: format_function_return(&func.result),
                            });
                        }
                    }
                    
                    let package = iface.package.as_ref()
                        .and_then(|pkg_id| resolve.packages.get(*pkg_id))
                        .map(|pkg| format!("{}:{}", pkg.name.namespace, pkg.name.name))
                        .unwrap_or_default();
                    
                    resource_infos.insert(pascal_name.clone(), ResourceInfo {
                        name: pascal_name,
                        package,
                        methods,
                        has_constructor,
                    });
                }
            }
        }
        _ => {}
    }
}

fn format_function_return(result: &Option<wit_parser::Type>) -> String {
    match result {
        Some(ty) => format!("{:?}", ty), // Simplified for now
        None => "()".to_string(),
    }
}

fn record_contains_resources(
    record: &wit_parser::Record,
    iface: &wit_parser::Interface,
    resolve: &wit_parser::Resolve,
) -> bool {
    record.fields.iter().any(|field| {
        type_is_or_contains_resource(&field.ty, iface, resolve)
    })
}

fn type_is_or_contains_resource(
    ty: &wit_parser::Type,
    iface: &wit_parser::Interface,
    resolve: &wit_parser::Resolve,
) -> bool {
    use wit_parser::Type;
    
    match ty {
        Type::Id(type_id) => {
            let typedef = &resolve.types[*type_id];
            match &typedef.kind {
                TypeDefKind::Resource => true,
                TypeDefKind::Record(record) => record_contains_resources(record, iface, resolve),
                TypeDefKind::Option(inner) | TypeDefKind::List(inner) => {
                    type_is_or_contains_resource(inner, iface, resolve)
                }
                TypeDefKind::Result(result) => {
                    result.ok.as_ref().map_or(false, |t| type_is_or_contains_resource(t, iface, resolve)) ||
                    result.err.as_ref().map_or(false, |t| type_is_or_contains_resource(t, iface, resolve))
                }
                TypeDefKind::Tuple(tuple) => {
                    tuple.types.iter().any(|t| type_is_or_contains_resource(t, iface, resolve))
                }
                TypeDefKind::Variant(variant) => {
                    variant.cases.iter().any(|case| {
                        case.ty.as_ref().map_or(false, |t| type_is_or_contains_resource(t, iface, resolve))
                    })
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && ch.is_uppercase() {
            result.push('_');
        }
        result.push(ch.to_lowercase().next().unwrap());
    }
    result
}

fn to_pascal_case(s: &str) -> String {
    s.split(&['-', '_'][..])
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars.as_str().to_lowercase().chars()).collect(),
            }
        })
        .collect()
}

