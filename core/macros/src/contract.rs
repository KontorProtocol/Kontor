use darling::FromMeta;
use heck::ToPascalCase;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
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
        
        // Integer is a record type, store it as a string representation
        impl stdlib::Store for crate::kontor::built_in::numbers::Integer {
            fn __set(ctx: &impl stdlib::WriteContext, path: stdlib::DotPathBuf, value: Self) {
                // Convert to string for storage using the numbers module
                let s = crate::kontor::built_in::numbers::integer_to_string(value);
                ctx.__set_str(&path, &s);
            }
        }

        impl stdlib::Retrieve for crate::kontor::built_in::numbers::Integer {
            fn __get(ctx: &impl stdlib::ReadContext, path: stdlib::DotPathBuf) -> Option<Self> {
                // Convert from string representation
                ctx.__get_str(&path).map(|s| crate::kontor::built_in::numbers::string_to_integer(s))
            }
        }

        impl Default for crate::kontor::built_in::numbers::Integer {
            fn default() -> Self {
                crate::kontor::built_in::numbers::u64_to_integer(0)
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

fn generate_resource_structs(resources: &HashSet<String>) -> TokenStream {
    let structs = resources.iter().map(|name| {
        let ident = format_ident!("{}", name);
        let _snake_name = to_snake_case(name);
        
        // For now, just use the generated type directly
        // We'll enhance this once we have proper resource handling
        quote! {
            // Resource type #ident will be available from wit-bindgen
        }
    });
    
    quote! { #(#structs)* }
}

fn generate_record_helpers(records_with_resources: &HashSet<String>) -> TokenStream {
    let helpers = records_with_resources.iter().map(|name| {
        let ident = format_ident!("{}", name);
        let snake_name = to_snake_case(name);
        let binding_type = format_ident!("{}", snake_name);
        
        quote! {
            /// Record wrapper for #name that may contain resources
            #[derive(Debug)]
            pub struct #ident {
                inner: #binding_type::#ident,
            }
            
            impl #ident {
                /// Create from wit-bindgen generated type
                pub fn from_binding(inner: #binding_type::#ident) -> Self {
                    Self { inner }
                }
                
                /// Convert to wit-bindgen generated type
                pub fn into_binding(self) -> #binding_type::#ident {
                    self.inner
                }
            }
        }
    });
    
    quote! { #(#helpers)* }
}

fn generate_conversion_helpers(resources: &HashSet<String>, records_with_resources: &HashSet<String>) -> TokenStream {
    // Generate conversion functions for nested types containing resources
    let all_types: HashSet<_> = resources.union(records_with_resources).cloned().collect();
    
    if all_types.is_empty() {
        return TokenStream::new();
    }
    
    let option_conversions = all_types.iter().map(|name| {
        let ident = format_ident!("{}", name);
        let snake_name = to_snake_case(name);
        let binding_mod = format_ident!("{}", snake_name);
        
        quote! {
            impl From<Option<#binding_mod::#ident>> for Option<#ident> {
                fn from(opt: Option<#binding_mod::#ident>) -> Self {
                    opt.map(#ident::from_binding)
                }
            }
            
            impl From<Option<#ident>> for Option<#binding_mod::#ident> {
                fn from(opt: Option<#ident>) -> Self {
                    opt.map(#ident::into_binding)
                }
            }
        }
    });
    
    let result_conversions = all_types.iter().map(|name| {
        let ident = format_ident!("{}", name);
        let snake_name = to_snake_case(name);
        let binding_mod = format_ident!("{}", snake_name);
        
        quote! {
            impl<E> From<Result<#binding_mod::#ident, E>> for Result<#ident, E> {
                fn from(res: Result<#binding_mod::#ident, E>) -> Self {
                    res.map(#ident::from_binding)
                }
            }
            
            impl<E> From<Result<#ident, E>> for Result<#binding_mod::#ident, E> {
                fn from(res: Result<#ident, E>) -> Self {
                    res.map(#ident::into_binding)
                }
            }
        }
    });
    
    quote! {
        // Conversion helpers for Option types
        #(#option_conversions)*
        
        // Conversion helpers for Result types
        #(#result_conversions)*
    }
}

fn generate_adapter_module(_name: &Ident, resources: &HashSet<String>, records_with_resources: &HashSet<String>) -> TokenStream {
    if resources.is_empty() && records_with_resources.is_empty() {
        return TokenStream::new();
    }
    
    // Generate adapter module that wraps the Guest trait implementation
    quote! {
        /// Resource adapter module
        /// This module provides the glue between move-only resource structs and wit-bindgen
        mod resource_adapter {
            use super::*;
            
            /// Helper to serialize resources via WAVE when crossing boundaries
            pub fn serialize_resource<T: Into<stdlib::wasm_wave::value::Value>>(resource: T) -> Vec<u8> {
                let value = resource.into();
                stdlib::wasm_wave::encode(&value).expect("Resource serialization failed")
            }
            
            /// Helper to deserialize resources via WAVE when receiving from host
            pub fn deserialize_resource<T: From<stdlib::wasm_wave::value::Value>>(bytes: &[u8]) -> T {
                let value = stdlib::wasm_wave::decode(bytes).expect("Resource deserialization failed");
                T::from(value)
            }
        }
    }
}
