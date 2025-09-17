use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone)]
pub struct ResourceMethod {
    pub name: String,
    pub is_static: bool,
    pub consumes_self: bool,
    pub params: Vec<String>,
    pub return_type: String,
}

#[derive(Debug, Clone)]
pub struct ResourceInfo {
    pub name: String,
    pub package: String,
    pub methods: Vec<ResourceMethod>,
    pub has_constructor: bool,
}

#[derive(Default, Clone)]
pub struct ContractResources {
    pub resources: HashMap<String, ResourceInfo>,
    pub imported_resources: HashSet<String>, // Resources imported from other packages
    pub exported_resources: HashSet<String>, // Resources exported by this contract
}

static REGISTRY: OnceLock<Mutex<HashMap<String, ContractResources>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, ContractResources>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_resource(manifest_dir: &str, resource: ResourceInfo) {
    let mut guard = registry().lock().expect("resource registry poisoned");
    let entry = guard.entry(manifest_dir.to_string()).or_default();
    entry.resources.insert(resource.name.clone(), resource);
}

pub fn set_resources(manifest_dir: &str, resources: HashSet<String>) {
    let mut guard = registry().lock().expect("resource registry poisoned");
    let entry = guard.entry(manifest_dir.to_string()).or_default();
    for resource_name in resources {
        entry.resources.entry(resource_name.clone()).or_insert(ResourceInfo {
            name: resource_name,
            package: String::new(),
            methods: Vec::new(),
            has_constructor: false,
        });
    }
}

pub fn set_imported_resources(manifest_dir: &str, imported: HashSet<String>) {
    let mut guard = registry().lock().expect("resource registry poisoned");
    let entry = guard.entry(manifest_dir.to_string()).or_default();
    entry.imported_resources = imported;
}

pub fn set_exported_resources(manifest_dir: &str, exported: HashSet<String>) {
    let mut guard = registry().lock().expect("resource registry poisoned");
    let entry = guard.entry(manifest_dir.to_string()).or_default();
    entry.exported_resources = exported;
}

pub fn is_resource_type(manifest_dir: &str, type_name: &str) -> bool {
    registry()
        .lock()
        .ok()
        .and_then(|guard| guard.get(manifest_dir).cloned())
        .map_or(false, |info| {
            info.resources.contains_key(type_name) || 
            info.imported_resources.contains(type_name)
        })
}

pub fn get_resource_info(manifest_dir: &str, type_name: &str) -> Option<ResourceInfo> {
    registry()
        .lock()
        .ok()
        .and_then(|guard| guard.get(manifest_dir).cloned())
        .and_then(|info| info.resources.get(type_name).cloned())
}

pub fn get_all_resources(manifest_dir: &str) -> ContractResources {
    registry()
        .lock()
        .ok()
        .and_then(|guard| guard.get(manifest_dir).cloned())
        .unwrap_or_default()
}
