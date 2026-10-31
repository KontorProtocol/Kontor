use std::{env, fs};
use wasmparser::{Parser, Payload};
use wit_component::ComponentEncoder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("input path required")?;
    let module = fs::read(&path)?;
    let component = ComponentEncoder::default()
        .module(&module)?
        .validate(true)
        .encode()?;
    let mut core_starts = 0;
    let mut component_starts = 0;
    let mut modules = 0;
    for payload in Parser::new(0).parse_all(&component) {
        match payload? {
            Payload::StartSection { .. } => core_starts += 1,
            Payload::ComponentStartSection { .. } => component_starts += 1,
            Payload::ModuleSection { .. } => modules += 1,
            _ => {}
        }
    }
    println!(
        "{} bytes={} embedded_modules={} core_starts={} component_starts={}",
        path,
        component.len(),
        modules,
        core_starts,
        component_starts
    );
    if core_starts != 0 || component_starts != 0 {
        return Err("encoded component contains a start section".into());
    }
    Ok(())
}
