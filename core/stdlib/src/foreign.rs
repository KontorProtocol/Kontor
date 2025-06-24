use anyhow::{Result, anyhow};
use std::path::Path;
use tokio::fs::read;
use wasmtime::{
    Engine, Store,
    component::{
        Component, Linker, Type, Val,
        wasm_wave::parser::Parser as WaveParser,
    },
};
use wit_component::ComponentEncoder;

type CallOperationFn = Box<dyn Fn(String, String) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>> + Send + Sync>;

#[derive(Clone)]
struct ForeignService {
    engine: Engine,
    component: Component,
}

impl ForeignService {
    async fn new(address: &str) -> Result<Self> {
        let path = Path::new(address);        
        // Check if the file exists
        if !path.exists() {
            return Err(anyhow!(
                "Invalid address: {} provided to foreign constructor. WASM file not found at {}",
                address, path.display()
            ));
        }
                
        let module_bytes = read(path).await?;
        let component_bytes = ComponentEncoder::default()
            .module(&module_bytes)?
            .validate(true)
            .encode()?;

        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;

        let component = Component::from_binary(&engine, &component_bytes)?;
        
        Ok(Self { engine, component })
    }

    // .call("sum", "1, 2")
    // result => 1, 2
    async fn call_function(&self, name: &str, args: &str) -> Result<String> {
        let mut store = Store::new(&self.engine, ());
        let linker = Linker::new(&self.engine);
        
        let s = format!("{}({})", name, args);
        let call = WaveParser::new(&s).parse_raw_func_call()?;
        
        let instance = linker.instantiate_async(&mut store, &self.component).await?;
        
        let func = instance
            .get_func(&mut store, call.name())
            .ok_or_else(|| anyhow::anyhow!("{} function not found in instance", name))?;
        let params = call.to_wasm_params(func.params(&store).iter().map(|(_, t)| t))?;
        let mut results = func
            .results(&store)
            .iter()
            .map(default_val_for_type)
            .collect::<Vec<_>>();
        func.call_async(&mut store, &params, &mut results).await?;
        
        if results.is_empty() {
            return Ok("()".to_string());
        }
        
        if results.len() == 1 {
            return Ok(results[0].to_wave()?);
        }
        
        // Multiple results as tuple
        let mut encoded_results = Vec::with_capacity(results.len());
        for val in &results {
            encoded_results.push(val.to_wave()?);
        }
        Ok(format!("{}", encoded_results.join(", ")))
    }
}

pub struct ForeignHostRep {
    pub call_operation: CallOperationFn,
}

impl ForeignHostRep {
    pub async fn new(address: String) -> Result<Self> {
        let caller = ForeignService::new(&address).await?;
        
        Ok(ForeignHostRep {
            call_operation: Box::new(move |name: String, args: String| {
                let caller = caller.clone();
                Box::pin(async move {
                    // Return the wave-encoded result or an error message
                    match caller.call_function(&name, &args).await {
                        Ok(wave_result) => wave_result,
                        Err(e) => format!("Error: {}", e),
                    }
                })
            }),
        })
    }
}

pub fn default_val_for_type(ty: &Type) -> Val {
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
                  let field_val = default_val_for_type(&field.ty);
                  (field.name.to_string(), field_val)
              })
              .collect::<Vec<_>>();
          Val::Record(fields)
      }
      Type::Tuple(tuple_ty) => {
          let fields = tuple_ty
              .types()
              .map(|ty| default_val_for_type(&ty))
              .collect::<Vec<_>>();
          Val::Tuple(fields)
      }
      Type::Variant(variant_ty) => {
          let first_case = variant_ty
              .cases()
              .next()
              .expect("Variant must have at least one case");
          let payload = first_case.ty.map(|ty| Box::new(default_val_for_type(&ty)));
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
              Val::Result(Ok(Some(Box::new(default_val_for_type(&ty)))))
          } else if let Some(ty) = result_ty.err() {
              Val::Result(Err(Some(Box::new(default_val_for_type(&ty)))))
          } else {
              Val::Result(Ok(None))
          }
      }
      Type::Flags(_) => Val::Flags(Vec::new()),
      Type::Own(_) => panic!("Cannot create a default Own value without a resource context"),
      Type::Borrow(_) => {
          panic!("Cannot create a default Borrow value without a resource context")
      }
  }
}
