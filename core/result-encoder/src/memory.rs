use std::convert::Infallible;

use anyhow::{Result, ensure};
use wasm_encoder::{
    EntityType, ImportSection, Instruction, MemArg, MemoryType, Module,
    reencode::{Error, Reencode, utils},
};
use wasmparser::{ImportSectionReader, Operator, Parser, TypeRef};

#[derive(Default)]
struct SharedMemory {
    byte: Option<u32>,
    pages: Option<u32>,
}

impl Reencode for SharedMemory {
    type Error = Infallible;

    fn memory_index(&mut self, index: u32) -> Result<u32, Error<Self::Error>> {
        Ok(index + 1)
    }

    fn parse_import_section(
        &mut self,
        imports: &mut ImportSection,
        section: ImportSectionReader<'_>,
    ) -> Result<(), Error<Self::Error>> {
        imports.import(
            "source",
            "memory",
            EntityType::Memory(MemoryType {
                minimum: 0,
                maximum: None,
                memory64: false,
                shared: false,
                page_size_log2: None,
            }),
        );
        let mut function = 0;
        for import in section.clone().into_imports() {
            let import = import?;
            if matches!(import.ty, TypeRef::Func(_)) {
                match (import.module, import.name) {
                    ("source", "byte") => self.byte = Some(function),
                    ("source", "pages") => self.pages = Some(function),
                    _ => {}
                }
                function += 1;
            }
        }
        utils::parse_import_section(self, imports, section)
    }

    fn instruction<'a>(
        &mut self,
        operator: Operator<'a>,
    ) -> Result<Instruction<'a>, Error<Self::Error>> {
        match operator {
            Operator::Call { function_index } if Some(function_index) == self.byte => {
                Ok(Instruction::I32Load8U(MemArg {
                    offset: 0,
                    align: 0,
                    memory_index: 0,
                }))
            }
            Operator::Call { function_index } if Some(function_index) == self.pages => {
                Ok(Instruction::MemorySize(0))
            }
            operator => utils::instruction(self, operator),
        }
    }
}

pub(super) fn inject(bytes: &[u8]) -> Result<Vec<u8>> {
    // Rust owns memory 0 in the compiled formatter. Add the source as memory 0
    // and move all original memory references to 1. Only the two explicit read
    // imports become source-memory instructions; its allocator and Unicode data
    // continue to use private memory. Function indices do not change.
    let mut reencoder = SharedMemory::default();
    let mut module = Module::new();
    reencoder.parse_core_module(&mut module, Parser::new(0), bytes)?;
    ensure!(
        reencoder.byte.is_some() && reencoder.pages.is_some(),
        "encoder source read imports are missing"
    );
    Ok(module.finish())
}
