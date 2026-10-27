use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;

use object::read::archive::ArchiveFile;
use object::{
    BinaryFormat, Object, ObjectComdat, ObjectKind, ObjectSection, ObjectSymbol, RelocationTarget,
    SectionFlags, SectionIndex, SymbolKind, SymbolSection,
};
use object::{File, elf, macho};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn normalized(name: &str, namespace: &str) -> String {
    if namespace.is_empty() {
        name.into()
    } else {
        name.replace(&format!("{namespace}_"), "")
    }
}

fn section_name(file: &File<'_>, index: SectionIndex, namespace: &str) -> Result<String> {
    let section = file.section_by_index(index)?;
    Ok(format!(
        "{}:{}",
        section.segment_name()?.unwrap_or(""),
        normalized(section.name()?, namespace)
    ))
}

fn retained<'data>(section: &impl ObjectSection<'data>) -> bool {
    match section.flags() {
        SectionFlags::Elf { sh_flags, .. } => {
            sh_flags.0 & elf::SHF_ALLOC.0 != 0 || section.name().ok() == Some(".note.GNU-stack")
        }
        SectionFlags::MachO { flags, .. } => flags.0 & macho::S_ATTR_DEBUG.0 == 0,
        _ => false,
    }
}

fn object_report(data: &[u8], namespace: &str) -> Result<Value> {
    let file = File::parse(data)?;
    if !matches!(file.format(), BinaryFormat::Elf | BinaryFormat::MachO)
        || file.kind() != ObjectKind::Relocatable
    {
        return Err("expected a relocatable ELF or Mach-O native object".into());
    }
    let mut comdats = Vec::new();
    for group in file.comdats() {
        let mut members = Vec::new();
        for index in group.sections() {
            if retained(&file.section_by_index(index)?) {
                members.push(section_name(&file, index, namespace)?);
            }
        }
        // Debug-macro groups do not contribute bytes to the loaded image.
        if !members.is_empty() {
            members.sort();
            comdats.push(json!({
                "name": normalized(group.name()?, namespace),
                "kind": format!("{:?}", group.kind()), "sections": members,
            }));
        }
    }
    let mut sections = BTreeMap::new();
    for section in file.sections().filter(retained) {
        let mut relocations = Vec::new();
        for (offset, relocation) in section.relocations() {
            let target = match relocation.target() {
                RelocationTarget::Symbol(index) => {
                    let symbol = file.symbol_by_index(index)?;
                    if symbol.kind() == SymbolKind::Section {
                        json!({"section": section_name(&file, symbol.section_index().ok_or("section symbol has no section")?, namespace)?})
                    } else {
                        json!({"symbol": normalized(symbol.name()?, namespace)})
                    }
                }
                RelocationTarget::Section(index) => {
                    json!({"section": section_name(&file, index, namespace)?})
                }
                RelocationTarget::Absolute => json!({"absolute": true}),
                _ => return Err("unsupported relocation target".into()),
            };
            relocations.push(json!({
                "offset": offset, "target": target, "addend": relocation.addend(),
                "implicit_addend": relocation.has_implicit_addend(),
                "flags": format!("{:?}", relocation.flags()),
                "kind": format!("{:?}", relocation.kind()),
                "encoding": format!("{:?}", relocation.encoding()), "size": relocation.size(),
            }));
        }
        let name = section_name(&file, section.index(), namespace)?;
        let value = json!({
            "address": section.address(), "size": section.size(), "align": section.align(),
            "kind": format!("{:?}", section.kind()), "flags": format!("{:?}", section.flags()),
            // Byte comparison is stricter than comparing normalized disassembly.
            // Relocations identify every link-time substitution separately.
            "bytes": section.data()?.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "relocations": relocations,
        });
        if sections.insert(name, value).is_some() {
            return Err("duplicate native section name".into());
        }
    }
    if sections.is_empty() {
        return Err("object contains no retained sections".into());
    }
    let mut symbols = Vec::new();
    for symbol in file.symbols() {
        if matches!(symbol.kind(), SymbolKind::File | SymbolKind::Section) {
            continue;
        }
        let section = match symbol.section() {
            SymbolSection::Section(index) => {
                if !retained(&file.section_by_index(index)?) {
                    continue;
                }
                section_name(&file, index, namespace)?
            }
            other => format!("{other:?}"),
        };
        symbols.push(json!({
            "name": normalized(symbol.name()?, namespace), "section": section,
            "address": symbol.address(), "size": symbol.size(),
            "kind": format!("{:?}", symbol.kind()), "scope": format!("{:?}", symbol.scope()),
            "weak": symbol.is_weak(), "flags": format!("{:?}", symbol.flags()),
        }));
    }
    symbols.sort_by_key(Value::to_string);
    Ok(json!({
        "format": format!("{:?}", file.format()), "architecture": format!("{:?}", file.architecture()),
        "little_endian": file.is_little_endian(), "flags": format!("{:?}", file.flags()),
        "sections": sections, "symbols": symbols, "comdats": comdats,
    }))
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: kontor-native-object-report FILE NAMESPACE (empty for upstream)".into(),
        );
    }
    let data = fs::read(&args[1])?;
    let result = if data.starts_with(b"!<arch>\n") {
        let archive = ArchiveFile::parse(data.as_slice())?;
        let mut members = Vec::new();
        for member in archive.members() {
            let member = member?;
            members.push(object_report(member.data(data.as_slice())?, &args[2])?);
        }
        if members.is_empty() {
            return Err("empty native archive".into());
        }
        json!({"members": members})
    } else {
        object_report(&data, &args[2])?
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
