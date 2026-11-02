use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::str;

#[derive(Clone, Debug)]
pub struct Namespace(String);

impl Namespace {
    pub fn parse(value: String) -> Result<Self, String> {
        let mut chars = value.chars();
        if value.len() > 96
            || !chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(
                "native namespace must be a nonempty C identifier of at most 96 bytes".into(),
            );
        }
        Ok(Self(value))
    }

    pub fn configured() -> Option<Self> {
        println!("cargo:rerun-if-env-changed=KONTOR_NATIVE_NAMESPACE");
        println!("cargo:rerun-if-env-changed=KONTOR_PROTOCOL_BUNDLE");
        let bundle = match env::var("KONTOR_PROTOCOL_BUNDLE") {
            Ok(value) if value == "1" => true,
            Err(env::VarError::NotPresent) => false,
            _ => panic!("KONTOR_PROTOCOL_BUNDLE must be absent or 1"),
        };
        match env::var("KONTOR_NATIVE_NAMESPACE") {
            Ok(value) => Some(Self::parse(value).expect("invalid KONTOR_NATIVE_NAMESPACE")),
            Err(env::VarError::NotPresent) if !bundle => None,
            Err(env::VarError::NotPresent) => {
                panic!("protocol bundle requires an explicit KONTOR_NATIVE_NAMESPACE")
            }
            Err(_) => panic!("KONTOR_NATIVE_NAMESPACE must be Unicode"),
        }
    }

    pub fn symbol(&self, name: &str) -> String {
        format!("{}_{}", self.0, name)
    }

    pub fn prefix(&self) -> String {
        format!("{}_", self.0)
    }

    pub fn require_preprocessable_target(&self) {
        if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            panic!("namespaced native bundles require a preprocessor-capable Unix or Wasm target");
        }
    }
}

pub fn rewrite_tokens(input: &[u8], rename: impl Fn(&str) -> Option<String>) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut pos = 0;
    while pos < input.len() {
        let start = pos;
        match input[pos] {
            b'"' | b'\'' => {
                let quote = input[pos];
                pos += 1;
                while pos < input.len() {
                    let byte = input[pos];
                    pos += 1;
                    if byte == b'\\' {
                        pos = (pos + 1).min(input.len());
                    } else if byte == quote || byte == b'\n' {
                        break;
                    }
                }
            }
            b'/' if input.get(pos + 1) == Some(&b'/') => {
                pos += 2;
                while pos < input.len() && input[pos] != b'\n' {
                    pos += 1;
                }
            }
            b'/' if input.get(pos + 1) == Some(&b'*') => {
                pos += 2;
                while pos < input.len() {
                    if input[pos] == b'*' && input.get(pos + 1) == Some(&b'/') {
                        pos += 2;
                        break;
                    }
                    pos += 1;
                }
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                pos += 1;
                while pos < input.len()
                    && (input[pos].is_ascii_alphanumeric() || input[pos] == b'_')
                {
                    pos += 1;
                }
                let identifier = str::from_utf8(&input[start..pos]).unwrap();
                if let Some(replacement) = rename(identifier) {
                    output.extend_from_slice(replacement.as_bytes());
                    continue;
                }
            }
            _ => pos += 1,
        }
        output.extend_from_slice(&input[start..pos]);
    }
    output
}

pub fn preprocess_sources(
    config: &cc::Build,
    sources: &[PathBuf],
    out_dir: &Path,
    rename: impl Fn(&str) -> Option<String>,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    fs::create_dir_all(out_dir)?;
    let mut generated = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        // Renaming before preprocessing changes #ifdef fallback selection and
        // misses names created by token pasting in blst.
        let expanded = config.clone().file(source).try_expand()?;
        let filename = source.file_name().ok_or("native source has no file name")?;
        let path = out_dir.join(format!("{index}-{}", filename.to_string_lossy()));
        fs::write(&path, rewrite_tokens(&expanded, &rename))?;
        generated.push(path);
    }
    Ok(generated)
}

#[cfg(test)]
mod tests {
    use super::{Namespace, rewrite_tokens};

    #[test]
    fn invalid_namespace_cannot_become_source_or_a_linker_option() {
        for value in ["", "1bad", "has-dash", "x;run", "x\n#define bad", "é"] {
            assert!(Namespace::parse(value.into()).is_err());
        }
        assert!(Namespace::parse("x".repeat(97)).is_err());
        assert_eq!(
            Namespace::parse("p1_abc".into()).unwrap().symbol("foo"),
            "p1_abc_foo"
        );
    }

    #[test]
    fn rewriting_preserves_literals_comments_and_identifier_boundaries() {
        let source = br#"foo(foo_suffix); "foo\"foo"; 'f'; // foo
/* foo */ foo; #line 1 "foo.c"
"#;
        let expected = br#"bundle_foo(foo_suffix); "foo\"foo"; 'f'; // foo
/* foo */ bundle_foo; #line 1 "foo.c"
"#;
        assert_eq!(
            rewrite_tokens(source, |name| (name == "foo").then(|| "bundle_foo".into())),
            expected
        );
    }

    #[test]
    fn assembly_symbols_are_rewritten_without_changing_strings_or_locals() {
        let source = b".globl _foo\n_foo:\n call _foo\n.Lfoo:\n.asciz \"_foo\"\n";
        let expected =
            b".globl _bundle_foo\n_bundle_foo:\n call _bundle_foo\n.Lfoo:\n.asciz \"_foo\"\n";
        assert_eq!(
            rewrite_tokens(source, |name| (name == "_foo")
                .then(|| "_bundle_foo".into())),
            expected
        );
    }

    #[test]
    fn apostrophes_in_assembly_comments_cannot_hide_the_next_line() {
        let source = b"# Don't skip the next call\n call foo\n# Isn't a character literal\n";
        let expected =
            b"# Don't skip the next call\n call bundle_foo\n# Isn't a character literal\n";
        assert_eq!(
            rewrite_tokens(source, |name| (name == "foo").then(|| "bundle_foo".into())),
            expected
        );
    }
}
