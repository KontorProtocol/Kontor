use ar_archive_writer::{write_archive_to_stream, ArchiveKind, NewArchiveMember, ObjectReader};
use kontor_native_build::{preprocess_sources, Namespace};
use std::env::var;
use std::fs::{self, metadata, read};
use std::io::Cursor;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const NATIVE_SYMBOLS: [&str; 4] = [
    "rust_psm_stack_direction",
    "rust_psm_stack_pointer",
    "rust_psm_replace_stack",
    "rust_psm_on_stack",
];

fn find_assembly(
    arch: &str,
    endian: &str,
    os: &str,
    env: &str,
    masm: bool,
) -> Option<(&'static str, bool)> {
    match (arch, endian, os, env) {
        // The implementations for stack switching exist, but, officially, doing so without Fibers
        // is not supported in Windows. For x86_64 the implementation actually works locally,
        // but failed tests in CI (???). Might want to have a feature for experimental support
        // here.
        ("x86", _, "windows", _) => {
            if masm {
                Some(("src/arch/x86_msvc.asm", false))
            } else {
                Some(("src/arch/x86_windows_gnu.s", false))
            }
        }
        ("x86_64", _, "windows", _) => {
            if masm {
                Some(("src/arch/x86_64_msvc.asm", false))
            } else {
                Some(("src/arch/x86_64_windows_gnu.s", false))
            }
        }
        ("x86_64", _, "cygwin", _) => Some(("src/arch/x86_64_windows_gnu.s", false)),
        ("arm", _, "windows", "msvc") => Some(("src/arch/arm_armasm.asm", false)),
        ("arm64ec", _, "windows", "msvc") => Some(("src/arch/arm64ec_armasm.asm", false)),
        ("aarch64", _, "windows", _) => {
            if masm {
                Some(("src/arch/aarch64_armasm.asm", false))
            } else {
                Some(("src/arch/aarch_aapcs64.s", false))
            }
        }
        ("x86", _, _, _) => Some(("src/arch/x86.s", true)),
        ("x86_64", _, _, _) => Some(("src/arch/x86_64.s", true)),
        ("arm", _, _, _) => Some(("src/arch/arm_aapcs.s", true)),
        ("aarch64", _, _, _) => Some(("src/arch/aarch_aapcs64.s", true)),
        ("powerpc", _, _, _) => Some(("src/arch/powerpc32.s", true)),
        ("powerpc64", _, _, "musl") => Some(("src/arch/powerpc64_openpower.s", true)),
        ("powerpc64", "little", _, _) => Some(("src/arch/powerpc64_openpower.s", true)),
        ("powerpc64", _, "aix", _) => Some(("src/arch/powerpc64_aix.s", true)),
        ("powerpc64", _, _, _) => Some(("src/arch/powerpc64.s", true)),
        ("s390x", _, _, _) => Some(("src/arch/zseries_linux.s", true)),
        ("mips", _, _, _) => Some(("src/arch/mips_eabi.s", true)),
        ("mips64", _, _, _) => Some(("src/arch/mips64_eabi.s", true)),
        ("sparc64", _, _, _) => Some(("src/arch/sparc64.s", true)),
        ("sparc", _, _, _) => Some(("src/arch/sparc_sysv.s", true)),
        ("riscv32", _, _, _) => Some(("src/arch/riscv.s", true)),
        ("riscv64", _, _, _) => Some(("src/arch/riscv64.s", true)),
        ("wasm32", _, _, _) => Some(("src/arch/wasm32.o", true)),
        ("loongarch64", _, _, _) => Some(("src/arch/loongarch64.s", true)),
        _ => None,
    }
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(switchable_stack,asm,link_asm)");
    println!("cargo:rustc-check-cfg=cfg(kontor_native_namespace)");
    let namespace = Namespace::configured();

    if var("CARGO_CFG_MIRI").is_ok() {
        // Miri doesn't have a stack limit and the inline asm wouldn't work on miri anyway.
        return;
    }

    let arch = var("CARGO_CFG_TARGET_ARCH").unwrap();
    let env = var("CARGO_CFG_TARGET_ENV").unwrap();
    let os = var("CARGO_CFG_TARGET_OS").unwrap();
    let endian = var("CARGO_CFG_TARGET_ENDIAN").unwrap();

    let mut cfg = cc::Build::new();

    let msvc = cfg.get_compiler().is_like_msvc();
    // If we're targeting msvc, either via regular MS toolchain or clang-cl, we
    // will _usually_ want to use the regular Microsoft assembler if it exists,
    // which is done for us within cc, however it _probably_ won't exist if
    // we're in a cross-compilation context pm a platform that can't natively
    // run Windows executables, so in that case we instead use the the equivalent
    // GAS assembly file instead. This logic can be removed once LLVM natively
    // supports compiling MASM, but that is not stable yet
    let masm = msvc && var("HOST").expect("HOST env not set").contains("windows");

    let asm = if let Some((asm, canswitch)) = find_assembly(&arch, &endian, &os, &env, masm) {
        println!("cargo:rustc-cfg=asm");
        println!("cargo:rustc-cfg=link_asm");
        if canswitch {
            println!("cargo:rustc-cfg=switchable_stack")
        }
        asm
    } else {
        println!(
            "cargo:warning=Target {}-{}-{} has no assembly files!",
            arch, os, env
        );
        return;
    };

    if !msvc {
        cfg.flag("-xassembler-with-cpp");
        cfg.define(&*format!("CFG_TARGET_OS_{}", os), None);
        cfg.define(&*format!("CFG_TARGET_ARCH_{}", arch), None);
        cfg.define(&*format!("CFG_TARGET_ENV_{}", env), None);
    }

    let asm = if let Some(namespace) = namespace {
        namespace.require_preprocessable_target();
        if asm.ends_with(".o") {
            panic!("namespaced psm requires assembly source, not a precompiled object");
        }
        println!("cargo:rerun-if-changed=src/arch");
        println!("cargo:rustc-cfg=kontor_native_namespace");
        println!("cargo:rustc-env=KONTOR_PSM_PREFIX={}", namespace.prefix());
        let out_dir = PathBuf::from(var("OUT_DIR").expect("OUT_DIR environment variable not set"));
        let generated = preprocess_sources(
            &cfg,
            &[PathBuf::from(asm)],
            &out_dir.join("kontor-assembly"),
            |symbol| {
                if NATIVE_SYMBOLS.contains(&symbol) {
                    Some(namespace.symbol(symbol))
                } else if symbol.starts_with('_') && NATIVE_SYMBOLS.contains(&&symbol[1..]) {
                    Some(format!("_{}", namespace.symbol(&symbol[1..])))
                } else {
                    None
                }
            },
        )
        .expect("failed to namespace psm assembly");
        generated
            .into_iter()
            .next()
            .expect("missing namespaced psm assembly")
    } else {
        PathBuf::from(asm)
    };

    // For wasm targets we ship a precompiled `*.o` file so we just pass that
    // directly to `ar` to assemble an archive. Otherwise we're actually
    // compiling the source assembly file.
    if asm.extension().is_some_and(|extension| extension == "o") {
        let out_dir = var("OUT_DIR").expect("OUT_DIR environment variable not set");
        let output_path = PathBuf::from(&out_dir).join("libpsm_s.a");

        let object_data = read(&asm).expect("Failed to read object file");
        let file_metadata = metadata(&asm).expect("Failed to read file metadata");

        // Extract file metadata
        let mtime = file_metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        #[cfg(unix)]
        let (uid, gid, perms) = (
            file_metadata.uid(),
            file_metadata.gid(),
            file_metadata.mode(),
        );

        #[cfg(not(unix))]
        let (uid, gid, perms) = (0, 0, 0o644);

        let filename = asm
            .file_name()
            .and_then(|name| name.to_str())
            .expect("assembly filename");
        let member = NewArchiveMember {
            buf: Box::new(object_data),
            object_reader:
                &ObjectReader {
                    get_symbols: |_data: &[u8],
                                  _callback: &mut dyn FnMut(
                        &[u8],
                    )
                        -> Result<(), std::io::Error>| Ok(true),
                    get_xcoff_member_alignment: |_data| 0,
                    is_64_bit_object_file: |_data| false,
                    is_any_arm64_coff: |_data| false,
                    is_ec_object_file: |_data| false,
                },
            member_name: filename.to_string(),
            mtime,
            uid,
            gid,
            perms,
        };

        let mut output_bytes = Cursor::new(Vec::new());
        write_archive_to_stream(
            &mut output_bytes,
            &[member],
            // Unfortunately, getDefaultKind() is not available in ar_archive_writer
            // however looking at the llvm-ar source it looks like for wasm32-any-any
            // it falls through to Gnu https://llvm.org/doxygen/Object_2Archive_8cpp_source.html
            ArchiveKind::Gnu,
            false,
            None,
        )
        .expect("Failed to write archive");

        fs::write(&output_path, output_bytes.into_inner()).expect("Failed to write archive file");

        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=psm_s");
    } else {
        cfg.file(asm);
        cfg.compile("libpsm_s.a");
    }
}
