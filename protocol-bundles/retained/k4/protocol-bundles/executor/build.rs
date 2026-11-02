fn main() {
    println!("cargo:rustc-check-cfg=cfg(kontor_observer)");
    println!("cargo:rustc-check-cfg=cfg(kontor_linked)");
    println!("cargo:rustc-check-cfg=cfg(kontor_retained)");
    println!("cargo:rustc-check-cfg=cfg(kontor_node)");
    println!("cargo:rustc-cfg=kontor_retained");
    println!("cargo:rustc-check-cfg=cfg(feature, values(\"testing\"))");
}
