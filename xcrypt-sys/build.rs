use std::env;
use std::path::PathBuf;

fn main() {
    let libxcrypt_include_dir =
        env::var("LIBXCRYPT_INCLUDE_DIR").expect("LIBXCRYPT_INCLUDE_DIR s not set");

    let bindings = bindgen::Builder::default()
        .header_contents("includes.h", "#include <crypt.h>")
        .clang_arg("-I")
        .clang_arg(&libxcrypt_include_dir)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");

    println!("cargo:rustc-link-lib=crypt");
}
