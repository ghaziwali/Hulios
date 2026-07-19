use aya_build::{build_ebpf, Package, Toolchain};

fn main() {
    let project_root = std::env::current_dir().unwrap();
    let bin_dir = project_root.parent().unwrap().join("bin");

    if let Some(path) = std::env::var_os("PATH") {
        let mut paths = std::env::split_paths(&path).collect::<Vec<_>>();
        paths.insert(0, bin_dir);
        let new_path = std::env::join_paths(paths).unwrap();
        std::env::set_var("PATH", new_path);
    }

    match build_ebpf(
        [Package {
            name: "hulios-ebpf",
            root_dir: "../hulios-ebpf",
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Nightly,
    ) {
        Ok(_) => {
            let out_dir = std::env::var_os("OUT_DIR").unwrap();
            let src_path = std::path::Path::new(&out_dir).join("hulios_ebpf");
            let out_path = std::path::Path::new(&out_dir).join("hulios_ebpf.bpf.o");
            if src_path.exists() {
                std::fs::copy(&src_path, &out_path).unwrap();
            } else {
                std::fs::write(&out_path, [0u8; 4]).unwrap();
            }
        }
        Err(e) => {
            println!("cargo:warning=failed to build ebpf program: {e}");
            println!(
                "cargo:warning=writing a dummy ebpf object file to allow compilation on stable"
            );
            let out_dir = std::env::var_os("OUT_DIR").unwrap();
            let out_path = std::path::Path::new(&out_dir).join("hulios_ebpf.bpf.o");
            std::fs::write(&out_path, [0u8; 4]).unwrap();
        }
    }
}
