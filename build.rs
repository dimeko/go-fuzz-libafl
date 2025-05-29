use vergen::{Emitter, SysinfoBuilder};

fn main() {
    let sysinfo = SysinfoBuilder::all_sysinfo().unwrap();

    Emitter::default().add_instructions(&sysinfo)
        .unwrap()
        .emit()
        .unwrap();

    let cpu_target = {
        println!("cargo:warning=No architecture specified defaulting to x86_64...");
        println!("cargo:rustc-cfg=feature=\"x86_64\"");
        println!("cargo:rustc-cfg=feature=\"64bit\"");
        "x86_64".to_string()
    };

    println!("cargo:rustc-env=CPU_TARGET={cpu_target}");
}
