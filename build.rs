use vergen::{BuildBuilder, CargoBuilder, Emitter, RustcBuilder, SysinfoBuilder};
use vergen_git2::Git2Builder;

fn main() {
    let build = BuildBuilder::all_build().unwrap();
    let cargo = CargoBuilder::all_cargo().unwrap();
    let git = Git2Builder::all_git().unwrap();
    let rustc = RustcBuilder::all_rustc().unwrap();
    let sysinfo = SysinfoBuilder::all_sysinfo().unwrap();

    Emitter::default()
        .add_instructions(&build)
        .unwrap()
        .add_instructions(&cargo)
        .unwrap()
        .add_instructions(&git)
        .unwrap()
        .add_instructions(&rustc)
        .unwrap()
        .add_instructions(&sysinfo)
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
