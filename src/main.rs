
mod fuzzer;
mod mutators;

fn main() {
    let _ = fuzzer::fuzz();
}
