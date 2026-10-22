//! Prints a parsed response: cargo run --example dump_fixture -- FILE.bin
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_fixture FILE.bin");
    let raw = std::fs::read(path).unwrap();
    match dns_stub::wire::parse(&raw) {
        Ok(m) => println!("{m:#?}"),
        Err(e) => println!("parse error: {e}"),
    }
}
