//! Records one raw response for the test fixtures:
//!   cargo run --example record_fixture -- NAME a|aaaa SERVER:53 OUT.bin
//! The query id is fixed at 0x0001 so fixtures are stable byte for byte
//! apart from what the server returns.
use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(a.len(), 4, "usage: NAME a|aaaa SERVER:53 OUT.bin");
    let qtype = if a[1] == "aaaa" {
        dns_stub::wire::TYPE_AAAA
    } else {
        dns_stub::wire::TYPE_A
    };
    let mut q = Vec::new();
    dns_stub::wire::build_query(1, &a[0], qtype, &mut q).unwrap();
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.send_to(&q, &a[2]).unwrap();
    let mut buf = [0u8; 1232];
    let (n, _) = s.recv_from(&mut buf).unwrap();
    std::fs::write(&a[3], &buf[..n]).unwrap();
    println!("{} bytes", n);
}
