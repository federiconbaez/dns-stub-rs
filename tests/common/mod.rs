#![allow(dead_code)]
use std::cell::Cell;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dns_stub::cache::Clock;

pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// `resp` with the id copied from `query`.
pub fn reply(resp: &[u8], query: &[u8]) -> Vec<u8> {
    let mut r = resp.to_vec();
    r[..2].copy_from_slice(&query[..2]);
    r
}

#[derive(Clone)]
pub struct ManualClock(pub Rc<Cell<Instant>>);

impl ManualClock {
    pub fn new() -> Self {
        ManualClock(Rc::new(Cell::new(Instant::now())))
    }
    pub fn advance(&self, secs: u64) {
        self.0.set(self.0.get() + Duration::from_secs(secs));
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.0.get()
    }
}

/// A scripted UDP server on 127.0.0.1. `script(n, query, sock, client)` is
/// called for the n-th query (0-based) and sends whatever it wants.
pub struct Fake {
    pub addr: SocketAddr,
    pub queries: Arc<AtomicUsize>,
}

pub fn fake_udp<F>(script: F) -> Fake
where
    F: Fn(usize, &[u8], &UdpSocket, SocketAddr) + Send + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let q = queries.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let i = q.fetch_add(1, Ordering::SeqCst);
            script(i, &buf[..n], &sock, from);
        }
    });
    Fake { addr, queries }
}

/// Serves one TCP query on `addr` with `resp` (id rewritten).
pub fn fake_tcp_once(addr: SocketAddr, resp: Vec<u8>) -> std::thread::JoinHandle<()> {
    use std::io::{Read, Write};
    let l = TcpListener::bind(addr).unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut len = [0u8; 2];
        s.read_exact(&mut len).unwrap();
        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut q).unwrap();
        let r = reply(&resp, &q);
        s.write_all(&(r.len() as u16).to_be_bytes()).unwrap();
        s.write_all(&r).unwrap();
    })
}

/// Builds a response by hand: question `qname`/`qtype`, then answers given as
/// (owner, rtype, ttl, rdata).
pub fn craft(rcode: u8, qname: &str, qtype: u16, answers: &[(&str, u16, u32, Vec<u8>)]) -> Vec<u8> {
    let mut m = vec![
        0,
        0,
        0x81,
        0x80 | rcode,
        0,
        1,
        0,
        answers.len() as u8,
        0,
        0,
        0,
        0,
    ];
    dns_stub::wire::encode_name(qname, &mut m).unwrap();
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    for (owner, rtype, ttl, rdata) in answers {
        dns_stub::wire::encode_name(owner, &mut m).unwrap();
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(rdata);
    }
    m
}

pub fn name_rdata(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    dns_stub::wire::encode_name(name, &mut v).unwrap();
    v
}
