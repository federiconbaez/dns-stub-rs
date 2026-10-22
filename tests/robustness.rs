//! The parser on hostile input: every truncation and many single-byte
//! mutations of the recorded responses, random bytes, and pointer bombs.
//! It must return Ok or Err, never panic, and stay fast.
mod common;

use std::time::Instant;

use common::fixture;
use dns_stub::wire::parse;
use dns_stub::{interpret, QType};
use proptest::prelude::*;

const FIXTURES: &[&str] = &[
    "example_com_a",
    "example_com_aaaa",
    "www_microsoft_com_a",
    "www_github_com_a",
    "github_com_aaaa_nodata",
    "example_com_nodata_blacklie",
    "nxdomain_tld",
];

fn exercise(m: &[u8]) {
    if let Ok(msg) = parse(m) {
        let name = msg
            .questions
            .first()
            .map(|q| q.name.clone())
            .unwrap_or_default();
        let _ = interpret(&msg, &name, QType::A, 86400);
        let _ = interpret(&msg, &name, QType::Aaaa, 86400);
    }
}

#[test]
fn every_fixture_parses_and_every_truncation_fails_cleanly() {
    for f in FIXTURES {
        let raw = fixture(f);
        assert!(parse(&raw).is_ok(), "{f}");
        for cut in 0..raw.len() {
            assert!(
                parse(&raw[..cut]).is_err(),
                "{f} cut at {cut} must not parse"
            );
        }
    }
}

#[test]
fn single_byte_mutations_never_panic() {
    let mut cases = 0u64;
    let mut ok = 0u64;
    for f in FIXTURES {
        let raw = fixture(f);
        for i in 0..raw.len() {
            for v in [
                0x00,
                0xFF,
                0xC0,
                0x3F,
                0x40,
                raw[i] ^ 0x01,
                raw[i] ^ 0x80,
                raw[i].wrapping_add(1),
            ] {
                let mut m = raw.clone();
                m[i] = v;
                if parse(&m).is_ok() {
                    ok += 1;
                }
                exercise(&m);
                cases += 1;
            }
        }
    }
    eprintln!("{cases} mutated messages, {ok} still parsed");
}

/// Two answers: the first is an unknown type whose RDATA holds the name "a"
/// followed by `n` pointers, each pointing at the previous one; the second
/// answer's owner name is a pointer to the last of them. Every jump is legal
/// (strictly backwards), so only the jump limit bounds the walk.
fn pointer_chain(n: usize) -> Vec<u8> {
    let mut m = vec![0, 1, 0x81, 0x80, 0, 0, 0, 2, 0, 0, 0, 0];
    m.extend_from_slice(&[0, 0, 99, 0, 1, 0, 0, 0, 0]); // owner ".", type 99, IN, ttl 0
    let rdlen_at = m.len();
    m.extend_from_slice(&[0, 0]);
    let rd_start = m.len();
    m.extend_from_slice(&[1, b'a', 0]);
    let mut prev = rd_start as u16;
    for _ in 0..n {
        let here = m.len() as u16;
        m.extend_from_slice(&(0xC000 | prev).to_be_bytes());
        prev = here;
    }
    let rdlen = (m.len() - rd_start) as u16;
    m[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    m.extend_from_slice(&(0xC000 | prev).to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
    m
}

#[test]
fn pointer_chains_are_bounded_by_the_jump_limit() {
    let ok = parse(&pointer_chain(62)).unwrap();
    assert_eq!(ok.answers[1].name, "a");
    let start = Instant::now();
    assert_eq!(
        parse(&pointer_chain(5000)).unwrap_err(),
        dns_stub::wire::WireError::BadPointer
    );
    assert!(start.elapsed().as_millis() < 100);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, ..ProptestConfig::default() })]

    #[test]
    fn random_bytes_never_panic(body in proptest::collection::vec(any::<u8>(), 0..600)) {
        exercise(&body);
    }

    #[test]
    fn random_bodies_after_a_plausible_header_never_panic(
        counts in proptest::array::uniform4(0u8..6),
        body in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        let mut m = vec![0, 1, 0x81, 0x80, 0, counts[0], 0, counts[1], 0, counts[2], 0, counts[3]];
        m.extend_from_slice(&body);
        exercise(&m);
    }
}
