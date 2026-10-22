//! The resolver against scripted local servers replaying recorded responses.
mod common;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use dns_stub::wire::{TYPE_A, TYPE_AAAA, TYPE_CNAME};
use dns_stub::{Answer, Config, QType, ResolveError, Resolver};

fn cfg(addr: SocketAddr) -> Config {
    let mut c = Config::new(addr);
    c.timeout = Duration::from_millis(300);
    c
}

fn serve(name: &'static str) -> Fake {
    let resp = fixture(name);
    fake_udp(move |_, q, s, to| {
        s.send_to(&reply(&resp, q), to).unwrap();
    })
}

#[test]
fn a_records_then_cache_then_expiry() {
    let f = serve("example_com_a");
    let clock = ManualClock::new();
    let mut r = Resolver::with_clock(cfg(f.addr), clock.clone());
    let want: Vec<IpAddr> = vec![
        "104.20.23.154".parse().unwrap(),
        "172.66.147.243".parse().unwrap(),
    ];
    let a = r.lookup("example.com", QType::A).unwrap();
    assert_eq!(
        a,
        Answer::Addrs {
            addrs: want.clone(),
            canonical: "example.com".into(),
            ttl: 26
        }
    );
    clock.advance(10);
    let b = r.lookup("EXAMPLE.com.", QType::A).unwrap();
    assert_eq!(b.ttl(), 16, "cached answer ages");
    assert_eq!((r.stats.udp_queries, r.stats.cache_hits), (1, 1));
    clock.advance(16);
    r.lookup("example.com", QType::A).unwrap();
    assert_eq!(r.stats.udp_queries, 2, "expired entry is fetched again");
    assert_eq!(f.queries.load(Ordering::SeqCst), 2);
}

#[test]
fn aaaa_and_type_is_part_of_the_cache_key() {
    let a = fixture("example_com_a");
    let aaaa = fixture("example_com_aaaa");
    let f = fake_udp(move |_, q, s, to| {
        let qtype = u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
        let r = if qtype == TYPE_AAAA { &aaaa } else { &a };
        s.send_to(&reply(r, q), to).unwrap();
    });
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    r.lookup("example.com", QType::A).unwrap();
    let Answer::Addrs { addrs, ttl, .. } = r.lookup("example.com", QType::Aaaa).unwrap() else {
        panic!()
    };
    assert!(addrs.iter().all(IpAddr::is_ipv6) && addrs.len() == 2 && ttl == 90);
    assert_eq!(r.stats.udp_queries, 2);
}

#[test]
fn cname_chains_take_the_minimum_ttl() {
    let f = serve("www_microsoft_com_a");
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    assert_eq!(
        r.lookup("www.microsoft.com", QType::A).unwrap(),
        Answer::Addrs {
            addrs: vec!["184.30.153.155".parse().unwrap()],
            canonical: "e13678.dscb.akamaiedge.net".into(),
            ttl: 1
        }
    );
    let f = serve("www_github_com_a");
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    let Answer::Addrs { canonical, ttl, .. } = r.lookup("www.github.com", QType::A).unwrap() else {
        panic!()
    };
    assert_eq!((canonical.as_str(), ttl), ("github.com", 27));
}

#[test]
fn negative_answers_use_the_soa_and_are_cached() {
    let f = serve("github_com_aaaa_nodata");
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    // min(SOA record TTL 3517, SOA MINIMUM 3600)
    assert_eq!(
        r.lookup("github.com", QType::Aaaa).unwrap(),
        Answer::NoData { ttl: 3517 }
    );
    r.lookup("github.com", QType::Aaaa).unwrap();
    assert_eq!(r.stats.udp_queries, 1);

    // example.com answers names that do not exist with NOERROR + SOA (no NXDOMAIN).
    let f = serve("example_com_nodata_blacklie");
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    assert_eq!(
        r.lookup("no-such-name-c9x.example.com", QType::A).unwrap(),
        Answer::NoData { ttl: 1800 }
    );

    let f = serve("nxdomain_tld");
    let mut c = cfg(f.addr);
    c.max_ttl = 3600;
    let mut r = Resolver::with_clock(c, ManualClock::new());
    assert_eq!(
        r.lookup("no-such-name.c9x-zz", QType::A).unwrap(),
        Answer::NxDomain { ttl: 3600 }
    );
    r.lookup("no-such-name.c9x-zz", QType::A).unwrap();
    assert_eq!(r.stats.cache_hits, 1);
}

#[test]
fn spoofed_and_mismatched_packets_are_ignored() {
    let good = fixture("example_com_a");
    let other = fixture("www_github_com_a");
    let f = fake_udp(move |_, q, s, to| {
        let mut wrong_id = reply(&good, q);
        wrong_id[0] ^= 0xFF;
        s.send_to(&wrong_id, to).unwrap();
        s.send_to(&reply(&other, q), to).unwrap(); // right id, other question
        let mut not_response = reply(&good, q);
        not_response[2] &= 0x7F; // QR = 0
        s.send_to(&not_response, to).unwrap();
        s.send_to(&reply(&good[..20], q), to).unwrap(); // right id, cut short
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        stranger.send_to(&reply(&good, q), to).unwrap(); // right bytes, wrong source
        std::thread::sleep(Duration::from_millis(20));
        s.send_to(&reply(&good, q), to).unwrap();
    });
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    let a = r.lookup("example.com", QType::A).unwrap();
    assert_eq!(a.ttl(), 26);
    assert_eq!(r.stats.ignored, 5);
    assert_eq!(r.stats.udp_queries, 1);
}

#[test]
fn retries_after_a_lost_packet_and_times_out_without_one() {
    let good = fixture("example_com_a");
    let f = fake_udp(move |i, q, s, to| {
        if i % 2 == 1 {
            s.send_to(&reply(&good, q), to).unwrap();
        }
    });
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    r.lookup("example.com", QType::A).unwrap();
    assert_eq!(r.stats.udp_queries, 2);

    let mut c = cfg(f.addr);
    c.attempts = 1;
    let mut r = Resolver::with_clock(c, ManualClock::new());
    assert!(matches!(
        r.lookup("example.com", QType::A),
        Err(ResolveError::Timeout)
    ));
}

#[test]
fn truncated_udp_answer_falls_back_to_tcp() {
    let full = fixture("www_microsoft_com_a");
    // Header + question only, TC set, no records.
    let mut tc = craft(0, "www.microsoft.com", TYPE_A, &[]);
    tc[2] |= 0x02;
    let f = fake_udp(move |_, q, s, to| {
        s.send_to(&reply(&tc, q), to).unwrap();
    });
    let t = fake_tcp_once(f.addr, full);
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    let Answer::Addrs { canonical, .. } = r.lookup("www.microsoft.com", QType::A).unwrap() else {
        panic!()
    };
    assert_eq!(canonical, "e13678.dscb.akamaiedge.net");
    assert_eq!((r.stats.udp_queries, r.stats.tcp_queries), (1, 1));
    t.join().unwrap();
}

#[test]
fn servfail_is_an_error_and_not_cached() {
    let sf = craft(2, "example.com", TYPE_A, &[]);
    let f = fake_udp(move |_, q, s, to| {
        s.send_to(&reply(&sf, q), to).unwrap();
    });
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    assert!(matches!(
        r.lookup("example.com", QType::A),
        Err(ResolveError::Rcode(2))
    ));
    assert!(matches!(
        r.lookup("example.com", QType::A),
        Err(ResolveError::Rcode(2))
    ));
    assert_eq!(r.stats.udp_queries, 2);
    assert_eq!(r.cached_entries(), 0);
}

#[test]
fn cname_loops_and_overlong_chains_are_rejected() {
    let lp = craft(
        0,
        "a.test",
        TYPE_A,
        &[
            ("a.test", TYPE_CNAME, 60, name_rdata("b.test")),
            ("b.test", TYPE_CNAME, 60, name_rdata("a.test")),
        ],
    );
    let m = dns_stub::wire::parse(&lp).unwrap();
    assert!(matches!(
        dns_stub::interpret(&m, "a.test", QType::A, 86400),
        Err(ResolveError::CnameLoop)
    ));

    let names: Vec<String> = (0..20).map(|i| format!("n{i}.test")).collect();
    let mut answers: Vec<(&str, u16, u32, Vec<u8>)> = (0..19)
        .map(|i| (names[i].as_str(), TYPE_CNAME, 60, name_rdata(&names[i + 1])))
        .collect();
    answers.push((names[19].as_str(), TYPE_A, 60, vec![10, 0, 0, 1]));
    let long = dns_stub::wire::parse(&craft(0, "n0.test", TYPE_A, &answers)).unwrap();
    assert!(matches!(
        dns_stub::interpret(&long, "n0.test", QType::A, 86400),
        Err(ResolveError::CnameLoop)
    ));
    // 16 hops is the limit and still resolves.
    let short = dns_stub::wire::parse(&craft(0, "n3.test", TYPE_A, &answers)).unwrap();
    assert!(dns_stub::interpret(&short, "n3.test", QType::A, 86400).is_ok());
}

#[test]
fn ttl_with_top_bit_is_zero_and_not_cached() {
    let resp = craft(
        0,
        "z.test",
        TYPE_A,
        &[("z.test", TYPE_A, 0x8000_0010, vec![10, 0, 0, 9])],
    );
    let f = fake_udp(move |_, q, s, to| {
        s.send_to(&reply(&resp, q), to).unwrap();
    });
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    assert_eq!(r.lookup("z.test", QType::A).unwrap().ttl(), 0);
    r.lookup("z.test", QType::A).unwrap();
    assert_eq!(r.stats.udp_queries, 2);
}

#[test]
fn bad_names_fail_before_any_packet() {
    let f = serve("example_com_a");
    let mut r = Resolver::with_clock(cfg(f.addr), ManualClock::new());
    assert!(matches!(
        r.lookup(&"x".repeat(64), QType::A),
        Err(ResolveError::BadName)
    ));
    assert!(matches!(
        r.lookup("a..b", QType::A),
        Err(ResolveError::BadName)
    ));
    assert_eq!(f.queries.load(Ordering::SeqCst), 0);
}

#[test]
fn cache_capacity_evicts_soonest_expiry() {
    use dns_stub::cache::Cache;
    let now = std::time::Instant::now();
    let mut c = Cache::new(2);
    let ans = |t| Answer::NoData { ttl: t };
    c.put("a", QType::A, ans(100), now);
    c.put("b", QType::A, ans(10), now);
    c.put("c", QType::A, ans(50), now);
    assert_eq!(c.len(), 2);
    assert!(
        c.get("b", QType::A, now).is_none(),
        "soonest expiry evicted"
    );
    assert!(c.get("a", QType::A, now).is_some() && c.get("c", QType::A, now).is_some());
}
