//! A stub DNS resolver: asks one recursive server for A or AAAA records over
//! UDP, falls back to TCP when the answer is truncated, follows CNAME chains
//! inside the answer and caches positive and negative results by TTL.
//!
//! Responses are only accepted from the server's address, with the query's
//! id, the QR bit set and the same question; anything else is counted and
//! ignored while the resolver keeps waiting.

pub mod cache;
pub mod wire;

use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use cache::{Cache, Clock, SystemClock};
use wire::{Message, RData, WireError};

/// Record type asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QType {
    A,
    Aaaa,
}

impl QType {
    pub fn code(self) -> u16 {
        match self {
            QType::A => wire::TYPE_A,
            QType::Aaaa => wire::TYPE_AAAA,
        }
    }
}

/// Outcome of a lookup. `ttl` is in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Addresses at the end of the CNAME chain, in server order.
    Addrs {
        addrs: Vec<IpAddr>,
        canonical: String,
        ttl: u32,
    },
    /// The name does not exist (RCODE 3).
    NxDomain { ttl: u32 },
    /// The name exists but has no record of this type.
    NoData { ttl: u32 },
}

impl Answer {
    pub fn ttl(&self) -> u32 {
        match self {
            Answer::Addrs { ttl, .. } | Answer::NxDomain { ttl } | Answer::NoData { ttl } => *ttl,
        }
    }

    pub fn with_ttl(&self, t: u32) -> Answer {
        let mut a = self.clone();
        match &mut a {
            Answer::Addrs { ttl, .. } | Answer::NxDomain { ttl } | Answer::NoData { ttl } => {
                *ttl = t
            }
        }
        a
    }
}

#[derive(Debug)]
pub enum ResolveError {
    Io(io::Error),
    /// No acceptable answer within `timeout` on any of the `attempts`.
    Timeout,
    /// The accepted response did not parse.
    Wire(WireError),
    /// Server error (SERVFAIL, REFUSED, ...); never cached.
    Rcode(u8),
    CnameLoop,
    BadName,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::Io(e) => write!(f, "i/o: {e}"),
            ResolveError::Timeout => write!(f, "timed out"),
            ResolveError::Wire(e) => write!(f, "malformed response: {e}"),
            ResolveError::Rcode(c) => write!(f, "server returned rcode {c}"),
            ResolveError::CnameLoop => write!(f, "CNAME chain loops or is too long"),
            ResolveError::BadName => write!(f, "invalid name"),
        }
    }
}

impl std::error::Error for ResolveError {}

impl From<io::Error> for ResolveError {
    fn from(e: io::Error) -> Self {
        ResolveError::Io(e)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server: SocketAddr,
    /// Per attempt.
    pub timeout: Duration,
    pub attempts: u32,
    /// TTLs above this are clamped.
    pub max_ttl: u32,
    pub cache_entries: usize,
}

impl Config {
    pub fn new(server: SocketAddr) -> Config {
        Config {
            server,
            timeout: Duration::from_secs(2),
            attempts: 2,
            max_ttl: 86_400,
            cache_entries: 1024,
        }
    }
}

/// Counters, mainly for tests and the CLI.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub udp_queries: u64,
    pub tcp_queries: u64,
    pub cache_hits: u64,
    /// Packets dropped for wrong source, id, flags or question.
    pub ignored: u64,
}

const MAX_CHAIN: usize = 16;

pub struct Resolver<C: Clock = SystemClock> {
    cfg: Config,
    cache: Cache,
    clock: C,
    ids: RandomState,
    counter: u64,
    pub stats: Stats,
}

impl Resolver<SystemClock> {
    pub fn new(cfg: Config) -> Self {
        Resolver::with_clock(cfg, SystemClock)
    }
}

impl<C: Clock> Resolver<C> {
    pub fn with_clock(cfg: Config, clock: C) -> Self {
        let cache = Cache::new(cfg.cache_entries);
        Resolver {
            cfg,
            cache,
            clock,
            ids: RandomState::new(),
            counter: 0,
            stats: Stats::default(),
        }
    }

    fn next_id(&mut self) -> u16 {
        self.counter += 1;
        let mut h = self.ids.build_hasher();
        h.write_u64(self.counter);
        h.finish() as u16
    }

    /// Resolves `name` (case-insensitive, optional trailing dot).
    pub fn lookup(&mut self, name: &str, qtype: QType) -> Result<Answer, ResolveError> {
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        let now = self.clock.now();
        if let Some(a) = self.cache.get(&name, qtype, now) {
            self.stats.cache_hits += 1;
            return Ok(a);
        }
        let id = self.next_id();
        let mut query = Vec::with_capacity(64);
        wire::build_query(id, &name, qtype.code(), &mut query)
            .map_err(|_| ResolveError::BadName)?;
        let mut msg = self.exchange_udp(&query, id, &name, qtype)?;
        if msg.header.tc {
            msg = self.exchange_tcp(&query, id, &name, qtype)?;
        }
        let ans = interpret(&msg, &name, qtype, self.cfg.max_ttl)?;
        self.cache.put(&name, qtype, ans.clone(), self.clock.now());
        Ok(ans)
    }

    pub fn cached_entries(&self) -> usize {
        self.cache.len()
    }

    fn acceptable(
        &mut self,
        buf: &[u8],
        id: u16,
        name: &str,
        qtype: QType,
    ) -> Option<Result<Message, ResolveError>> {
        // Cheap id check first so random junk does not cost a parse.
        if buf.len() < 2 || u16::from_be_bytes([buf[0], buf[1]]) != id {
            self.stats.ignored += 1;
            return None;
        }
        let msg = match wire::parse(buf) {
            Ok(m) => m,
            // Right id but unparseable: a spoofer can produce that too, so
            // keep waiting for a good copy rather than failing.
            Err(_) => {
                self.stats.ignored += 1;
                return None;
            }
        };
        let q_ok = msg.questions.len() == 1
            && msg.questions[0].name == name
            && msg.questions[0].qtype == qtype.code()
            && msg.questions[0].qclass == wire::CLASS_IN;
        if !msg.header.qr || msg.header.opcode != 0 || !q_ok {
            self.stats.ignored += 1;
            return None;
        }
        Some(Ok(msg))
    }

    fn exchange_udp(
        &mut self,
        query: &[u8],
        id: u16,
        name: &str,
        qtype: QType,
    ) -> Result<Message, ResolveError> {
        let bind: SocketAddr = if self.cfg.server.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let sock = UdpSocket::bind(bind)?;
        let mut buf = [0u8; 1232];
        for _ in 0..self.cfg.attempts.max(1) {
            sock.send_to(query, self.cfg.server)?;
            self.stats.udp_queries += 1;
            let deadline = Instant::now() + self.cfg.timeout;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                sock.set_read_timeout(Some(left))?;
                let (n, from) = match sock.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break
                    }
                    Err(e) => return Err(e.into()),
                };
                if from != self.cfg.server {
                    self.stats.ignored += 1;
                    continue;
                }
                if let Some(r) = self.acceptable(&buf[..n], id, name, qtype) {
                    return r;
                }
            }
        }
        Err(ResolveError::Timeout)
    }

    fn exchange_tcp(
        &mut self,
        query: &[u8],
        id: u16,
        name: &str,
        qtype: QType,
    ) -> Result<Message, ResolveError> {
        self.stats.tcp_queries += 1;
        let mut s = TcpStream::connect_timeout(&self.cfg.server, self.cfg.timeout)?;
        s.set_read_timeout(Some(self.cfg.timeout))?;
        s.set_write_timeout(Some(self.cfg.timeout))?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        s.write_all(&framed)?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).map_err(timeout_kind)?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).map_err(timeout_kind)?;
        match self.acceptable(&buf, id, name, qtype) {
            Some(r) => r,
            // Over TCP there is no one else on the connection: a mismatch is
            // a broken server, reported as a wire error.
            None => Err(ResolveError::Wire(WireError::Truncated)),
        }
    }
}

fn timeout_kind(e: io::Error) -> ResolveError {
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        ResolveError::Timeout
    } else {
        ResolveError::Io(e)
    }
}

/// Negative TTL from the SOA in the authority section (RFC 2308 §5):
/// min(SOA TTL, SOA MINIMUM); 0 (not cached) without a SOA.
fn negative_ttl(msg: &Message) -> u32 {
    msg.authority
        .iter()
        .find_map(|r| match r.data {
            RData::Soa { minimum, .. } => Some(r.ttl.min(minimum)),
            _ => None,
        })
        .unwrap_or(0)
}

/// Turns a validated response into an [`Answer`].
pub fn interpret(
    msg: &Message,
    name: &str,
    qtype: QType,
    max_ttl: u32,
) -> Result<Answer, ResolveError> {
    match msg.header.rcode {
        wire::RCODE_NOERROR => {}
        wire::RCODE_NXDOMAIN => {
            return Ok(Answer::NxDomain {
                ttl: negative_ttl(msg).min(max_ttl),
            })
        }
        rc => return Err(ResolveError::Rcode(rc)),
    }
    let mut target = name.to_string();
    let mut seen = HashSet::new();
    let mut ttl = u32::MAX;
    for _ in 0..=MAX_CHAIN {
        if !seen.insert(target.clone()) {
            return Err(ResolveError::CnameLoop);
        }
        let mut addrs = Vec::new();
        let mut addr_ttl = u32::MAX;
        for r in msg
            .answers
            .iter()
            .filter(|r| r.name == target && r.class == wire::CLASS_IN)
        {
            match (&r.data, qtype) {
                (RData::A(a), QType::A) => addrs.push(IpAddr::V4(*a)),
                (RData::Aaaa(a), QType::Aaaa) => addrs.push(IpAddr::V6(*a)),
                _ => continue,
            }
            addr_ttl = addr_ttl.min(r.ttl);
        }
        if !addrs.is_empty() {
            return Ok(Answer::Addrs {
                addrs,
                canonical: target,
                ttl: ttl.min(addr_ttl).min(max_ttl),
            });
        }
        let next = msg.answers.iter().find_map(|r| match &r.data {
            RData::Cname(c) if r.name == target => Some((c.clone(), r.ttl)),
            _ => None,
        });
        match next {
            Some((c, t)) => {
                ttl = ttl.min(t);
                target = c;
            }
            None => {
                // No data at the end of the chain. The negative TTL also may
                // not outlive the CNAMEs that led here.
                return Ok(Answer::NoData {
                    ttl: negative_ttl(msg).min(ttl).min(max_ttl),
                });
            }
        }
    }
    Err(ResolveError::CnameLoop)
}
