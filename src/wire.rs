//! DNS wire format (RFC 1035): query building and response parsing.
//!
//! Parsing never panics on any input; every malformed message is a
//! [`WireError`]. Names are returned lowercase, without the trailing dot,
//! with `.` `\` and non-printable label bytes escaped as `\DDD`.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

/// Longest name on the wire, length octets included.
const MAX_WIRE_NAME: usize = 255;
/// Compression pointers followed per name before giving up.
const MAX_JUMPS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The message ends inside a field.
    Truncated,
    /// Label type 0b01 / 0b10 (reserved) or a bad label in a query name.
    BadLabel,
    /// A compression pointer that does not point strictly backwards.
    BadPointer,
    NameTooLong,
    /// RDATA length does not fit the record type.
    BadRdata {
        rtype: u16,
    },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "message truncated"),
            WireError::BadLabel => write!(f, "bad label"),
            WireError::BadPointer => write!(f, "compression pointer does not point backwards"),
            WireError::NameTooLong => write!(f, "name longer than 255 octets"),
            WireError::BadRdata { rtype } => write!(f, "bad rdata for type {rtype}"),
        }
    }
}

impl std::error::Error for WireError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        minimum: u32,
    },
    Other {
        rtype: u16,
        len: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    /// Seconds; values with the top bit set are read as 0 (RFC 2181 §8).
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

/// Writes a recursive query for `name` (dotted, optional trailing dot).
pub fn build_query(id: u16, name: &str, qtype: u16, out: &mut Vec<u8>) -> Result<(), WireError> {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1
    encode_name(name, out)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(())
}

/// Encodes a plain dotted name (no escapes). Rejects empty labels, labels
/// over 63 octets and names over 255 octets on the wire.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), WireError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let start = out.len();
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(WireError::BadLabel);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() - start > MAX_WIRE_NAME {
        out.truncate(start);
        return Err(WireError::NameTooLong);
    }
    Ok(())
}

struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let s = self.msg.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a possibly compressed name starting at the cursor.
    fn name(&mut self) -> Result<String, WireError> {
        let mut out = String::new();
        let mut wire_len = 0usize;
        let mut pos = self.pos;
        let mut resume: Option<usize> = None;
        let mut jumps = 0;
        // Every pointer must go strictly below the start of the run of labels
        // it ends, so targets strictly decrease and loops are impossible.
        let mut run_start = pos;
        loop {
            let len = *self.msg.get(pos).ok_or(WireError::Truncated)? as usize;
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        if resume.is_none() {
                            resume = Some(pos + 1);
                        }
                        break;
                    }
                    let label = self
                        .msg
                        .get(pos + 1..pos + 1 + len)
                        .ok_or(WireError::Truncated)?;
                    wire_len += 1 + len;
                    if wire_len + 1 > MAX_WIRE_NAME {
                        return Err(WireError::NameTooLong);
                    }
                    if !out.is_empty() {
                        out.push('.');
                    }
                    for &b in label {
                        match b {
                            b'.' | b'\\' => {
                                out.push('\\');
                                out.push(b as char);
                            }
                            0x21..=0x7E => out.push(b.to_ascii_lowercase() as char),
                            _ => out.push_str(&format!("\\{b:03}")),
                        }
                    }
                    pos += 1 + len;
                }
                0xC0 => {
                    let lo = *self.msg.get(pos + 1).ok_or(WireError::Truncated)? as usize;
                    let target = ((len & 0x3F) << 8) | lo;
                    if target >= run_start || jumps == MAX_JUMPS {
                        return Err(WireError::BadPointer);
                    }
                    jumps += 1;
                    if resume.is_none() {
                        resume = Some(pos + 2);
                    }
                    pos = target;
                    run_start = target;
                }
                _ => return Err(WireError::BadLabel),
            }
        }
        self.pos = resume.unwrap();
        Ok(out)
    }

    fn record(&mut self) -> Result<Record, WireError> {
        let name = self.name()?;
        let rtype = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let ttl = if ttl & 0x8000_0000 != 0 { 0 } else { ttl };
        let rdlen = self.u16()? as usize;
        let rd_start = self.pos;
        let rdata = self.take(rdlen)?;
        let bad = WireError::BadRdata { rtype };
        let data = match rtype {
            TYPE_A => RData::A(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).map_err(|_| bad)?)),
            TYPE_AAAA => RData::Aaaa(Ipv6Addr::from(
                <[u8; 16]>::try_from(rdata).map_err(|_| bad)?,
            )),
            TYPE_CNAME | TYPE_SOA => {
                // Names inside RDATA may point anywhere earlier in the message,
                // but must not run past the RDATA itself.
                let mut sub = Reader {
                    msg: &self.msg[..rd_start + rdlen],
                    pos: rd_start,
                };
                let d = if rtype == TYPE_CNAME {
                    RData::Cname(sub.name()?)
                } else {
                    let mname = sub.name()?;
                    let rname = sub.name()?;
                    let serial = sub.u32()?;
                    sub.take(12)?; // refresh, retry, expire
                    let minimum = sub.u32()?;
                    RData::Soa {
                        mname,
                        rname,
                        serial,
                        minimum,
                    }
                };
                if sub.pos != rd_start + rdlen {
                    return Err(bad);
                }
                d
            }
            _ => RData::Other { rtype, len: rdlen },
        };
        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            data,
        })
    }
}

/// Parses a complete DNS message.
pub fn parse(msg: &[u8]) -> Result<Message, WireError> {
    let mut r = Reader { msg, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let header = Header {
        id,
        qr: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0xF) as u8,
        aa: flags & 0x0400 != 0,
        tc: flags & 0x0200 != 0,
        rd: flags & 0x0100 != 0,
        ra: flags & 0x0080 != 0,
        rcode: (flags & 0xF) as u8,
    };
    let counts = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
    // Each question needs at least 5 bytes and each record 11; reject
    // counts that cannot fit before allocating anything.
    let min = counts[0] as usize * 5
        + (counts[1] as usize + counts[2] as usize + counts[3] as usize) * 11;
    if min > msg.len() - r.pos {
        return Err(WireError::Truncated);
    }
    let mut questions = Vec::with_capacity(counts[0] as usize);
    for _ in 0..counts[0] {
        let name = r.name()?;
        questions.push(Question {
            name,
            qtype: r.u16()?,
            qclass: r.u16()?,
        });
    }
    let mut sections: [Vec<Record>; 3] = Default::default();
    for (i, sec) in sections.iter_mut().enumerate() {
        for _ in 0..counts[i + 1] {
            sec.push(r.record()?);
        }
    }
    let [answers, authority, additional] = sections;
    Ok(Message {
        header,
        questions,
        answers,
        authority,
        additional,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_bytes() {
        let mut q = Vec::new();
        build_query(0xBEEF, "Example.COM.", TYPE_AAAA, &mut q).unwrap();
        assert_eq!(
            q,
            [
                0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'E', b'x', b'a', b'm', b'p',
                b'l', b'e', 3, b'C', b'O', b'M', 0, 0, 28, 0, 1
            ]
        );
    }

    #[test]
    fn name_limits() {
        let mut v = Vec::new();
        assert!(encode_name(&"a".repeat(63), &mut v).is_ok());
        assert_eq!(
            encode_name(&"a".repeat(64), &mut v),
            Err(WireError::BadLabel)
        );
        assert_eq!(encode_name("a..b", &mut v), Err(WireError::BadLabel));
        // 4 labels of 63 = 4*64 + 1 = 257 octets: too long; 3*64 + 62 + 1 = 255 fits.
        let l63 = "a".repeat(63);
        assert_eq!(
            encode_name(&[&l63[..], &l63, &l63, &l63].join("."), &mut v),
            Err(WireError::NameTooLong)
        );
        v.clear();
        assert!(encode_name(&[&l63[..], &l63, &l63, &"a".repeat(61)].join("."), &mut v).is_ok());
        assert_eq!(v.len(), 255);
        v.clear();
        encode_name(".", &mut v).unwrap();
        assert_eq!(v, [0]);
    }

    fn msg_with_name(name_bytes: &[u8]) -> Vec<u8> {
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(name_bytes);
        m.extend_from_slice(&[0, 1, 0, 1]);
        m
    }

    #[test]
    fn pointers() {
        // Pointer to itself (offset 12) is rejected, as is a forward pointer.
        assert_eq!(
            parse(&msg_with_name(&[0xC0, 12])).unwrap_err(),
            WireError::BadPointer
        );
        assert_eq!(
            parse(&msg_with_name(&[0xC0, 40])).unwrap_err(),
            WireError::BadPointer
        );
        // Two labels pointing at each other cannot loop: the second must point
        // below its own start.
        assert_eq!(
            parse(&msg_with_name(&[1, b'a', 0xC0, 12])).unwrap_err(),
            WireError::BadPointer
        );
        assert_eq!(
            parse(&msg_with_name(&[0x40, 0])).unwrap_err(),
            WireError::BadLabel
        );
        assert_eq!(
            parse(&msg_with_name(&[3, b'a'])).unwrap_err(),
            WireError::Truncated
        );
    }

    #[test]
    fn label_escaping_and_case() {
        let m = parse(&msg_with_name(&[3, b'A', b'.', 0x07, 2, b'\\', b'Z', 0])).unwrap();
        assert_eq!(m.questions[0].name, "a\\.\\007.\\\\z");
    }

    #[test]
    fn absurd_counts_rejected_without_allocating() {
        let m = [
            0, 1, 0x81, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        assert_eq!(parse(&m).unwrap_err(), WireError::Truncated);
    }
}
