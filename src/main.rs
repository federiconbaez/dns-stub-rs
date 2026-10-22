//! dnsstub NAME [--aaaa] [--server IP:PORT]
use std::net::SocketAddr;
use std::process::ExitCode;

use dns_stub::{Answer, Config, QType, Resolver};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut name = None;
    let mut qtype = QType::A;
    let mut server: SocketAddr = "1.1.1.1:53".parse().unwrap();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--aaaa" => qtype = QType::Aaaa,
            "--server" => match args.next().and_then(|s| s.parse().ok()) {
                Some(s) => server = s,
                None => {
                    eprintln!("--server needs IP:PORT");
                    return ExitCode::from(2);
                }
            },
            _ if name.is_none() => name = Some(a),
            _ => {
                eprintln!("usage: dnsstub NAME [--aaaa] [--server IP:PORT]");
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        eprintln!("usage: dnsstub NAME [--aaaa] [--server IP:PORT]");
        return ExitCode::from(2);
    };
    let mut r = Resolver::new(Config::new(server));
    match r.lookup(&name, qtype) {
        Ok(Answer::Addrs {
            addrs,
            canonical,
            ttl,
        }) => {
            for a in addrs {
                println!("{a}");
            }
            eprintln!("canonical {canonical}, ttl {ttl}s");
            ExitCode::SUCCESS
        }
        Ok(Answer::NxDomain { ttl }) => {
            eprintln!("NXDOMAIN (negative ttl {ttl}s)");
            ExitCode::from(1)
        }
        Ok(Answer::NoData { ttl }) => {
            eprintln!("no {qtype:?} records (negative ttl {ttl}s)");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(3)
        }
    }
}
