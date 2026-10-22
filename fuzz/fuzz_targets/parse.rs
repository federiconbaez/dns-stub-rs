#![no_main]
use dns_stub::{interpret, wire::parse, QType};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = parse(data) {
        let name = msg.questions.first().map(|q| q.name.clone()).unwrap_or_default();
        let _ = interpret(&msg, &name, QType::A, 86_400);
        let _ = interpret(&msg, &name, QType::Aaaa, 86_400);
    }
});
