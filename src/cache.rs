//! TTL cache for answers, positive and negative, with an injectable clock.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{Answer, QType};

/// Time source; tests drive a manual one.
pub trait Clock {
    fn now(&self) -> Instant;
}

/// The real monotonic clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Debug)]
pub struct Cache {
    map: HashMap<(String, QType), (Answer, Instant)>,
    capacity: usize,
}

impl Cache {
    pub fn new(capacity: usize) -> Cache {
        Cache {
            map: HashMap::new(),
            capacity,
        }
    }

    /// Returns a live entry with its TTL lowered to the seconds remaining.
    pub fn get(&mut self, name: &str, qtype: QType, now: Instant) -> Option<Answer> {
        let key = (name.to_string(), qtype);
        let (ans, exp) = self.map.get(&key)?;
        if *exp <= now {
            self.map.remove(&key);
            return None;
        }
        let left = (*exp - now).as_secs() as u32;
        Some(ans.with_ttl(left))
    }

    /// Stores `ans` for its TTL. TTL 0 is not stored.
    pub fn put(&mut self, name: &str, qtype: QType, ans: Answer, now: Instant) {
        let ttl = ans.ttl();
        if ttl == 0 || self.capacity == 0 {
            return;
        }
        if self.map.len() >= self.capacity {
            self.map.retain(|_, (_, exp)| *exp > now);
        }
        if self.map.len() >= self.capacity {
            // Still full: drop the entry that would expire first.
            if let Some(k) = self
                .map
                .iter()
                .min_by_key(|(_, (_, exp))| *exp)
                .map(|(k, _)| k.clone())
            {
                self.map.remove(&k);
            }
        }
        self.map.insert(
            (name.to_string(), qtype),
            (ans, now + Duration::from_secs(ttl as u64)),
        );
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
