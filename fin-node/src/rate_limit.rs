#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::disallowed_types)]

use crate::config::RateLimitConfig;
use std::collections::HashMap;
use std::sync::Mutex;

/// Abstraction for deterministic testing.
pub trait TimeSource: Send + Sync + 'static {
    fn now_millis(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now_millis(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        u64::try_from(ms).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Decision {
    pub allowed: bool,
    /// Recommended Retry-After in seconds when denied.
    pub retry_after_secs: u64,
}

#[derive(Debug)]
struct Bucket {
    tokens_scaled: u128,
    last_ms: u64,
}

/// Simple in-memory token bucket rate limiter (best-effort).
///
/// Notes:
/// - Per-process only (not distributed).
/// - Deterministic tests via injected time source.
pub struct RateLimiter<T: TimeSource> {
    cfg: RateLimitConfig,
    time: T,
    per_ip: Mutex<HashMap<String, Bucket>>,
    per_actor: Mutex<HashMap<String, Bucket>>,
}

impl<T: TimeSource> RateLimiter<T> {
    pub fn new(cfg: RateLimitConfig, time: T) -> Self {
        Self {
            cfg,
            time,
            per_ip: Mutex::new(HashMap::new()),
            per_actor: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn check_ip(&self, ip: &str) -> Decision {
        self.check(&self.per_ip, ip)
    }

    pub fn check_actor(&self, actor: &str) -> Decision {
        self.check(&self.per_actor, actor)
    }

    fn check(&self, map: &Mutex<HashMap<String, Bucket>>, key: &str) -> Decision {
        if !self.cfg.enabled {
            return Decision {
                allowed: true,
                retry_after_secs: 0,
            };
        }

        // Defensive: treat empty keys as a shared bucket.
        let k = if key.trim().is_empty() {
            "<unknown>"
        } else {
            key
        };

        // Fixed-point token arithmetic.
        const SCALE: u128 = 1_000_000;
        let cap = u128::from(self.cfg.burst.max(1)) * SCALE;
        let rate_per_min = u128::from(self.cfg.requests_per_minute.max(1));
        let rate_per_ms = rate_per_min * SCALE / 60_000;
        // If rate is extremely low, force a minimum so retry calculation doesn't divide by zero.
        let rate_per_ms = rate_per_ms.max(1);

        let now = self.time.now_millis();
        let mut guard = map.lock().expect("rate limiter mutex poisoned");
        let b = guard.entry(k.to_string()).or_insert_with(|| Bucket {
            tokens_scaled: cap,
            last_ms: now,
        });

        // Refill.
        let elapsed = now.saturating_sub(b.last_ms);
        if elapsed > 0 {
            let refill = u128::from(elapsed) * rate_per_ms;
            b.tokens_scaled = (b.tokens_scaled + refill).min(cap);
            b.last_ms = now;
        }

        if b.tokens_scaled >= SCALE {
            b.tokens_scaled -= SCALE;
            Decision {
                allowed: true,
                retry_after_secs: 0,
            }
        } else {
            let missing = SCALE - b.tokens_scaled;
            // millis until next whole token.
            let wait_ms = missing.div_ceil(rate_per_ms);
            let retry_after_secs_u128 = wait_ms.div_ceil(1000).max(1);
            let retry_after_secs = u64::try_from(retry_after_secs_u128).unwrap_or(u64::MAX);
            Decision {
                allowed: false,
                retry_after_secs,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    struct FakeTime {
        now: AtomicU64,
    }

    impl FakeTime {
        fn new(start_ms: u64) -> Self {
            Self {
                now: AtomicU64::new(start_ms),
            }
        }
        fn advance_ms(&self, delta: u64) {
            self.now.fetch_add(delta, Ordering::SeqCst);
        }
    }

    impl TimeSource for FakeTime {
        fn now_millis(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn token_bucket_allows_burst_then_denies() {
        let cfg = RateLimitConfig {
            enabled: true,
            requests_per_minute: 60, // 1 rps
            burst: 2,
        };
        let time = FakeTime::new(0);
        let rl = RateLimiter::new(cfg, time);

        assert!(rl.check_ip("1.2.3.4").allowed);
        assert!(rl.check_ip("1.2.3.4").allowed);
        let d = rl.check_ip("1.2.3.4");
        assert!(!d.allowed);
        assert!(d.retry_after_secs >= 1);
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let cfg = RateLimitConfig {
            enabled: true,
            requests_per_minute: 60, // 1 rps
            burst: 1,
        };
        let time = FakeTime::new(0);
        let rl = RateLimiter::new(cfg, time);

        assert!(rl.check_actor("acc-alice").allowed);
        assert!(!rl.check_actor("acc-alice").allowed);

        rl.time.advance_ms(1000);
        assert!(rl.check_actor("acc-alice").allowed);
    }
}
