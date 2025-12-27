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

/// Route categories for differentiated rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteCategory {
    /// General read/write endpoints (default).
    General,
    /// Transaction submission endpoints (higher cost).
    Submit,
    /// Bridge proof submission (higher cost).
    BridgeProof,
    /// Intent operations (higher cost).
    Intent,
    /// Health/metrics endpoints (exempt from rate limiting).
    Health,
}

impl RouteCategory {
    /// Get the route category from a path.
    pub fn from_path(path: &str) -> Self {
        match path {
            // Health endpoints exempt from rate limiting
            "/healthz" | "/readyz" | "/metrics" => Self::Health,

            // Submit endpoints
            "/fin/actions"
            | "/data/datasets"
            | "/data/licenses"
            | "/data/attestations"
            | "/data/listings"
            | "/data/allowlist/licensors"
            | "/data/allowlist/attestors" => Self::Submit,

            // Bridge proof endpoints
            p if p.starts_with("/bridge/proofs") => Self::BridgeProof,

            // Intent endpoints
            "/linkage/buy-license" => Self::Intent,
            p if p.starts_with("/bridge/intent") => Self::Intent,

            // All other endpoints
            _ => Self::General,
        }
    }

    /// Get the cost multiplier for this route category.
    /// Higher cost means fewer allowed requests.
    pub fn cost_multiplier(&self) -> u32 {
        match self {
            Self::Health => 0, // Free (not rate limited)
            Self::General => 1,
            Self::Submit => 2,
            Self::BridgeProof => 3,
            Self::Intent => 2,
        }
    }

    /// Get a label for metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::General => "general",
            Self::Submit => "submit",
            Self::BridgeProof => "bridge_proof",
            Self::Intent => "intent",
        }
    }
}

/// Simple in-memory token bucket rate limiter (best-effort).
///
/// Notes:
/// - Per-process only (not distributed).
/// - Deterministic tests via injected time source.
/// - Integer-only timers (no jitter or random backoff).
/// - Route-aware cost multipliers.
pub struct RateLimiter<T: TimeSource> {
    cfg: RateLimitConfig,
    time: T,
    per_ip: Mutex<HashMap<String, Bucket>>,
    per_actor: Mutex<HashMap<String, Bucket>>,
    /// Per-route category buckets (for differentiated limits).
    /// Currently unused but reserved for future per-route-category limiting.
    #[allow(dead_code)]
    per_route: Mutex<HashMap<(String, RouteCategory), Bucket>>,
}

impl<T: TimeSource> RateLimiter<T> {
    pub fn new(cfg: RateLimitConfig, time: T) -> Self {
        Self {
            cfg,
            time,
            per_ip: Mutex::new(HashMap::new()),
            per_actor: Mutex::new(HashMap::new()),
            per_route: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    #[allow(dead_code)] // Reserved for future use
    pub fn check_ip(&self, ip: &str) -> Decision {
        self.check(&self.per_ip, ip, 1)
    }

    pub fn check_actor(&self, actor: &str) -> Decision {
        self.check(&self.per_actor, actor, 1)
    }

    /// Check rate limit for a specific route category.
    /// Uses the route's cost multiplier for differentiated limiting.
    pub fn check_route(&self, ip: &str, path: &str) -> Decision {
        let category = RouteCategory::from_path(path);

        // Health endpoints are never rate limited
        if category == RouteCategory::Health {
            return Decision {
                allowed: true,
                retry_after_secs: 0,
            };
        }

        let cost = category.cost_multiplier();
        if cost == 0 {
            return Decision {
                allowed: true,
                retry_after_secs: 0,
            };
        }

        // Use combined key for route-specific tracking
        let key = format!("{}:{}", ip, category.label());
        self.check(&self.per_ip, &key, cost)
    }

    /// Check with a cost multiplier (1 = standard, 2 = double cost, etc.).
    fn check(&self, map: &Mutex<HashMap<String, Bucket>>, key: &str, cost: u32) -> Decision {
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

        // Fixed-point token arithmetic (deterministic, integer-only).
        const SCALE: u128 = 1_000_000;
        let cap = u128::from(self.cfg.burst.max(1)) * SCALE;
        let rate_per_min = u128::from(self.cfg.requests_per_minute.max(1));
        let rate_per_ms = rate_per_min * SCALE / 60_000;
        // If rate is extremely low, force a minimum so retry calculation doesn't divide by zero.
        let rate_per_ms = rate_per_ms.max(1);

        // Cost multiplier for differentiated routes
        let token_cost = SCALE * u128::from(cost.max(1));

        let now = self.time.now_millis();
        let mut guard = map.lock().expect("rate limiter mutex poisoned");
        let b = guard.entry(k.to_string()).or_insert_with(|| Bucket {
            tokens_scaled: cap,
            last_ms: now,
        });

        // Refill (deterministic, no jitter).
        let elapsed = now.saturating_sub(b.last_ms);
        if elapsed > 0 {
            let refill = u128::from(elapsed) * rate_per_ms;
            b.tokens_scaled = (b.tokens_scaled + refill).min(cap);
            b.last_ms = now;
        }

        if b.tokens_scaled >= token_cost {
            b.tokens_scaled -= token_cost;
            Decision {
                allowed: true,
                retry_after_secs: 0,
            }
        } else {
            let missing = token_cost.saturating_sub(b.tokens_scaled);
            // millis until enough tokens (deterministic).
            let wait_ms = missing.div_ceil(rate_per_ms);
            let retry_after_secs_u128 = wait_ms.div_ceil(1000).max(1);
            let retry_after_secs = u64::try_from(retry_after_secs_u128).unwrap_or(u64::MAX);
            Decision {
                allowed: false,
                retry_after_secs,
            }
        }
    }

    /// Get configuration (for observability).
    #[allow(dead_code)] // Reserved for future use
    pub fn config(&self) -> &RateLimitConfig {
        &self.cfg
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
