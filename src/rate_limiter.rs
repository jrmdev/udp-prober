use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SharedRateLimiter {
    inner: Mutex<RateLimiterState>,
}

#[derive(Debug)]
struct RateLimiterState {
    bandwidth_bits_per_second: u64,
    packets_per_second: Option<u64>,
    next_bandwidth_slot: Instant,
    next_packet_slot: Instant,
}

impl SharedRateLimiter {
    pub fn new(bandwidth_bits_per_second: u64, packets_per_second: Option<u64>) -> Self {
        let now = Instant::now();
        Self {
            inner: Mutex::new(RateLimiterState {
                bandwidth_bits_per_second,
                packets_per_second,
                next_bandwidth_slot: now,
                next_packet_slot: now,
            }),
        }
    }

    pub fn reserve(&self, packet_bytes: usize) -> Instant {
        let mut state = self.inner.lock().expect("rate limiter poisoned");
        let now = Instant::now();
        let scheduled_at =
            state
                .next_bandwidth_slot
                .max(now)
                .max(if state.packets_per_second.is_some() {
                    state.next_packet_slot
                } else {
                    now
                });

        let bandwidth_interval = Duration::from_secs_f64(
            (packet_bytes as f64 * 8.0) / state.bandwidth_bits_per_second as f64,
        );
        state.next_bandwidth_slot = scheduled_at + bandwidth_interval;

        if let Some(packets_per_second) = state.packets_per_second {
            let packet_interval = Duration::from_secs_f64(1.0 / packets_per_second as f64);
            state.next_packet_slot = scheduled_at + packet_interval;
        }

        scheduled_at
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::SharedRateLimiter;

    #[test]
    fn limiter_serializes_packet_slots() {
        let limiter = SharedRateLimiter::new(8_000, Some(10));
        let first = limiter.reserve(100);
        let second = limiter.reserve(100);
        let third = limiter.reserve(100);

        assert!(second >= first + Duration::from_millis(100));
        assert!(third >= second + Duration::from_millis(100));
        assert!(first >= Instant::now() - Duration::from_secs(1));
    }
}
