use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash, Hasher, RandomState},
    net::{IpAddr, Ipv4Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

use http::{HeaderValue, Response, StatusCode, header};

use crate::{response, response::ResponseBody};

const SHARD_COUNT: usize = 64;
const MAX_ENTRIES_PER_SHARD: usize = 1024;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RateLimit {
    interval: Duration,
    burst: u32,
}

impl RateLimit {
    pub(crate) fn parse(value: &str, burst: Option<u32>) -> Result<Self, String> {
        let (count, unit) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid rate limit: {value}; expected N/s, N/m, or N/h"))?;
        let count = count
            .parse::<u32>()
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                format!("invalid rate limit: {value}; request count must be greater than zero")
            })?;
        let (unit_seconds, unit_nanos) = match unit {
            "s" => (1, NANOS_PER_SECOND),
            "m" => (60, 60 * NANOS_PER_SECOND),
            "h" => (3600, 3600 * NANOS_PER_SECOND),
            _ => {
                return Err(format!(
                    "invalid rate limit: {value}; expected N/s, N/m, or N/h"
                ));
            }
        };
        let interval_nanos = (unit_nanos / u128::from(count)).max(1);
        let interval = Duration::new(
            u64::try_from(interval_nanos / NANOS_PER_SECOND)
                .expect("rate interval seconds fit in u64"),
            u32::try_from(interval_nanos % NANOS_PER_SECOND)
                .expect("rate interval nanoseconds fit in u32"),
        );
        let burst = burst.unwrap_or_else(|| count.div_ceil(unit_seconds));
        if burst == 0 {
            return Err("rate limit burst must be greater than zero".to_owned());
        }
        Ok(Self { interval, burst })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ClientKey {
    V4(Ipv4Addr),
    V6([u8; 8]),
}

impl From<IpAddr> for ClientKey {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) => Self::V4(address),
            IpAddr::V6(address) => match address.to_ipv4_mapped() {
                Some(address) => Self::V4(address),
                None => {
                    let octets = address.octets();
                    let mut prefix = [0; 8];
                    prefix.copy_from_slice(&octets[..8]);
                    Self::V6(prefix)
                }
            },
        }
    }
}

pub(crate) struct RateLimiter {
    interval: Duration,
    tolerance: Duration,
    max_entries_per_shard: usize,
    shard_hasher: RandomState,
    shards: [Mutex<HashMap<ClientKey, Instant>>; SHARD_COUNT],
}

impl RateLimiter {
    pub(crate) fn new(limit: RateLimit) -> Self {
        Self::with_shard_capacity(limit, MAX_ENTRIES_PER_SHARD)
    }

    fn with_shard_capacity(limit: RateLimit, max_entries_per_shard: usize) -> Self {
        Self {
            interval: limit.interval,
            tolerance: limit.interval.saturating_mul(limit.burst.saturating_sub(1)),
            max_entries_per_shard: max_entries_per_shard.max(1),
            shard_hasher: RandomState::new(),
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn check(&self, address: IpAddr) -> Result<(), Duration> {
        self.check_at(address, Instant::now())
    }

    fn check_at(&self, address: IpAddr, now: Instant) -> Result<(), Duration> {
        let key = ClientKey::from(address);
        let mut hasher = self.shard_hasher.build_hasher();
        key.hash(&mut hasher);
        let index = (hasher.finish() as usize) % SHARD_COUNT;
        let mut shard = self.shards[index]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if !shard.contains_key(&key) && shard.len() >= self.max_entries_per_shard {
            shard.retain(|_, tat| *tat > now);
            if shard.len() >= self.max_entries_per_shard
                && let Some(key_to_evict) = shard
                    .iter()
                    .min_by_key(|(_, tat)| **tat)
                    .map(|(key, _)| *key)
            {
                shard.remove(&key_to_evict);
            }
        }

        let previous = shard.get(&key).copied().unwrap_or(now);
        let debt = previous.saturating_duration_since(now);
        if debt > self.tolerance {
            return Err(debt.saturating_sub(self.tolerance));
        }

        let base = previous.max(now);
        let next = base.checked_add(self.interval).unwrap_or(base);
        shard.insert(key, next);
        Ok(())
    }

    #[cfg(test)]
    fn shard_sizes(&self) -> Vec<usize> {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .collect()
    }
}

pub(crate) fn too_many_requests(retry_after: Duration) -> Response<ResponseBody> {
    let mut response =
        response::error_response(StatusCode::TOO_MANY_REQUESTS, "too many requests\n");
    let seconds = retry_after
        .as_secs()
        .saturating_add(u64::from(retry_after.subsec_nanos() > 0))
        .max(1);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
    response
}

#[cfg(test)]
mod tests {
    use super::{RateLimit, RateLimiter};
    use std::{
        net::IpAddr,
        time::{Duration, Instant},
    };

    #[test]
    fn parses_rate_units_and_defaults_burst() {
        let per_second = RateLimit::parse("20/s", None).unwrap();
        assert_eq!(per_second.interval, Duration::from_millis(50));
        assert_eq!(per_second.burst, 20);

        let per_minute = RateLimit::parse("20/m", None).unwrap();
        assert_eq!(per_minute.interval, Duration::from_secs(3));
        assert_eq!(per_minute.burst, 1);

        let per_hour = RateLimit::parse("1/h", Some(2)).unwrap();
        assert_eq!(per_hour.interval, Duration::from_secs(3600));
        assert_eq!(per_hour.burst, 2);
    }

    #[test]
    fn rejects_invalid_rates_and_bursts() {
        for invalid in ["0/s", "-1/s", "one/m", "1", "1/ms", "1/s/extra"] {
            assert!(RateLimit::parse(invalid, None).is_err(), "{invalid}");
        }
        assert!(RateLimit::parse("1/s", Some(0)).is_err());
    }

    #[test]
    fn allows_burst_then_returns_the_time_until_refill() {
        let limiter = RateLimiter::new(RateLimit::parse("2/s", Some(2)).unwrap());
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let now = Instant::now();

        assert_eq!(limiter.check_at(address, now), Ok(()));
        assert_eq!(limiter.check_at(address, now), Ok(()));
        assert_eq!(
            limiter.check_at(address, now),
            Err(Duration::from_millis(500))
        );
        assert_eq!(
            limiter.check_at(address, now + Duration::from_millis(500)),
            Ok(())
        );
    }

    #[test]
    fn groups_ipv6_addresses_by_prefix_and_normalizes_mapped_ipv4() {
        let limiter = RateLimiter::new(RateLimit::parse("1/s", Some(1)).unwrap());
        let now = Instant::now();
        let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let same_prefix: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limiter.check_at(first, now), Ok(()));
        assert!(limiter.check_at(same_prefix, now).is_err());
        assert_eq!(limiter.check_at(other_prefix, now), Ok(()));

        let ipv4: IpAddr = "192.0.2.9".parse().unwrap();
        let other_ipv4: IpAddr = "192.0.2.10".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.9".parse().unwrap();
        assert_eq!(limiter.check_at(ipv4, now), Ok(()));
        assert_eq!(limiter.check_at(other_ipv4, now), Ok(()));
        assert!(limiter.check_at(mapped, now).is_err());
    }

    #[test]
    fn bounds_state_per_shard() {
        let limiter =
            RateLimiter::with_shard_capacity(RateLimit::parse("1/s", Some(1)).unwrap(), 2);
        let now = Instant::now();
        for address in 0..512_u32 {
            let _ = limiter.check_at(IpAddr::V4(address.into()), now);
        }
        let sizes = limiter.shard_sizes();
        assert!(sizes.iter().all(|size| *size <= 2));
        assert!(sizes.contains(&2));
    }
}
