use core::num::NonZeroU32;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter, middleware::NoOpMiddleware};
use std::{net::IpAddr, sync::Arc};

type Key = IpAddr;

#[derive(Clone)]
pub struct Limiter {
    inner: Arc<DefaultKeyedRateLimiter<Key, NoOpMiddleware>>,
}

impl Limiter {
    pub fn new(quota: u32) -> Limiter {
        Limiter {
            inner: Arc::new(RateLimiter::keyed(Quota::per_second(
                NonZeroU32::new(quota).expect("quota must be > 0"),
            ))),
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        self.inner.check_key(&ip).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_until_quota_then_denies() {
        let lim = Limiter::new(50);
        let ip = "1.2.3.4".parse::<IpAddr>().unwrap();
        for _ in 0..50 {
            assert!(lim.check(ip));
        }
        assert!(!lim.check(ip));
    }
}
