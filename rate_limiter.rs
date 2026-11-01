use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter, middleware::NoOpMiddleware};
use nonzero_macros::nonzero;
use std::net::IpAddr;

pub struct Limiter {
    inner: DefaultKeyedRateLimiter<IpAddr, NoOpMiddleware>,
}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter {
            inner: RateLimiter::keyed(Quota::per_second(nonzero!(50u32))),
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
        let lim = Limiter::new();
        let ip = "1.2.3.4".parse::<IpAddr>().unwrap();
        for _ in 0..50 {
            assert!(lim.check(ip));
        }
        assert!(!lim.check(ip));
    }
}
