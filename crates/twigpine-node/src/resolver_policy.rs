//! DNS resolver for the node's outbound HTTP clients that refuses to hand the
//! connector any address a peer or webhook owner should not be able to reach.
//!
//! The resolver runs one lookup per new connection and keeps no cache, so a
//! name that answered public earlier and private now is refused now. An answer
//! is accepted only when it holds 1 to 32 distinct addresses and every one
//! passes `is_public_ip`; otherwise the whole answer is refused, never
//! filtered or truncated.

// The clients that install this resolver are wired in by later changes.
#![allow(dead_code)]

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tracing::warn;

use crate::api::peers::is_public_ip;

const LOOKUP_DEADLINE: Duration = Duration::from_secs(5);
const MAX_ANSWERS: usize = 32;

type LookupFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>;
type LookupFn = dyn Fn(String) -> LookupFuture + Send + Sync;

/// Why an answer was refused. Each variant has a fixed log reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denial {
    NonPublic,
    Empty,
    TooMany,
    LookupError,
    Deadline,
}

impl Denial {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Denial::NonPublic => "non-public answer",
            Denial::Empty => "empty answer",
            Denial::TooMany => "too many answers",
            Denial::LookupError => "lookup error",
            Denial::Deadline => "lookup deadline exceeded",
        }
    }
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Denial {}

/// Deduplicate `answers` and accept them only when there are 1 to `max`
/// distinct addresses and every one is public.
pub(crate) fn check_answers(answers: &[IpAddr], max: usize) -> Result<Vec<IpAddr>, Denial> {
    let mut seen = HashSet::new();
    let distinct: Vec<IpAddr> = answers
        .iter()
        .copied()
        .filter(|a| seen.insert(*a))
        .collect();
    if distinct.is_empty() {
        return Err(Denial::Empty);
    }
    if distinct.len() > max {
        return Err(Denial::TooMany);
    }
    if !distinct.iter().all(|a| is_public_ip(*a)) {
        return Err(Denial::NonPublic);
    }
    Ok(distinct)
}

#[derive(Clone)]
pub(crate) struct ResolverPolicy {
    lookup: Arc<LookupFn>,
    deadline: Duration,
    max_answers: usize,
}

impl ResolverPolicy {
    pub(crate) fn new<F>(lookup: F, deadline: Duration, max_answers: usize) -> Self
    where
        F: Fn(String) -> LookupFuture + Send + Sync + 'static,
    {
        Self {
            lookup: Arc::new(lookup),
            deadline,
            max_answers,
        }
    }

    /// The system resolver under the production deadline and answer cap.
    pub(crate) fn production() -> Self {
        Self::new(
            |host| {
                Box::pin(async move {
                    let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
                    Ok(addrs.map(|a| a.ip()).collect())
                })
            },
            LOOKUP_DEADLINE,
            MAX_ANSWERS,
        )
    }

    /// Look `host` up and return the checked addresses, or the reason for
    /// refusal. Logs each refusal once.
    pub(crate) async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, Denial> {
        let result =
            match tokio::time::timeout(self.deadline, (self.lookup)(host.to_string())).await {
                Err(_) => Err(Denial::Deadline),
                Ok(Err(_)) => Err(Denial::LookupError),
                Ok(Ok(answers)) => check_answers(&answers, self.max_answers),
            };
        if let Err(denial) = result {
            warn!(host = %host, reason = denial.reason(), "resolver policy refused hostname");
        }
        result
    }
}

impl Resolve for ResolverPolicy {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        Box::pin(async move {
            let addrs = this.resolve_host(name.as_str()).await?;
            // reqwest replaces the port with the URL's port.
            let addrs: Addrs = Box::new(
                addrs
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::{Name, Resolve};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn fixed(answers: Vec<IpAddr>) -> (ResolverPolicy, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let policy = ResolverPolicy::new(
            move |_host| {
                c.fetch_add(1, Ordering::SeqCst);
                let a = answers.clone();
                Box::pin(async move { Ok(a) })
            },
            Duration::from_secs(5),
            32,
        );
        (policy, calls)
    }

    #[test]
    fn denies_each_non_public_single_answer() {
        for s in [
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "64:ff9b:1::a00:1",
            "2002:7f00:1::",
            "0.0.0.0",
            "::",
        ] {
            assert_eq!(
                check_answers(&[ip(s)], 32),
                Err(Denial::NonPublic),
                "{s} must be denied"
            );
        }
    }

    #[test]
    fn permits_public_answers_and_returns_them() {
        for s in ["93.184.216.34", "2606:4700::1111", "64:ff9b::5db8:d822"] {
            assert_eq!(check_answers(&[ip(s)], 32), Ok(vec![ip(s)]), "{s}");
        }
    }

    #[test]
    fn mixed_answers_are_denied_in_both_orders() {
        assert_eq!(
            check_answers(&[ip("93.184.216.34"), ip("127.0.0.1")], 32),
            Err(Denial::NonPublic)
        );
        assert_eq!(
            check_answers(&[ip("10.0.0.1"), ip("93.184.216.34")], 32),
            Err(Denial::NonPublic)
        );
    }

    #[test]
    fn empty_answer_is_denied() {
        assert_eq!(check_answers(&[], 32), Err(Denial::Empty));
    }

    fn distinct(n: u32) -> Vec<IpAddr> {
        (0..n)
            .map(|i| IpAddr::from([93, 184, (i / 250) as u8, (i % 250) as u8 + 1]))
            .collect()
    }

    #[test]
    fn answer_count_cap_counts_distinct_addresses() {
        assert_eq!(check_answers(&distinct(33), 32), Err(Denial::TooMany));
        assert_eq!(check_answers(&distinct(32), 32).unwrap().len(), 32);
        let mut dup = distinct(32);
        dup.push(dup[0]);
        assert_eq!(dup.len(), 33);
        assert_eq!(check_answers(&dup, 32).unwrap(), distinct(32));
    }

    #[tokio::test]
    async fn lookup_error_is_denied() {
        let p = ResolverPolicy::new(
            |_| Box::pin(async { Err(std::io::Error::other("boom")) }),
            Duration::from_secs(5),
            32,
        );
        assert_eq!(p.resolve_host("x.invalid").await, Err(Denial::LookupError));
    }

    #[tokio::test]
    async fn stalled_lookup_hits_the_deadline() {
        let release = Arc::new(tokio::sync::Notify::new());
        let r = release.clone();
        let p = ResolverPolicy::new(
            move |_| {
                let r = r.clone();
                Box::pin(async move {
                    r.notified().await;
                    Ok(vec![IpAddr::from([93, 184, 216, 34])])
                })
            },
            Duration::from_millis(100),
            32,
        );
        let out = tokio::time::timeout(Duration::from_secs(3), p.resolve_host("slow.invalid"))
            .await
            .expect("lookup deadline was not enforced");
        assert_eq!(out, Err(Denial::Deadline));
        release.notify_waiters();
    }

    #[tokio::test]
    async fn every_resolution_looks_up_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let p = ResolverPolicy::new(
            move |_| {
                let n = c.fetch_add(1, Ordering::SeqCst);
                let a = if n == 0 {
                    IpAddr::from([93, 184, 216, 34])
                } else {
                    IpAddr::from([127, 0, 0, 1])
                };
                Box::pin(async move { Ok(vec![a]) })
            },
            Duration::from_secs(5),
            32,
        );
        assert!(p.resolve_host("rebind.invalid").await.is_ok());
        assert_eq!(
            p.resolve_host("rebind.invalid").await,
            Err(Denial::NonPublic)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn each_denial_has_its_fixed_reason() {
        assert_eq!(Denial::NonPublic.reason(), "non-public answer");
        assert_eq!(Denial::Empty.reason(), "empty answer");
        assert_eq!(Denial::TooMany.reason(), "too many answers");
        assert_eq!(Denial::LookupError.reason(), "lookup error");
        assert_eq!(Denial::Deadline.reason(), "lookup deadline exceeded");
    }

    #[tokio::test]
    async fn resolve_trait_denies_loopback_and_permits_public() {
        let name = || "rebind.invalid".parse::<Name>().unwrap();

        let (denying, _) = fixed(vec![ip("127.0.0.1")]);
        assert!(denying.resolve(name()).await.is_err());

        let (permitting, calls) = fixed(vec![ip("93.184.216.34")]);
        let got: Vec<SocketAddr> = permitting.resolve(name()).await.unwrap().collect();
        assert_eq!(got, vec![SocketAddr::new(ip("93.184.216.34"), 0)]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
