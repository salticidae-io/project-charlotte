//! Process-lifetime traffic counters for the whole server and each virtual host.
//!
//! Counters are keyed by a vhost's primary name so they survive configuration
//! reloads. Tables cache each counter, keeping requests off the map lock.

use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use http_body::{Body, Frame};

#[derive(Default)]
pub(crate) struct Counters {
    requests: AtomicU64,
    client_errors: AtomicU64,
    server_errors: AtomicU64,
    bot_challenges: AtomicU64,
    bot_blocks: AtomicU64,
    bot_logged: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Counters {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "requests": self.requests.load(Ordering::Relaxed),
            "client_errors": self.client_errors.load(Ordering::Relaxed),
            "server_errors": self.server_errors.load(Ordering::Relaxed),
            "bot_challenges": self.bot_challenges.load(Ordering::Relaxed),
            "bot_blocks": self.bot_blocks.load(Ordering::Relaxed),
            "bot_logged": self.bot_logged.load(Ordering::Relaxed),
            "bytes_in": self.bytes_in.load(Ordering::Relaxed),
            "bytes_out": self.bytes_out.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BotIntervention {
    Challenge,
    Block,
    Log,
}

#[derive(Default)]
pub(crate) struct Traffic {
    total: Arc<Counters>,
    vhosts: Mutex<BTreeMap<String, Arc<Counters>>>,
}

/// The counters a single request contributes to.
#[derive(Clone)]
pub(crate) struct RequestTraffic {
    total: Arc<Counters>,
    vhost: Option<Arc<Counters>>,
}

impl Traffic {
    /// Records the start of a request routed to `vhost` (if any).
    #[cfg(test)]
    pub(crate) fn start(&self, vhost: Option<&str>) -> RequestTraffic {
        self.start_with(vhost.map(|name| self.counters(name)))
    }

    pub(crate) fn counters(&self, name: &str) -> Arc<Counters> {
        let mut vhosts = self.vhosts.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(vhosts.entry(name.to_owned()).or_default())
    }

    pub(crate) fn start_with(&self, vhost: Option<Arc<Counters>>) -> RequestTraffic {
        let traffic = RequestTraffic {
            total: Arc::clone(&self.total),
            vhost,
        };
        traffic.each(|counters| counters.requests.fetch_add(1, Ordering::Relaxed));
        traffic
    }

    pub(crate) fn snapshot(&self) -> serde_json::Value {
        let vhosts = self
            .vhosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(name, counters)| (name.clone(), Arc::clone(counters)))
            .collect::<Vec<_>>();
        serde_json::json!({
            "total": self.total.json(),
            "vhosts": vhosts
                .iter()
                .map(|(name, counters)| (name.clone(), counters.json()))
                .collect::<serde_json::Map<_, _>>(),
        })
    }

    pub(crate) fn retain(&self, names: &HashSet<&str>) {
        self.vhosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|name, _| names.contains(name.as_str()));
    }
}

impl RequestTraffic {
    fn each(&self, f: impl Fn(&Counters) -> u64) {
        f(&self.total);
        if let Some(vhost) = &self.vhost {
            f(vhost);
        }
    }

    pub(crate) fn status(&self, status: http::StatusCode) {
        if status.is_client_error() {
            self.each(|c| c.client_errors.fetch_add(1, Ordering::Relaxed));
        } else if status.is_server_error() {
            self.each(|c| c.server_errors.fetch_add(1, Ordering::Relaxed));
        }
    }

    pub(crate) fn bot(&self, intervention: BotIntervention) {
        self.each(|c| {
            let counter = match intervention {
                BotIntervention::Challenge => &c.bot_challenges,
                BotIntervention::Block => &c.bot_blocks,
                BotIntervention::Log => &c.bot_logged,
            };
            counter.fetch_add(1, Ordering::Relaxed)
        });
    }

    fn bytes(&self, inbound: bool, len: usize) {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        self.each(|c| {
            let counter = if inbound { &c.bytes_in } else { &c.bytes_out };
            counter.fetch_add(len, Ordering::Relaxed)
        });
    }
}

/// Counts body data frames into request traffic as they are polled.
pub(crate) struct TrafficBody<B> {
    inner: std::pin::Pin<Box<B>>,
    traffic: RequestTraffic,
    inbound: bool,
}

impl<B> TrafficBody<B> {
    pub(crate) fn inbound(inner: B, traffic: RequestTraffic) -> Self {
        Self {
            inner: Box::pin(inner),
            traffic,
            inbound: true,
        }
    }

    pub(crate) fn outbound(inner: B, traffic: RequestTraffic) -> Self {
        Self {
            inner: Box::pin(inner),
            traffic,
            inbound: false,
        }
    }
}

impl<B> Body for TrafficBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.inner.as_mut().poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(frame))) = &result
            && let Some(data) = frame.data_ref()
        {
            self.traffic.bytes(self.inbound, data.len());
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    #[tokio::test]
    async fn counts_server_and_vhost_traffic() {
        let traffic = Traffic::default();
        let request = traffic.start(Some("example.com"));
        request.status(http::StatusCode::NOT_FOUND);
        request.bot(BotIntervention::Challenge);
        request.bot(BotIntervention::Block);
        request.bot(BotIntervention::Log);
        let body = TrafficBody::inbound(Full::new(Bytes::from_static(b"abc")), request.clone());
        body.collect().await.unwrap();
        let body = TrafficBody::outbound(Full::new(Bytes::from_static(b"hello")), request);
        body.collect().await.unwrap();
        traffic
            .start(None)
            .status(http::StatusCode::INTERNAL_SERVER_ERROR);

        let snapshot = traffic.snapshot();
        assert_eq!(snapshot["total"]["requests"], 2);
        assert_eq!(snapshot["total"]["client_errors"], 1);
        assert_eq!(snapshot["total"]["server_errors"], 1);
        assert_eq!(snapshot["total"]["bot_challenges"], 1);
        assert_eq!(snapshot["total"]["bot_blocks"], 1);
        assert_eq!(snapshot["total"]["bot_logged"], 1);
        assert_eq!(snapshot["total"]["bytes_in"], 3);
        assert_eq!(snapshot["total"]["bytes_out"], 5);
        let vhost = &snapshot["vhosts"]["example.com"];
        assert_eq!(vhost["requests"], 1);
        assert_eq!(vhost["client_errors"], 1);
        assert_eq!(vhost["server_errors"], 0);
        assert_eq!(vhost["bot_challenges"], 1);
        assert_eq!(vhost["bot_blocks"], 1);
        assert_eq!(vhost["bot_logged"], 1);
        assert_eq!(vhost["bytes_out"], 5);
    }

    #[test]
    fn cached_counters_are_shared_and_removed_vhosts_are_pruned() {
        let traffic = Traffic::default();
        let cached = traffic.counters("retained.example");
        traffic.start_with(Some(Arc::clone(&cached)));
        assert!(Arc::ptr_eq(&cached, &traffic.counters("retained.example")));

        let retired = traffic.counters("retired.example");
        traffic.start_with(Some(retired));
        traffic.retain(&HashSet::from(["retained.example"]));

        let snapshot = traffic.snapshot();
        assert!(snapshot["vhosts"].get("retained.example").is_some());
        assert!(snapshot["vhosts"].get("retired.example").is_none());
    }
}
