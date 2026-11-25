//! Trusted-proxy matching and forwarded-client resolution.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use http::{HeaderMap, HeaderName, HeaderValue};

const MAX_FORWARDED_HOPS: usize = 64;
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        let address = normalize_ip(address);
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = ipv4_mask(self.prefix);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = ipv6_mask(self.prefix);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for TrustedProxy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) if !address.is_empty() && !prefix.is_empty() => (
                address,
                Some(prefix.parse::<u8>().map_err(|_| invalid_proxy(value))?),
            ),
            Some(_) => return Err(invalid_proxy(value)),
            None => (value, None),
        };
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| invalid_proxy(value))?;
        let (address, prefix) = match address {
            IpAddr::V4(address) => {
                let prefix = prefix.unwrap_or(32);
                if prefix > 32 {
                    return Err(invalid_proxy(value));
                }
                (IpAddr::V4(address), prefix)
            }
            IpAddr::V6(address) => {
                if let Some(mapped) = address.to_ipv4_mapped() {
                    match prefix {
                        Some(prefix) if prefix < 96 => return Err(invalid_proxy(value)),
                        Some(prefix) => {
                            let prefix = prefix - 96;
                            if prefix > 32 {
                                return Err(invalid_proxy(value));
                            }
                            (IpAddr::V4(mapped), prefix)
                        }
                        None => (IpAddr::V4(mapped), 32),
                    }
                } else {
                    let prefix = prefix.unwrap_or(128);
                    if prefix > 128 {
                        return Err(invalid_proxy(value));
                    }
                    (IpAddr::V6(address), prefix)
                }
            }
        };
        let network = match address {
            IpAddr::V4(address) => {
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & ipv4_mask(prefix)))
            }
            IpAddr::V6(address) => {
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & ipv6_mask(prefix)))
            }
        };
        Ok(Self { network, prefix })
    }
}

fn invalid_proxy(value: &str) -> String {
    format!("invalid trusted proxy address or CIDR: {value}")
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

#[derive(Clone, Copy, Debug)]
struct ForwardedAddress {
    ip: IpAddr,
    port: Option<u16>,
}

impl ForwardedAddress {
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Some(Self {
                ip: normalize_ip(ip),
                port: None,
            });
        }
        let address = value.parse::<SocketAddr>().ok()?;
        Some(Self {
            ip: normalize_ip(address.ip()),
            port: Some(address.port()),
        })
    }
}

pub(crate) fn resolve(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[TrustedProxy],
) -> (SocketAddr, Option<String>) {
    if !trusted_proxies
        .iter()
        .any(|proxy| proxy.contains(peer.ip()))
    {
        return (peer, None);
    }

    let mut reversed_addresses = Vec::with_capacity(MAX_FORWARDED_HOPS);
    'headers: for value in headers.get_all(&X_FORWARDED_FOR).iter().rev() {
        let Ok(value) = value.to_str() else {
            break;
        };
        for item in value.split(',').rev() {
            if reversed_addresses.len() == MAX_FORWARDED_HOPS {
                break 'headers;
            }
            let Some(address) = ForwardedAddress::parse(item) else {
                break 'headers;
            };
            reversed_addresses.push(address);
        }
    }
    if reversed_addresses.is_empty() {
        return (peer, None);
    }

    let client = reversed_addresses
        .iter()
        .find(|address| {
            !trusted_proxies
                .iter()
                .any(|proxy| proxy.contains(address.ip))
        })
        .or_else(|| reversed_addresses.last())
        .expect("non-empty forwarded address list");
    let client = SocketAddr::new(client.ip, client.port.unwrap_or(peer.port()));
    let chain = reversed_addresses
        .iter()
        .rev()
        .map(|address| address.ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    (client, Some(chain))
}

pub(crate) fn sanitize(headers: &mut HeaderMap, trusted_chain: Option<&str>) {
    headers.remove(&X_FORWARDED_FOR);
    if let Some(chain) = trusted_chain
        && let Ok(value) = HeaderValue::from_str(chain)
    {
        headers.insert(X_FORWARDED_FOR.clone(), value);
    }
}

#[cfg(any(feature = "proxy", test))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectPeer(pub SocketAddr);

#[cfg(test)]
mod tests {
    use super::{DirectPeer, MAX_FORWARDED_HOPS, TrustedProxy, resolve, sanitize};
    use http::{HeaderMap, HeaderValue};
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        str::FromStr,
    };

    fn peer(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    fn trusted(values: &[&str]) -> Vec<TrustedProxy> {
        values
            .iter()
            .map(|value| TrustedProxy::from_str(value).unwrap())
            .collect()
    }

    #[test_fuzz::test_fuzz]
    fn trusted_proxy_spec(value: String) {
        if let Ok(proxy) = TrustedProxy::from_str(&value) {
            let width = match proxy.network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            assert!(proxy.prefix <= width);
            assert!(proxy.contains(proxy.network));

            let address = value
                .split_once('/')
                .map_or(value.as_str(), |(address, _)| address);
            if let Ok(address) = address.parse::<IpAddr>() {
                assert!(proxy.contains(address));
            }
        }
    }

    #[test]
    fn fuzz_seed_trusted_proxy_spec() {
        trusted_proxy_spec("192.0.2.1".to_owned());
        trusted_proxy_spec("10.2.3.4/8".to_owned());
        trusted_proxy_spec("2001:db8::1/64".to_owned());
        trusted_proxy_spec("::ffff:192.0.2.1/120".to_owned());
        trusted_proxy_spec("192.0.2.1/33".to_owned());
    }

    #[test_fuzz::test_fuzz]
    fn forwarded_resolve(
        peer_bytes: Vec<u8>,
        peer_port: u16,
        header_values: Vec<Vec<u8>>,
        proxy_values: Vec<String>,
    ) {
        let peer_ip = match peer_bytes.as_slice() {
            [a, b, c, d] => IpAddr::V4(Ipv4Addr::from([*a, *b, *c, *d])),
            bytes if bytes.len() == 16 => {
                let bytes = <[u8; 16]>::try_from(bytes).expect("length was checked");
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let peer = SocketAddr::new(peer_ip, peer_port);
        let mut headers = HeaderMap::new();
        for value in header_values {
            if let Ok(value) = HeaderValue::from_bytes(&value) {
                headers.append("x-forwarded-for", value);
            }
        }
        let trusted_proxies = proxy_values
            .iter()
            .filter_map(|value| TrustedProxy::from_str(value).ok())
            .collect::<Vec<_>>();
        let peer_is_trusted = trusted_proxies
            .iter()
            .any(|proxy| proxy.contains(peer.ip()));

        let (client, chain) = resolve(peer, &headers, &trusted_proxies);
        if !peer_is_trusted {
            assert_eq!((client, chain), (peer, None));
            return;
        }

        let Some(chain) = chain else {
            assert_eq!(client, peer);
            return;
        };

        let chain_addresses = chain
            .split(", ")
            .map(|address| {
                address
                    .parse::<IpAddr>()
                    .expect("resolved chain contains IPs")
            })
            .collect::<Vec<_>>();
        assert!(!chain_addresses.is_empty());
        assert!(chain_addresses.len() <= MAX_FORWARDED_HOPS);
        assert!(HeaderValue::from_str(&chain).is_ok());
        assert!(chain_addresses.contains(&client.ip()));
        if trusted_proxies
            .iter()
            .any(|proxy| proxy.contains(client.ip()))
        {
            assert!(
                chain_addresses.iter().all(|address| {
                    trusted_proxies.iter().any(|proxy| proxy.contains(*address))
                })
            );
        }

        let mut sanitized = headers;
        sanitize(&mut sanitized, Some(&chain));
        let sanitized_values = sanitized.get_all("x-forwarded-for");
        assert_eq!(sanitized_values.iter().count(), 1);
        assert_eq!(
            sanitized_values.iter().next().unwrap().as_bytes(),
            chain.as_bytes()
        );
    }

    #[test]
    fn fuzz_seed_forwarded_resolve() {
        forwarded_resolve(
            vec![127, 0, 0, 1],
            8080,
            vec![b"203.0.113.9".to_vec(), b"10.0.0.2".to_vec()],
            vec!["127.0.0.1".to_owned(), "10.0.0.0/8".to_owned()],
        );
        forwarded_resolve(
            vec![198, 51, 100, 4],
            54321,
            vec![b"203.0.113.9".to_vec()],
            vec!["127.0.0.1".to_owned()],
        );
        forwarded_resolve(
            vec![0; 16],
            443,
            vec![b"invalid, [2001:db8::1]:4321".to_vec()],
            vec!["::/0".to_owned()],
        );
        forwarded_resolve(vec![1, 2, 3], 80, vec![vec![0xff]], vec!["bad".to_owned()]);
    }

    #[test]
    fn parses_trusted_proxy_cidrs_and_rejects_invalid_prefixes() {
        let network = TrustedProxy::from_str("10.2.3.4/8").unwrap();
        assert!(network.contains("10.9.8.7".parse().unwrap()));
        assert!(!network.contains("11.9.8.7".parse().unwrap()));
        assert!(
            TrustedProxy::from_str("::1")
                .unwrap()
                .contains("::1".parse().unwrap())
        );
        assert!(TrustedProxy::from_str("192.0.2.1/32").is_ok());
        assert!(TrustedProxy::from_str("192.0.2.1/33").is_err());
        assert!(TrustedProxy::from_str("2001:db8::/129").is_err());
        assert!(TrustedProxy::from_str("192.0.2.1/not-a-prefix").is_err());
        assert!(TrustedProxy::from_str("bad/24").is_err());
    }

    #[test]
    fn ignores_forwarded_addresses_from_an_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        let direct_peer = peer("198.51.100.4:54321");

        assert_eq!(
            resolve(direct_peer, &headers, &trusted(&["127.0.0.1"])),
            (direct_peer, None)
        );
    }

    #[test]
    fn resolves_trusted_forwarded_chain_and_normalizes_header_lines() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        headers.append("x-forwarded-for", HeaderValue::from_static("10.0.0.2"));
        let (client, chain) = resolve(
            peer("127.0.0.1:8080"),
            &headers,
            &trusted(&["127.0.0.1", "10.0.0.0/8"]),
        );
        assert_eq!(client, peer("203.0.113.9:8080"));
        assert_eq!(chain.as_deref(), Some("203.0.113.9, 10.0.0.2"));
    }

    #[test]
    fn stops_at_invalid_entries_and_accepts_address_ports() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("spoofed, invalid, [2001:db8::1]:4321"),
        );
        let (client, chain) = resolve(peer("127.0.0.1:8080"), &headers, &trusted(&["127.0.0.1"]));
        assert_eq!(client, peer("[2001:db8::1]:4321"));
        assert_eq!(chain.as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn normalizes_mapped_addresses_and_caps_hop_count() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("::ffff:203.0.113.8"),
        );
        let (client, chain) = resolve(
            peer("[::ffff:127.0.0.1]:8080"),
            &headers,
            &trusted(&["127.0.0.1"]),
        );
        assert_eq!(client, peer("203.0.113.8:8080"));
        assert_eq!(chain.as_deref(), Some("203.0.113.8"));

        let long_chain = std::iter::repeat_n("10.0.0.2", 70)
            .collect::<Vec<_>>()
            .join(", ");
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&long_chain).unwrap(),
        );
        let (_, Some(chain)) = resolve(peer("127.0.0.1:8080"), &headers, &trusted(&["127.0.0.1"]))
        else {
            panic!("expected a trusted forwarded chain")
        };
        assert_eq!(chain.split(", ").count(), 64);
    }

    #[test]
    fn sanitizes_headers_and_escapes_log_fields() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_static("spoofed"));
        headers.append("x-forwarded-for", HeaderValue::from_static("also-spoofed"));
        sanitize(&mut headers, Some("203.0.113.9"));
        assert_eq!(headers.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "203.0.113.9");
        sanitize(&mut headers, None);
        assert!(!headers.contains_key("x-forwarded-for"));
        assert_eq!(DirectPeer(peer("127.0.0.1:80")).0, peer("127.0.0.1:80"));
    }
}
