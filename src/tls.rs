use std::{error::Error, fs::File, io::BufReader, sync::Arc};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{
    config::{Config, TlsFiles},
    vhost::{Router, match_score, normalize_host},
};

pub(crate) struct TlsSetup {
    pub(crate) tcp: Arc<rustls::ServerConfig>,
    pub(crate) http3: Arc<rustls::ServerConfig>,
}

#[derive(Debug)]
struct SniResolver {
    entries: Vec<(String, Arc<CertifiedKey>)>,
    fallback: Option<Arc<CertifiedKey>>,
}

impl TlsSetup {
    pub(crate) fn load(
        config: &Config,
        router: &Router,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        let (certificate_entries, default_certificate) = router.sni_certificates();
        let fallback_files = config.tls.as_ref().or(default_certificate.as_ref());
        if certificate_entries.is_empty() && fallback_files.is_none() {
            return Ok(None);
        }

        let entries = certificate_entries
            .into_iter()
            .map(|(name, files)| Ok((name, load_certified_key(&files)?)))
            .collect::<Result<Vec<_>, Box<dyn Error + Send + Sync>>>()?;
        let fallback = fallback_files.map(load_certified_key).transpose()?;
        let resolver = Arc::new(SniResolver { entries, fallback });
        let tcp = server_config(
            resolver.clone(),
            &[b"h2".to_vec(), b"http/1.1".to_vec()],
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )?;
        let http3 = server_config(resolver, &[b"h3".to_vec()], &[&rustls::version::TLS13])?;
        Ok(Some(Self { tcp, http3 }))
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        select_key(
            &self.entries,
            self.fallback.as_ref(),
            client_hello.server_name(),
        )
        .cloned()
    }
}

fn select_index<T>(entries: &[(String, T)], host: &str) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .filter_map(|(index, (pattern, _))| match_score(pattern, host).map(|score| (index, score)))
        .max_by_key(|(_, score)| *score)
        .map(|(index, _)| index)
}

fn select_key<'a, T>(
    entries: &'a [(String, T)],
    fallback: Option<&'a T>,
    server_name: Option<&str>,
) -> Option<&'a T> {
    server_name
        .and_then(normalize_host)
        .and_then(|host| select_index(entries, &host))
        .map(|index| &entries[index].1)
        .or(fallback)
}

fn load_certified_key(files: &TlsFiles) -> Result<Arc<CertifiedKey>, Box<dyn Error + Send + Sync>> {
    let cert_file = File::open(&files.cert)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    if certs.is_empty() {
        return Err(format!(
            "TLS certificate file contains no certificates: {}",
            files.cert.display()
        )
        .into());
    }

    let key_file = File::open(&files.key)?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| {
        format!(
            "TLS private-key file contains no private key: {}",
            files.key.display()
        )
    })?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

fn server_config(
    resolver: Arc<dyn ResolvesServerCert>,
    alpn_protocols: &[Vec<u8>],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<Arc<rustls::ServerConfig>, Box<dyn Error + Send + Sync>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn_protocols.to_vec();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::{select_index, select_key};

    #[test]
    fn selects_exact_and_longest_wildcard_then_falls_back() {
        let entries = vec![
            ("*.example.test".to_owned(), "wildcard"),
            ("api.example.test".to_owned(), "exact"),
            ("*.dev.example.test".to_owned(), "long-wildcard"),
        ];
        assert_eq!(
            entries[select_index(&entries, "api.example.test").unwrap()].1,
            "exact"
        );
        assert_eq!(
            entries[select_index(&entries, "api.dev.example.test").unwrap()].1,
            "long-wildcard"
        );
        assert_eq!(
            entries[select_index(&entries, "www.example.test").unwrap()].1,
            "wildcard"
        );
        assert!(select_index(&entries, "unknown.test").is_none());
    }

    #[test]
    fn uses_fallback_for_unknown_or_missing_sni_and_none_without_fallback() {
        let entries = vec![("alpha.test".to_owned(), "alpha")];
        let fallback = "default";
        assert_eq!(
            select_key(&entries, Some(&fallback), Some("unknown.test")),
            Some(&fallback)
        );
        assert_eq!(select_key(&entries, Some(&fallback), None), Some(&fallback));
        assert_eq!(select_key(&entries, None, Some("unknown.test")), None);
        assert_eq!(select_key(&entries, None, None), None);
    }
}
