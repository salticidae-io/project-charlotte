//! Rustls configuration and static or ACME-backed SNI certificate selection.

use std::{error::Error, sync::Arc};

use rustls::{
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject},
    },
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

#[cfg(feature = "acme")]
use crate::acme::{AcmeCertificateStore, AcmeManager};
use crate::{
    config::{Config, TlsFiles},
    vhost::{Router, match_score, normalize_host},
};

pub(crate) struct TlsSetup {
    pub(crate) tcp: Arc<rustls::ServerConfig>,
    #[cfg(feature = "http3")]
    pub(crate) http3: Arc<rustls::ServerConfig>,
    pub(crate) sni: SniHandle,
}

#[derive(Debug)]
struct SniResolver {
    static_entries: std::sync::RwLock<StaticCertificates>,
    #[cfg(feature = "acme")]
    acme: Option<AcmeCertificateStore>,
}

#[derive(Debug)]
struct StaticCertificates {
    entries: Vec<(String, Arc<CertifiedKey>)>,
    fallback: Option<Arc<CertifiedKey>>,
}

#[derive(Clone)]
pub(crate) struct SniHandle {
    resolver: Arc<SniResolver>,
}

impl TlsSetup {
    pub(crate) fn load(
        config: &Config,
        router: &Router,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        let (certificate_entries, default_certificate) = router.sni_certificates();
        let fallback_files = config.tls.as_ref().or(default_certificate.as_ref());
        #[cfg(feature = "acme")]
        let acme = router.acme_manager().map(AcmeManager::certificate_store);
        #[cfg(feature = "acme")]
        let has_acme = acme.is_some();
        #[cfg(not(feature = "acme"))]
        let has_acme = false;
        if certificate_entries.is_empty()
            && fallback_files.is_none()
            && !has_acme
            && !(config.tls_bind.is_some() && router.vhost_dir().is_some())
        {
            return Ok(None);
        }

        let static_certificates = load_static_certificates(certificate_entries, fallback_files)?;
        let resolver = Arc::new(SniResolver {
            static_entries: std::sync::RwLock::new(static_certificates),
            #[cfg(feature = "acme")]
            acme,
        });
        let tcp = server_config(
            resolver.clone(),
            &[b"h2".to_vec(), b"http/1.1".to_vec()],
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )?;
        #[cfg(feature = "http3")]
        let http3 = server_config(
            resolver.clone(),
            &[b"h3".to_vec()],
            &[&rustls::version::TLS13],
        )?;
        Ok(Some(Self {
            tcp,
            #[cfg(feature = "http3")]
            http3,
            sni: SniHandle { resolver },
        }))
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(client_hello.server_name())
    }
}

impl SniResolver {
    fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        #[cfg(feature = "acme")]
        if let Some(key) = server_name
            .and_then(normalize_host)
            .and_then(|host| self.acme.as_ref().and_then(|store| store.get(&host)))
        {
            return Some(key);
        }
        let static_entries = self
            .static_entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        select_key(
            &static_entries.entries,
            static_entries.fallback.as_ref(),
            server_name,
        )
        .cloned()
    }
}

impl SniHandle {
    pub(crate) fn update(
        &self,
        config: &Config,
        router: &Router,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (certificate_entries, default_certificate) = router.sni_certificates();
        let fallback_files = config.tls.as_ref().or(default_certificate.as_ref());
        let updated = load_static_certificates(certificate_entries, fallback_files)?;
        *self
            .resolver
            .static_entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = updated;
        Ok(())
    }
}

fn load_static_certificates(
    certificate_entries: Vec<(String, TlsFiles)>,
    fallback_files: Option<&TlsFiles>,
) -> Result<StaticCertificates, Box<dyn Error + Send + Sync>> {
    let entries = certificate_entries
        .into_iter()
        .map(|(name, files)| Ok((name, load_certified_key(&files)?)))
        .collect::<Result<Vec<_>, Box<dyn Error + Send + Sync>>>()?;
    let fallback = fallback_files.map(load_certified_key).transpose()?;
    Ok(StaticCertificates { entries, fallback })
}

fn select_index<T>(entries: &[(String, T)], host: &str) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .filter_map(|(index, (pattern, _))| match_score(pattern, host).map(|score| (index, score)))
        .max_by_key(|(_, score)| *score)
        .map(|(index, _)| index)
}

pub(crate) fn select_key<'a, T>(
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

pub(crate) fn load_certified_key(
    files: &TlsFiles,
) -> Result<Arc<CertifiedKey>, Box<dyn Error + Send + Sync>> {
    let certs = CertificateDer::pem_file_iter(&files.cert)?
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    if certs.is_empty() {
        return Err(format!(
            "TLS certificate file contains no certificates: {}",
            files.cert.display()
        )
        .into());
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(&files.key).map_err(
        |error| -> Box<dyn Error + Send + Sync> {
            match error {
                pem::Error::NoItemsFound => format!(
                    "TLS private-key file contains no private key: {}",
                    files.key.display()
                )
                .into(),
                other => Box::new(other),
            }
        },
    )?;
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
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[cfg(feature = "acme")]
    use super::{SniResolver, StaticCertificates};
    use super::{load_certified_key, select_index, select_key};
    #[cfg(feature = "acme")]
    use crate::acme::AcmeCertificateStore;
    use crate::{
        config::TlsFiles,
        vhost::{match_score, normalize_host},
    };

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn certificate_files(name: &str) -> (PathBuf, TlsFiles, Vec<u8>) {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "project-charlotte-tls-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let certificate = generated.cert.der().to_vec();
        let files = TlsFiles {
            cert: directory.join("cert.pem"),
            key: directory.join("key.pem"),
        };
        std::fs::write(&files.cert, generated.cert.pem()).unwrap();
        std::fs::write(&files.key, generated.signing_key.serialize_pem()).unwrap();
        (directory, files, certificate)
    }

    #[test]
    fn empty_certificate_file_returns_existing_error() {
        let (_directory, files, _) = certificate_files("empty-cert.test");
        std::fs::write(&files.cert, []).unwrap();

        let error = load_certified_key(&files).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "TLS certificate file contains no certificates: {}",
                files.cert.display()
            )
        );
    }

    #[test]
    fn empty_private_key_file_returns_existing_error() {
        let (_directory, files, _) = certificate_files("empty-key.test");
        std::fs::write(&files.key, []).unwrap();

        let error = load_certified_key(&files).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "TLS private-key file contains no private key: {}",
                files.key.display()
            )
        );
    }

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

    #[cfg(feature = "acme")]
    #[test]
    fn acme_certificate_takes_precedence_over_static_and_fallback_certificates() {
        let (dynamic_dir, dynamic_files, dynamic_der) = certificate_files("alpha.test");
        let (static_dir, static_files, _) = certificate_files("alpha.test");
        let (fallback_dir, fallback_files, _) = certificate_files("fallback.test");
        let store = AcmeCertificateStore::new();
        store
            .insert(
                "alpha.test".to_owned(),
                load_certified_key(&dynamic_files).unwrap(),
            )
            .unwrap();
        let resolver = SniResolver {
            static_entries: std::sync::RwLock::new(StaticCertificates {
                entries: vec![(
                    "alpha.test".to_owned(),
                    load_certified_key(&static_files).unwrap(),
                )],
                fallback: Some(load_certified_key(&fallback_files).unwrap()),
            }),
            acme: Some(store),
        };

        assert_eq!(
            resolver.resolve_name(Some("ALPHA.TEST.")).unwrap().cert[0].as_ref(),
            dynamic_der
        );

        std::fs::remove_dir_all(dynamic_dir).unwrap();
        std::fs::remove_dir_all(static_dir).unwrap();
        std::fs::remove_dir_all(fallback_dir).unwrap();
    }

    /// Certificate selection must return the best-matching entry, and use
    /// the fallback only when no entry matches the server name.
    #[test_fuzz::test_fuzz]
    fn sni_selection(names: Vec<String>, server_name: Option<String>, fallback: bool) {
        const FALLBACK: usize = usize::MAX;
        let entries = names.into_iter().zip(0usize..).collect::<Vec<_>>();
        let selected = select_key(
            &entries,
            fallback.then_some(&FALLBACK),
            server_name.as_deref(),
        );
        let host = server_name.as_deref().and_then(normalize_host);
        let score = |pattern: &str| host.as_deref().and_then(|host| match_score(pattern, host));
        match selected {
            Some(&index) if index != FALLBACK => {
                let best = score(&entries[index].0).expect("selected entry matches the name");
                assert!(
                    entries
                        .iter()
                        .all(|(pattern, _)| score(pattern).is_none_or(|other| other <= best))
                );
            }
            other => {
                assert_eq!(other.is_some(), fallback);
                assert!(entries.iter().all(|(pattern, _)| score(pattern).is_none()));
            }
        }
    }

    #[test]
    fn fuzz_seed_sni_selection() {
        let names = vec![
            "*.example.test".to_owned(),
            "api.example.test".to_owned(),
            "*.dev.example.test".to_owned(),
        ];
        sni_selection(names.clone(), Some("API.Example.Test.".to_owned()), true);
        sni_selection(names.clone(), Some("a.dev.example.test".to_owned()), false);
        sni_selection(names, None, false);
    }
}
