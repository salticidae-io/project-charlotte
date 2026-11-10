use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs, io,
    net::IpAddr,
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::Mutex, time::timeout};

use crate::{config::AcmeSettings, tls, vhost::normalize_host};

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const FAILURE_BACKOFF: Duration = Duration::from_secs(10 * 60);
const ORDER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
static NEXT_CACHE_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub(crate) struct AcmeCertificateStore {
    entries: Arc<RwLock<HashMap<String, CachedCertificate>>>,
}

impl std::fmt::Debug for AcmeCertificateStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AcmeCertificateStore")
    }
}

#[derive(Clone)]
struct CachedCertificate {
    key: Arc<CertifiedKey>,
    not_after: i64,
}

impl AcmeCertificateStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(crate) fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(host)
            .map(|entry| Arc::clone(&entry.key))
    }

    fn needs_renewal(&self, host: &str) -> bool {
        let entries = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match entries.get(host) {
            Some(entry) => {
                let now = Utc::now().timestamp();
                entry.not_after <= now.saturating_add(RENEW_BEFORE.as_secs() as i64)
            }
            None => true,
        }
    }

    pub(crate) fn insert(
        &self,
        host: String,
        key: Arc<CertifiedKey>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let not_after = certificate_not_after(&key)?;
        self.entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(host, CachedCertificate { key, not_after });
        Ok(())
    }

    fn retain_hosts(&self, hosts: &HashSet<String>) {
        self.entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|host, _| hosts.contains(host));
    }
}

#[derive(Clone)]
pub(crate) struct AcmeManager {
    inner: Arc<AcmeInner>,
}

struct AcmeInner {
    settings: AcmeSettings,
    eligible: RwLock<HashSet<String>>,
    store: AcmeCertificateStore,
    challenges: Mutex<HashMap<(String, String), String>>,
    in_flight: Mutex<HashSet<String>>,
    failures: Mutex<HashMap<String, Instant>>,
    account: Mutex<Option<Account>>,
}

#[derive(Serialize, Deserialize)]
struct StoredAccount {
    directory: String,
    credentials: AccountCredentials,
}

impl AcmeManager {
    pub(crate) async fn load(
        settings: AcmeSettings,
        names: Vec<String>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        ensure_private_directory(&settings.cache).await?;
        let eligible: HashSet<_> = names
            .into_iter()
            .filter(|name| acme_dns_name(name))
            .collect();
        let store = AcmeCertificateStore::new();
        for name in &eligible {
            let files = cache_files(&settings.cache, name);
            let cert_exists = secure_existing_cache_file(&files.cert, 0o644).await?;
            let key_exists = secure_existing_cache_file(&files.key, 0o600).await?;
            if cert_exists && key_exists {
                match tls::load_certified_key(&files) {
                    Ok(key) => {
                        if let Err(error) = store.insert(name.clone(), key) {
                            eprintln!("ACME cached certificate for {name} is invalid: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("ACME cached certificate for {name} could not be loaded: {error}")
                    }
                }
            }
        }

        Ok(Self {
            inner: Arc::new(AcmeInner {
                settings,
                eligible: RwLock::new(eligible),
                store,
                challenges: Mutex::new(HashMap::new()),
                in_flight: Mutex::new(HashSet::new()),
                failures: Mutex::new(HashMap::new()),
                account: Mutex::new(None),
            }),
        })
    }

    pub(crate) fn cache_dir(&self) -> &Path {
        &self.inner.settings.cache
    }

    pub(crate) fn certificate_store(&self) -> AcmeCertificateStore {
        self.inner.store.clone()
    }

    pub(crate) async fn set_eligible(
        &self,
        names: Vec<String>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let eligible: HashSet<_> = names
            .into_iter()
            .filter(|name| acme_dns_name(name))
            .collect();
        for name in &eligible {
            if self.inner.store.get(name).is_some() {
                continue;
            }
            let files = cache_files(&self.inner.settings.cache, name);
            let cert_exists = secure_existing_cache_file(&files.cert, 0o644).await?;
            let key_exists = secure_existing_cache_file(&files.key, 0o600).await?;
            if cert_exists && key_exists {
                match tls::load_certified_key(&files) {
                    Ok(key) => {
                        if let Err(error) = self.inner.store.insert(name.clone(), key) {
                            eprintln!("ACME cached certificate for {name} is invalid: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("ACME cached certificate for {name} could not be loaded: {error}")
                    }
                }
            }
        }
        self.inner.store.retain_hosts(&eligible);
        *self
            .inner
            .eligible
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = eligible;
        Ok(())
    }

    pub(crate) fn maybe_provision(&self, host: &str) {
        let Some(host) = normalize_host(host) else {
            return;
        };
        if !self
            .inner
            .eligible
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&host)
            || !self.inner.store.needs_renewal(&host)
        {
            return;
        }

        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            {
                let mut in_flight = inner.in_flight.lock().await;
                if in_flight.contains(&host) {
                    return;
                }
                let mut failures = inner.failures.lock().await;
                if failures
                    .get(&host)
                    .is_some_and(|until| *until > Instant::now())
                {
                    return;
                }
                failures.remove(&host);
                in_flight.insert(host.clone());
            }

            let result = provision(&inner, &host).await;
            inner
                .challenges
                .lock()
                .await
                .retain(|(name, _), _| name != &host);
            inner.in_flight.lock().await.remove(&host);
            match result {
                Ok(()) => {
                    inner.failures.lock().await.remove(&host);
                    eprintln!("ACME certificate provisioned for {host}");
                }
                Err(error) => {
                    eprintln!("ACME provisioning failed for {host}: {error}");
                    inner
                        .failures
                        .lock()
                        .await
                        .insert(host, Instant::now() + FAILURE_BACKOFF);
                }
            }
        });
    }

    pub(crate) async fn challenge_response(&self, host: &str, path: &str) -> Option<String> {
        let host = normalize_host(host)?;
        let token = challenge_token(path)?;
        self.inner
            .challenges
            .lock()
            .await
            .get(&(host, token.to_owned()))
            .cloned()
    }
}

/// Extracts the token from an HTTP-01 challenge path. Only the base64url
/// alphabet that ACME tokens use is accepted.
fn challenge_token(path: &str) -> Option<&str> {
    let token = path.strip_prefix(CHALLENGE_PREFIX)?;
    (!token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
    .then_some(token)
}

async fn provision(inner: &AcmeInner, host: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let account = account(inner).await?;
    let identifiers = [Identifier::Dns(host.to_owned())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err(format!("unexpected authorization status for {host}").into()),
            }
            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| format!("ACME server did not offer HTTP-01 for {host}"))?;
            let token = challenge.token.clone();
            let response = challenge.key_authorization().as_str().to_owned();
            inner
                .challenges
                .lock()
                .await
                .insert((host.to_owned(), token), response);
            challenge.set_ready().await?;
        }
    }

    let retry = RetryPolicy::new().timeout(ORDER_TIMEOUT);
    let status = timeout(ORDER_TIMEOUT, order.poll_ready(&retry)).await??;
    if status != OrderStatus::Ready {
        return Err(format!("ACME order for {host} did not become ready: {status:?}").into());
    }
    let private_key = order.finalize().await?;
    let certificate = timeout(ORDER_TIMEOUT, order.poll_certificate(&retry)).await??;
    let files = cache_files(&inner.settings.cache, host);
    write_cache_file(&files.cert, certificate.as_bytes(), 0o644).await?;
    write_cache_file(&files.key, private_key.as_bytes(), 0o600).await?;
    let key = tls::load_certified_key(&files)?;
    if inner
        .eligible
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(host)
    {
        inner.store.insert(host.to_owned(), key)?;
    }
    Ok(())
}

async fn account(inner: &AcmeInner) -> Result<Account, Box<dyn Error + Send + Sync>> {
    let mut account = inner.account.lock().await;
    if let Some(account) = account.as_ref() {
        return Ok(account.clone());
    }

    let path = inner.settings.cache.join("account.json");
    let loaded = if secure_existing_cache_file(&path, 0o600).await? {
        let bytes = tokio::fs::read(&path).await?;
        let stored: StoredAccount = serde_json::from_slice(&bytes)?;
        if stored.directory != inner.settings.directory {
            return Err("ACME account cache belongs to a different directory URL".into());
        }
        let builder = match &inner.settings.ca_root {
            Some(path) => Account::builder_with_root(path)?,
            None => Account::builder()?,
        };
        Some(builder.from_credentials(stored.credentials).await?)
    } else {
        None
    };

    let restored = match loaded {
        Some(account) => account,
        None => {
            let builder = match &inner.settings.ca_root {
                Some(path) => Account::builder_with_root(path)?,
                None => Account::builder()?,
            };
            let contacts: Vec<&str> = inner.settings.contacts.iter().map(String::as_str).collect();
            let (account, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contacts,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    inner.settings.directory.clone(),
                    None,
                )
                .await?;
            let stored = StoredAccount {
                directory: inner.settings.directory.clone(),
                credentials,
            };
            let bytes = serde_json::to_vec(&stored)?;
            write_cache_file(&path, &bytes, 0o600).await?;
            account
        }
    };
    *account = Some(restored.clone());
    Ok(restored)
}

async fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACME cache path must be a real directory, not a symlink",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            tokio::fs::create_dir_all(path).await?;
        }
        Err(error) => return Err(error),
    }
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME cache path must be a real directory",
        ));
    }
    tokio::fs::set_permissions(path, fs::Permissions::from_mode(0o700)).await
}

async fn write_cache_file(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let temporary_path = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        NEXT_CACHE_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temporary_path)
        .await?;
    let write_result = async {
        file.write_all(contents).await?;
        file.sync_all().await?;
        Ok::<(), io::Error>(())
    }
    .await;
    drop(file);
    let result = match write_result {
        Ok(()) => match tokio::fs::rename(&temporary_path, path).await {
            Ok(()) => tokio::fs::set_permissions(path, fs::Permissions::from_mode(mode)).await,
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary_path).await;
    }
    result
}

async fn secure_existing_cache_file(path: &Path, mode: u32) -> io::Result<bool> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_file() => {
            tokio::fs::set_permissions(path, fs::Permissions::from_mode(mode)).await?;
            Ok(true)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME cache entries must be regular files, not symlinks",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn cache_files(cache: &Path, host: &str) -> crate::config::TlsFiles {
    crate::config::TlsFiles {
        cert: cache.join(format!("{host}.cert.pem")),
        key: cache.join(format!("{host}.key.pem")),
    }
}

fn certificate_not_after(key: &CertifiedKey) -> Result<i64, Box<dyn Error + Send + Sync>> {
    let certificate = key
        .cert
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "certificate chain is empty"))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(parsed.validity().not_after.timestamp())
}

fn acme_dns_name(name: &str) -> bool {
    if name.starts_with("*.") || name.parse::<IpAddr>().is_ok() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::{
        AcmeCertificateStore, AcmeManager, AcmeSettings, CHALLENGE_PREFIX, acme_dns_name,
        cache_files, certificate_not_after, challenge_token,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::tls;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_cache() -> PathBuf {
        std::env::temp_dir().join(format!(
            "project-charlotte-acme-{}-{}",
            std::process::id(),
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn only_exact_dns_names_are_eligible() {
        assert!(acme_dns_name("alpha.example.test"));
        assert!(!acme_dns_name("*.example.test"));
        assert!(!acme_dns_name("127.0.0.1"));
        assert!(!acme_dns_name("bad_label.example.test"));
        assert!(!acme_dns_name("-invalid.example.test"));
    }

    #[tokio::test]
    async fn challenge_path_returns_only_matching_host_and_token() {
        let cache = temp_cache();
        let manager = AcmeManager::load(
            AcmeSettings {
                directory: "http://127.0.0.1:1/directory".to_owned(),
                cache: cache.clone(),
                contacts: Vec::new(),
                ca_root: None,
            },
            vec!["alpha.example.test".to_owned()],
        )
        .await
        .unwrap();
        manager.inner.challenges.lock().await.insert(
            ("alpha.example.test".to_owned(), "token_123".to_owned()),
            "token_123.thumbprint".to_owned(),
        );
        assert_eq!(
            manager
                .challenge_response(
                    "ALPHA.EXAMPLE.TEST.",
                    "/.well-known/acme-challenge/token_123"
                )
                .await
                .as_deref(),
            Some("token_123.thumbprint")
        );
        assert!(
            manager
                .challenge_response(
                    "other.example.test",
                    "/.well-known/acme-challenge/token_123"
                )
                .await
                .is_none()
        );
        assert!(
            manager
                .challenge_response(
                    "alpha.example.test",
                    "/.well-known/acme-challenge/token_123/extra"
                )
                .await
                .is_none()
        );
        tokio::fs::remove_dir_all(cache).await.unwrap();
    }

    #[tokio::test]
    async fn cached_certificate_is_loaded_into_dynamic_store() {
        let cache = temp_cache();
        tokio::fs::create_dir_all(&cache).await.unwrap();
        let generated =
            rcgen::generate_simple_self_signed(vec!["alpha.example.test".to_owned()]).unwrap();
        let files = cache_files(&cache, "alpha.example.test");
        tokio::fs::write(&files.cert, generated.cert.pem())
            .await
            .unwrap();
        tokio::fs::write(&files.key, generated.signing_key.serialize_pem())
            .await
            .unwrap();
        let manager = AcmeManager::load(
            AcmeSettings {
                directory: "http://127.0.0.1:1/directory".to_owned(),
                cache: cache.clone(),
                contacts: Vec::new(),
                ca_root: None,
            },
            vec!["alpha.example.test".to_owned()],
        )
        .await
        .unwrap();
        assert!(
            manager
                .certificate_store()
                .get("alpha.example.test")
                .is_some()
        );
        assert!(
            certificate_not_after(
                &manager
                    .certificate_store()
                    .get("alpha.example.test")
                    .unwrap()
            )
            .is_ok()
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&files.key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        tokio::fs::remove_dir_all(cache).await.unwrap();
    }

    #[test]
    fn absent_and_expiring_certificates_need_renewal() {
        let store = AcmeCertificateStore::new();
        assert!(store.needs_renewal("alpha.example.test"));
        let generated =
            rcgen::generate_simple_self_signed(vec!["alpha.example.test".to_owned()]).unwrap();
        let cache = temp_cache();
        std::fs::create_dir_all(&cache).unwrap();
        let files = cache_files(&cache, "alpha.example.test");
        std::fs::write(&files.cert, generated.cert.pem()).unwrap();
        std::fs::write(&files.key, generated.signing_key.serialize_pem()).unwrap();
        let key = tls::load_certified_key(&files).unwrap();
        store.insert("alpha.example.test".to_owned(), key).unwrap();
        assert!(!store.needs_renewal("alpha.example.test"));
        store
            .entries
            .write()
            .unwrap()
            .get_mut("alpha.example.test")
            .unwrap()
            .not_after = 0;
        assert!(store.needs_renewal("alpha.example.test"));
        std::fs::remove_dir_all(cache).unwrap();
    }

    /// Eligible names become cache file names, so nothing that passes the
    /// check may address a file outside the cache directory.
    #[test_fuzz::test_fuzz]
    fn dns_name(name: String) {
        if !acme_dns_name(&name) {
            return;
        }
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        );
        let cache = std::path::Path::new("/cache");
        let files = cache_files(cache, &name);
        for file in [files.cert, files.key] {
            assert_eq!(file.parent(), Some(cache));
            assert!(
                file.file_name()
                    .is_some_and(|file_name| file_name.to_string_lossy().starts_with(&name))
            );
        }
    }

    #[test]
    fn fuzz_seed_dns_name() {
        dns_name("alpha.example.test".to_owned());
        dns_name("../escape".to_owned());
        dns_name("*.example.test".to_owned());
    }

    #[test_fuzz::test_fuzz]
    fn challenge_path(path: String) {
        if let Some(token) = challenge_token(&path) {
            assert!(!token.is_empty());
            assert!(
                token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            );
            assert_eq!(format!("{CHALLENGE_PREFIX}{token}"), path);
        }
    }

    #[test]
    fn fuzz_seed_challenge_path() {
        challenge_path("/.well-known/acme-challenge/token_123".to_owned());
        challenge_path("/.well-known/acme-challenge/../secret".to_owned());
        challenge_path("/.well-known/acme-challenge/".to_owned());
    }
}
