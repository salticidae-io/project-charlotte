use std::{path::PathBuf, sync::Arc, time::Duration};

use notify::{RecursiveMode, Watcher};
use tokio::{sync::watch, task::JoinHandle};

use crate::{acme::AcmeManager, config::Config, tls::SniHandle, vhost::Router};

pub(crate) fn spawn_watcher(
    router: Arc<Router>,
    dir: PathBuf,
    config: Config,
    sni: Option<SniHandle>,
    acme: Option<AcmeManager>,
    mut shutdown: watch::Receiver<bool>,
) -> notify::Result<JoinHandle<()>> {
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = events_tx.send(event);
    })?;
    watcher.watch(&dir, RecursiveMode::NonRecursive)?;

    Ok(tokio::spawn(async move {
        let _watcher = watcher;
        loop {
            tokio::select! {
                event = events_rx.recv() => {
                    match event {
                        Some(Ok(_)) => {}
                        Some(Err(error)) => eprintln!("vhost directory watcher error: {error}"),
                        None => break,
                    }
                }
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }

            let deadline = tokio::time::sleep(Duration::from_millis(250));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    event = events_rx.recv() => {
                        match event {
                            Some(Ok(_)) => {}
                            Some(Err(error)) => eprintln!("vhost directory watcher error: {error}"),
                            None => return,
                        }
                    }
                    result = shutdown.changed() => {
                        if result.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                }
            }

            match router.reload_dir().await {
                Ok(true) => {
                    eprintln!("reloaded virtual hosts from {}", dir.display());
                    if let Some(sni) = &sni
                        && let Err(error) = sni.update(&config, &router)
                    {
                        eprintln!("failed to reload virtual-host TLS certificates: {error}");
                    }
                    if let Some(acme) = &acme
                        && let Err(error) = acme.set_eligible(router.acme_names()).await
                    {
                        eprintln!("failed to update ACME virtual-host names: {error}");
                    }
                }
                Ok(false) => {}
                Err(error) => eprintln!("failed to reload virtual hosts: {error}"),
            }
        }
    }))
}
