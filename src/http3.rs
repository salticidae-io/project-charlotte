//! QUIC and HTTP/3 connection handling and request forwarding to the router.

use std::{error::Error, io, net::SocketAddr, sync::Arc};

use bytes::{Buf, Bytes};
use futures_util::stream;
use h3::server::RequestResolver;
use http::Response;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use quinn::{Endpoint, VarInt};
use tokio::{sync::watch, task::JoinSet};

use crate::vhost::{Router, TlsSni};

type H3Resolver = RequestResolver<h3_quinn::Connection, Bytes>;

pub(crate) fn bind(
    address: SocketAddr,
    tls_config: &Arc<rustls::ServerConfig>,
) -> Result<(Endpoint, SocketAddr), Box<dyn Error + Send + Sync>> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config.as_ref().clone())?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = Endpoint::server(server_config, address)?;
    let local_address = endpoint.local_addr()?;
    Ok((endpoint, local_address))
}

pub(crate) async fn serve(
    endpoint: Endpoint,
    local: SocketAddr,
    router: Arc<Router>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let router = Arc::clone(&router);
                connections.spawn(async move {
                    if let Err(error) = serve_connection(incoming, local, router).await {
                        crate::log_error!("HTTP/3 connection failed: {error}");
                    }
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    crate::log_error!("HTTP/3 connection task failed: {error}");
                }
            }
        }
    }

    endpoint.close(VarInt::from_u32(0), b"server shutdown");
    endpoint.wait_idle().await;
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            crate::log_error!("HTTP/3 connection task failed: {error}");
        }
    }
    Ok(())
}

async fn serve_connection(
    incoming: quinn::Incoming,
    local: SocketAddr,
    router: Arc<Router>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let connection = incoming.await?;
    let peer = connection.remote_address();
    let sni = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name)
        .map(Arc::<str>::from);
    let mut h3_connection = h3::server::builder()
        .build(h3_quinn::Connection::new(connection))
        .await?;
    let mut requests = JoinSet::new();

    loop {
        tokio::select! {
            accepted = h3_connection.accept() => {
                match accepted? {
                    Some(resolver) => {
                        let router = Arc::clone(&router);
                        let sni = sni.clone();
                        requests.spawn(async move {
                            if let Err(error) =
                                serve_request(resolver, router, peer, local, sni).await
                            {
                                crate::log_error!("HTTP/3 request failed: {error}");
                            }
                        });
                    }
                    None => break,
                }
            }
            result = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = result {
                    crate::log_error!("HTTP/3 request task failed: {error}");
                }
            }
        }
    }
    while let Some(result) = requests.join_next().await {
        if let Err(error) = result {
            crate::log_error!("HTTP/3 request task failed: {error}");
        }
    }
    Ok(())
}

async fn serve_request(
    resolver: H3Resolver,
    router: Arc<Router>,
    peer: SocketAddr,
    local: SocketAddr,
    sni: Option<Arc<str>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (mut request, request_stream) = resolver.resolve_request().await?;
    request.extensions_mut().insert(TlsSni(sni));
    let (mut send_stream, recv_stream) = request_stream.split();
    let body_stream = stream::unfold(recv_stream, |mut recv_stream| async move {
        match recv_stream.recv_data().await {
            Ok(Some(mut data)) => {
                let bytes = data.copy_to_bytes(data.remaining());
                Some((Ok::<_, io::Error>(Frame::data(bytes)), recv_stream))
            }
            Ok(None) => None,
            Err(error) => Some((Err(io::Error::other(error.to_string())), recv_stream)),
        }
    });
    let request = request.map(|()| StreamBody::new(body_stream));
    let response = router.dispatch(request, peer, local).await;
    let (parts, mut body) = response.into_parts();
    send_stream
        .send_response(Response::from_parts(parts, ()))
        .await?;

    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            send_stream.send_data(data).await?;
        }
    }
    send_stream.finish().await?;
    Ok(())
}
