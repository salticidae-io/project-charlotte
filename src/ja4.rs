use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_CAPTURE: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClientHelloInfo {
    pub(crate) ja4: String,
    pub(crate) max_version: u16,
    pub(crate) ciphers: Vec<u16>,
    pub(crate) extensions: Vec<u16>,
    pub(crate) alpn: Vec<String>,
    pub(crate) sig_algs: Vec<u16>,
    pub(crate) sni: Option<String>,
    pub(crate) grease: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct TlsFingerprint(pub(crate) Arc<ClientHelloInfo>);

pub(crate) struct RecordingStream<S> {
    inner: S,
    captured: Arc<Mutex<Vec<u8>>>,
}

impl<S> RecordingStream<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            captured: Arc::new(Mutex::new(Vec::with_capacity(MAX_CAPTURE))),
        }
    }

    pub(crate) fn captured(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.captured)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let newly_read = &buffer.filled()[before..];
            if !newly_read.is_empty() {
                let mut captured = self
                    .captured
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let remaining = MAX_CAPTURE.saturating_sub(captured.len());
                captured.extend_from_slice(&newly_read[..newly_read.len().min(remaining)]);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

pub(crate) fn parse_client_hello(bytes: &[u8]) -> Option<ClientHelloInfo> {
    let handshake = handshake_message(bytes)?;
    if handshake.first().copied()? != 1 {
        return None;
    }
    let message_len = read_u24(handshake.get(1..4)?)?;
    let body = handshake.get(4..4 + message_len)?;
    parse_hello_body(body)
}

fn handshake_message(records: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    let mut handshake = Vec::new();
    let mut expected_len = None;
    while offset + 5 <= records.len() {
        if records[offset] != 22 {
            return None;
        }
        let record_len = usize::from(u16::from_be_bytes([
            records[offset + 3],
            records[offset + 4],
        ]));
        offset += 5;
        let record = records.get(offset..offset.checked_add(record_len)?)?;
        offset += record_len;
        handshake.extend_from_slice(record);
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return None;
            }
            let length = usize::try_from(read_u24(&handshake[1..4])?).ok()?;
            expected_len = Some(length.checked_add(4)?);
        }
        if expected_len.is_some_and(|length| handshake.len() >= length) {
            return Some(handshake);
        }
    }
    None
}

fn parse_hello_body(body: &[u8]) -> Option<ClientHelloInfo> {
    let mut cursor = Cursor::new(body);
    let legacy_version = cursor.u16()?;
    cursor.take(32)?;
    let session_id_len = usize::from(cursor.u8()?);
    cursor.take(session_id_len)?;
    let cipher_bytes_len = usize::from(cursor.u16()?);
    let cipher_bytes = cursor.take(cipher_bytes_len)?;
    if cipher_bytes.len() % 2 != 0 {
        return None;
    }
    let ciphers = u16_list(cipher_bytes)?;
    let compression_methods_len = usize::from(cursor.u8()?);
    cursor.take(compression_methods_len)?;
    let extensions_len = usize::from(cursor.u16()?);
    let extensions_bytes = cursor.take(extensions_len)?;
    if !cursor.is_empty() {
        return None;
    }

    let mut extensions = Vec::new();
    let mut alpn = Vec::new();
    let mut sig_algs = Vec::new();
    let mut sni = None;
    let mut max_version = legacy_version;
    let mut grease = false;
    let mut extension_cursor = Cursor::new(extensions_bytes);
    while !extension_cursor.is_empty() {
        let extension_type = extension_cursor.u16()?;
        let data_len = usize::from(extension_cursor.u16()?);
        let data = extension_cursor.take(data_len)?;
        extensions.push(extension_type);
        match extension_type {
            0 => sni = parse_sni(data),
            13 => sig_algs = parse_u16_vector(data)?,
            16 => alpn = parse_alpn(data)?,
            43 => {
                if let Some(versions) = parse_supported_versions(data) {
                    grease |= versions.iter().copied().any(is_grease);
                    max_version = versions
                        .into_iter()
                        .filter(|version| !is_grease(*version))
                        .max()
                        .unwrap_or(legacy_version);
                }
            }
            _ => {}
        }
    }
    grease |= ciphers
        .iter()
        .chain(&extensions)
        .chain(&sig_algs)
        .copied()
        .any(is_grease);
    let ja4 = make_ja4(
        max_version,
        &ciphers,
        &extensions,
        &alpn,
        &sig_algs,
        sni.as_deref(),
    );
    Some(ClientHelloInfo {
        ja4,
        max_version,
        ciphers,
        extensions,
        alpn,
        sig_algs,
        sni,
        grease,
    })
}

fn parse_sni(data: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(data);
    let list_len = usize::from(cursor.u16()?);
    let mut list = Cursor::new(cursor.take(list_len)?);
    while !list.is_empty() {
        let name_type = list.u8()?;
        let name_len = usize::from(list.u16()?);
        let name = list.take(name_len)?;
        if name_type == 0 {
            return std::str::from_utf8(name).ok().map(str::to_owned);
        }
    }
    None
}

fn parse_alpn(data: &[u8]) -> Option<Vec<String>> {
    let mut cursor = Cursor::new(data);
    let list_len = usize::from(cursor.u16()?);
    let mut list = Cursor::new(cursor.take(list_len)?);
    let mut protocols = Vec::new();
    while !list.is_empty() {
        let protocol_len = usize::from(list.u8()?);
        let protocol = list.take(protocol_len)?;
        protocols.push(std::str::from_utf8(protocol).ok()?.to_owned());
    }
    Some(protocols)
}

fn parse_u16_vector(data: &[u8]) -> Option<Vec<u16>> {
    let mut cursor = Cursor::new(data);
    let list_len = usize::from(cursor.u16()?);
    let values = u16_list(cursor.take(list_len)?)?;
    cursor.is_empty().then_some(values)
}

fn parse_supported_versions(data: &[u8]) -> Option<Vec<u16>> {
    let length = usize::from(*data.first()?);
    u16_list(data.get(1..1 + length)?)
}

fn u16_list(data: &[u8]) -> Option<Vec<u16>> {
    if data.len() % 2 != 0 {
        return None;
    }
    Some(
        data.chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect(),
    )
}

fn make_ja4(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    alpn: &[String],
    sig_algs: &[u16],
    sni: Option<&str>,
) -> String {
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni_flag = sni
        .and_then(|name| name.parse::<std::net::IpAddr>().ok())
        .map_or_else(|| if sni.is_some() { "d" } else { "i" }, |_| "i");
    let cipher_values = sorted_values(ciphers.iter().copied());
    let extension_values = sorted_values(
        extensions
            .iter()
            .copied()
            .filter(|value| *value != 0 && *value != 16),
    );
    let signature_values = sig_algs
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_count = ciphers
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .count()
        .min(99);
    let extension_count = extensions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .count()
        .min(99);
    let alpn = alpn.first().map_or_else(
        || "00".to_owned(),
        |protocol| {
            let first = protocol.chars().next().unwrap_or('0');
            let last = protocol.chars().last().unwrap_or('0');
            format!("{first}{last}").to_ascii_lowercase()
        },
    );
    let extension_and_signature_values =
        if extension_values.is_empty() && signature_values.is_empty() {
            String::new()
        } else if signature_values.is_empty() {
            extension_values
        } else {
            format!("{extension_values}_{signature_values}")
        };
    format!(
        "t{version}{sni_flag}{cipher_count:02}{extension_count:02}{alpn}_{}_{}",
        hash_values_or_empty(&cipher_values),
        hash_values_or_empty(&extension_and_signature_values)
    )
}

fn sorted_values(values: impl Iterator<Item = u16>) -> String {
    let mut values = values
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
        .into_iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hash_values(value: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    digest.as_ref()[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_values_or_empty(value: &str) -> String {
    if value.is_empty() {
        "000000000000".to_owned()
    } else {
        hash_values(value)
    }
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn read_u24(bytes: &[u8]) -> Option<usize> {
    let value = bytes.get(..3)?;
    Some((usize::from(value[0]) << 16) | (usize::from(value[1]) << 8) | usize::from(value[2]))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let value = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(value)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordingStream, parse_client_hello};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn client_hello(grease: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        let ciphers = if grease {
            [0x0a0a_u16, 0x1301, 0x1302]
        } else {
            [0x1301_u16, 0x1302, 0]
        };
        let cipher_count = if grease { 3 } else { 2 };
        body.extend_from_slice(&((cipher_count * 2) as u16).to_be_bytes());
        for cipher in ciphers.into_iter().take(cipher_count) {
            body.extend_from_slice(&cipher.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        let mut extensions = Vec::new();
        let sni = b"\x00\x0e\x00\x00\x0bexample.com";
        push_extension(&mut extensions, 0, sni);
        let alpn = b"\x00\x03\x02h2";
        push_extension(&mut extensions, 16, alpn);
        let sigs = b"\x00\x04\x04\x03\x08\x04";
        push_extension(&mut extensions, 13, sigs);
        let versions = b"\x02\x03\x04";
        push_extension(&mut extensions, 43, versions);
        if grease {
            push_extension(&mut extensions, 0x1a1a, &[]);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0, 0, 0];
        let length = body.len();
        handshake[1] = ((length >> 16) & 0xff) as u8;
        handshake[2] = ((length >> 8) & 0xff) as u8;
        handshake[3] = (length & 0xff) as u8;
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn push_extension(extensions: &mut Vec<u8>, kind: u16, data: &[u8]) {
        extensions.extend_from_slice(&kind.to_be_bytes());
        extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(data);
    }

    #[test]
    fn parses_client_hello_fields_and_builds_ja4_prefix() {
        let hello = parse_client_hello(&client_hello(false)).unwrap();
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, ["h2"]);
        assert_eq!(hello.max_version, 0x0304);
        assert_eq!(hello.ja4, "t13d0204h2_62ed6f6ca7ad_ef5f37ab036a");
    }

    #[test]
    fn grease_does_not_change_fingerprint() {
        let normal = parse_client_hello(&client_hello(false)).unwrap();
        let grease = parse_client_hello(&client_hello(true)).unwrap();
        assert_eq!(normal.ja4, grease.ja4);
        assert!(grease.grease);
    }

    #[test]
    fn parses_rustls_client_hello_with_alpn() {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut hello_bytes = Vec::new();
        client.write_tls(&mut hello_bytes).unwrap();
        let hello = parse_client_hello(&hello_bytes).unwrap();
        assert!(hello.ja4.starts_with("t13d"));
        assert!(hello.ja4.contains("h2_"));
    }

    #[tokio::test]
    async fn recording_stream_captures_split_input() {
        let (mut writer, reader) = duplex(1024);
        let stream = RecordingStream::new(reader);
        let captured = stream.captured();
        let mut stream = stream;
        let first = client_hello(false);
        let split = first.len() / 2;
        writer.write_all(&first[..split]).await.unwrap();
        let mut prefix = vec![0; split];
        stream.read_exact(&mut prefix).await.unwrap();
        writer.write_all(&first[split..]).await.unwrap();
        let mut suffix = vec![0; first.len() - split];
        stream.read_exact(&mut suffix).await.unwrap();
        assert!(
            parse_client_hello(
                &captured
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            )
            .is_some()
        );
    }
}
