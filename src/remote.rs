//! Opt-in client for the Again shared-cache HTTP service.
//!
//! Local Again remains account-free: this module is inert until a caller
//! constructs it with an endpoint and bearer token. The client does not
//! serialize tokens, marks the authorization header sensitive, omits it from
//! errors, and redacts it from Debug. Process memory, external proxy policy,
//! crash reporting, and caller logging remain deployment responsibilities.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, ClientBuilder, Method, Response, StatusCode, Url};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};

use crate::team::{
    BlobRef, Digest, RemoteCacheManifest, VerificationContext, VerificationError, verify_candidate,
};
use crate::team_crypto::Ed25519Verifier;

pub const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct RemoteClient {
    base_url: Url,
    bearer_token: String,
    http: Client,
}

impl fmt::Debug for RemoteClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteClient")
            .field("base_url", &self.base_url.as_str())
            .field("bearer_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RemoteError {
    #[error("endpoint URL is invalid")]
    InvalidEndpoint,
    #[error("HTTPS is required for shared-cache endpoints")]
    InsecureEndpoint,
    #[error("HTTP test mode is limited to loopback endpoints")]
    NonLoopbackTestEndpoint,
    #[error("bearer token does not match the ag1 token format")]
    InvalidToken,
    #[error("repository identifier is invalid")]
    InvalidRepository,
    #[error("request binding does not match the endpoint path")]
    RequestBindingMismatch,
    #[error("upload exceeds the blob limit")]
    BlobTooLarge,
    #[error("manifest exceeds the JSON limit")]
    ManifestTooLarge,
    #[error("uploaded bytes do not match their BLAKE3 digest or declared size")]
    UploadDigestMismatch,
    #[error("response body exceeds the {limit} byte limit")]
    ResponseTooLarge { limit: usize },
    #[error("response did not include a valid Content-Length")]
    MissingContentLength,
    #[error("response digest does not match the requested digest")]
    DigestMismatch,
    #[error("response size does not match the requested size")]
    SizeMismatch,
    #[error("response digest header is missing or inconsistent")]
    DigestHeaderMismatch,
    #[error("manifest JSON is invalid")]
    InvalidManifest,
    #[error("remote manifest verification failed: {0}")]
    ManifestVerification(VerificationError),
    #[error("request timed out during {operation}")]
    Timeout { operation: &'static str },
    #[error("transport failed during {operation}")]
    Transport { operation: &'static str },
    #[error("redirects are forbidden for bearer-token requests")]
    RedirectRejected,
    #[error("remote service rejected the request as unauthorized")]
    Unauthorized,
    #[error("remote service denied the request")]
    Forbidden,
    #[error("remote resource was not found")]
    NotFound,
    #[error("remote request conflicted with existing state")]
    Conflict,
    #[error("remote manifest or blob failed validation")]
    ValidationFailed,
    #[error("remote request body was too large")]
    PayloadTooLarge,
    #[error("remote service rejected the media type")]
    UnsupportedMediaType,
    #[error("remote rate limit exceeded")]
    RateLimited,
    #[error("remote service returned an unexpected status: {0}")]
    UnexpectedStatus(u16),
}

impl RemoteClient {
    /// Construct the production client. Plain HTTP is never accepted here.
    pub fn new(endpoint: &str, bearer_token: impl Into<String>) -> Result<Self, RemoteError> {
        Self::build(endpoint, bearer_token.into(), false)
    }

    /// Explicit numeric-loopback-only HTTP mode for deterministic unit tests.
    /// System and environment proxies are disabled in this mode.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn new_for_loopback_test(
        endpoint: &str,
        bearer_token: impl Into<String>,
    ) -> Result<Self, RemoteError> {
        Self::build(endpoint, bearer_token.into(), true)
    }

    fn build(
        endpoint: &str,
        bearer_token: String,
        allow_loopback_http: bool,
    ) -> Result<Self, RemoteError> {
        let base_url = Url::parse(endpoint).map_err(|_| RemoteError::InvalidEndpoint)?;
        if base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(RemoteError::InvalidEndpoint);
        }
        if base_url.scheme() != "https"
            && (!allow_loopback_http || base_url.scheme() != "http" || !is_loopback(&base_url))
        {
            return Err(if allow_loopback_http {
                RemoteError::NonLoopbackTestEndpoint
            } else {
                RemoteError::InsecureEndpoint
            });
        }
        if !is_bearer_token(&bearer_token) {
            return Err(RemoteError::InvalidToken);
        }
        let mut builder = ClientBuilder::new()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .redirect(Policy::none());
        if allow_loopback_http {
            builder = builder.no_proxy();
        }
        let http = builder.build().map_err(|_| RemoteError::InvalidEndpoint)?;
        Ok(Self {
            base_url,
            bearer_token,
            http,
        })
    }

    pub async fn put_blob(
        &self,
        repository_id: &str,
        blob: &BlobRef,
        bytes: &[u8],
    ) -> Result<(), RemoteError> {
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(RemoteError::BlobTooLarge);
        }
        if blob.size_bytes != bytes.len() as u64 || digest_bytes(bytes) != blob.digest {
            return Err(RemoteError::UploadDigestMismatch);
        }
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let url = self.resource_url(repository_id, "blobs", &blob.digest.to_hex())?;
        let response = self
            .send(
                Method::PUT,
                url,
                "put blob",
                bytes,
                Some("application/octet-stream"),
                deadline,
            )
            .await?;
        expect_status(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            "put blob",
        )?;
        Ok(())
    }

    pub async fn head_blob(
        &self,
        repository_id: &str,
        digest: &Digest,
    ) -> Result<u64, RemoteError> {
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let url = self.resource_url(repository_id, "blobs", &digest.to_hex())?;
        let response = self
            .send(Method::HEAD, url, "head blob", &[], None, deadline)
            .await?;
        let response = expect_status(response, &[StatusCode::OK], "head blob")?;
        validate_digest_header(&response, digest)?;
        bounded_content_length(&response, MAX_BLOB_BYTES)
    }

    pub async fn get_blob(
        &self,
        repository_id: &str,
        blob: &BlobRef,
    ) -> Result<Vec<u8>, RemoteError> {
        if blob.size_bytes > MAX_BLOB_BYTES as u64 {
            return Err(RemoteError::BlobTooLarge);
        }
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let url = self.resource_url(repository_id, "blobs", &blob.digest.to_hex())?;
        let response = self
            .send(Method::GET, url, "get blob", &[], None, deadline)
            .await?;
        let response = expect_status(response, &[StatusCode::OK], "get blob")?;
        validate_digest_header(&response, &blob.digest)?;
        if let Some(length) = response.content_length() {
            if length > MAX_BLOB_BYTES as u64 {
                return Err(RemoteError::ResponseTooLarge {
                    limit: MAX_BLOB_BYTES,
                });
            }
            if length != blob.size_bytes {
                return Err(RemoteError::SizeMismatch);
            }
        }
        let bytes = read_bounded(response, MAX_BLOB_BYTES, "get blob", deadline).await?;
        if bytes.len() as u64 != blob.size_bytes {
            return Err(RemoteError::SizeMismatch);
        }
        if digest_bytes(&bytes) != blob.digest {
            return Err(RemoteError::DigestMismatch);
        }
        Ok(bytes)
    }

    pub async fn delete_blob(
        &self,
        repository_id: &str,
        digest: &Digest,
    ) -> Result<(), RemoteError> {
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let url = self.resource_url(repository_id, "blobs", &digest.to_hex())?;
        let response = self
            .send(Method::DELETE, url, "delete blob", &[], None, deadline)
            .await?;
        expect_status(response, &[StatusCode::NO_CONTENT], "delete blob")?;
        Ok(())
    }

    pub async fn put_manifest(
        &self,
        repository_id: &str,
        manifest: &RemoteCacheManifest,
    ) -> Result<(), RemoteError> {
        let request_key = manifest.request_key.to_hex();
        if manifest.repository_id != repository_id {
            return Err(RemoteError::RequestBindingMismatch);
        }
        let body = serde_json::to_vec(manifest).map_err(|_| RemoteError::InvalidManifest)?;
        if body.len() > MAX_MANIFEST_BYTES {
            return Err(RemoteError::ManifestTooLarge);
        }
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let url = self.resource_url(repository_id, "manifests", &request_key)?;
        let response = self
            .send(
                Method::PUT,
                url,
                "put manifest",
                &body,
                Some("application/json"),
                deadline,
            )
            .await?;
        expect_status(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            "put manifest",
        )?;
        Ok(())
    }

    /// Fetches a manifest, but does not return it until the caller-supplied
    /// bindings/trust snapshot, lifecycle/privacy rules, and the concrete
    /// Ed25519 verifier all accept it. The caller remains responsible for
    /// obtaining fresh trust and revocation state through an authenticated
    /// channel and for recomputing every expected input binding locally.
    pub async fn get_manifest(
        &self,
        repository_id: &str,
        request_key: &Digest,
        context: &VerificationContext,
        verifier: &Ed25519Verifier,
    ) -> Result<RemoteCacheManifest, RemoteError> {
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let url = self.resource_url(repository_id, "manifests", &request_key.to_hex())?;
        let response = self
            .send(Method::GET, url, "get manifest", &[], None, deadline)
            .await?;
        let response = expect_status(response, &[StatusCode::OK], "get manifest")?;
        let body = read_bounded(response, MAX_MANIFEST_BYTES, "get manifest", deadline).await?;
        let manifest: RemoteCacheManifest =
            serde_json::from_slice(&body).map_err(|_| RemoteError::InvalidManifest)?;
        verify_candidate(&manifest, context, verifier)
            .map_err(RemoteError::ManifestVerification)?;
        if manifest.repository_id != repository_id || manifest.request_key != *request_key {
            return Err(RemoteError::RequestBindingMismatch);
        }
        Ok(manifest)
    }

    pub async fn delete_manifest(
        &self,
        repository_id: &str,
        request_key: &Digest,
    ) -> Result<(), RemoteError> {
        let deadline = Instant::now() + TOTAL_TIMEOUT;
        let url = self.resource_url(repository_id, "manifests", &request_key.to_hex())?;
        let response = self
            .send(Method::DELETE, url, "delete manifest", &[], None, deadline)
            .await?;
        expect_status(response, &[StatusCode::NO_CONTENT], "delete manifest")?;
        Ok(())
    }

    fn resource_url(
        &self,
        repository_id: &str,
        resource: &str,
        identifier: &str,
    ) -> Result<Url, RemoteError> {
        if !is_route_identifier(repository_id) || !is_digest_identifier(identifier) {
            return Err(RemoteError::InvalidRepository);
        }
        let mut url = self.base_url.clone();
        let base_path = url.path().trim_end_matches('/');
        url.set_path(&format!(
            "{base_path}/v1/repositories/{repository_id}/{resource}/{identifier}"
        ));
        Ok(url)
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        operation: &'static str,
        body: &[u8],
        content_type: Option<&'static str>,
        deadline: Instant,
    ) -> Result<Response, RemoteError> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", self.bearer_token))
            .map_err(|_| RemoteError::InvalidToken)?;
        authorization.set_sensitive(true);
        let mut request = self
            .http
            .request(method, url)
            .header(AUTHORIZATION, authorization);
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        match timeout_at(deadline, request.body(body.to_vec()).send()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) if error.is_timeout() => Err(RemoteError::Timeout { operation }),
            Ok(Err(_)) => Err(RemoteError::Transport { operation }),
            Err(_) => Err(RemoteError::Timeout { operation }),
        }
    }
}

fn is_loopback(url: &Url) -> bool {
    url.host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

fn is_route_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._:-".contains(&byte))
        })
}

fn is_bearer_token(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(version), Some(token_id), Some(secret), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    version == "ag1"
        && !token_id.is_empty()
        && token_id.len() <= 64
        && token_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._:-".contains(&byte))
        })
        && (32..=128).contains(&secret.len())
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_digest_identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex(blake3::hash(bytes).to_hex().as_ref())
        .expect("BLAKE3 always emits 64 hex bytes")
}

fn expect_status(
    response: Response,
    expected: &[StatusCode],
    _operation: &'static str,
) -> Result<Response, RemoteError> {
    let status = response.status();
    if expected.contains(&status) {
        return Ok(response);
    }
    if status.is_redirection() {
        return Err(RemoteError::RedirectRejected);
    }
    let error = match status {
        StatusCode::UNAUTHORIZED => RemoteError::Unauthorized,
        StatusCode::FORBIDDEN => RemoteError::Forbidden,
        StatusCode::NOT_FOUND => RemoteError::NotFound,
        StatusCode::CONFLICT => RemoteError::Conflict,
        StatusCode::UNPROCESSABLE_ENTITY => RemoteError::ValidationFailed,
        StatusCode::PAYLOAD_TOO_LARGE => RemoteError::PayloadTooLarge,
        StatusCode::UNSUPPORTED_MEDIA_TYPE => RemoteError::UnsupportedMediaType,
        StatusCode::TOO_MANY_REQUESTS => RemoteError::RateLimited,
        _ => RemoteError::UnexpectedStatus(status.as_u16()),
    };
    drop(response);
    Err(error)
}

fn validate_digest_header(response: &Response, expected: &Digest) -> Result<(), RemoteError> {
    let Some(value) = response.headers().get("x-again-blake3") else {
        return Err(RemoteError::DigestHeaderMismatch);
    };
    let Ok(value) = value.to_str() else {
        return Err(RemoteError::DigestHeaderMismatch);
    };
    if value != expected.to_hex() {
        return Err(RemoteError::DigestHeaderMismatch);
    }
    Ok(())
}

fn bounded_content_length(response: &Response, limit: usize) -> Result<u64, RemoteError> {
    let Some(value) = response.headers().get(CONTENT_LENGTH) else {
        return Err(RemoteError::MissingContentLength);
    };
    let Ok(value) = value.to_str() else {
        return Err(RemoteError::MissingContentLength);
    };
    let Ok(length) = value.parse::<u64>() else {
        return Err(RemoteError::MissingContentLength);
    };
    if length > limit as u64 {
        return Err(RemoteError::ResponseTooLarge { limit });
    }
    Ok(length)
}

async fn read_bounded(
    mut response: Response,
    limit: usize,
    operation: &'static str,
    deadline: Instant,
) -> Result<Vec<u8>, RemoteError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(RemoteError::ResponseTooLarge { limit });
    }
    let capacity = response.content_length().unwrap_or(0).min(limit as u64) as usize;
    let mut output = Vec::with_capacity(capacity);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(RemoteError::Timeout { operation });
        }
        let read_deadline = deadline.min(now + READ_TIMEOUT);
        match timeout_at(read_deadline, response.chunk()).await {
            Ok(Ok(Some(bytes))) => {
                if bytes.len() > limit.saturating_sub(output.len()) {
                    return Err(RemoteError::ResponseTooLarge { limit });
                }
                output.extend_from_slice(&bytes);
            }
            Ok(Ok(None)) => break,
            Ok(Err(error)) if error.is_timeout() => {
                return Err(RemoteError::Timeout { operation });
            }
            Ok(Err(_)) => return Err(RemoteError::Transport { operation }),
            Err(_) => return Err(RemoteError::Timeout { operation }),
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    use super::*;
    use crate::team::{
        BlobRef, PrivacyClass, PrivacyMetadata, Shareability, SignatureAlgorithm, SignatureEnvelope,
    };
    use crate::team_crypto::{Ed25519Signer, Ed25519Verifier};

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TEST_TOKEN: &str = "ag1.test.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[derive(Clone)]
    struct MockResponse {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        header_delay: Duration,
        body_delay: Duration,
    }

    #[derive(Debug)]
    struct MockRequest {
        method: String,
        target: String,
        headers: String,
        body: Vec<u8>,
    }

    fn response(status: u16, body: Vec<u8>, headers: Vec<(&'static str, String)>) -> MockResponse {
        MockResponse {
            status,
            headers,
            body,
            header_delay: Duration::ZERO,
            body_delay: Duration::ZERO,
        }
    }

    fn delayed_response(
        status: u16,
        body: Vec<u8>,
        header_delay: Duration,
        body_delay: Duration,
    ) -> MockResponse {
        MockResponse {
            status,
            headers: Vec::new(),
            body,
            header_delay,
            body_delay,
        }
    }

    fn server(
        responses: Vec<MockResponse>,
    ) -> (String, Arc<Mutex<Vec<MockRequest>>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let saved = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for mock in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                saved.lock().unwrap().push(request);
                write_response(&mut stream, &mock);
            }
        });
        (address, requests, handle)
    }

    fn read_request(stream: &mut TcpStream) -> MockRequest {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end;
        loop {
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = end + 4;
                break;
            }
        }
        let headers_text = String::from_utf8_lossy(&bytes[..header_end]).to_string();
        let content_length = headers_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim())
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(0);
        while bytes.len() - header_end < content_length {
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        let first = headers_text.lines().next().unwrap();
        let mut first_parts = first.split_whitespace();
        MockRequest {
            method: first_parts.next().unwrap().to_owned(),
            target: first_parts.next().unwrap().to_owned(),
            headers: headers_text,
            body: bytes[header_end..header_end + content_length].to_vec(),
        }
    }

    fn write_response(stream: &mut TcpStream, response: &MockResponse) {
        thread::sleep(response.header_delay);
        let reason = match response.status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            302 => "Found",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "Test",
        };
        let mut output = format!(
            "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            response.status,
            reason,
            response.body.len()
        );
        for (name, value) in &response.headers {
            output.push_str(name);
            output.push_str(": ");
            output.push_str(value);
            output.push_str("\r\n");
        }
        output.push_str("\r\n");
        if stream.write_all(output.as_bytes()).is_err() {
            return;
        }
        thread::sleep(response.body_delay);
        let _ = stream.write_all(&response.body);
    }

    fn fixture() -> (
        RemoteCacheManifest,
        VerificationContext,
        Ed25519Verifier,
        Ed25519Signer,
    ) {
        let signer =
            Ed25519Signer::from_secret_key("key-remote", "producer-remote", &[3; 32]).unwrap();
        let mut manifest = RemoteCacheManifest {
            schema_version: 1,
            record_id: "record-remote".into(),
            tenant_id: "tenant-remote".into(),
            repository_id: "repo-remote".into(),
            request_key: Digest::from_hex(ZERO).unwrap(),
            policy_digest: Digest::from_hex(ONE).unwrap(),
            execution_profile_digest: Digest::from_hex(ZERO).unwrap(),
            platform_digest: Digest::from_hex(ONE).unwrap(),
            image_digest: Digest::from_hex(ZERO).unwrap(),
            stdout: BlobRef {
                digest: Digest::from_hex(ONE).unwrap(),
                size_bytes: 5,
            },
            stderr: BlobRef {
                digest: Digest::from_hex(ZERO).unwrap(),
                size_bytes: 0,
            },
            producer_id: "producer-remote".into(),
            created_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            privacy: PrivacyMetadata {
                classification: PrivacyClass::Internal,
                shareability: Shareability::Repository,
                secret_tainted: false,
            },
            signature: Some(SignatureEnvelope {
                schema_version: 1,
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "key-remote".into(),
                signature: vec![0; 64],
            }),
        };
        signer.sign_manifest(&mut manifest).unwrap();
        let verifier = Ed25519Verifier::from_public_key(
            signer.key_id(),
            signer.producer_id(),
            &signer.public_key_bytes(),
        )
        .unwrap();
        let context = VerificationContext {
            tenant_id: manifest.tenant_id.clone(),
            repository_id: manifest.repository_id.clone(),
            request_key: manifest.request_key,
            policy_digest: manifest.policy_digest,
            execution_profile_digest: manifest.execution_profile_digest,
            platform_digest: manifest.platform_digest,
            image_digest: manifest.image_digest,
            now_unix_seconds: 150,
            trusted_producer_keys: std::collections::BTreeMap::from([(
                "key-remote".into(),
                "producer-remote".into(),
            )]),
            revoked_key_ids: std::collections::BTreeSet::new(),
            revoked_record_ids: std::collections::BTreeSet::new(),
        };
        (manifest, context, verifier, signer)
    }

    #[test]
    fn valid_round_trip_uses_auth_and_all_service_endpoints() {
        test_runtime().block_on(async {
            let (manifest, context, verifier, signer) = fixture();
            let bytes = b"hello".to_vec();
            let digest = digest_bytes(&bytes);
            let blob = BlobRef {
                digest,
                size_bytes: bytes.len() as u64,
            };
            let manifest_body = serde_json::to_vec(&manifest).unwrap();
            let headers = vec![("x-again-blake3", digest.to_hex())];
            let (endpoint, requests, thread) = server(vec![
                response(201, Vec::new(), Vec::new()),
                // The service's HEAD response advertises the blob size in
                // Content-Length; the mock body is ignored by the HEAD client.
                response(200, bytes.clone(), headers.clone()),
                response(200, bytes.clone(), headers),
                response(201, Vec::new(), Vec::new()),
                response(200, manifest_body, Vec::new()),
                response(204, Vec::new(), Vec::new()),
                response(204, Vec::new(), Vec::new()),
            ]);
            let token = "ag1.test-secret.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let client = RemoteClient::new_for_loopback_test(&endpoint, token).unwrap();
            client.put_blob("repo-remote", &blob, &bytes).await.unwrap();
            assert_eq!(
                client.head_blob("repo-remote", &blob.digest).await.unwrap(),
                bytes.len() as u64
            );
            assert_eq!(client.get_blob("repo-remote", &blob).await.unwrap(), bytes);
            client.put_manifest("repo-remote", &manifest).await.unwrap();
            assert_eq!(
                client
                    .get_manifest("repo-remote", &manifest.request_key, &context, &verifier)
                    .await
                    .unwrap(),
                manifest
            );
            client
                .delete_manifest("repo-remote", &manifest.request_key)
                .await
                .unwrap();
            client
                .delete_blob("repo-remote", &blob.digest)
                .await
                .unwrap();
            thread.join().unwrap();
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 7);
            assert!(requests.iter().all(|request| {
                request
                    .headers
                    .to_ascii_lowercase()
                    .contains(&format!("authorization: bearer {token}"))
            }));
            assert_eq!(requests[0].method, "PUT");
            assert!(
                requests[0]
                    .target
                    .starts_with("/v1/repositories/repo-remote/blobs/")
            );
            assert_eq!(requests[1].method, "HEAD");
            assert_eq!(requests[2].method, "GET");
            assert_eq!(requests[3].method, "PUT");
            assert_eq!(requests[4].method, "GET");
            assert_eq!(requests[5].method, "DELETE");
            assert_eq!(requests[6].method, "DELETE");
            assert_eq!(requests[0].body, bytes);
            assert!(!format!("{client:?}").contains(token));
            let _ = signer;
        });
    }

    #[test]
    fn endpoint_and_redirect_policies_are_fail_closed() {
        test_runtime().block_on(async {
            assert_eq!(
                RemoteClient::new("http://example.test", TEST_TOKEN).unwrap_err(),
                RemoteError::InsecureEndpoint
            );
            assert_eq!(
                RemoteClient::new_for_loopback_test("http://example.test", TEST_TOKEN).unwrap_err(),
                RemoteError::NonLoopbackTestEndpoint
            );
            assert_eq!(
                RemoteClient::new_for_loopback_test("http://localhost:8080", TEST_TOKEN)
                    .unwrap_err(),
                RemoteError::NonLoopbackTestEndpoint
            );
            assert_eq!(
                RemoteClient::new("https://embedded:credential@example.test", TEST_TOKEN,)
                    .unwrap_err(),
                RemoteError::InvalidEndpoint
            );
            let (endpoint, _, thread) = server(vec![response(
                302,
                Vec::new(),
                vec![("Location", "http://127.0.0.1/evil".into())],
            )]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            assert_eq!(
                client
                    .delete_blob("repo-remote", &Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap_err(),
                RemoteError::RedirectRejected
            );
            thread.join().unwrap();
        });
    }

    #[test]
    fn one_deadline_covers_response_headers_and_body() {
        test_runtime().block_on(async {
            let (endpoint, _, thread) = server(vec![delayed_response(
                200,
                b"{}".to_vec(),
                Duration::from_millis(20),
                Duration::from_millis(200),
            )]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let url = client
                .resource_url("repo-remote", "manifests", ZERO)
                .unwrap();
            let result = async {
                let deadline = Instant::now() + Duration::from_millis(100);
                let response = client
                    .send(Method::GET, url, "deadline test", &[], None, deadline)
                    .await?;
                let response = expect_status(response, &[StatusCode::OK], "deadline test")?;
                read_bounded(response, MAX_MANIFEST_BYTES, "deadline test", deadline).await
            }
            .await;
            assert_eq!(
                result.unwrap_err(),
                RemoteError::Timeout {
                    operation: "deadline test"
                }
            );
            thread.join().unwrap();
        });
    }

    #[test]
    fn oversized_and_digest_mismatched_responses_are_rejected() {
        test_runtime().block_on(async {
            let oversized = vec![b'x'; MAX_MANIFEST_BYTES + 1];
            let (endpoint, _, thread) = server(vec![response(200, oversized, Vec::new())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let (manifest, context, verifier, _) = fixture();
            assert_eq!(
                client
                    .get_manifest("repo-remote", &manifest.request_key, &context, &verifier)
                    .await
                    .unwrap_err(),
                RemoteError::ResponseTooLarge {
                    limit: MAX_MANIFEST_BYTES
                }
            );
            thread.join().unwrap();

            let expected = BlobRef {
                digest: digest_bytes(b"good"),
                size_bytes: 4,
            };
            let (endpoint, _, thread) = server(vec![response(
                200,
                b"bad!".to_vec(),
                vec![("x-again-blake3", expected.digest.to_hex())],
            )]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            assert_eq!(
                client.get_blob("repo-remote", &expected).await.unwrap_err(),
                RemoteError::DigestMismatch
            );
            thread.join().unwrap();
        });
    }

    #[test]
    fn strict_status_mapping_and_token_validation_are_redacted() {
        test_runtime().block_on(async {
            assert_eq!(
                RemoteClient::new_for_loopback_test("http://127.0.0.1:1", "").unwrap_err(),
                RemoteError::InvalidToken
            );
            assert_eq!(
                RemoteClient::new_for_loopback_test(
                    "http://127.0.0.1:1",
                    "ag1.id.secret with spaces"
                )
                .unwrap_err(),
                RemoteError::InvalidToken
            );
            let (endpoint, _, thread) = server(vec![response(429, Vec::new(), Vec::new())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            assert_eq!(
                client
                    .delete_blob("repo-remote", &Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap_err(),
                RemoteError::RateLimited
            );
            assert!(!format!("{client:?}").contains(TEST_TOKEN));
            thread.join().unwrap();
        });
    }
}
