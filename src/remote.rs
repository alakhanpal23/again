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
use zeroize::Zeroizing;

use crate::team::{
    BlobRef, Digest, RemoteCacheManifest, VerificationContext, VerificationError, verify_candidate,
};
use crate::team_config::{ReadToken, TeamLookupBudgetV1, TeamPublishBudgetV1, WriteToken};
use crate::team_crypto::Ed25519Verifier;
use crate::team_lookup_bundle::{TeamLookupBundleStreamValidator, TeamLookupBundleWireError};
use crate::team_manifest_v2::{EncryptedRemoteCacheManifestV2, EncryptedStreamRefV2};
use crate::trust_bundle::{
    TrustBoundRequest, TrustBundleError, TrustBundleV1, VerifiedTrustBundle,
};

pub const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Leaves explicit head-row overhead below Cloudflare D1's 2,000,000-byte
/// string/BLOB/row ceiling. Durable local checkpoints have a separate limit.
pub const MAX_TRUST_BUNDLE_BYTES: usize = 1_500_000;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const REPOSITORY_GENERATION_HEADER: &str = "x-again-repository-generation";
const SERVICE_ERROR_CODE_HEADER: &str = "x-again-error-code";
const MAX_SERVICE_ERROR_CODE_BYTES: usize = 64;

pub struct RemoteClient {
    base_url: Url,
    bearer_token: Zeroizing<String>,
    http: Client,
    credential_role: CredentialRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialRole {
    Legacy,
    TeamRead,
    TeamWrite,
}

/// One pull-only lookup with a single wall-clock deadline and cumulative
/// request/response budgets. It has no mutation methods and cannot outlive the
/// authenticated client that created it.
pub(crate) struct RemotePullSession<'a> {
    client: &'a RemoteClient,
    repository_id: String,
    generation_id: String,
    max_requests: u8,
    requests_used: u8,
    max_response_bytes: u64,
    response_bytes: u64,
    deadline: Instant,
}

/// One producer transaction using a read-only credential for fresh trust and
/// an independently provisioned write credential for encrypted uploads. All
/// four requests share one request-count, transfer-byte, and wall-clock
/// budget. This type has no delete operation.
pub(crate) struct RemotePublishSession<'a> {
    read_client: &'a RemoteClient,
    write_client: &'a RemoteClient,
    repository_id: String,
    generation_id: String,
    max_requests: u8,
    requests_used: u8,
    max_transfer_bytes: u64,
    transfer_bytes: u64,
    deadline: Instant,
}

impl fmt::Debug for RemotePublishSession<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemotePublishSession")
            .field("repository_id", &self.repository_id)
            .field("max_requests", &self.max_requests)
            .field("requests_used", &self.requests_used)
            .field("max_transfer_bytes", &self.max_transfer_bytes)
            .field("transfer_bytes", &self.transfer_bytes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RemotePullSession<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemotePullSession")
            .field("repository_id", &self.repository_id)
            .field("max_requests", &self.max_requests)
            .field("requests_used", &self.requests_used)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("response_bytes", &self.response_bytes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RemoteClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteClient")
            .field("base_url", &self.base_url.as_str())
            .field("bearer_token", &"<redacted>")
            .field("credential_role", &self.credential_role)
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
    #[error("repository generation is malformed or does not match the bound session")]
    RepositoryGenerationMismatch,
    #[error("verified trust bundle is bound to a different cache origin")]
    TrustOriginMismatch,
    #[error("verified trust bundle rejected the requested bindings: {0}")]
    TrustBundle(TrustBundleError),
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
    #[error("response included a malformed or duplicate Content-Length")]
    InvalidContentLength,
    #[error("response media type is missing, duplicated, or unexpected")]
    InvalidResponseContentType,
    #[error("response digest does not match the requested digest")]
    DigestMismatch,
    #[error("response size does not match the requested size")]
    SizeMismatch,
    #[error("response digest header is missing or inconsistent")]
    DigestHeaderMismatch,
    #[error("manifest JSON is invalid")]
    InvalidManifest,
    #[error("trust-bundle JSON is invalid")]
    InvalidTrustBundle,
    #[error("encrypted manifest-v2 JSON is invalid")]
    InvalidManifestV2,
    #[error("lookup-bundle framing is invalid: {0}")]
    InvalidLookupBundle(TeamLookupBundleWireError),
    #[error("remote lookup exceeded its request-count budget")]
    RequestBudgetExceeded,
    #[error("remote lookup exceeded its cumulative response-byte budget")]
    ResponseBudgetExceeded,
    #[error("remote publication exceeded its cumulative transfer-byte budget")]
    TransferBudgetExceeded,
    #[error("read and write clients are bound to different endpoint origins")]
    PublishOriginMismatch,
    #[error("publication requires distinct read-role and write-role credentials")]
    PublishCredentialRoleMismatch,
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
    #[error("no encrypted manifest exists for the exact lookup request")]
    ManifestNotFound,
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
    #[error("remote service rejected the request ({code}, status {status})")]
    ServiceRejected {
        code: String,
        status: u16,
        class: ServiceErrorClass,
    },
    #[error("remote service returned a malformed or unknown error-code header")]
    InvalidServiceErrorCode,
    #[error("remote service returned an unexpected status: {0}")]
    UnexpectedStatus(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceErrorClass {
    Transient,
    ConfigurationOrAuth,
    Corruption,
}

impl RemoteClient {
    /// Construct the production client. Plain HTTP is never accepted here.
    pub fn new(endpoint: &str, bearer_token: impl Into<String>) -> Result<Self, RemoteError> {
        Self::build(
            endpoint,
            Zeroizing::new(bearer_token.into()),
            false,
            CredentialRole::Legacy,
        )
    }

    pub(crate) fn new_team_read(endpoint: &str, token: &ReadToken) -> Result<Self, RemoteError> {
        Self::build(
            endpoint,
            Zeroizing::new(token.expose().to_owned()),
            false,
            CredentialRole::TeamRead,
        )
    }

    pub(crate) fn new_team_write(endpoint: &str, token: &WriteToken) -> Result<Self, RemoteError> {
        Self::build(
            endpoint,
            Zeroizing::new(token.expose().to_owned()),
            false,
            CredentialRole::TeamWrite,
        )
    }

    /// Explicit numeric-loopback-only HTTP mode for deterministic unit tests.
    /// System and environment proxies are disabled in this mode.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn new_for_loopback_test(
        endpoint: &str,
        bearer_token: impl Into<String>,
    ) -> Result<Self, RemoteError> {
        Self::build(
            endpoint,
            Zeroizing::new(bearer_token.into()),
            true,
            CredentialRole::Legacy,
        )
    }

    fn build(
        endpoint: &str,
        bearer_token: Zeroizing<String>,
        allow_loopback_http: bool,
        credential_role: CredentialRole,
    ) -> Result<Self, RemoteError> {
        let base_url = Url::parse(endpoint).map_err(|_| RemoteError::InvalidEndpoint)?;
        if base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.path() != "/"
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
            credential_role,
        })
    }

    pub(crate) fn endpoint_origin(&self) -> String {
        self.base_url.origin().ascii_serialization()
    }

    pub(crate) fn begin_pull(
        &self,
        repository_id: &str,
        generation_id: &str,
        budget: TeamLookupBudgetV1,
    ) -> Result<RemotePullSession<'_>, RemoteError> {
        if !is_route_identifier(repository_id) {
            return Err(RemoteError::InvalidRepository);
        }
        if !is_generation_id(generation_id) {
            return Err(RemoteError::RepositoryGenerationMismatch);
        }
        Ok(RemotePullSession {
            client: self,
            repository_id: repository_id.to_owned(),
            generation_id: generation_id.to_owned(),
            max_requests: budget.max_requests(),
            requests_used: 0,
            max_response_bytes: budget.max_response_bytes(),
            response_bytes: 0,
            deadline: Instant::now() + Duration::from_millis(budget.total_timeout_ms()),
        })
    }

    pub(crate) fn begin_publish<'a>(
        &'a self,
        write_client: &'a RemoteClient,
        repository_id: &str,
        generation_id: &str,
        budget: TeamPublishBudgetV1,
    ) -> Result<RemotePublishSession<'a>, RemoteError> {
        if !is_route_identifier(repository_id) {
            return Err(RemoteError::InvalidRepository);
        }
        if !is_generation_id(generation_id) {
            return Err(RemoteError::RepositoryGenerationMismatch);
        }
        if self.endpoint_origin() != write_client.endpoint_origin() {
            return Err(RemoteError::PublishOriginMismatch);
        }
        if self.credential_role != CredentialRole::TeamRead
            || write_client.credential_role != CredentialRole::TeamWrite
            || self.bearer_token.as_bytes() == write_client.bearer_token.as_bytes()
        {
            return Err(RemoteError::PublishCredentialRoleMismatch);
        }
        Ok(RemotePublishSession {
            read_client: self,
            write_client,
            repository_id: repository_id.to_owned(),
            generation_id: generation_id.to_owned(),
            max_requests: budget.max_requests(),
            requests_used: 0,
            max_transfer_bytes: budget.max_transfer_bytes(),
            transfer_bytes: 0,
            deadline: Instant::now() + Duration::from_millis(budget.total_timeout_ms()),
        })
    }

    /// Low-level mutation primitive. This remains crate-private until the
    /// publication path requires a validated privacy/provenance capability.
    #[allow(dead_code)]
    pub(crate) async fn put_blob(
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

    #[allow(dead_code)]
    pub(crate) async fn delete_blob(
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

    /// Low-level mutation primitive. Callers outside this crate must not be
    /// able to upload bytes before privacy and provenance admission exists.
    #[allow(dead_code)]
    pub(crate) async fn put_manifest(
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

    /// Fetch and authenticate one manifest using a single sealed trust
    /// capability. Producer keys, revocations, and the verifier are derived
    /// from that same capability, and its origin is checked before network I/O.
    pub async fn get_trusted_manifest(
        &self,
        trust: &VerifiedTrustBundle,
        request: TrustBoundRequest,
        now_unix_seconds: u64,
    ) -> Result<RemoteCacheManifest, RemoteError> {
        if self.base_url.origin().ascii_serialization() != trust.endpoint_origin() {
            return Err(RemoteError::TrustOriginMismatch);
        }
        let context = trust
            .verification_context(request, now_unix_seconds)
            .map_err(RemoteError::TrustBundle)?;
        let repository_id = context.repository_id.clone();
        self.get_manifest(
            &repository_id,
            &request.request_key,
            &context,
            trust.producer_verifier(),
        )
        .await
    }

    /// Low-level candidate fetch. This remains crate-private because a raw
    /// `VerificationContext` and verifier are only safe when derived together
    /// from one authenticated, fresh trust capability. The future product
    /// path exposes that combined operation instead of these separable inputs.
    #[allow(dead_code)]
    pub(crate) async fn get_manifest(
        &self,
        repository_id: &str,
        request_key: &Digest,
        context: &VerificationContext,
        verifier: &Ed25519Verifier,
    ) -> Result<RemoteCacheManifest, RemoteError> {
        if context.repository_id != repository_id || context.request_key != *request_key {
            return Err(RemoteError::RequestBindingMismatch);
        }
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

    #[allow(dead_code)]
    pub(crate) async fn delete_manifest(
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
        self.send_with_generation(method, url, operation, body, content_type, deadline, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_generation_bound(
        &self,
        method: Method,
        url: Url,
        operation: &'static str,
        body: &[u8],
        content_type: Option<&'static str>,
        deadline: Instant,
        generation_id: &str,
    ) -> Result<Response, RemoteError> {
        if !is_generation_id(generation_id) {
            return Err(RemoteError::RepositoryGenerationMismatch);
        }
        self.send_with_generation(
            method,
            url,
            operation,
            body,
            content_type,
            deadline,
            Some(generation_id),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_with_generation(
        &self,
        method: Method,
        url: Url,
        operation: &'static str,
        body: &[u8],
        content_type: Option<&'static str>,
        deadline: Instant,
        generation_id: Option<&str>,
    ) -> Result<Response, RemoteError> {
        let mut authorization_bytes = Zeroizing::new(Vec::with_capacity(
            "Bearer ".len() + self.bearer_token.len(),
        ));
        authorization_bytes.extend_from_slice(b"Bearer ");
        authorization_bytes.extend_from_slice(self.bearer_token.as_bytes());
        let mut authorization =
            HeaderValue::from_bytes(&authorization_bytes).map_err(|_| RemoteError::InvalidToken)?;
        authorization.set_sensitive(true);
        let mut request = self
            .http
            .request(method, url)
            .header(AUTHORIZATION, authorization);
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        if let Some(generation_id) = generation_id {
            request = request.header(REPOSITORY_GENERATION_HEADER, generation_id);
        }
        match timeout_at(deadline, request.body(body.to_vec()).send()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) if error.is_timeout() => Err(RemoteError::Timeout { operation }),
            Ok(Err(_)) => Err(RemoteError::Transport { operation }),
            Err(_) => Err(RemoteError::Timeout { operation }),
        }
    }
}

impl RemotePullSession<'_> {
    pub(crate) fn endpoint_origin(&self) -> String {
        self.client.endpoint_origin()
    }

    pub(crate) fn repository_id(&self) -> &str {
        &self.repository_id
    }

    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Fetch one untrusted lookup-bundle v1 body in a single bounded request.
    ///
    /// This transport method validates only HTTP framing, the exact endpoint
    /// generation and cumulative budgets. The caller must parse the fixed
    /// envelope and perform every trust/manifest/digest/AEAD/privacy check
    /// before treating any contained bytes as a cache hit.
    pub(crate) async fn fetch_lookup_bundle_v1_body(
        &mut self,
        request_key: &Digest,
    ) -> Result<Vec<u8>, RemoteError> {
        let url = self.client.resource_url(
            &self.repository_id,
            "lookup-bundles",
            &request_key.to_hex(),
        )?;
        self.consume_request()?;
        let response = self
            .client
            .send_generation_bound(
                Method::GET,
                url,
                "get lookup bundle",
                &[],
                None,
                self.deadline,
                &self.generation_id,
            )
            .await?;
        let response = expect_status(response, &[StatusCode::OK], "get lookup bundle")?;
        validate_generation_header(&response, &self.generation_id)?;
        validate_exact_content_type(
            &response,
            crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE,
        )?;
        let declared_length = optional_content_length(&response)?;
        let remaining = self
            .max_response_bytes
            .checked_sub(self.response_bytes)
            .ok_or(RemoteError::ResponseBudgetExceeded)?;
        if declared_length.is_some_and(|length| length > remaining) {
            return Err(RemoteError::ResponseBudgetExceeded);
        }
        let resource_limit = effective_bounded_read_limit(
            usize::try_from(crate::team_config::MAX_LOOKUP_RESPONSE_BYTES)
                .map_err(|_| RemoteError::ResponseBudgetExceeded)?,
            remaining,
        );
        let bytes = match read_lookup_bundle_bounded(
            response,
            resource_limit,
            remaining,
            "get lookup bundle",
            self.deadline,
        )
        .await
        {
            Err(RemoteError::ResponseTooLarge { .. })
                if remaining < crate::team_config::MAX_LOOKUP_RESPONSE_BYTES =>
            {
                return Err(RemoteError::ResponseBudgetExceeded);
            }
            result => result?,
        };
        self.response_bytes = self
            .response_bytes
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= self.max_response_bytes)
            .ok_or(RemoteError::ResponseBudgetExceeded)?;
        if declared_length.is_some_and(|length| length != bytes.len() as u64) {
            return Err(RemoteError::SizeMismatch);
        }
        Ok(bytes)
    }

    /// Fetch only the repository's latest signed trust bundle. This is still
    /// untrusted wire data; callers must verify it against their pinned root
    /// and durable epoch tracker before using any manifest.
    pub(crate) async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
        let mut url = self.client.base_url.clone();
        url.set_path(&format!(
            "/v1/repositories/{}/trust-bundles/latest",
            self.repository_id
        ));
        let bytes = self
            .get_bounded(url, "get trust bundle", MAX_TRUST_BUNDLE_BYTES)
            .await?;
        decode_team_trust_response(&bytes)
    }

    /// Fetch one strict encrypted manifest-v2 by the sealed request digest.
    pub(crate) async fn fetch_manifest_v2(
        &mut self,
        request_key: &Digest,
    ) -> Result<EncryptedRemoteCacheManifestV2, RemoteError> {
        let url =
            self.client
                .resource_url(&self.repository_id, "manifests", &request_key.to_hex())?;
        let bytes = self
            .get_bounded(url, "get encrypted manifest", MAX_MANIFEST_BYTES)
            .await?;
        decode_team_manifest_v2_response(&bytes)
    }

    /// Fetch one exact ciphertext object named by the manifest. Size, digest,
    /// and digest response header are all checked before bytes can escape.
    pub(crate) async fn fetch_ciphertext(
        &mut self,
        blob: &EncryptedStreamRefV2,
    ) -> Result<Vec<u8>, RemoteError> {
        if blob.ciphertext_size_bytes > MAX_BLOB_BYTES as u64 {
            return Err(RemoteError::BlobTooLarge);
        }
        if blob.ciphertext_size_bytes > self.max_response_bytes.saturating_sub(self.response_bytes)
        {
            return Err(RemoteError::ResponseBudgetExceeded);
        }
        let url = self.client.resource_url(
            &self.repository_id,
            "blobs",
            &blob.ciphertext_digest.to_hex(),
        )?;
        self.consume_request()?;
        let response = self
            .client
            .send_generation_bound(
                Method::GET,
                url,
                "get encrypted blob",
                &[],
                None,
                self.deadline,
                &self.generation_id,
            )
            .await?;
        let response = expect_status(response, &[StatusCode::OK], "get encrypted blob")?;
        validate_generation_header(&response, &self.generation_id)?;
        validate_digest_header(&response, &blob.ciphertext_digest)?;
        if response
            .content_length()
            .is_some_and(|length| length != blob.ciphertext_size_bytes)
        {
            return Err(RemoteError::SizeMismatch);
        }
        let bytes = self
            .read_and_account(response, "get encrypted blob", MAX_BLOB_BYTES)
            .await?;
        validate_team_ciphertext_response(blob, &bytes)?;
        Ok(bytes)
    }

    fn consume_request(&mut self) -> Result<(), RemoteError> {
        if self.requests_used >= self.max_requests {
            return Err(RemoteError::RequestBudgetExceeded);
        }
        self.requests_used += 1;
        if Instant::now() >= self.deadline {
            return Err(RemoteError::Timeout {
                operation: "remote pull",
            });
        }
        Ok(())
    }

    async fn get_bounded(
        &mut self,
        url: Url,
        operation: &'static str,
        resource_limit: usize,
    ) -> Result<Vec<u8>, RemoteError> {
        self.consume_request()?;
        let response = self
            .client
            .send_generation_bound(
                Method::GET,
                url,
                operation,
                &[],
                None,
                self.deadline,
                &self.generation_id,
            )
            .await?;
        let response = expect_status(response, &[StatusCode::OK], operation)?;
        validate_generation_header(&response, &self.generation_id)?;
        self.read_and_account(response, operation, resource_limit)
            .await
    }

    async fn read_and_account(
        &mut self,
        response: Response,
        operation: &'static str,
        resource_limit: usize,
    ) -> Result<Vec<u8>, RemoteError> {
        let remaining = self
            .max_response_bytes
            .checked_sub(self.response_bytes)
            .ok_or(RemoteError::ResponseBudgetExceeded)?;
        if response
            .content_length()
            .is_some_and(|length| length > remaining)
        {
            return Err(RemoteError::ResponseBudgetExceeded);
        }
        let effective_limit = effective_bounded_read_limit(resource_limit, remaining);
        let bytes = match read_bounded(response, effective_limit, operation, self.deadline).await {
            Err(RemoteError::ResponseTooLarge { .. }) if remaining < resource_limit as u64 => {
                return Err(RemoteError::ResponseBudgetExceeded);
            }
            result => result?,
        };
        self.response_bytes = self
            .response_bytes
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= self.max_response_bytes)
            .ok_or(RemoteError::ResponseBudgetExceeded)?;
        Ok(bytes)
    }
}

/// Decode the exact bounded body returned by the team trust route.
///
/// HTTP status, generation, length, request-count, byte, and deadline checks
/// remain in `RemotePullSession`; this pure decoder preserves the final body
/// error used by the production legacy path.
pub(crate) fn decode_team_trust_response(bytes: &[u8]) -> Result<TrustBundleV1, RemoteError> {
    serde_json::from_slice(bytes).map_err(|_| RemoteError::InvalidTrustBundle)
}

/// Decode the exact bounded body returned by the encrypted manifest-v2 route.
pub(crate) fn decode_team_manifest_v2_response(
    bytes: &[u8],
) -> Result<EncryptedRemoteCacheManifestV2, RemoteError> {
    serde_json::from_slice(bytes).map_err(|_| RemoteError::InvalidManifestV2)
}

/// Apply the production legacy blob route's post-body checks in their exact
/// order. Header and response-budget checks intentionally remain at the HTTP
/// boundary and run before this pure validation.
pub(crate) fn validate_team_ciphertext_response(
    blob: &EncryptedStreamRefV2,
    bytes: &[u8],
) -> Result<(), RemoteError> {
    if bytes.len() as u64 != blob.ciphertext_size_bytes {
        return Err(RemoteError::SizeMismatch);
    }
    if digest_bytes(bytes) != blob.ciphertext_digest {
        return Err(RemoteError::DigestMismatch);
    }
    Ok(())
}

impl RemotePublishSession<'_> {
    pub(crate) fn endpoint_origin(&self) -> String {
        self.read_client.endpoint_origin()
    }

    pub(crate) fn repository_id(&self) -> &str {
        &self.repository_id
    }

    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Fetch untrusted current trust using only the read credential. The body
    /// counts against the same transfer budget later used for uploads.
    pub(crate) async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
        let mut url = self.read_client.base_url.clone();
        url.set_path(&format!(
            "/v1/repositories/{}/trust-bundles/latest",
            self.repository_id
        ));
        self.consume_request("get trust bundle")?;
        let response = self
            .read_client
            .send_generation_bound(
                Method::GET,
                url,
                "get trust bundle",
                &[],
                None,
                self.deadline,
                &self.generation_id,
            )
            .await?;
        let response = expect_status(response, &[StatusCode::OK], "get trust bundle")?;
        validate_generation_header(&response, &self.generation_id)?;
        let bytes = self
            .read_and_account(response, "get trust bundle", MAX_TRUST_BUNDLE_BYTES)
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| RemoteError::InvalidTrustBundle)
    }

    /// Upload one exact ciphertext object. Digest/size validation happens
    /// before request accounting or network mutation.
    pub(crate) async fn put_ciphertext(
        &mut self,
        reference: &EncryptedStreamRefV2,
        ciphertext: &[u8],
    ) -> Result<(), RemoteError> {
        if reference.ciphertext_size_bytes > MAX_BLOB_BYTES as u64
            || ciphertext.len() > MAX_BLOB_BYTES
        {
            return Err(RemoteError::BlobTooLarge);
        }
        if reference.ciphertext_size_bytes != ciphertext.len() as u64
            || digest_bytes(ciphertext) != reference.ciphertext_digest
        {
            return Err(RemoteError::UploadDigestMismatch);
        }
        self.consume_upload("put encrypted blob", ciphertext.len() as u64)?;
        let url = self.write_client.resource_url(
            &self.repository_id,
            "blobs",
            &reference.ciphertext_digest.to_hex(),
        )?;
        let response = self
            .write_client
            .send_generation_bound(
                Method::PUT,
                url,
                "put encrypted blob",
                ciphertext,
                Some("application/octet-stream"),
                self.deadline,
                &self.generation_id,
            )
            .await?;
        let response = expect_status(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            "put encrypted blob",
        )?;
        validate_generation_header(&response, &self.generation_id)?;
        Ok(())
    }

    /// Publish the signed encrypted manifest last. Idempotent 204 and newly
    /// created 201 are both successful terminal states; conflicts remain
    /// fail-closed and are never "fixed" by deleting prior objects.
    pub(crate) async fn put_manifest_v2(
        &mut self,
        manifest: &EncryptedRemoteCacheManifestV2,
    ) -> Result<(), RemoteError> {
        if manifest.repository_id != self.repository_id
            || manifest.generation_id != self.generation_id
        {
            return Err(RemoteError::RequestBindingMismatch);
        }
        let body = serde_json::to_vec(manifest).map_err(|_| RemoteError::InvalidManifestV2)?;
        if body.len() > MAX_MANIFEST_BYTES {
            return Err(RemoteError::ManifestTooLarge);
        }
        self.consume_upload("put encrypted manifest", body.len() as u64)?;
        let url = self.write_client.resource_url(
            &self.repository_id,
            "manifests",
            &manifest.request_key.to_hex(),
        )?;
        let response = self
            .write_client
            .send_generation_bound(
                Method::PUT,
                url,
                "put encrypted manifest",
                &body,
                Some("application/json"),
                self.deadline,
                &self.generation_id,
            )
            .await?;
        let response = expect_status(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            "put encrypted manifest",
        )?;
        validate_generation_header(&response, &self.generation_id)?;
        Ok(())
    }

    fn consume_request(&mut self, operation: &'static str) -> Result<(), RemoteError> {
        if self.requests_used >= self.max_requests {
            return Err(RemoteError::RequestBudgetExceeded);
        }
        if Instant::now() >= self.deadline {
            return Err(RemoteError::Timeout { operation });
        }
        self.requests_used += 1;
        Ok(())
    }

    fn consume_upload(
        &mut self,
        operation: &'static str,
        body_bytes: u64,
    ) -> Result<(), RemoteError> {
        if body_bytes > self.max_transfer_bytes.saturating_sub(self.transfer_bytes) {
            return Err(RemoteError::TransferBudgetExceeded);
        }
        self.consume_request(operation)?;
        self.transfer_bytes = self
            .transfer_bytes
            .checked_add(body_bytes)
            .filter(|total| *total <= self.max_transfer_bytes)
            .ok_or(RemoteError::TransferBudgetExceeded)?;
        Ok(())
    }

    async fn read_and_account(
        &mut self,
        response: Response,
        operation: &'static str,
        resource_limit: usize,
    ) -> Result<Vec<u8>, RemoteError> {
        let remaining = self
            .max_transfer_bytes
            .checked_sub(self.transfer_bytes)
            .ok_or(RemoteError::TransferBudgetExceeded)?;
        if response
            .content_length()
            .is_some_and(|length| length > remaining)
        {
            return Err(RemoteError::TransferBudgetExceeded);
        }
        let effective_limit = effective_bounded_read_limit(resource_limit, remaining);
        let bytes = match read_bounded(response, effective_limit, operation, self.deadline).await {
            Err(RemoteError::ResponseTooLarge { .. }) if remaining < resource_limit as u64 => {
                return Err(RemoteError::TransferBudgetExceeded);
            }
            result => result?,
        };
        self.transfer_bytes = self
            .transfer_bytes
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= self.max_transfer_bytes)
            .ok_or(RemoteError::TransferBudgetExceeded)?;
        Ok(bytes)
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

fn is_generation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex(blake3::hash(bytes).to_hex().as_ref())
        .expect("BLAKE3 always emits 64 hex bytes")
}

fn parse_service_error_code(
    response: &Response,
) -> Result<Option<(String, ServiceErrorClass)>, RemoteError> {
    let mut values = response.headers().get_all(SERVICE_ERROR_CODE_HEADER).iter();
    let Some(value) = values.next() else {
        // Edge/CDN-generated timeout and 5xx responses do not necessarily
        // carry the application's typed error header. Preserve their generic
        // HTTP status so the caller can classify availability failures as
        // transient. Typed cache-miss semantics still require the exact
        // service code; a bare 404 remains ordinary hard NotFound.
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RemoteError::InvalidServiceErrorCode);
    }
    let value = value
        .to_str()
        .map_err(|_| RemoteError::InvalidServiceErrorCode)?;
    if value.is_empty() || value.len() > MAX_SERVICE_ERROR_CODE_BYTES {
        return Err(RemoteError::InvalidServiceErrorCode);
    }
    let class = classify_service_error_code(value).ok_or(RemoteError::InvalidServiceErrorCode)?;
    Ok(Some((value.to_owned(), class)))
}

fn classify_service_error_code(value: &str) -> Option<ServiceErrorClass> {
    let class = match value {
        "blob_pending"
        | "blob_state_changed"
        | "blob_storage_unavailable"
        | "blob_unavailable"
        | "delete_state_unavailable"
        | "internal_error"
        | "rate_limited"
        | "request_timeout"
        | "repository_state_changed"
        | "trust_changed" => ServiceErrorClass::Transient,

        "admin_required"
        | "body_too_large"
        | "content_length_mismatch"
        | "invalid_blob_size"
        | "invalid_byte_array"
        | "invalid_content_length"
        | "invalid_cursor"
        | "invalid_digest"
        | "invalid_epoch"
        | "invalid_field"
        | "invalid_fields"
        | "invalid_hex"
        | "invalid_identifier"
        | "invalid_json"
        | "invalid_json_shape"
        | "invalid_lifetime"
        | "invalid_limit"
        | "invalid_origin"
        | "invalid_producer_public_key"
        | "invalid_public_key"
        | "invalid_repository_generation"
        | "length_required"
        | "local_only"
        | "metadata_quota_exceeded"
        | "method_not_allowed"
        | "permission_denied"
        | "quota_exceeded"
        | "repository_generation_required"
        | "too_many_entries"
        | "truncated_body"
        | "unauthorized"
        | "unsupported_media_type" => ServiceErrorClass::ConfigurationOrAuth,

        "active_key_revoked"
        | "blob_conflict"
        | "blob_deleting"
        | "blob_integrity_failure"
        | "blob_quarantined"
        | "blob_referenced"
        | "delete_incomplete"
        | "digest_mismatch"
        | "endpoint_mismatch"
        | "expired_manifest"
        | "expired_trust_bundle"
        | "execution_profile_not_allowed"
        | "fresh_trust_required"
        | "future_manifest"
        | "future_trust_bundle"
        | "invalid_signature"
        | "image_not_allowed"
        | "key_binding_conflict"
        | "manifest_conflict"
        | "manifest_not_found"
        | "manifest_state_corrupt"
        | "nonce_reuse"
        | "nonempty_stderr"
        | "not_found"
        | "producer_registry_mismatch"
        | "producer_revoked"
        | "platform_not_allowed"
        | "policy_not_allowed"
        | "record_revoked"
        | "repository_deleting"
        | "repository_generation_mismatch"
        | "repository_mismatch"
        | "request_key_mismatch"
        | "secret_tainted"
        | "tenant_mismatch"
        | "trust_bundle_too_large"
        | "trust_epoch_conflict"
        | "trust_epoch_rollback"
        | "trust_key_rebinding"
        | "trust_record_revocation_rollback"
        | "trust_revocation_rollback"
        | "trust_root_rebinding"
        | "trust_state_corrupt"
        | "unencrypted_confidential"
        | "unsorted_or_duplicate"
        | "unsupported_proof"
        | "unsupported_result_status"
        | "unsupported_schema"
        | "unsupported_signature"
        | "untrusted_producer"
        | "untrusted_root" => ServiceErrorClass::Corruption,
        _ => return None,
    };
    Some(class)
}

fn service_error_status_matches(code: &str, status: StatusCode) -> bool {
    match code {
        "unauthorized" => status == StatusCode::UNAUTHORIZED,
        "admin_required" | "permission_denied" => status == StatusCode::FORBIDDEN,
        "not_found" => status == StatusCode::NOT_FOUND,
        "manifest_not_found" => status == StatusCode::NOT_FOUND,
        "rate_limited" => status == StatusCode::TOO_MANY_REQUESTS,
        "request_timeout" => status == StatusCode::REQUEST_TIMEOUT,
        "body_too_large" => status == StatusCode::PAYLOAD_TOO_LARGE,
        "unsupported_media_type" => status == StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "length_required" => status == StatusCode::LENGTH_REQUIRED,
        "method_not_allowed" => status == StatusCode::METHOD_NOT_ALLOWED,
        "internal_error" => status == StatusCode::INTERNAL_SERVER_ERROR,
        _ => status.is_client_error() || status.is_server_error(),
    }
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
    if let Some((code, class)) = parse_service_error_code(&response)? {
        if !service_error_status_matches(&code, status) {
            return Err(RemoteError::InvalidServiceErrorCode);
        }
        match code.as_str() {
            "unauthorized" => return Err(RemoteError::Unauthorized),
            "admin_required" | "permission_denied" => return Err(RemoteError::Forbidden),
            "not_found" => return Err(RemoteError::NotFound),
            "manifest_not_found" => return Err(RemoteError::ManifestNotFound),
            "rate_limited" => return Err(RemoteError::RateLimited),
            "body_too_large" => return Err(RemoteError::PayloadTooLarge),
            "unsupported_media_type" => return Err(RemoteError::UnsupportedMediaType),
            _ => {}
        }
        return Err(RemoteError::ServiceRejected {
            code,
            status: status.as_u16(),
            class,
        });
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

fn validate_generation_header(response: &Response, expected: &str) -> Result<(), RemoteError> {
    let mut values = response
        .headers()
        .get_all(REPOSITORY_GENERATION_HEADER)
        .iter();
    let Some(value) = values.next() else {
        return Err(RemoteError::RepositoryGenerationMismatch);
    };
    if values.next().is_some() {
        return Err(RemoteError::RepositoryGenerationMismatch);
    }
    let Ok(value) = value.to_str() else {
        return Err(RemoteError::RepositoryGenerationMismatch);
    };
    if value != expected {
        return Err(RemoteError::RepositoryGenerationMismatch);
    }
    Ok(())
}

fn validate_exact_content_type(response: &Response, expected: &str) -> Result<(), RemoteError> {
    let mut values = response.headers().get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(RemoteError::InvalidResponseContentType);
    };
    if values.next().is_some() || value.as_bytes() != expected.as_bytes() {
        return Err(RemoteError::InvalidResponseContentType);
    }
    Ok(())
}

fn optional_content_length(response: &Response) -> Result<Option<u64>, RemoteError> {
    let mut values = response.headers().get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RemoteError::InvalidContentLength);
    }
    let value = value
        .to_str()
        .map_err(|_| RemoteError::InvalidContentLength)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RemoteError::InvalidContentLength);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| RemoteError::InvalidContentLength)
}

fn effective_bounded_read_limit(resource_limit: usize, remaining_budget: u64) -> usize {
    match usize::try_from(remaining_budget) {
        Ok(remaining_budget) => resource_limit.min(remaining_budget),
        // A budget larger than the address space cannot further constrain an
        // already-addressable resource limit.
        Err(_) => resource_limit,
    }
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

async fn read_lookup_bundle_bounded(
    mut response: Response,
    limit: usize,
    remaining_budget: u64,
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
    let mut validator = TeamLookupBundleStreamValidator::new(remaining_budget.min(limit as u64));
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
                validator
                    .push(&bytes)
                    .map_err(RemoteError::InvalidLookupBundle)?;
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
    validator
        .finish()
        .map_err(RemoteError::InvalidLookupBundle)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::team::{
        BlobRef, PrivacyClass, PrivacyMetadata, SIGNATURE_ENVELOPE_SCHEMA_VERSION, Shareability,
        SignatureAlgorithm, SignatureEnvelope,
    };
    use crate::team_crypto::{Ed25519Signer, Ed25519Verifier};
    use crate::team_manifest_v2::{
        ENCRYPTED_MANIFEST_SCHEMA_VERSION, EncryptedRemoteCacheManifestV2, EncryptedStreamRefV2,
        LOCAL_RESULT_PROOF_SCHEMA_VERSION, ManifestSignatureV2, POLY1305_TAG_BYTES, ResultStatusV2,
    };
    use crate::trust_bundle::{
        ExpectedTrustBundle, PinnedRootKey, ProducerKeyBindingV1, TRUST_BUNDLE_SCHEMA_VERSION,
        TrustBundleV1, TrustEpochTracker, verify_trust_bundle,
    };

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TEST_TOKEN: &str = "ag1.test.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_WRITE_TOKEN: &str = "ag1.test.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn effective_read_limit_checks_u64_to_usize_boundaries() {
        assert_eq!(effective_bounded_read_limit(1_024, 0), 0);
        assert_eq!(effective_bounded_read_limit(1_024, 511), 511);
        assert_eq!(effective_bounded_read_limit(1_024, 1_024), 1_024);
        assert_eq!(effective_bounded_read_limit(1_024, 2_048), 1_024);
        assert_eq!(
            effective_bounded_read_limit(1_024, u64::from(u32::MAX) + 1),
            1_024
        );
        assert_eq!(
            effective_bounded_read_limit(usize::MAX, u64::MAX),
            usize::MAX
        );
    }

    fn team_clients(
        endpoint: &str,
        read_token: &str,
        write_token: &str,
    ) -> (RemoteClient, RemoteClient) {
        let read = RemoteClient::build(
            endpoint,
            Zeroizing::new(read_token.to_owned()),
            true,
            CredentialRole::TeamRead,
        )
        .unwrap();
        let write = RemoteClient::build(
            endpoint,
            Zeroizing::new(write_token.to_owned()),
            true,
            CredentialRole::TeamWrite,
        )
        .unwrap();
        (read, write)
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
        let mut headers = headers;
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(REPOSITORY_GENERATION_HEADER))
        {
            headers.push((REPOSITORY_GENERATION_HEADER, GENERATION.into()));
        }
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
            headers: vec![(REPOSITORY_GENERATION_HEADER, GENERATION.into())],
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
                if let Some(request) = read_request(&mut stream) {
                    saved.lock().unwrap().push(request);
                    write_response(&mut stream, &mock);
                }
            }
        });
        (address, requests, handle)
    }

    fn read_request(stream: &mut TcpStream) -> Option<MockRequest> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end;
        loop {
            let count = stream.read(&mut chunk).unwrap();
            if count == 0 {
                return None;
            }
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
            if count == 0 {
                return None;
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let first = headers_text.lines().next().unwrap();
        let mut first_parts = first.split_whitespace();
        Some(MockRequest {
            method: first_parts.next().unwrap().to_owned(),
            target: first_parts.next().unwrap().to_owned(),
            headers: headers_text,
            body: bytes[header_end..header_end + content_length].to_vec(),
        })
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

    fn verified_trust(
        endpoint_origin: &str,
        manifest: &RemoteCacheManifest,
        producer: &Ed25519Signer,
    ) -> VerifiedTrustBundle {
        let root = SigningKey::from_bytes(&[9; 32]);
        let mut bundle = TrustBundleV1 {
            schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
            root_key_id: "root-key-remote".into(),
            tenant_id: manifest.tenant_id.clone(),
            repository_id: manifest.repository_id.clone(),
            generation_id: GENERATION.into(),
            endpoint_origin: endpoint_origin.into(),
            epoch: 1,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            active_producer_keys: vec![ProducerKeyBindingV1 {
                key_id: producer.key_id().into(),
                producer_id: producer.producer_id().into(),
                public_key: producer.public_key_bytes(),
            }],
            revoked_key_ids: Vec::new(),
            revoked_record_ids: Vec::new(),
            allowed_policy_digests: vec![manifest.policy_digest],
            allowed_execution_profile_digests: vec![manifest.execution_profile_digest],
            allowed_platform_digests: vec![manifest.platform_digest],
            allowed_image_digests: vec![manifest.image_digest],
            signature: Vec::new(),
        };
        bundle.signature = root
            .sign(&bundle.canonical_signing_bytes())
            .to_bytes()
            .to_vec();
        let pinned =
            PinnedRootKey::from_public_key("root-key-remote", &root.verifying_key().to_bytes())
                .unwrap();
        verify_trust_bundle(
            bundle,
            ExpectedTrustBundle {
                tenant_id: &manifest.tenant_id,
                repository_id: &manifest.repository_id,
                generation_id: GENERATION,
                endpoint_origin,
            },
            &pinned,
            150,
            &mut TrustEpochTracker::new(),
        )
        .unwrap()
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
            assert_eq!(
                RemoteClient::new("https://example.test/cache", TEST_TOKEN).unwrap_err(),
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
    fn trusted_fetch_seals_origin_context_and_verifier_before_network_io() {
        test_runtime().block_on(async {
            let (manifest, _, _, producer) = fixture();
            let trust = verified_trust("https://cache.example.test", &manifest, &producer);
            let request = TrustBoundRequest {
                request_key: manifest.request_key,
                policy_digest: manifest.policy_digest,
                execution_profile_digest: manifest.execution_profile_digest,
                platform_digest: manifest.platform_digest,
                image_digest: manifest.image_digest,
            };

            let wrong_origin = RemoteClient::new("https://other.example.test", TEST_TOKEN).unwrap();
            assert_eq!(
                wrong_origin
                    .get_trusted_manifest(&trust, request, 150)
                    .await
                    .unwrap_err(),
                RemoteError::TrustOriginMismatch
            );

            let right_origin = RemoteClient::new("https://cache.example.test", TEST_TOKEN).unwrap();
            let mut disallowed = request;
            disallowed.image_digest = Digest::from_hex(ONE).unwrap();
            // The fixture image digest is ZERO, so the authenticated allowlist
            // rejects this before the client attempts network I/O.
            assert_eq!(
                right_origin
                    .get_trusted_manifest(&trust, disallowed, 150)
                    .await
                    .unwrap_err(),
                RemoteError::TrustBundle(TrustBundleError::ImageDigestNotAllowed)
            );
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
            let (endpoint, _, thread) = server(vec![response(
                429,
                Vec::new(),
                vec![(SERVICE_ERROR_CODE_HEADER, "rate_limited".into())],
            )]);
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

    #[test]
    fn typed_service_error_codes_are_strict_and_security_classified() {
        test_runtime().block_on(async {
            let responses = vec![
                response(
                    500,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "internal_error".into())],
                ),
                response(
                    422,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "invalid_json".into())],
                ),
                response(
                    409,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "trust_epoch_rollback".into())],
                ),
                response(
                    408,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "request_timeout".into())],
                ),
                response(
                    500,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "unknown_programmer_code".into())],
                ),
                response(
                    404,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "not_found".into())],
                ),
                response(
                    404,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "manifest_not_found".into())],
                ),
                response(503, Vec::new(), Vec::new()),
                response(404, Vec::new(), Vec::new()),
                response(
                    500,
                    Vec::new(),
                    vec![
                        (SERVICE_ERROR_CODE_HEADER, "internal_error".into()),
                        (SERVICE_ERROR_CODE_HEADER, "internal_error".into()),
                    ],
                ),
                response(
                    500,
                    Vec::new(),
                    vec![(SERVICE_ERROR_CODE_HEADER, "not_found".into())],
                ),
            ];
            let (endpoint, _, thread) = server(responses);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let digest = Digest::from_hex(ZERO).unwrap();
            for expected in [
                RemoteError::ServiceRejected {
                    code: "internal_error".into(),
                    status: 500,
                    class: ServiceErrorClass::Transient,
                },
                RemoteError::ServiceRejected {
                    code: "invalid_json".into(),
                    status: 422,
                    class: ServiceErrorClass::ConfigurationOrAuth,
                },
                RemoteError::ServiceRejected {
                    code: "trust_epoch_rollback".into(),
                    status: 409,
                    class: ServiceErrorClass::Corruption,
                },
                RemoteError::ServiceRejected {
                    code: "request_timeout".into(),
                    status: 408,
                    class: ServiceErrorClass::Transient,
                },
                RemoteError::InvalidServiceErrorCode,
                RemoteError::NotFound,
                RemoteError::ManifestNotFound,
                RemoteError::UnexpectedStatus(503),
                RemoteError::NotFound,
                RemoteError::InvalidServiceErrorCode,
                RemoteError::InvalidServiceErrorCode,
            ] {
                assert_eq!(
                    client
                        .delete_blob("repo-remote", &digest)
                        .await
                        .unwrap_err(),
                    expected
                );
            }
            thread.join().unwrap();
        });
    }

    #[test]
    fn client_classification_covers_the_exact_service_error_allowlist() {
        let source = include_str!("../service/src/util.ts");
        let mut inside = false;
        let mut codes = Vec::new();
        for line in source.lines() {
            if line.contains("const SERVICE_ERROR_CODES = new Set([") {
                inside = true;
                continue;
            }
            if inside && line.trim() == "]);" {
                break;
            }
            if inside {
                let trimmed = line.trim();
                if let Some(code) = trimmed
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix("\","))
                {
                    codes.push(code);
                }
            }
        }
        assert_eq!(codes.len(), 93, "service error-code set changed");
        assert!(
            codes
                .iter()
                .all(|code| classify_service_error_code(code).is_some()),
            "every emitted service error code must have an explicit client security class"
        );
        assert_eq!(classify_service_error_code("unknown_programmer_code"), None);
    }

    #[test]
    fn manifest_route_and_verification_context_must_match_before_network_io() {
        test_runtime().block_on(async {
            let client =
                RemoteClient::new_for_loopback_test("http://127.0.0.1:1", TEST_TOKEN).unwrap();
            let (manifest, context, verifier, _) = fixture();

            let mut wrong_repository = context.clone();
            wrong_repository.repository_id = "repo-other".into();
            assert_eq!(
                client
                    .get_manifest(
                        "repo-remote",
                        &manifest.request_key,
                        &wrong_repository,
                        &verifier,
                    )
                    .await
                    .unwrap_err(),
                RemoteError::RequestBindingMismatch
            );

            let mut wrong_request = context;
            wrong_request.request_key = Digest::from_hex(ONE).unwrap();
            assert_eq!(
                client
                    .get_manifest(
                        "repo-remote",
                        &manifest.request_key,
                        &wrong_request,
                        &verifier,
                    )
                    .await
                    .unwrap_err(),
                RemoteError::RequestBindingMismatch
            );
        });
    }

    fn trust_bundle_wire_body() -> Vec<u8> {
        serde_json::to_vec(&TrustBundleV1 {
            schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
            root_key_id: "root-key-remote".into(),
            tenant_id: "tenant-remote".into(),
            repository_id: "repo-remote".into(),
            generation_id: GENERATION.into(),
            endpoint_origin: "https://cache.example.test".into(),
            epoch: 1,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            active_producer_keys: Vec::new(),
            revoked_key_ids: Vec::new(),
            revoked_record_ids: Vec::new(),
            allowed_policy_digests: Vec::new(),
            allowed_execution_profile_digests: Vec::new(),
            allowed_platform_digests: Vec::new(),
            allowed_image_digests: Vec::new(),
            signature: Vec::new(),
        })
        .unwrap()
    }

    fn lookup_bundle_wire_body() -> Vec<u8> {
        let trust = b"{\"trust\":true}";
        let manifest = b"{\"manifest\":true}";
        let stdout = b"stdout-ciphertext";
        let stderr = b"stderr-ciphertext";
        let mut body = vec![0_u8; crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_HEADER_BYTES];
        body[..8].copy_from_slice(&crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_MAGIC);
        body[8..10].copy_from_slice(
            &crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_SCHEMA_VERSION.to_be_bytes(),
        );
        body[12..16].copy_from_slice(&(trust.len() as u32).to_be_bytes());
        body[16..20].copy_from_slice(&(manifest.len() as u32).to_be_bytes());
        body[20..24].copy_from_slice(&(stdout.len() as u32).to_be_bytes());
        body[24..28].copy_from_slice(&(stderr.len() as u32).to_be_bytes());
        body.extend_from_slice(trust);
        body.extend_from_slice(manifest);
        body.extend_from_slice(stdout);
        body.extend_from_slice(stderr);
        body
    }

    fn encrypted_manifest_wire(
        stdout: EncryptedStreamRefV2,
        stderr: EncryptedStreamRefV2,
    ) -> EncryptedRemoteCacheManifestV2 {
        EncryptedRemoteCacheManifestV2 {
            schema_version: ENCRYPTED_MANIFEST_SCHEMA_VERSION,
            record_id: "record-v2".into(),
            tenant_id: "tenant-remote".into(),
            repository_id: "repo-remote".into(),
            generation_id: GENERATION.into(),
            request_key: Digest::from_hex(ZERO).unwrap(),
            policy_digest: Digest::from_hex(ONE).unwrap(),
            classifier_digest: Digest::from_hex(ZERO).unwrap(),
            execution_profile_digest: Digest::from_hex(ONE).unwrap(),
            platform_digest: Digest::from_hex(ZERO).unwrap(),
            image_digest: Digest::from_hex(ONE).unwrap(),
            result_status: ResultStatusV2::Success,
            duration_micros: 1,
            proof_schema_version: LOCAL_RESULT_PROOF_SCHEMA_VERSION,
            producer_version: "producer-v1".into(),
            local_proof_digest: Digest::from_hex(ZERO).unwrap(),
            privacy: PrivacyMetadata {
                classification: PrivacyClass::Internal,
                shareability: Shareability::Repository,
                secret_tainted: false,
            },
            repository_encryption_key_id: "repository-key-1".into(),
            stdout,
            stderr,
            producer_id: "producer-remote".into(),
            created_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            signature: ManifestSignatureV2 {
                schema_version: SIGNATURE_ENVELOPE_SCHEMA_VERSION,
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "key-remote".into(),
                signature: vec![0; 64],
            },
        }
    }

    #[test]
    fn pull_session_fetches_only_exact_latest_trust_route_with_auth() {
        test_runtime().block_on(async {
            let (endpoint, requests, thread) =
                server(vec![response(200, trust_bundle_wire_body(), Vec::new())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(4, 1_000_000, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            let bundle = pull.fetch_latest_trust_bundle().await.unwrap();
            assert_eq!(bundle.repository_id, "repo-remote");
            thread.join().unwrap();

            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "GET");
            assert_eq!(
                requests[0].target,
                "/v1/repositories/repo-remote/trust-bundles/latest"
            );
            assert!(
                requests[0]
                    .headers
                    .to_ascii_lowercase()
                    .contains(&format!("authorization: bearer {TEST_TOKEN}").to_ascii_lowercase())
            );
        });
    }

    #[test]
    fn pull_session_fetches_one_strict_lookup_bundle_request() {
        test_runtime().block_on(async {
            let body = lookup_bundle_wire_body();
            let (endpoint, requests, thread) = server(vec![response(
                200,
                body.clone(),
                vec![(
                    "Content-Type",
                    crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
                )],
            )]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(1, body.len() as u64, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            let fetched = pull
                .fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                .await
                .unwrap();
            assert_eq!(fetched, body);
            let parsed = crate::team_lookup_bundle::parse_team_lookup_bundle_v1(
                &fetched,
                fetched.len() as u64,
            )
            .unwrap();
            assert_eq!(parsed.initial_trust_json(), b"{\"trust\":true}");
            assert_eq!(parsed.manifest_json(), b"{\"manifest\":true}");
            thread.join().unwrap();

            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "GET");
            assert_eq!(
                requests[0].target,
                format!("/v1/repositories/repo-remote/lookup-bundles/{ZERO}")
            );
            let headers = requests[0].headers.to_ascii_lowercase();
            assert!(
                headers
                    .contains(&format!("authorization: bearer {TEST_TOKEN}").to_ascii_lowercase())
            );
            assert!(headers.contains(&format!("{REPOSITORY_GENERATION_HEADER}: {GENERATION}")));
        });
    }

    #[test]
    fn lookup_bundle_transport_validates_framing_during_bounded_read() {
        test_runtime().block_on(async {
            let content_type = || {
                vec![(
                    "Content-Type",
                    crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
                )]
            };

            let mut impossible = lookup_bundle_wire_body();
            impossible[20..24].copy_from_slice(&(MAX_BLOB_BYTES as u32 + 1).to_be_bytes());
            let (endpoint, requests, thread) =
                server(vec![response(200, impossible, content_type())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(1, 40 * 1024 * 1024, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap_err(),
                RemoteError::InvalidLookupBundle(
                    crate::team_lookup_bundle::TeamLookupBundleWireError::StdoutCiphertextTooLarge,
                )
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 1);

            let mut trailing = lookup_bundle_wire_body();
            trailing.push(0);
            let (endpoint, requests, thread) =
                server(vec![response(200, trailing, content_type())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap_err(),
                RemoteError::InvalidLookupBundle(
                    crate::team_lookup_bundle::TeamLookupBundleWireError::TrailingBytes,
                )
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn cancelling_bundle_read_does_not_refund_or_retry_request_budget() {
        test_runtime().block_on(async {
            let mut delayed = response(
                200,
                lookup_bundle_wire_body(),
                vec![(
                    "Content-Type",
                    crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
                )],
            );
            delayed.body_delay = Duration::from_millis(300);
            let (endpoint, requests, thread) = server(vec![delayed]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(1, 1_000_000, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();

            assert!(
                tokio::time::timeout(
                    Duration::from_millis(50),
                    pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap()),
                )
                .await
                .is_err()
            );
            assert_eq!(
                pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap_err(),
                RemoteError::RequestBudgetExceeded
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn bundle_pull_uses_exactly_two_requests_under_one_budget_without_retry() {
        test_runtime().block_on(async {
            let bundle_body = lookup_bundle_wire_body();
            let trust_body = trust_bundle_wire_body();
            let bundle_headers = vec![(
                "Content-Type",
                crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
            )];
            let (endpoint, requests, thread) = server(vec![
                response(200, bundle_body.clone(), bundle_headers.clone()),
                response(200, trust_body.clone(), Vec::new()),
            ]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(
                2,
                (bundle_body.len() + trust_body.len()) as u64,
                5_000,
            );
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();

            assert_eq!(
                pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap(),
                bundle_body
            );
            assert_eq!(
                pull.fetch_latest_trust_bundle()
                    .await
                    .unwrap()
                    .repository_id,
                "repo-remote"
            );
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::RequestBudgetExceeded
            );
            thread.join().unwrap();

            {
                let requests = requests.lock().unwrap();
                assert_eq!(requests.len(), 2);
                assert_eq!(
                    requests[0].target,
                    format!("/v1/repositories/repo-remote/lookup-bundles/{ZERO}")
                );
                assert_eq!(
                    requests[1].target,
                    "/v1/repositories/repo-remote/trust-bundles/latest"
                );
                assert!(requests.iter().all(|request| request.method == "GET"));
            }

            // Both response bodies consume the same cumulative byte budget.
            // The second request is made, but its body can never escape once
            // the bytes remaining after the bundle are insufficient.
            let (endpoint, requests, thread) = server(vec![
                response(200, bundle_body.clone(), bundle_headers.clone()),
                response(200, trust_body.clone(), Vec::new()),
            ]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(
                2,
                (bundle_body.len() + trust_body.len() - 1) as u64,
                5_000,
            );
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                .await
                .unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::ResponseBudgetExceeded
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 2);

            // The wall-clock deadline is also shared. Spending most of it on
            // the bundled payload leaves only the remainder for final trust;
            // there is no fresh per-request timeout and no retry.
            let mut delayed_bundle = response(200, bundle_body, bundle_headers);
            delayed_bundle.body_delay = Duration::from_millis(400);
            let mut delayed_trust = response(200, trust_body, Vec::new());
            delayed_trust.body_delay = Duration::from_millis(400);
            let (endpoint, requests, thread) = server(vec![delayed_bundle, delayed_trust]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(2, 1_000_000, 600);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                .await
                .unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::Timeout {
                    operation: "get trust bundle"
                }
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 2);
        });
    }

    #[test]
    fn lookup_bundle_rejects_missing_wrong_or_duplicate_response_headers() {
        test_runtime().block_on(async {
            let body = lookup_bundle_wire_body();
            let cases = [
                (Vec::new(), RemoteError::InvalidResponseContentType),
                (
                    vec![("Content-Type", "application/json".into())],
                    RemoteError::InvalidResponseContentType,
                ),
                (
                    vec![
                        (
                            "Content-Type",
                            crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
                        ),
                        (
                            "Content-Type",
                            crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
                        ),
                    ],
                    RemoteError::InvalidResponseContentType,
                ),
                (
                    vec![
                        (
                            "Content-Type",
                            crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
                        ),
                        ("Content-Length", body.len().to_string()),
                    ],
                    RemoteError::InvalidContentLength,
                ),
            ];

            for (headers, expected) in cases {
                let (endpoint, _, thread) = server(vec![response(200, body.clone(), headers)]);
                let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
                let budget = TeamLookupBudgetV1::new_for_test(1, body.len() as u64, 5_000);
                let mut pull = client
                    .begin_pull("repo-remote", GENERATION, budget)
                    .unwrap();
                assert_eq!(
                    pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                        .await
                        .unwrap_err(),
                    expected
                );
                thread.join().unwrap();
            }

            let duplicate_generation = MockResponse {
                status: 200,
                headers: vec![
                    (REPOSITORY_GENERATION_HEADER, GENERATION.into()),
                    (REPOSITORY_GENERATION_HEADER, GENERATION.into()),
                    (
                        "Content-Type",
                        crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE.into(),
                    ),
                ],
                body: body.clone(),
                header_delay: Duration::ZERO,
                body_delay: Duration::ZERO,
            };
            let (endpoint, _, thread) = server(vec![duplicate_generation]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(1, body.len() as u64, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap_err(),
                RemoteError::RepositoryGenerationMismatch
            );
            thread.join().unwrap();

            // A gateway/CDN bare 404 is never the typed cache-miss signal.
            // Only the authenticated `manifest_not_found` service code can
            // be promoted to TeamPullError::CacheMiss by the outer layer.
            let (endpoint, requests, thread) = server(vec![response(404, Vec::new(), Vec::new())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(1, body.len() as u64, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_lookup_bundle_v1_body(&Digest::from_hex(ZERO).unwrap())
                    .await
                    .unwrap_err(),
                RemoteError::NotFound
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn pull_session_request_and_cumulative_byte_budgets_fail_closed() {
        test_runtime().block_on(async {
            let body = trust_bundle_wire_body();
            let (endpoint, requests, thread) =
                server(vec![response(200, body.clone(), Vec::new())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(1, 1_000_000, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            pull.fetch_latest_trust_bundle().await.unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::RequestBudgetExceeded
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 1);

            let (endpoint, requests, thread) = server(vec![
                response(200, body.clone(), Vec::new()),
                response(200, body.clone(), Vec::new()),
            ]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(4, body.len() as u64 * 2 - 1, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            pull.fetch_latest_trust_bundle().await.unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::ResponseBudgetExceeded
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 2);
        });
    }

    #[test]
    fn pull_session_fetches_strict_v2_manifest_and_exact_ciphertext_objects() {
        test_runtime().block_on(async {
            let stdout_bytes = b"stdout-ciphertext".to_vec();
            let stderr_bytes = vec![0xabu8; POLY1305_TAG_BYTES as usize];
            let stdout = EncryptedStreamRefV2 {
                ciphertext_digest: digest_bytes(&stdout_bytes),
                ciphertext_size_bytes: stdout_bytes.len() as u64,
                nonce: [7; 24],
            };
            let stderr = EncryptedStreamRefV2 {
                ciphertext_digest: digest_bytes(&stderr_bytes),
                ciphertext_size_bytes: stderr_bytes.len() as u64,
                nonce: [8; 24],
            };
            let manifest = encrypted_manifest_wire(stdout.clone(), stderr.clone());
            let (endpoint, requests, thread) = server(vec![
                response(200, serde_json::to_vec(&manifest).unwrap(), Vec::new()),
                response(
                    200,
                    stdout_bytes.clone(),
                    vec![("x-again-blake3", stdout.ciphertext_digest.to_hex())],
                ),
                response(
                    200,
                    stderr_bytes.clone(),
                    vec![("x-again-blake3", stderr.ciphertext_digest.to_hex())],
                ),
            ]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(4, 1_000_000, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            let fetched = pull.fetch_manifest_v2(&manifest.request_key).await.unwrap();
            assert_eq!(fetched, manifest);
            assert_eq!(
                pull.fetch_ciphertext(&fetched.stdout).await.unwrap(),
                stdout_bytes
            );
            assert_eq!(
                pull.fetch_ciphertext(&fetched.stderr).await.unwrap(),
                stderr_bytes
            );
            thread.join().unwrap();

            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            for request in requests.iter() {
                assert!(
                    request
                        .headers
                        .to_ascii_lowercase()
                        .contains(&format!("{REPOSITORY_GENERATION_HEADER}: {GENERATION}"))
                );
            }
            assert_eq!(
                requests[0].target,
                format!(
                    "/v1/repositories/repo-remote/manifests/{}",
                    manifest.request_key.to_hex()
                )
            );
            assert_eq!(
                requests[1].target,
                format!(
                    "/v1/repositories/repo-remote/blobs/{}",
                    stdout.ciphertext_digest.to_hex()
                )
            );
            assert_eq!(
                requests[2].target,
                format!(
                    "/v1/repositories/repo-remote/blobs/{}",
                    stderr.ciphertext_digest.to_hex()
                )
            );
        });
    }

    #[test]
    fn team_sessions_require_exact_generation_on_requests_and_responses() {
        test_runtime().block_on(async {
            let client =
                RemoteClient::new_for_loopback_test("http://127.0.0.1:1", TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(4, 1_000_000, 5_000);
            assert_eq!(
                client.begin_pull("repo-remote", "ABC", budget).unwrap_err(),
                RemoteError::RepositoryGenerationMismatch
            );

            let missing = MockResponse {
                status: 200,
                headers: Vec::new(),
                body: trust_bundle_wire_body(),
                header_delay: Duration::ZERO,
                body_delay: Duration::ZERO,
            };
            let (endpoint, requests, thread) = server(vec![missing]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::RepositoryGenerationMismatch
            );
            thread.join().unwrap();
            assert!(
                requests.lock().unwrap()[0]
                    .headers
                    .to_ascii_lowercase()
                    .contains(&format!("{REPOSITORY_GENERATION_HEADER}: {GENERATION}"))
            );

            let generation_b = "fedcba9876543210fedcba9876543210";
            let (endpoint, _, thread) = server(vec![response(
                200,
                trust_bundle_wire_body(),
                vec![(REPOSITORY_GENERATION_HEADER, generation_b.into())],
            )]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::RepositoryGenerationMismatch
            );
            thread.join().unwrap();
        });
    }

    #[test]
    fn pull_session_enforces_dedicated_trust_limit_and_strict_json() {
        test_runtime().block_on(async {
            let oversized = vec![b' '; MAX_TRUST_BUNDLE_BYTES + 1];
            let (endpoint, _, thread) = server(vec![response(200, oversized, Vec::new())]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget =
                TeamLookupBudgetV1::new_for_test(4, MAX_TRUST_BUNDLE_BYTES as u64 + 1, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::ResponseTooLarge {
                    limit: MAX_TRUST_BUNDLE_BYTES
                }
            );
            thread.join().unwrap();

            let mut value: serde_json::Value =
                serde_json::from_slice(&trust_bundle_wire_body()).unwrap();
            value["unexpected"] = serde_json::Value::Bool(true);
            let (endpoint, _, thread) = server(vec![response(
                200,
                serde_json::to_vec(&value).unwrap(),
                Vec::new(),
            )]);
            let client = RemoteClient::new_for_loopback_test(&endpoint, TEST_TOKEN).unwrap();
            let budget = TeamLookupBudgetV1::new_for_test(4, 1_000_000, 5_000);
            let mut pull = client
                .begin_pull("repo-remote", GENERATION, budget)
                .unwrap();
            assert_eq!(
                pull.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::InvalidTrustBundle
            );
            thread.join().unwrap();
        });
    }

    #[test]
    fn publish_session_uses_separate_tokens_and_manifest_last_routes() {
        test_runtime().block_on(async {
            let trust_body = trust_bundle_wire_body();
            let stdout_bytes = vec![0x31; POLY1305_TAG_BYTES as usize];
            let stderr_bytes = vec![0x32; POLY1305_TAG_BYTES as usize];
            let stdout = EncryptedStreamRefV2 {
                ciphertext_digest: digest_bytes(&stdout_bytes),
                ciphertext_size_bytes: stdout_bytes.len() as u64,
                nonce: [7; 24],
            };
            let stderr = EncryptedStreamRefV2 {
                ciphertext_digest: digest_bytes(&stderr_bytes),
                ciphertext_size_bytes: stderr_bytes.len() as u64,
                nonce: [8; 24],
            };
            let manifest = encrypted_manifest_wire(stdout.clone(), stderr.clone());
            let (endpoint, requests, thread) = server(vec![
                response(200, trust_body, Vec::new()),
                response(204, Vec::new(), Vec::new()),
                response(204, Vec::new(), Vec::new()),
                response(201, Vec::new(), Vec::new()),
            ]);
            let read_token = "ag1.reader.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let write_token = "ag1.writer.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
            let (read, write) = team_clients(&endpoint, read_token, write_token);
            let budget = TeamPublishBudgetV1::new_for_test(4, 1_000_000, 5_000);
            let mut publish = read
                .begin_publish(&write, "repo-remote", GENERATION, budget)
                .unwrap();
            publish.fetch_latest_trust_bundle().await.unwrap();
            publish
                .put_ciphertext(&stdout, &stdout_bytes)
                .await
                .unwrap();
            publish
                .put_ciphertext(&stderr, &stderr_bytes)
                .await
                .unwrap();
            publish.put_manifest_v2(&manifest).await.unwrap();
            assert_eq!(
                publish.fetch_latest_trust_bundle().await.unwrap_err(),
                RemoteError::RequestBudgetExceeded
            );
            thread.join().unwrap();

            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 4);
            assert_eq!(requests[0].method, "GET");
            assert!(requests[0].headers.contains(read_token));
            assert!(!requests[0].headers.contains(write_token));
            assert_eq!(requests[1].method, "PUT");
            assert!(requests[1].headers.contains(write_token));
            assert_eq!(requests[1].body, stdout_bytes);
            assert_eq!(requests[2].body, stderr_bytes);
            assert_eq!(
                requests[3].target,
                format!(
                    "/v1/repositories/repo-remote/manifests/{}",
                    manifest.request_key.to_hex()
                )
            );
        });
    }

    #[test]
    fn publish_session_transfer_request_deadline_and_origin_budgets_fail_closed() {
        test_runtime().block_on(async {
            let trust_body = trust_bundle_wire_body();
            let (endpoint, requests, thread) =
                server(vec![response(200, trust_body.clone(), Vec::new())]);
            let (read, write) = team_clients(&endpoint, TEST_TOKEN, TEST_WRITE_TOKEN);
            let budget = TeamPublishBudgetV1::new_for_test(4, trust_body.len() as u64, 5_000);
            let mut publish = read
                .begin_publish(&write, "repo-remote", GENERATION, budget)
                .unwrap();
            publish.fetch_latest_trust_bundle().await.unwrap();
            let bytes = vec![0x44; POLY1305_TAG_BYTES as usize];
            let reference = EncryptedStreamRefV2 {
                ciphertext_digest: digest_bytes(&bytes),
                ciphertext_size_bytes: bytes.len() as u64,
                nonce: [9; 24],
            };
            assert_eq!(
                publish
                    .put_ciphertext(&reference, &bytes)
                    .await
                    .unwrap_err(),
                RemoteError::TransferBudgetExceeded
            );
            thread.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 1);

            let (endpoint, _, thread) = server(vec![delayed_response(
                200,
                trust_body,
                Duration::from_millis(25),
                Duration::ZERO,
            )]);
            let (read, write) = team_clients(&endpoint, TEST_TOKEN, TEST_WRITE_TOKEN);
            let budget = TeamPublishBudgetV1::new_for_test(4, 1_000_000, 1);
            let mut publish = read
                .begin_publish(&write, "repo-remote", GENERATION, budget)
                .unwrap();
            assert!(matches!(
                publish.fetch_latest_trust_bundle().await,
                Err(RemoteError::Timeout { .. })
            ));
            thread.join().unwrap();

            let first = RemoteClient::build(
                "http://127.0.0.1:1",
                Zeroizing::new(TEST_TOKEN.to_owned()),
                true,
                CredentialRole::TeamRead,
            )
            .unwrap();
            let second = RemoteClient::build(
                "http://127.0.0.1:2",
                Zeroizing::new(TEST_TOKEN.to_owned()),
                true,
                CredentialRole::TeamWrite,
            )
            .unwrap();
            let budget = TeamPublishBudgetV1::new_for_test(4, 1_000_000, 5_000);
            assert_eq!(
                first
                    .begin_publish(&second, "repo-remote", GENERATION, budget)
                    .unwrap_err(),
                RemoteError::PublishOriginMismatch
            );

            let legacy_read =
                RemoteClient::new_for_loopback_test("http://127.0.0.1:1", TEST_TOKEN).unwrap();
            let legacy_write =
                RemoteClient::new_for_loopback_test("http://127.0.0.1:1", TEST_TOKEN).unwrap();
            assert_eq!(
                legacy_read
                    .begin_publish(&legacy_write, "repo-remote", GENERATION, budget)
                    .unwrap_err(),
                RemoteError::PublishCredentialRoleMismatch
            );

            let (same_read, same_write) =
                team_clients("http://127.0.0.1:1", TEST_TOKEN, TEST_TOKEN);
            assert_eq!(
                same_read
                    .begin_publish(&same_write, "repo-remote", GENERATION, budget)
                    .unwrap_err(),
                RemoteError::PublishCredentialRoleMismatch
            );
        });
    }

    #[test]
    fn client_debug_never_contains_bearer_secret() {
        let client = RemoteClient::new("https://cache.example.test", TEST_TOKEN).unwrap();
        let rendered = format!("{client:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(TEST_TOKEN));
    }
}
