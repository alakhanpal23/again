#![cfg(target_os = "macos")]

//! Manual live-system proof for the encrypted team-cache path.
//!
//! This test deliberately exercises the production HTTPS-only Again binary
//! against a real local Wrangler Worker reached through a temporary Cloudflare
//! Quick Tunnel. It is ignored because it requires outbound network access,
//! starts external processes, and takes materially longer than deterministic
//! unit/integration tests.
//!
//! Run from the repository root:
//!
//! ```text
//! AGAIN_TEAM_LIVE_E2E=1 cargo +1.88.0 test --locked \
//!   --test team_service_live_e2e -- --ignored --nocapture
//! ```

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use again::team::Digest;
use again::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_CONTENT_TYPE;
use again::trust_bundle::{ProducerKeyBindingV1, TRUST_BUNDLE_SCHEMA_VERSION, TrustBundleV1};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

const TENANT_ID: &str = "live-tenant";
const REPOSITORY_ID: &str = "live-repository";
const ROOT_KEY_ID: &str = "live-root-key";
const PRODUCER_KEY_ID: &str = "live-producer-key";
const PRODUCER_ID: &str = "live-producer";
const INPUT_BYTES: &[u8] = b"proof-carrying team reuse over production HTTPS\n";
const MISS_BYTES: &[u8] = b"read-only misses execute locally once\n";
const LATENCY_SAMPLES: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GeneratedSecretLeak {
    source_index: usize,
    secret_index: usize,
}

fn find_generated_secret_leak(
    sources: &[&[u8]],
    generated_secrets: &[Vec<u8>],
) -> Option<GeneratedSecretLeak> {
    sources
        .iter()
        .enumerate()
        .find_map(|(source_index, source)| {
            generated_secrets
                .iter()
                .enumerate()
                .find(|(_, secret)| {
                    !secret.is_empty()
                        && secret.len() <= source.len()
                        && source
                            .windows(secret.len())
                            .any(|window| window == secret.as_slice())
                })
                .map(|(secret_index, _)| GeneratedSecretLeak {
                    source_index,
                    secret_index,
                })
        })
}

#[test]
fn generated_secret_scan_detects_exact_material_without_retaining_it_in_errors() {
    let secret = b"generated-secret-material".to_vec();
    assert_eq!(
        find_generated_secret_leak(&[b"ordinary log line"], std::slice::from_ref(&secret)),
        None
    );
    assert_eq!(
        find_generated_secret_leak(
            &[b"prefix generated-secret-material suffix"],
            std::slice::from_ref(&secret),
        ),
        Some(GeneratedSecretLeak {
            source_index: 0,
            secret_index: 0,
        })
    );
    assert!(
        !format!(
            "{:?}",
            GeneratedSecretLeak {
                source_index: 0,
                secret_index: 0,
            }
        )
        .contains("generated-secret-material")
    );
}

#[test]
#[ignore = "diagnostic probe for an already-running public HTTPS endpoint"]
fn production_rustls_health_probe() {
    let endpoint = std::env::var("AGAIN_TEAM_HTTPS_PROBE")
        .expect("set AGAIN_TEAM_HTTPS_PROBE to a canonical HTTPS origin");
    let http = HttpHarness::new();
    wait_for_health(&http, &endpoint, "production rustls probe");
}

#[derive(Debug)]
struct Token {
    id: String,
    secret: String,
}

impl Token {
    fn random(role: &str) -> Self {
        Self {
            id: format!("live-{role}-{}", Uuid::new_v4().simple()),
            secret: Uuid::new_v4().simple().to_string(),
        }
    }

    fn bearer(&self) -> String {
        format!("ag1.{}.{}", self.id, self.secret)
    }
}

struct ServiceTokens {
    admin: Token,
    read: Token,
    write: Token,
}

impl ServiceTokens {
    fn random() -> Self {
        Self {
            admin: Token::random("admin"),
            read: Token::random("reader"),
            write: Token::random("writer"),
        }
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "decode HTTP {} response JSON: {error}; body={}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}

fn assert_one_exact_header(headers: &HeaderMap, name: &str, expected: &str, label: &str) {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .unwrap_or_else(|| panic!("{label} header is missing"));
    assert!(values.next().is_none(), "{label} header is duplicated");
    assert_eq!(value.as_bytes(), expected.as_bytes(), "{label} differs");
}

struct HttpHarness {
    runtime: Runtime,
    client: reqwest::Client,
}

impl HttpHarness {
    fn new() -> Self {
        Self::build(false)
    }

    fn loopback_self_signed() -> Self {
        Self::build(true)
    }

    fn build(accept_invalid_certificates: bool) -> Self {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build live E2E HTTP runtime");
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            // This is enabled only for Wrangler's self-signed loopback
            // readiness/scheduled-test listener. Actual Again clients and
            // every public Quick Tunnel request use the strict constructor.
            .danger_accept_invalid_certs(accept_invalid_certificates)
            .build()
            .expect("build live E2E HTTP client");
        Self { runtime, client }
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        method: Method,
        url: &str,
        token: Option<&Token>,
        generation: Option<&str>,
        if_match: Option<&str>,
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        self.runtime.block_on(async {
            let mut request = self.client.request(method, url);
            if let Some(token) = token {
                request = request.header(AUTHORIZATION, format!("Bearer {}", token.bearer()));
            }
            if let Some(generation) = generation {
                request = request.header("x-again-repository-generation", generation);
            }
            if let Some(if_match) = if_match {
                request = request.header("if-match", format!("\"{if_match}\""));
            }
            if let Some(content_type) = content_type {
                request = request.header(CONTENT_TYPE, content_type);
            }
            if let Some(body) = body {
                request = request.body(body);
            }
            let response = request.send().await.expect("send live E2E HTTP request");
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .bytes()
                .await
                .expect("read live E2E HTTP response")
                .to_vec();
            HttpResponse {
                status,
                headers,
                body,
            }
        })
    }

    fn try_get(&self, url: &str) -> Result<HttpResponse, String> {
        self.runtime.block_on(async {
            let response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|error| format!("{error:#}"))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .bytes()
                .await
                .map_err(|error| format!("{error:#}"))?
                .to_vec();
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

struct WorkerGuard {
    wrangler_child: Child,
    wrangler_process_group: i32,
    wrangler_log_path: PathBuf,
    tunnel_child: Child,
    tunnel_process_group: i32,
    tunnel_log_path: PathBuf,
}

impl WorkerGuard {
    fn start(
        wrangler: &Path,
        cloudflared: &Path,
        service_root: &Path,
        state: &Path,
        wrangler_log_path: &Path,
        tunnel_log_path: &Path,
        local_port: u16,
    ) -> Self {
        let stdout = File::create(wrangler_log_path).expect("create Wrangler live E2E log");
        let stderr = stdout.try_clone().expect("clone Wrangler live E2E log");
        let mut command = Command::new(wrangler);
        command
            .current_dir(service_root)
            .args([
                "dev",
                "--local",
                "--local-protocol",
                "https",
                "--port",
                &local_port.to_string(),
                "--persist-to",
            ])
            .arg(state)
            .args([
                "--test-scheduled",
                "--show-interactive-dev-session",
                "true",
                "--log-level",
                "debug",
            ])
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .process_group(0);
        let wrangler_child = command.spawn().expect("start local HTTPS Wrangler Worker");
        let wrangler_process_group =
            i32::try_from(wrangler_child.id()).expect("Wrangler process id fits i32");

        let tunnel_stdout = File::create(tunnel_log_path).expect("create cloudflared live E2E log");
        let tunnel_stderr = tunnel_stdout
            .try_clone()
            .expect("clone cloudflared live E2E log");
        let origin = format!("https://127.0.0.1:{local_port}");
        let mut tunnel_command = Command::new(cloudflared);
        tunnel_command
            .args([
                "tunnel",
                "--url",
                &origin,
                "--no-tls-verify",
                "--no-autoupdate",
                "--loglevel",
                "info",
                "--output",
                "default",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(tunnel_stdout))
            .stderr(Stdio::from(tunnel_stderr))
            .process_group(0);
        let tunnel_child = tunnel_command
            .spawn()
            .expect("start no-account cloudflared Quick Tunnel");
        let tunnel_process_group =
            i32::try_from(tunnel_child.id()).expect("cloudflared process id fits i32");
        Self {
            wrangler_child,
            wrangler_process_group,
            wrangler_log_path: wrangler_log_path.to_owned(),
            tunnel_child,
            tunnel_process_group,
            tunnel_log_path: tunnel_log_path.to_owned(),
        }
    }

    fn wait_for_https_origin(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut discovered_origin = None;
        while Instant::now() < deadline {
            if let Some(status) = self
                .wrangler_child
                .try_wait()
                .expect("poll Wrangler process")
            {
                panic!(
                    "Wrangler exited before Quick Tunnel readiness ({status}); log:\n{}",
                    fs::read_to_string(&self.wrangler_log_path).unwrap_or_default()
                );
            }
            if let Some(status) = self
                .tunnel_child
                .try_wait()
                .expect("poll cloudflared process")
            {
                panic!(
                    "cloudflared exited before creating a Quick Tunnel ({status}); log:\n{}",
                    fs::read_to_string(&self.tunnel_log_path).unwrap_or_default()
                );
            }
            let log = fs::read_to_string(&self.tunnel_log_path).unwrap_or_default();
            if discovered_origin.is_none() {
                discovered_origin = quick_tunnel_origin(&log);
            }
            if log.contains("Registered tunnel connection") {
                if let Some(origin) = discovered_origin {
                    // The hostname is printed before tunnel registration. An
                    // immediate system lookup can observe and cache NXDOMAIN;
                    // wait until registration plus a small DNS propagation
                    // window before the production rustls client resolves it.
                    thread::sleep(Duration::from_secs(5));
                    return origin;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "Quick Tunnel URL did not appear within 120 seconds; log:\n{}",
            fs::read_to_string(&self.tunnel_log_path).unwrap_or_default()
        );
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        terminate_process_group(&mut self.tunnel_child, self.tunnel_process_group);
        terminate_process_group(&mut self.wrangler_child, self.wrangler_process_group);
    }
}

fn terminate_process_group(child: &mut Child, process_group: i32) {
    // SAFETY: `kill` receives a negative, test-created process-group id and no
    // Rust memory. SIGTERM/SIGKILL are valid signal numbers.
    unsafe {
        libc::kill(-process_group, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    // SAFETY: same process-group argument and signal validity as above.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    let _ = child.wait();
}

#[derive(Debug)]
struct ClientFixture {
    workspace: PathBuf,
    profile: PathBuf,
    runtime_checkpoint: PathBuf,
    state: PathBuf,
    home: PathBuf,
}

impl ClientFixture {
    #[allow(clippy::too_many_arguments)]
    fn create(
        root: &Path,
        name: &str,
        endpoint_origin: &str,
        generation_id: &str,
        tokens: &ServiceTokens,
        repository_key: &[u8; 32],
        root_key: &SigningKey,
        producer_key: &SigningKey,
        publisher: bool,
    ) -> Self {
        let client_root = root.join(name);
        let workspace = client_root.join("workspace");
        let private = client_root.join("private");
        let checkpoints = private.join("checkpoints");
        let state = private.join("state");
        let home = private.join("home");
        for directory in [
            &client_root,
            &workspace,
            &private,
            &checkpoints,
            &state,
            &home,
            &workspace.join("src"),
        ] {
            fs::create_dir_all(directory).expect("create live E2E client directory");
            set_mode(directory, 0o700);
        }
        fs::write(workspace.join("src/input.txt"), INPUT_BYTES).expect("write shared input");
        fs::write(workspace.join("src/miss.txt"), MISS_BYTES).expect("write miss input");

        let read_token = private.join("read.token");
        let write_token = private.join("write.token");
        let repository_key_file = private.join("repository-key.json");
        let sharing_policy = private.join("sharing-policy.json");
        let producer_signing_key = private.join("producer-signing-key.json");
        let profile = private.join("profile.json");
        let trust_checkpoint = checkpoints.join("trust.json");
        let runtime_checkpoint = checkpoints.join("runtime.json");

        write_private(&read_token, tokens.read.bearer().as_bytes());
        write_private(&write_token, tokens.write.bearer().as_bytes());
        write_private_json(
            &repository_key_file,
            &json!({
                "schema_version": 1,
                "namespace": "again.repository-encryption-key.v1",
                "key_id": "live-repository-key",
                "key_hex": lower_hex(repository_key),
            }),
        );
        write_private_json(
            &sharing_policy,
            &json!({
                "schema_version": 1,
                "namespace": "again.repository-sharing-policy.v1",
                "version": "live-sharing-v1",
                "include_prefixes": ["src"],
                "exclude_prefixes": [".env", ".git", "target"],
                "max_output_bytes": 1024 * 1024,
            }),
        );
        write_private_json(
            &producer_signing_key,
            &json!({
                "schema_version": 1,
                "namespace": "again.producer-signing-key.v1",
                "key_id": PRODUCER_KEY_ID,
                "producer_id": PRODUCER_ID,
                "secret_key_hex": lower_hex(&producer_key.to_bytes()),
            }),
        );

        let mut profile_json = json!({
            "schema_version": 1,
            "namespace": "again.team-profile.v1",
            "endpoint_origin": endpoint_origin,
            "tenant_id": TENANT_ID,
            "repository_id": REPOSITORY_ID,
            "generation_id": generation_id,
            "pinned_root_key_id": ROOT_KEY_ID,
            "pinned_root_public_key_hex": lower_hex(&root_key.verifying_key().to_bytes()),
            "read_token_file": read_token,
            "repository_key_file": repository_key_file,
            "sharing_policy_file": sharing_policy,
            "checkpoint_file": trust_checkpoint,
            "runtime_attestation_checkpoint_file": runtime_checkpoint,
            "lookup_protocol": "bundle_v1",
            "lookup_budget": {
                "max_requests": 2,
                "max_response_bytes": 20 * 1024 * 1024,
                "total_timeout_ms": 30_000,
            },
        });
        if publisher {
            profile_json["publisher"] = json!({
                "write_token_file": write_token,
                "producer_signing_key_file": producer_signing_key,
                "publish_budget": {
                    "max_requests": 4,
                    "max_transfer_bytes": 20 * 1024 * 1024,
                    "total_timeout_ms": 30_000,
                },
            });
        }
        write_private_json(&profile, &profile_json);
        Self {
            workspace,
            profile,
            runtime_checkpoint,
            state,
            home,
        }
    }

    fn run_team(&self, arguments: &[&str]) -> TimedOutput {
        let mut command = Command::new(again_binary());
        command
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", audited_path())
            .env("HOME", &self.home)
            .env("AGAIN_HOME", &self.state)
            .args(["team", "run", "--profile"])
            .arg(&self.profile)
            .arg("--")
            .args(arguments);
        timed_output(&mut command, "run actual Again team client")
    }

    fn inspect(&self, arguments: &[&str]) -> Value {
        let mut command = Command::new(again_binary());
        let output = command
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", audited_path())
            .env("HOME", &self.home)
            .env("AGAIN_HOME", &self.state)
            .args(["team", "inspect", "--profile"])
            .arg(&self.profile)
            .args(["--json", "--"])
            .args(arguments)
            .output()
            .expect("run actual Again team inspection");
        assert_success(&output, "Again team inspection");
        assert!(output.stderr.is_empty(), "inspection emitted diagnostics");
        serde_json::from_slice(&output.stdout).expect("decode Again team inspection")
    }

    fn explain(&self) -> Value {
        let mut command = Command::new(again_binary());
        let output = command
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", audited_path())
            .env("HOME", &self.home)
            .env("AGAIN_HOME", &self.state)
            .args(["explain", "--json"])
            .output()
            .expect("explain live E2E team event");
        assert_success(&output, "Again explain");
        serde_json::from_slice(&output.stdout).expect("decode Again explain JSON")
    }
}

#[derive(Debug)]
struct TimedOutput {
    output: Output,
    elapsed_micros: u64,
}

#[test]
#[ignore = "requires outbound Quick Tunnel access and starts a real Wrangler Worker"]
fn production_https_two_client_lifecycle_and_adversarial_proof() {
    if std::env::var("AGAIN_TEAM_LIVE_E2E").as_deref() != Ok("1") {
        eprintln!("skipped: set AGAIN_TEAM_LIVE_E2E=1 to authorize the public Quick Tunnel test");
        return;
    }

    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let service_root = repository_root.join("service");
    let wrangler = service_root.join("node_modules/.bin/wrangler");
    assert!(
        wrangler.is_file(),
        "run `npm ci` in service before live E2E"
    );
    let cloudflared = wrangler_cloudflared_binary();
    let provenance = live_e2e_provenance(&repository_root, &wrangler, &cloudflared);

    let temporary = TempDir::new().expect("create live E2E root");
    set_mode(temporary.path(), 0o700);
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonicalize live E2E root");
    let service_state = root.join("service-state");
    let service_log = root.join("wrangler.log");
    let tunnel_log = root.join("cloudflared.log");
    fs::create_dir(&service_state).expect("create local service state");
    set_mode(&service_state, 0o700);

    apply_migrations(&wrangler, &service_root, &service_state);
    let tokens = ServiceTokens::random();
    seed_tenant_and_tokens(&wrangler, &service_root, &service_state, &root, &tokens);

    let local_port = unused_non_ephemeral_loopback_port();
    let mut worker = WorkerGuard::start(
        &wrangler,
        &cloudflared,
        &service_root,
        &service_state,
        &service_log,
        &tunnel_log,
        local_port,
    );
    let local_http = HttpHarness::loopback_self_signed();
    wait_for_health(
        &local_http,
        &format!("https://127.0.0.1:{local_port}"),
        "local Wrangler",
    );
    let endpoint = worker.wait_for_https_origin();
    wait_for_public_dns(&endpoint);
    let http = HttpHarness::new();
    wait_for_health(&http, &endpoint, "Quick Tunnel");

    let generation_a = create_repository(&http, &endpoint, &tokens.admin);
    let root_key = signing_key_from_random_bytes();
    let producer_key = signing_key_from_random_bytes();
    let repository_key = random_32_bytes();
    provision_root(&wrangler, &service_root, &service_state, &root, &root_key);
    register_producer(
        &http,
        &endpoint,
        &tokens.admin,
        &generation_a,
        &producer_key,
    );

    let publisher_a = ClientFixture::create(
        &root,
        "publisher-a",
        &endpoint,
        &generation_a,
        &tokens,
        &repository_key,
        &root_key,
        &producer_key,
        true,
    );
    let reader_b = ClientFixture::create(
        &root,
        "reader-b",
        &endpoint,
        &generation_a,
        &tokens,
        &repository_key,
        &root_key,
        &producer_key,
        false,
    );
    let wrong_key = random_32_bytes();
    let mut generated_secrets = vec![
        tokens.admin.bearer().into_bytes(),
        tokens.read.bearer().into_bytes(),
        tokens.write.bearer().into_bytes(),
        tokens.admin.secret.as_bytes().to_vec(),
        tokens.read.secret.as_bytes().to_vec(),
        tokens.write.secret.as_bytes().to_vec(),
    ];
    for key in [
        repository_key,
        wrong_key,
        root_key.to_bytes(),
        producer_key.to_bytes(),
    ] {
        generated_secrets.push(key.to_vec());
        generated_secrets.push(lower_hex(&key).into_bytes());
    }
    let wrong_key_reader = ClientFixture::create(
        &root,
        "reader-wrong-key",
        &endpoint,
        &generation_a,
        &tokens,
        &wrong_key,
        &root_key,
        &producer_key,
        false,
    );

    let command = ["cat", "src/input.txt"];
    let inspection_a = publisher_a.inspect(&command);
    assert_eq!(inspection_a["scope"]["generation_id"], generation_a);
    publish_fresh_trust(
        &http,
        &endpoint,
        &tokens.admin,
        &generation_a,
        &inspection_a,
        &root_key,
        1,
    );
    clone_runtime_checkpoint(&publisher_a, &reader_b);
    clone_runtime_checkpoint(&publisher_a, &wrong_key_reader);

    let published = publisher_a.run_team(&command);
    assert_exact_success(&published.output, INPUT_BYTES, "publisher miss/publication");
    assert_event(&publisher_a, "executed", "TEAM_CAPTURED_AND_PUBLISHED");

    let request_key = inspection_a["request"]["request_key"]
        .as_str()
        .expect("inspection request key");
    // This is a standalone public-transport diagnostic, not an observation of
    // the client's two-request lookup sequence. It proves that the Worker and
    // Quick Tunnel preserve the FixedLength framing required by the streamed
    // bundle response.
    let public_bundle = http.request(
        Method::GET,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}/lookup-bundles/{request_key}"),
        Some(&tokens.read),
        Some(&generation_a),
        None,
        None,
        None,
    );
    assert_eq!(
        public_bundle.status,
        StatusCode::OK,
        "public bundle GET failed: {}",
        String::from_utf8_lossy(&public_bundle.body)
    );
    assert_one_exact_header(
        &public_bundle.headers,
        "content-type",
        TEAM_LOOKUP_BUNDLE_CONTENT_TYPE,
        "bundle content type",
    );
    assert_one_exact_header(
        &public_bundle.headers,
        "x-again-repository-generation",
        &generation_a,
        "bundle repository generation",
    );
    let mut content_lengths = public_bundle.headers.get_all(CONTENT_LENGTH).iter();
    let content_length = content_lengths
        .next()
        .expect("public bundle response omitted Content-Length");
    assert!(
        content_lengths.next().is_none(),
        "public bundle response duplicated Content-Length"
    );
    let content_length = content_length
        .to_str()
        .expect("public bundle Content-Length is not visible ASCII");
    assert!(
        !content_length.is_empty() && content_length.bytes().all(|byte| byte.is_ascii_digit()),
        "public bundle Content-Length is not one decimal value"
    );
    assert_eq!(
        content_length
            .parse::<usize>()
            .expect("public bundle Content-Length fits usize"),
        public_bundle.body.len(),
        "public bundle Content-Length differs from received body length"
    );

    let first_hit = reader_b.run_team(&command);
    assert_exact_success(&first_hit.output, INPUT_BYTES, "second-client exact hit");
    assert_event(&reader_b, "replayed_full", "TEAM_EXACT_REMOTE_REUSE");

    let manifest = get_manifest(&http, &endpoint, &tokens.read, &generation_a, request_key);
    assert_eq!(manifest["generation_id"], generation_a);
    assert_eq!(manifest["schema_version"], 2);

    // Rotate the signed authorization head without changing the producer or
    // payload. The bundled first response may carry either epoch during a
    // concurrent deployment, but the mandatory second request must advance
    // and persist epoch 2 before plaintext is released.
    publish_fresh_trust(
        &http,
        &endpoint,
        &tokens.admin,
        &generation_a,
        &inspection_a,
        &root_key,
        2,
    );
    let post_rotation_hit = reader_b.run_team(&command);
    assert_exact_success(
        &post_rotation_hit.output,
        INPUT_BYTES,
        "post-trust-rotation bundled hit",
    );
    assert_event(&reader_b, "replayed_full", "TEAM_EXACT_REMOTE_REUSE");

    let read_only_miss = reader_b.run_team(&["cat", "src/miss.txt"]);
    assert_exact_success(&read_only_miss.output, MISS_BYTES, "read-only miss");
    assert_event(
        &reader_b,
        "bypassed_no_store",
        "TEAM_MISS_READ_ONLY_PROFILE",
    );

    let wrong_key_result = wrong_key_reader.run_team(&command);
    assert_exact_success(
        &wrong_key_result.output,
        INPUT_BYTES,
        "wrong repository key fallback",
    );
    assert_event(
        &wrong_key_reader,
        "quarantined",
        "TEAM_PULL_CORRUPTION_DEGRADED",
    );

    // Prove that a wrong local key did not mutate or poison server state.
    let after_wrong_key = reader_b.run_team(&command);
    assert_exact_success(&after_wrong_key.output, INPUT_BYTES, "post-wrong-key hit");
    assert_event(&reader_b, "replayed_full", "TEAM_EXACT_REMOTE_REUSE");

    let native_latency = native_latency_samples(&reader_b.workspace, &command, LATENCY_SAMPLES);
    let mut remote_latency = Vec::with_capacity(LATENCY_SAMPLES);
    for _ in 0..LATENCY_SAMPLES {
        let hit = reader_b.run_team(&command);
        assert_exact_success(&hit.output, INPUT_BYTES, "latency exact hit");
        assert_event(&reader_b, "replayed_full", "TEAM_EXACT_REMOTE_REUSE");
        remote_latency.push(hit.elapsed_micros);
    }

    corrupt_ciphertext(
        &wrangler,
        &service_root,
        &service_state,
        &root,
        &generation_a,
        &manifest,
    );
    let corrupted = reader_b.run_team(&command);
    assert_exact_success(&corrupted.output, INPUT_BYTES, "corrupt R2 fallback");
    assert_event(&reader_b, "quarantined", "TEAM_PULL_CORRUPTION_DEGRADED");

    revoke_producer(&http, &endpoint, &tokens.admin, &generation_a);
    let hidden = http.request(
        Method::GET,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}/manifests/{request_key}"),
        Some(&tokens.read),
        Some(&generation_a),
        None,
        None,
        None,
    );
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    let revoked = reader_b.run_team(&command);
    assert_exact_success(&revoked.output, INPUT_BYTES, "revoked producer fallback");
    assert_event(
        &reader_b,
        "bypassed_no_store",
        "TEAM_MISS_READ_ONLY_PROFILE",
    );

    delete_repository(&http, &endpoint, &tokens.admin, &generation_a);
    complete_repository_deletion(
        &http,
        &endpoint,
        &wrangler,
        &service_root,
        &service_state,
        &root,
    );
    let generation_b = create_repository(&http, &endpoint, &tokens.admin);
    assert_ne!(
        generation_a, generation_b,
        "repository generation was reused"
    );

    let stale_read = http.request(
        Method::GET,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}/trust-bundles/latest"),
        Some(&tokens.read),
        Some(&generation_a),
        None,
        None,
        None,
    );
    assert_eq!(stale_read.status, StatusCode::PRECONDITION_FAILED);
    let stale_cli = reader_b.run_team(&command);
    assert_exact_success(
        &stale_cli.output,
        INPUT_BYTES,
        "stale generation CLI fallback",
    );
    let stale_event = reader_b.explain();
    assert_ne!(stale_event["reason"], "TEAM_EXACT_REMOTE_REUSE");
    assert_ne!(stale_event["disposition"], "replayed_full");

    provision_root(&wrangler, &service_root, &service_state, &root, &root_key);
    register_producer(
        &http,
        &endpoint,
        &tokens.admin,
        &generation_b,
        &producer_key,
    );
    let publisher_b = ClientFixture::create(
        &root,
        "publisher-generation-b",
        &endpoint,
        &generation_b,
        &tokens,
        &repository_key,
        &root_key,
        &producer_key,
        true,
    );
    let reader_generation_b = ClientFixture::create(
        &root,
        "reader-generation-b",
        &endpoint,
        &generation_b,
        &tokens,
        &repository_key,
        &root_key,
        &producer_key,
        false,
    );
    clone_runtime_checkpoint(&publisher_a, &publisher_b);
    clone_runtime_checkpoint(&publisher_a, &reader_generation_b);
    let inspection_b = publisher_b.inspect(&command);
    assert_ne!(
        inspection_a["request"]["request_key"], inspection_b["request"]["request_key"],
        "generation must change the portable request key"
    );
    publish_fresh_trust(
        &http,
        &endpoint,
        &tokens.admin,
        &generation_b,
        &inspection_b,
        &root_key,
        1,
    );
    let republished = publisher_b.run_team(&command);
    assert_exact_success(&republished.output, INPUT_BYTES, "generation B publication");
    assert_event(&publisher_b, "executed", "TEAM_CAPTURED_AND_PUBLISHED");
    let generation_b_hit = reader_generation_b.run_team(&command);
    assert_exact_success(&generation_b_hit.output, INPUT_BYTES, "generation B hit");
    assert_event(
        &reader_generation_b,
        "replayed_full",
        "TEAM_EXACT_REMOTE_REUSE",
    );

    let native_summary = latency_summary(&native_latency);
    let remote_summary = latency_summary(&remote_latency);
    let report = json!({
        "schema_version": 1,
        "recorded_at_unix_seconds": unix_seconds(),
        "provenance": provenance,
        "transport": "production-rustls-over-cloudflare-quick-tunnel-https",
        "lookup_protocol": "bundle_v1",
        "max_requests_per_exact_hit": 2,
        "request_count_evidence": {
            "observed_by_live_harness": false,
            "separate_public_framing_get_is_not_counted": true,
            "note": "The live profile enforces the ceiling; the deterministic remote::tests::bundle_pull_uses_exactly_two_requests_under_one_budget_without_retry test observes the exact two client routes. The direct public GET here validates response framing only.",
        },
        "service": "wrangler-local-d1-r2",
        "clients": 2,
        "checks": {
            "publisher_miss_and_publish": true,
            "public_bundle_content_length_matches_body": true,
            "second_client_exact_hit": true,
            "post_rotation_second_client_exact_hit": true,
            "read_only_miss_local_fallback": true,
            "wrong_repository_key_quarantined": true,
            "r2_corruption_quarantined": true,
            "producer_revocation_hides_manifest": true,
            "old_generation_transport_rejected_412": true,
            "old_generation_cli_never_hit": true,
            "new_generation_republish_and_hit": true,
            "generated_secret_log_scan_passed": true,
            "temporary_secret_tree_removed_before_report_write": true,
        },
        "generation": {
            "old_and_new_differ": generation_a != generation_b,
            "request_keys_differ": inspection_a["request"]["request_key"]
                != inspection_b["request"]["request_key"],
        },
        "latency_micros": {
            "sample_count": LATENCY_SAMPLES,
            "native": native_summary,
            "quick_tunnel_exact_hit": remote_summary,
            "note": "Quick Tunnel latency is transport evidence, not a production speed gate",
        },
    });
    let report_bytes =
        serde_json::to_vec_pretty(&report).expect("encode live E2E report for secret scan");

    // Stop both writers before inspecting their complete logs. Only opaque
    // indexes are reported on failure, so the assertion itself cannot echo a
    // discovered credential into another log.
    drop(worker);
    let wrangler_log = fs::read(&service_log).expect("read completed Wrangler log");
    let cloudflared_log = fs::read(&tunnel_log).expect("read completed cloudflared log");
    let scan_sources = [
        wrangler_log.as_slice(),
        cloudflared_log.as_slice(),
        report_bytes.as_slice(),
        public_bundle.body.as_slice(),
    ];
    assert_eq!(
        find_generated_secret_leak(&scan_sources, &generated_secrets),
        None,
        "a generated secret appeared in a persisted log/report source"
    );

    let temporary_root = root.clone();
    temporary
        .close()
        .expect("remove live E2E temporary credential tree");
    assert!(
        !temporary_root.exists(),
        "live E2E temporary credential tree remained after close"
    );

    let report_path = std::env::var_os("AGAIN_TEAM_LIVE_E2E_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository_root.join("target/team-service-live-e2e-report.json"));
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).expect("create live E2E report directory");
    }
    fs::write(&report_path, report_bytes).expect("write live E2E report");
    eprintln!("live team E2E report: {}", report_path.display());
}

fn again_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_again"))
}

fn audited_path() -> String {
    let mut directories = vec!["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    if Path::new("/opt/homebrew/bin").is_dir() {
        directories.insert(0, "/opt/homebrew/bin");
    }
    directories.join(":")
}

fn quick_tunnel_origin(log: &str) -> Option<String> {
    log.split_whitespace().find_map(|token| {
        let start = token.find("https://")?;
        let candidate = token[start..].trim_matches(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, ':' | '/' | '.' | '-'))
        });
        let origin = candidate.trim_end_matches('/');
        origin
            .ends_with(".trycloudflare.com")
            .then(|| origin.to_owned())
    })
}

fn unused_non_ephemeral_loopback_port() -> u16 {
    // Wrangler allocates several ephemeral inspector/worker ports before it
    // binds the requested public local port. Feeding it a just-released OS
    // ephemeral port can race Wrangler's own allocations. Select from a
    // non-ephemeral test range instead.
    (41_000..42_000)
        .find(|port| TcpListener::bind(("127.0.0.1", *port)).is_ok())
        .expect("find unused non-ephemeral loopback port")
}

fn wrangler_cloudflared_binary() -> PathBuf {
    if let Some(explicit) = std::env::var_os("AGAIN_TEAM_CLOUDFLARED") {
        let candidate = PathBuf::from(explicit);
        assert!(
            candidate.is_file(),
            "AGAIN_TEAM_CLOUDFLARED is not a file: {}",
            candidate.display()
        );
        return candidate;
    }

    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME for Wrangler cache"));
    let cache = home.join("Library/Preferences/.wrangler/cloudflared");
    let candidate = fs::read_dir(&cache)
        .unwrap_or_else(|error| {
            panic!(
                "read Wrangler cloudflared cache {}: {error}; run `wrangler dev --tunnel` once or set AGAIN_TEAM_CLOUDFLARED",
                cache.display()
            )
        })
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("cloudflared"))
        .filter(|path| path.is_file())
        .max();
    candidate.unwrap_or_else(|| {
        panic!(
            "Wrangler cloudflared binary is absent under {}; run `wrangler dev --tunnel` once or set AGAIN_TEAM_CLOUDFLARED",
            cache.display()
        )
    })
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("set mode on {}: {error}", path.display()));
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    set_mode(path, 0o600);
}

fn write_private_json(path: &Path, value: &Value) {
    write_private(
        path,
        &serde_json::to_vec(value).expect("encode private live E2E JSON"),
    );
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("write lower hex");
    }
    output
}

fn random_32_bytes() -> [u8; 32] {
    let mut output = [0_u8; 32];
    output[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    output[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    output
}

fn signing_key_from_random_bytes() -> SigningKey {
    SigningKey::from_bytes(&random_32_bytes())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_secs()
}

fn live_e2e_provenance(repository_root: &Path, wrangler: &Path, cloudflared: &Path) -> Value {
    let commit_output = Command::new("/usr/bin/git")
        .current_dir(repository_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("read live E2E source commit");
    assert_success(&commit_output, "read live E2E source commit");
    let source_commit = String::from_utf8(commit_output.stdout)
        .expect("Git source commit is UTF-8")
        .trim()
        .to_owned();

    let status_output = Command::new("/usr/bin/git")
        .current_dir(repository_root)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .expect("read live E2E working-tree state");
    assert_success(&status_output, "read live E2E working-tree state");
    let status = String::from_utf8(status_output.stdout).expect("Git status is UTF-8");

    let production_source_set = [
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
        PathBuf::from("src"),
        PathBuf::from("service/package.json"),
        PathBuf::from("service/package-lock.json"),
        PathBuf::from("service/tsconfig.json"),
        PathBuf::from("service/worker-configuration.d.ts"),
        PathBuf::from("service/wrangler.jsonc"),
        PathBuf::from("service/src"),
        PathBuf::from("service/migrations"),
    ];

    json!({
        "source_commit": source_commit,
        "working_tree_dirty": !status.is_empty(),
        "working_tree_entry_count": status.lines().count(),
        "production_source_set_blake3": source_set_blake3(
            repository_root,
            &production_source_set,
        ),
        "client_binary_blake3": file_blake3(&again_binary()),
        "live_harness_blake3": file_blake3(
            &repository_root.join("tests/team_service_live_e2e.rs"),
        ),
        "wrangler_version": tool_version(wrangler),
        "cloudflared_version": tool_version(cloudflared),
        "host_os": std::env::consts::OS,
        "host_arch": std::env::consts::ARCH,
    })
}

fn source_set_blake3(repository_root: &Path, roots: &[PathBuf]) -> String {
    let mut files = Vec::new();
    for relative in roots {
        collect_source_files(repository_root, relative, &mut files);
    }
    files.sort();
    files.dedup();

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again-live-e2e-production-source-set-v1\0");
    for relative in files {
        let relative_bytes = relative.to_string_lossy();
        let absolute = repository_root.join(&relative);
        let metadata = fs::symlink_metadata(&absolute).expect("stat live E2E source file");
        assert!(
            metadata.file_type().is_file(),
            "live E2E source set contains a non-regular file: {}",
            relative.display()
        );
        hasher.update(&(relative_bytes.len() as u64).to_be_bytes());
        hasher.update(relative_bytes.as_bytes());
        hasher.update(&metadata.len().to_be_bytes());
        update_blake3_from_file(&mut hasher, &absolute);
    }
    hasher.finalize().to_hex().to_string()
}

fn collect_source_files(repository_root: &Path, relative: &Path, files: &mut Vec<PathBuf>) {
    let absolute = repository_root.join(relative);
    let metadata = fs::symlink_metadata(&absolute).unwrap_or_else(|error| {
        panic!(
            "stat live E2E source-set path {}: {error}",
            relative.display()
        )
    });
    if metadata.file_type().is_file() {
        files.push(relative.to_path_buf());
        return;
    }
    assert!(
        metadata.file_type().is_dir(),
        "live E2E source-set path is neither a directory nor a regular file: {}",
        relative.display()
    );
    let mut children = fs::read_dir(&absolute)
        .expect("read live E2E source directory")
        .map(|entry| entry.expect("read live E2E source entry").file_name())
        .collect::<Vec<_>>();
    children.sort();
    for child in children {
        collect_source_files(repository_root, &relative.join(child), files);
    }
}

fn file_blake3(path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    update_blake3_from_file(&mut hasher, path);
    hasher.finalize().to_hex().to_string()
}

fn update_blake3_from_file(hasher: &mut blake3::Hasher, path: &Path) {
    let mut file = File::open(path)
        .unwrap_or_else(|error| panic!("open provenance file {}: {error}", path.display()));
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read provenance file {}: {error}", path.display()));
        if read == 0 {
            return;
        }
        hasher.update(&buffer[..read]);
    }
}

fn tool_version(path: &Path) -> String {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("read {} version: {error}", path.display()));
    assert_success(&output, "read live E2E tool version");
    let bytes = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    String::from_utf8(bytes)
        .expect("tool version is UTF-8")
        .trim()
        .to_owned()
}

fn sha256_hex(secret: &str) -> String {
    let mut child = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start shasum for token provisioning");
    child
        .stdin
        .as_mut()
        .expect("shasum stdin")
        .write_all(secret.as_bytes())
        .expect("hash token secret without argv exposure");
    let output = child.wait_with_output().expect("finish token hash");
    assert_success(&output, "shasum token provisioning");
    String::from_utf8(output.stdout)
        .expect("shasum emits UTF-8")
        .split_whitespace()
        .next()
        .expect("shasum digest")
        .to_owned()
}

fn run_wrangler(
    wrangler: &Path,
    service_root: &Path,
    arguments: &[&str],
    path_arguments: &[&Path],
    label: &str,
) -> Output {
    let mut command = Command::new(wrangler);
    command.current_dir(service_root).args(arguments);
    for path in path_arguments {
        command.arg(path);
    }
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    assert_success(&output, label);
    output
}

fn apply_migrations(wrangler: &Path, service_root: &Path, state: &Path) {
    run_wrangler(
        wrangler,
        service_root,
        &["d1", "migrations", "apply", "DB", "--local", "--persist-to"],
        &[state],
        "apply local D1 migrations",
    );
}

fn seed_tenant_and_tokens(
    wrangler: &Path,
    service_root: &Path,
    state: &Path,
    root: &Path,
    tokens: &ServiceTokens,
) {
    let now = unix_seconds();
    let sql_path = root.join("seed.sql");
    let sql = format!(
        "INSERT INTO tenants(id,name,quota_bytes,metadata_quota_units,created_at) VALUES \
         ('{TENANT_ID}','Live E2E',67108864,100000,{now});\n\
         INSERT INTO auth_tokens(id,tenant_id,subject,secret_sha256,repository_scope,permissions,created_at,expires_at) VALUES \
         ('{}','{TENANT_ID}','live-admin','{}',NULL,'admin',{now},{});\n\
         INSERT INTO auth_tokens(id,tenant_id,subject,secret_sha256,repository_scope,permissions,created_at,expires_at) VALUES \
         ('{}','{TENANT_ID}','live-reader','{}',NULL,'read,audit',{now},{});\n\
         INSERT INTO auth_tokens(id,tenant_id,subject,secret_sha256,repository_scope,permissions,created_at,expires_at) VALUES \
         ('{}','{TENANT_ID}','live-writer','{}',NULL,'write',{now},{});\n",
        tokens.admin.id,
        sha256_hex(&tokens.admin.secret),
        now + 3_600,
        tokens.read.id,
        sha256_hex(&tokens.read.secret),
        now + 3_600,
        tokens.write.id,
        sha256_hex(&tokens.write.secret),
        now + 3_600,
    );
    fs::write(&sql_path, sql).expect("write hash-only D1 seed SQL");
    run_wrangler(
        wrangler,
        service_root,
        &["d1", "execute", "DB", "--local", "--persist-to"],
        &[state, Path::new("--file"), &sql_path],
        "seed local D1 tenant and tokens",
    );
}

fn provision_root(
    wrangler: &Path,
    service_root: &Path,
    state: &Path,
    root: &Path,
    root_key: &SigningKey,
) {
    let sql_path = root.join(format!("root-{}.sql", Uuid::new_v4().simple()));
    let sql = format!(
        "INSERT INTO trust_root_keys(tenant_id,repository_id,root_key_id,public_key_hex,created_at) \
         VALUES ('{TENANT_ID}','{REPOSITORY_ID}','{ROOT_KEY_ID}','{}',{});\n",
        lower_hex(&root_key.verifying_key().to_bytes()),
        unix_seconds(),
    );
    fs::write(&sql_path, sql).expect("write nonsecret trust-root SQL");
    run_wrangler(
        wrangler,
        service_root,
        &["d1", "execute", "DB", "--local", "--persist-to"],
        &[state, Path::new("--file"), &sql_path],
        "provision local D1 trust root",
    );
}

fn run_d1_sql(
    wrangler: &Path,
    service_root: &Path,
    state: &Path,
    root: &Path,
    sql: &str,
    label: &str,
) {
    let sql_path = root.join(format!("query-{}.sql", Uuid::new_v4().simple()));
    fs::write(&sql_path, sql).expect("write live E2E D1 SQL");
    run_wrangler(
        wrangler,
        service_root,
        &["d1", "execute", "DB", "--local", "--persist-to"],
        &[state, Path::new("--file"), &sql_path],
        label,
    );
}

fn wait_for_health(http: &HttpHarness, endpoint: &str, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_observation = String::from("no response");
    while Instant::now() < deadline {
        let response = http.try_get(&format!("{endpoint}/v1/health"));
        last_observation = response.as_ref().map_or_else(
            |error| format!("transport error: {error}"),
            |response| {
                format!(
                    "status={} body={}",
                    response.status,
                    String::from_utf8_lossy(&response.body)
                )
            },
        );
        if response.as_ref().is_ok_and(|response| {
            response.status == StatusCode::OK
                && serde_json::from_slice::<Value>(&response.body)
                    .is_ok_and(|body| body["service"] == "again-cache")
        }) {
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("{label} health endpoint did not become ready: {last_observation}");
}

fn wait_for_public_dns(endpoint: &str) {
    let url = reqwest::Url::parse(endpoint).expect("parse Quick Tunnel origin");
    let host = url.host_str().expect("Quick Tunnel origin hostname");
    // Quick Tunnel registration can precede public wildcard DNS propagation
    // by more than two minutes. Keep the wait bounded, but long enough that a
    // freshly issued hostname is not misclassified as a product failure.
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut last_observation = String::from("no lookup attempted");
    while Instant::now() < deadline {
        match (host, 443).to_socket_addrs() {
            Ok(mut addresses) => {
                if addresses.next().is_some() {
                    return;
                }
                last_observation = "lookup returned no addresses".into();
            }
            Err(error) => last_observation = error.to_string(),
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("Quick Tunnel hostname {host} did not resolve: {last_observation}");
}

fn create_repository(http: &HttpHarness, endpoint: &str, admin: &Token) -> String {
    let response = http.request(
        Method::POST,
        &format!("{endpoint}/v1/repositories"),
        Some(admin),
        None,
        None,
        Some("application/json"),
        Some(
            serde_json::to_vec(&json!({ "repository_id": REPOSITORY_ID }))
                .expect("encode repository request"),
        ),
    );
    assert!(
        matches!(response.status, StatusCode::CREATED | StatusCode::OK),
        "create repository failed: {} {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    let generation = response.json()["generation_id"]
        .as_str()
        .expect("repository generation")
        .to_owned();
    assert_eq!(generation.len(), 32);
    assert_eq!(
        response
            .headers
            .get("x-again-repository-generation")
            .and_then(|value| value.to_str().ok()),
        Some(generation.as_str())
    );
    generation
}

fn register_producer(
    http: &HttpHarness,
    endpoint: &str,
    admin: &Token,
    generation: &str,
    producer_key: &SigningKey,
) {
    let response = http.request(
        Method::PUT,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}/producers/{PRODUCER_KEY_ID}"),
        Some(admin),
        Some(generation),
        None,
        Some("application/json"),
        Some(
            serde_json::to_vec(&json!({
                "producer_id": PRODUCER_ID,
                "public_key_hex": lower_hex(&producer_key.verifying_key().to_bytes()),
            }))
            .expect("encode producer registration"),
        ),
    );
    assert!(
        matches!(
            response.status,
            StatusCode::CREATED | StatusCode::NO_CONTENT
        ),
        "register producer failed: {} {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
}

fn digest_list(value: &Value, field: &str) -> Vec<Digest> {
    serde_json::from_value::<Vec<String>>(value[field].clone())
        .unwrap_or_else(|error| panic!("decode {field}: {error}"))
        .into_iter()
        .map(|digest| Digest::from_hex(&digest).expect("inspection emits strict digest"))
        .collect()
}

fn publish_fresh_trust(
    http: &HttpHarness,
    endpoint: &str,
    admin: &Token,
    generation: &str,
    inspection: &Value,
    root_key: &SigningKey,
    epoch: u64,
) {
    let requirements = &inspection["trust_requirements"];
    let public_key: [u8; 32] =
        serde_json::from_value(requirements["active_producer_keys"][0]["public_key"].clone())
            .expect("inspection producer public key");
    let issued = unix_seconds();
    let mut bundle = TrustBundleV1 {
        schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
        root_key_id: ROOT_KEY_ID.into(),
        tenant_id: TENANT_ID.into(),
        repository_id: REPOSITORY_ID.into(),
        generation_id: generation.into(),
        endpoint_origin: endpoint.into(),
        epoch,
        issued_at_unix_seconds: issued,
        expires_at_unix_seconds: issued + 300,
        active_producer_keys: vec![ProducerKeyBindingV1 {
            key_id: PRODUCER_KEY_ID.into(),
            producer_id: PRODUCER_ID.into(),
            public_key,
        }],
        revoked_key_ids: Vec::new(),
        revoked_record_ids: Vec::new(),
        allowed_policy_digests: digest_list(requirements, "allowed_policy_digests"),
        allowed_execution_profile_digests: digest_list(
            requirements,
            "allowed_execution_profile_digests",
        ),
        allowed_platform_digests: digest_list(requirements, "allowed_platform_digests"),
        allowed_image_digests: digest_list(requirements, "allowed_image_digests"),
        signature: Vec::new(),
    };
    bundle.signature = root_key
        .sign(&bundle.canonical_signing_bytes())
        .to_bytes()
        .to_vec();
    let response = http.request(
        Method::PUT,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}/trust-bundles/latest"),
        Some(admin),
        Some(generation),
        None,
        Some("application/json"),
        Some(serde_json::to_vec(&bundle).expect("encode signed trust bundle")),
    );
    assert!(
        matches!(
            response.status,
            StatusCode::CREATED | StatusCode::NO_CONTENT
        ),
        "publish trust failed: {} {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
}

fn get_manifest(
    http: &HttpHarness,
    endpoint: &str,
    read: &Token,
    generation: &str,
    request_key: &str,
) -> Value {
    let response = http.request(
        Method::GET,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}/manifests/{request_key}"),
        Some(read),
        Some(generation),
        None,
        None,
        None,
    );
    assert_eq!(
        response.status,
        StatusCode::OK,
        "get manifest failed: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

fn clone_runtime_checkpoint(source: &ClientFixture, destination: &ClientFixture) {
    assert!(source.runtime_checkpoint.is_file());
    fs::copy(&source.runtime_checkpoint, &destination.runtime_checkpoint)
        .expect("clone reviewed runtime checkpoint between isolated clients");
    set_mode(&destination.runtime_checkpoint, 0o600);
}

fn timed_output(command: &mut Command, label: &str) -> TimedOutput {
    let started = Instant::now();
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    TimedOutput {
        output,
        elapsed_micros: started.elapsed().as_micros().min(u64::MAX as u128) as u64,
    }
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed ({}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_exact_success(output: &Output, expected: &[u8], label: &str) {
    assert_success(output, label);
    assert_eq!(output.stdout, expected, "{label} changed stdout");
    assert!(output.stderr.is_empty(), "{label} changed stderr");
}

#[track_caller]
fn assert_event(client: &ClientFixture, disposition: &str, reason: &str) {
    let event = client.explain();
    assert_eq!(
        event["disposition"], disposition,
        "unexpected disposition; full explain event={event}"
    );
    assert_eq!(
        event["reason"], reason,
        "unexpected reason; full explain event={event}"
    );
}

fn native_latency_samples(workspace: &Path, command: &[&str], samples: usize) -> Vec<u64> {
    let mut output = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut process = Command::new(command[0]);
        process
            .current_dir(workspace)
            .env_clear()
            .env("PATH", audited_path())
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args(&command[1..]);
        let measured = timed_output(&mut process, "native latency sample");
        assert_exact_success(&measured.output, INPUT_BYTES, "native latency sample");
        output.push(measured.elapsed_micros);
    }
    output
}

fn latency_summary(samples: &[u64]) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |numerator: usize| {
        let index = (sorted.len() * numerator).div_ceil(100).saturating_sub(1);
        sorted[index.min(sorted.len() - 1)]
    };
    json!({
        "min": sorted[0],
        "p50": percentile(50),
        "p95": percentile(95),
        "max": sorted[sorted.len() - 1],
    })
}

fn corrupt_ciphertext(
    wrangler: &Path,
    service_root: &Path,
    state: &Path,
    root: &Path,
    generation: &str,
    manifest: &Value,
) {
    let digest = manifest["stdout"]["ciphertext_digest"]
        .as_str()
        .expect("stdout ciphertext digest");
    let sql = format!(
        "SELECT r2_key, incarnation_id, state FROM blobs \
         WHERE tenant_id = '{TENANT_ID}' AND repository_id = '{REPOSITORY_ID}' \
         AND digest = '{digest}'"
    );
    let mut query = Command::new(wrangler);
    query
        .current_dir(service_root)
        .args(["d1", "execute", "DB", "--local", "--persist-to"])
        .arg(state)
        .args(["--command", &sql, "--json"]);
    let query_output = query.output().expect("query live blob R2 identity");
    assert_success(&query_output, "query live blob R2 identity");
    let query_json: Value = serde_json::from_slice(&query_output.stdout)
        .expect("Wrangler D1 JSON output for live blob identity");
    let row = query_json
        .pointer("/0/results/0")
        .expect("one live blob identity row");
    assert_eq!(row["state"], "ready", "ciphertext blob must be ready");
    let incarnation = row["incarnation_id"]
        .as_str()
        .expect("live blob incarnation id");
    assert!(
        incarnation.len() == 32
            && incarnation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "live blob incarnation id is not canonical lowercase hex"
    );
    let r2_key = row["r2_key"].as_str().expect("live blob R2 key");
    assert_eq!(
        r2_key,
        format!("v1/{TENANT_ID}/{REPOSITORY_ID}/{generation}/blake3/{digest}/{incarnation}"),
        "D1 R2 identity does not match the expected immutable incarnation key"
    );

    let corrupt = root.join("corrupt-ciphertext.bin");
    fs::write(&corrupt, b"corrupt").expect("write corrupt ciphertext fixture");
    let object = format!("again-cache-blobs/{r2_key}");
    let object_path = PathBuf::from(object);
    run_wrangler(
        wrangler,
        service_root,
        &["r2", "object", "put"],
        &[
            &object_path,
            Path::new("--local"),
            Path::new("--persist-to"),
            state,
            Path::new("--file"),
            &corrupt,
            Path::new("--force"),
        ],
        "overwrite local R2 object with corrupt bytes",
    );

    let readback = root.join("corrupt-ciphertext-readback.bin");
    run_wrangler(
        wrangler,
        service_root,
        &["r2", "object", "get"],
        &[
            &object_path,
            Path::new("--local"),
            Path::new("--persist-to"),
            state,
            Path::new("--file"),
            &readback,
        ],
        "read back corrupt local R2 object",
    );
    assert_eq!(
        fs::read(readback).expect("read corrupt R2 readback"),
        b"corrupt",
        "R2 corruption helper did not mutate the exact live object"
    );
}

fn revoke_producer(http: &HttpHarness, endpoint: &str, admin: &Token, generation: &str) {
    let response = http.request(
        Method::DELETE,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}/producers/{PRODUCER_KEY_ID}"),
        Some(admin),
        Some(generation),
        None,
        None,
        None,
    );
    assert_eq!(
        response.status,
        StatusCode::NO_CONTENT,
        "revoke producer failed: {}",
        String::from_utf8_lossy(&response.body)
    );
}

fn delete_repository(http: &HttpHarness, endpoint: &str, admin: &Token, generation: &str) {
    let response = http.request(
        Method::DELETE,
        &format!("{endpoint}/v1/repositories/{REPOSITORY_ID}"),
        Some(admin),
        None,
        Some(generation),
        None,
        None,
    );
    assert_eq!(
        response.status,
        StatusCode::ACCEPTED,
        "delete repository failed: {}",
        String::from_utf8_lossy(&response.body)
    );
}

fn complete_repository_deletion(
    http: &HttpHarness,
    endpoint: &str,
    wrangler: &Path,
    service_root: &Path,
    state: &Path,
    root: &Path,
) {
    // The production state machine requires two empty R2 observations 60
    // seconds apart. Drive the first observation through the real scheduled
    // handler, then advance only the persisted test timestamps by 61 seconds.
    // Every R2/D1 phase and final guarded deletion still runs through Worker
    // code; this avoids a wall-clock sleep in a manual integration gate.
    for _ in 0..4 {
        let response = http.request(
            Method::GET,
            &format!("{endpoint}/__scheduled?cron=%2A%2F15%20%2A%20%2A%20%2A%20%2A"),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            response.status.is_success(),
            "scheduled repository deletion pass failed: {}",
            response.status
        );
        thread::sleep(Duration::from_millis(100));
    }
    run_d1_sql(
        wrangler,
        service_root,
        state,
        root,
        "UPDATE repository_deletions \
         SET requested_at = requested_at - 61, last_empty_at = last_empty_at - 61, \
             next_attempt_at = 0 \
         WHERE tenant_id = 'live-tenant' AND repository_id = 'live-repository' \
           AND phase = 'r2' AND empty_confirmations = 1 AND last_empty_at IS NOT NULL;",
        "advance live E2E repository deletion confirmation clock",
    );
    for _ in 0..8 {
        let response = http.request(
            Method::GET,
            &format!("{endpoint}/__scheduled?cron=%2A%2F15%20%2A%20%2A%20%2A%20%2A"),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(response.status.is_success());
        thread::sleep(Duration::from_millis(100));
    }
    run_d1_sql(
        wrangler,
        service_root,
        state,
        root,
        "INSERT INTO tenants(id,name,quota_bytes,metadata_quota_units,created_at) \
         SELECT 'live-tenant','repository-not-finalized',0,0,0 \
         WHERE EXISTS(SELECT 1 FROM repositories \
         WHERE tenant_id = 'live-tenant' AND id = 'live-repository');",
        "prove live E2E repository deletion finalized",
    );
}
