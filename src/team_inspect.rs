//! Deterministic, non-executing bootstrap inspection for team-cache trust.
//!
//! This path stops after the exact local admission shared with `team run`.
//! It never constructs a remote client and never enters capture or fallback.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::fingerprint::SessionFileDigestCache;
use crate::privacy::publication_classifier_digest_v1;
use crate::store::Store;
use crate::team::Digest;
use crate::team_admission::{TeamAdmission, admit_team_command, preflight_team_command};
use crate::team_config::{TeamLookupProtocolV1, load_producer_signer};
use crate::team_request_key::TeamRequestKeyV1;
use crate::trust_bundle::{MAX_TRUST_BUNDLE_LIFETIME_SECONDS, TRUST_BUNDLE_SCHEMA_VERSION};

const INSPECTION_SCHEMA_VERSION: u16 = 1;
const INSPECTION_NAMESPACE: &str = "again.team-inspection.v1";

#[derive(Debug, Serialize, PartialEq, Eq)]
struct TeamInspectionV1 {
    schema_version: u16,
    namespace: &'static str,
    lookup_protocol: TeamLookupProtocolV1,
    scope: InspectionScopeV1,
    request: InspectionRequestV1,
    producer: InspectionProducerV1,
    trust_requirements: TrustRequirementsV1,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct InspectionScopeV1 {
    endpoint_origin: String,
    tenant_id: String,
    repository_id: String,
    generation_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct InspectionRequestV1 {
    request_key: String,
    policy_digest: String,
    classifier_digest: String,
    execution_profile_digest: String,
    platform_digest: String,
    image_digest: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct InspectionProducerV1 {
    producer_id: String,
    key_id: String,
    public_key_hex: String,
}

/// Authenticated fields the offline signer must copy into a fresh trust bundle.
/// Epoch, issue/expiry time, and signature are intentionally absent so output
/// remains deterministic and cannot be mistaken for an already valid bundle.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct TrustRequirementsV1 {
    trust_bundle_schema_version: u16,
    max_lifetime_seconds: u64,
    root_key_id: String,
    tenant_id: String,
    repository_id: String,
    generation_id: String,
    endpoint_origin: String,
    active_producer_keys: Vec<TrustProducerKeyV1>,
    revoked_key_ids: Vec<String>,
    revoked_record_ids: Vec<String>,
    allowed_policy_digests: Vec<String>,
    allowed_execution_profile_digests: Vec<String>,
    allowed_platform_digests: Vec<String>,
    allowed_image_digests: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct TrustProducerKeyV1 {
    key_id: String,
    producer_id: String,
    public_key: [u8; 32],
}

/// Inspect one exact team request without transport or target execution.
pub(crate) fn inspect(profile_path: PathBuf, command: Vec<OsString>, json: bool) -> Result<i32> {
    if !json {
        bail!("team inspection requires --json");
    }

    let preflight = preflight_team_command(profile_path, command)?;
    let mut persistent_digest_cache = Store::open_for_workspace(preflight.workspace())
        .context("open strong team file-digest cache")?;
    let mut digest_cache = SessionFileDigestCache::new(&mut persistent_digest_cache);
    let admission = admit_team_command(preflight, &mut digest_cache)?;
    let remote_admission = admission.remote_request_admission().map_err(|_| {
        anyhow::anyhow!("team request is local-only under its repository sharing policy")
    })?;
    if !remote_admission.matches(admission.sharing_policy(), admission.request()) {
        bail!("team request privacy admission no longer matches the sealed request");
    }
    let signer = load_producer_signer(admission.profile())
        .context("load producer identity for team inspection")?;
    let signer = signer.signer();
    let document = inspection_document(
        &admission,
        signer.key_id(),
        signer.producer_id(),
        signer.public_key_bytes(),
    );

    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &document).context("serialize strict team inspection")?;
    stdout.write_all(b"\n").context("write team inspection")?;
    stdout.flush().context("flush team inspection")?;
    Ok(0)
}

fn inspection_document(
    admission: &TeamAdmission,
    key_id: &str,
    producer_id: &str,
    public_key: [u8; 32],
) -> TeamInspectionV1 {
    let request = inspection_request(admission.request(), publication_classifier_digest_v1());
    let descriptor = admission.request().descriptor();
    let scope = InspectionScopeV1 {
        endpoint_origin: admission.profile().endpoint_origin().to_owned(),
        tenant_id: descriptor.tenant_id().to_owned(),
        repository_id: descriptor.repository_id().to_owned(),
        generation_id: descriptor.generation_id().to_owned(),
    };
    let producer = InspectionProducerV1 {
        producer_id: producer_id.to_owned(),
        key_id: key_id.to_owned(),
        public_key_hex: lower_hex(&public_key),
    };
    let trust_requirements = TrustRequirementsV1 {
        trust_bundle_schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
        max_lifetime_seconds: MAX_TRUST_BUNDLE_LIFETIME_SECONDS,
        root_key_id: admission.profile().pinned_root().key_id().to_owned(),
        tenant_id: scope.tenant_id.clone(),
        repository_id: scope.repository_id.clone(),
        generation_id: scope.generation_id.clone(),
        endpoint_origin: scope.endpoint_origin.clone(),
        active_producer_keys: vec![TrustProducerKeyV1 {
            key_id: key_id.to_owned(),
            producer_id: producer_id.to_owned(),
            public_key,
        }],
        revoked_key_ids: Vec::new(),
        revoked_record_ids: Vec::new(),
        allowed_policy_digests: vec![request.policy_digest.clone()],
        allowed_execution_profile_digests: vec![request.execution_profile_digest.clone()],
        allowed_platform_digests: vec![request.platform_digest.clone()],
        allowed_image_digests: vec![request.image_digest.clone()],
    };
    TeamInspectionV1 {
        schema_version: INSPECTION_SCHEMA_VERSION,
        namespace: INSPECTION_NAMESPACE,
        lookup_protocol: admission.profile().lookup_protocol(),
        scope,
        request,
        producer,
        trust_requirements,
    }
}

fn inspection_request(
    request: &TeamRequestKeyV1,
    classifier_digest: Digest,
) -> InspectionRequestV1 {
    let descriptor = request.descriptor();
    InspectionRequestV1 {
        request_key: request.digest().to_hex(),
        policy_digest: descriptor.policy_digest().to_hex(),
        classifier_digest: classifier_digest.to_hex(),
        execution_profile_digest: descriptor.execution_profile_digest().to_hex(),
        platform_digest: descriptor.platform_digest().to_hex(),
        image_digest: descriptor.image_digest().to_hex(),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::team_request_key::{TeamRequestKeyInput, build_team_request_key_v1};

    fn digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}{}", "00".repeat(31))).unwrap()
    }

    fn request_fixture(temp: &TempDir) -> TeamRequestKeyV1 {
        fs::write(
            temp.path().join("selected.txt"),
            b"stable inspection input\n",
        )
        .unwrap();
        let argv = [OsString::from("cat"), OsString::from("selected.txt")];
        let environment = [
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
        ];
        build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: "tenant-a",
            repository_id: "repo-a",
            generation_id: "0123456789abcdef0123456789abcdef",
            workspace: temp.path(),
            cwd: temp.path(),
            argv: &argv,
            environment: &environment,
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: digest(1),
            execution_profile_digest: digest(2),
            platform_digest: digest(3),
            image_digest: digest(4),
        })
        .unwrap()
    }

    #[test]
    fn request_output_is_exactly_derived_from_the_sealed_run_descriptor() {
        let temp = TempDir::new().unwrap();
        let sealed = request_fixture(&temp);
        let output = inspection_request(&sealed, digest(5));
        let descriptor = sealed.descriptor();

        assert_eq!(output.request_key, sealed.digest().to_hex());
        assert_eq!(output.policy_digest, descriptor.policy_digest().to_hex());
        assert_eq!(
            output.execution_profile_digest,
            descriptor.execution_profile_digest().to_hex()
        );
        assert_eq!(
            output.platform_digest,
            descriptor.platform_digest().to_hex()
        );
        assert_eq!(output.image_digest, descriptor.image_digest().to_hex());
        assert_eq!(output.classifier_digest, digest(5).to_hex());
    }

    #[test]
    fn deterministic_json_has_no_secret_or_signing_placeholders() {
        let scope = InspectionScopeV1 {
            endpoint_origin: "https://cache.example.test".into(),
            tenant_id: "tenant-a".into(),
            repository_id: "repo-a".into(),
            generation_id: "0123456789abcdef0123456789abcdef".into(),
        };
        let request = InspectionRequestV1 {
            request_key: digest(1).to_hex(),
            policy_digest: digest(2).to_hex(),
            classifier_digest: digest(3).to_hex(),
            execution_profile_digest: digest(4).to_hex(),
            platform_digest: digest(5).to_hex(),
            image_digest: digest(6).to_hex(),
        };
        let producer = InspectionProducerV1 {
            producer_id: "producer-a".into(),
            key_id: "key-a".into(),
            public_key_hex: lower_hex(&[7; 32]),
        };
        let document = TeamInspectionV1 {
            schema_version: INSPECTION_SCHEMA_VERSION,
            namespace: INSPECTION_NAMESPACE,
            lookup_protocol: TeamLookupProtocolV1::LegacyV2,
            scope: scope.clone(),
            request: request.clone(),
            producer,
            trust_requirements: TrustRequirementsV1 {
                trust_bundle_schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
                max_lifetime_seconds: MAX_TRUST_BUNDLE_LIFETIME_SECONDS,
                root_key_id: "root-a".into(),
                tenant_id: scope.tenant_id,
                repository_id: scope.repository_id,
                generation_id: scope.generation_id,
                endpoint_origin: scope.endpoint_origin,
                active_producer_keys: vec![TrustProducerKeyV1 {
                    key_id: "key-a".into(),
                    producer_id: "producer-a".into(),
                    public_key: [7; 32],
                }],
                revoked_key_ids: Vec::new(),
                revoked_record_ids: Vec::new(),
                allowed_policy_digests: vec![request.policy_digest],
                allowed_execution_profile_digests: vec![request.execution_profile_digest],
                allowed_platform_digests: vec![request.platform_digest],
                allowed_image_digests: vec![request.image_digest],
            },
        };

        let first = serde_json::to_vec(&document).unwrap();
        let second = serde_json::to_vec(&document).unwrap();
        assert_eq!(first, second);
        let text = String::from_utf8(first).unwrap();
        for forbidden in [
            "ag1.secret-token-material",
            "repository-key-secret",
            "producer-private-key-secret",
            "secret_key",
            "token_file",
            "repository_key_file",
            "signing_key_file",
            "runtime_attestation_checkpoint_file",
            "sharing_policy_file",
            "issued_at_unix_seconds",
            "expires_at_unix_seconds",
            "signature",
            "environment",
            "workspace",
        ] {
            assert!(!text.contains(forbidden), "inspection leaked {forbidden}");
        }
    }
}
