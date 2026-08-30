//! Typed, bounded task definitions and lifecycle values.
//!
//! These values describe durable local coordination state. They do not carry
//! authorization: every store operation still requires the exact repository,
//! workspace, and authorization scope selected by the authenticated transport.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub const MAX_TASK_PROMPT_BYTES_V1: usize = 8 * 1024;
pub const MAX_TASK_ACCEPTANCE_CRITERIA_V1: usize = 32;
pub const MAX_TASK_ACCEPTANCE_CRITERION_BYTES_V1: usize = 512;
pub const MAX_TASK_DEPENDENCIES_V1: usize = 64;
pub const MAX_TASK_GRAPH_DEPTH_V1: usize = 32;
pub const MAX_TASK_LIST_ITEMS_V1: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStateV1 {
    Waiting,
    Active,
    Blocked,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStateV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Active => "active",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "waiting" => Self::Waiting,
            "active" => Self::Active,
            "blocked" => Self::Blocked,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => bail!("invalid_task_state"),
        })
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRelationKindV1 {
    Parent,
    Dependency,
    Supersedes,
}

impl TaskRelationKindV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::Dependency => "dependency",
            Self::Supersedes => "supersedes",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "parent" => Self::Parent,
            "dependency" => Self::Dependency,
            "supersedes" => Self::Supersedes,
            _ => bail!("invalid_task_relation_kind"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDefinitionV1 {
    prompt: String,
    acceptance_criteria: Vec<String>,
    parent_task_id: Option<String>,
    dependency_task_ids: Vec<String>,
    supersedes_task_id: Option<String>,
    definition_digest: String,
}

impl TaskDefinitionV1 {
    pub fn new(
        prompt: &str,
        acceptance_criteria: Vec<String>,
        parent_task_id: Option<String>,
        mut dependency_task_ids: Vec<String>,
        supersedes_task_id: Option<String>,
    ) -> Result<Self> {
        validate_task_text_v1(prompt, MAX_TASK_PROMPT_BYTES_V1, "invalid_task_description")?;
        screen_sensitive_text_v1(prompt)?;
        if acceptance_criteria.len() > MAX_TASK_ACCEPTANCE_CRITERIA_V1 {
            bail!("task_acceptance_capacity_exceeded");
        }
        for criterion in &acceptance_criteria {
            validate_task_text_v1(
                criterion,
                MAX_TASK_ACCEPTANCE_CRITERION_BYTES_V1,
                "invalid_acceptance_criterion",
            )?;
            screen_sensitive_text_v1(criterion)?;
        }
        if acceptance_criteria
            .iter()
            .enumerate()
            .any(|(index, criterion)| acceptance_criteria[..index].contains(criterion))
        {
            bail!("duplicate_acceptance_criterion");
        }
        if dependency_task_ids.len() > MAX_TASK_DEPENDENCIES_V1 {
            bail!("task_dependency_capacity_exceeded");
        }
        if let Some(parent) = parent_task_id.as_deref() {
            validate_task_selector_v1(parent)?;
        }
        if let Some(supersedes) = supersedes_task_id.as_deref() {
            validate_task_selector_v1(supersedes)?;
        }
        for dependency in &dependency_task_ids {
            validate_task_selector_v1(dependency)?;
        }
        dependency_task_ids.sort();
        if dependency_task_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            bail!("duplicate_task_dependency");
        }
        let definition_digest = task_definition_digest_v1(
            prompt,
            &acceptance_criteria,
            parent_task_id.as_deref(),
            &dependency_task_ids,
            supersedes_task_id.as_deref(),
        );
        Ok(Self {
            prompt: prompt.to_owned(),
            acceptance_criteria,
            parent_task_id,
            dependency_task_ids,
            supersedes_task_id,
            definition_digest,
        })
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }
    pub fn acceptance_criteria(&self) -> &[String] {
        &self.acceptance_criteria
    }
    pub fn parent_task_id(&self) -> Option<&str> {
        self.parent_task_id.as_deref()
    }
    pub fn dependency_task_ids(&self) -> &[String] {
        &self.dependency_task_ids
    }
    pub fn supersedes_task_id(&self) -> Option<&str> {
        self.supersedes_task_id.as_deref()
    }
    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBlockerV1 {
    pub task_id: String,
    pub state: TaskStateV1,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecordV1 {
    pub canonical_task_id: String,
    pub requested_task_id: String,
    pub definition: TaskDefinitionV1,
    pub revision: u64,
    pub state: TaskStateV1,
    pub state_generation: u64,
    pub blockers: Vec<TaskBlockerV1>,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskTransitionV1 {
    pub sequence: u64,
    pub task_id: String,
    pub from_state: Option<TaskStateV1>,
    pub to_state: TaskStateV1,
    pub state_generation: u64,
    pub lease_id: Option<String>,
    pub reason: String,
    pub created_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum TaskClaimOutcomeV1 {
    Leader {
        lease_id: String,
        lease_generation: u64,
        state_generation: u64,
        expires_at_ms: i64,
    },
    Join {
        lease_id: String,
        lease_generation: u64,
        state_generation: u64,
        leader_agent_id: String,
        expires_at_ms: i64,
    },
    Waiting {
        state_generation: u64,
        blockers: Vec<TaskBlockerV1>,
    },
    Terminal {
        state: TaskStateV1,
        state_generation: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskExportV1 {
    pub task: TaskRecordV1,
    pub aliases: Vec<String>,
    pub transitions: Vec<TaskTransitionV1>,
}

pub fn validate_task_selector_v1(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b' ')
        })
    {
        bail!("invalid_context_task_selector");
    }
    Ok(())
}

/// Deterministic admission screen for agent-authored durable text.
///
/// This intentionally recognizes only credential-shaped material. It does not
/// attempt semantic classification and never returns the rejected content.
pub fn screen_sensitive_text_v1(value: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin openssh private key-----",
        "authorization: bearer ",
        "aws_secret_access_key=",
        "aws_secret_access_key:",
        "client_secret=",
        "private_key=",
        "password=",
        "password:",
        "api_key=",
        "api-key:",
    ];
    if MARKERS.iter().any(|marker| lower.contains(marker))
        || has_prefixed_secret_v1(value, "sk-", 16)
        || has_prefixed_secret_v1(value, "ghp_", 20)
        || has_prefixed_secret_v1(value, "github_pat_", 20)
        || has_aws_access_key_v1(value)
        || has_url_credentials_v1(value)
    {
        bail!("sensitive_content_refused");
    }
    Ok(())
}

pub(crate) fn task_definition_digest_v1(
    prompt: &str,
    acceptance_criteria: &[String],
    parent_task_id: Option<&str>,
    dependency_task_ids: &[String],
    supersedes_task_id: Option<&str>,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.task-definition.v1\0");
    hash_field_v1(&mut hasher, prompt.as_bytes());
    hasher.update(&(acceptance_criteria.len() as u64).to_le_bytes());
    for criterion in acceptance_criteria {
        hash_field_v1(&mut hasher, criterion.as_bytes());
    }
    hash_optional_v1(&mut hasher, parent_task_id);
    hasher.update(&(dependency_task_ids.len() as u64).to_le_bytes());
    for dependency in dependency_task_ids {
        hash_field_v1(&mut hasher, dependency.as_bytes());
    }
    hash_optional_v1(&mut hasher, supersedes_task_id);
    hasher.finalize().to_hex().to_string()
}

fn validate_task_text_v1(value: &str, maximum: usize, code: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character != '\n' && character != '\t' && character.is_control())
    {
        bail!(code);
    }
    Ok(())
}

fn has_prefixed_secret_v1(value: &str, prefix: &str, minimum_suffix: usize) -> bool {
    value.match_indices(prefix).any(|(offset, _)| {
        value[offset + prefix.len()..]
            .bytes()
            .take_while(u8::is_ascii_alphanumeric)
            .take(minimum_suffix)
            .count()
            == minimum_suffix
    })
}

fn has_aws_access_key_v1(value: &str) -> bool {
    value.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn has_url_credentials_v1(value: &str) -> bool {
    value.split_ascii_whitespace().any(|word| {
        let Some(scheme) = word.find("://") else {
            return false;
        };
        let authority = &word[scheme + 3..];
        let end = authority.find('/').unwrap_or(authority.len());
        authority[..end].contains('@') && authority[..end].contains(':')
    })
}

fn hash_optional_v1(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hash_field_v1(hasher, value.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn hash_field_v1(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_digest_binds_every_field_and_sorts_dependencies() {
        let first = TaskDefinitionV1::new(
            "Implement the lifecycle",
            vec!["Transitions are CAS checked".to_owned()],
            Some("parent".to_owned()),
            vec!["dep-b".to_owned(), "dep-a".to_owned()],
            Some("revision-one".to_owned()),
        )
        .unwrap();
        let reordered = TaskDefinitionV1::new(
            "Implement the lifecycle",
            vec!["Transitions are CAS checked".to_owned()],
            Some("parent".to_owned()),
            vec!["dep-a".to_owned(), "dep-b".to_owned()],
            Some("revision-one".to_owned()),
        )
        .unwrap();
        assert_eq!(first.definition_digest(), reordered.definition_digest());

        for changed in [
            TaskDefinitionV1::new(
                "Different prompt",
                vec!["Transitions are CAS checked".to_owned()],
                Some("parent".to_owned()),
                vec!["dep-a".to_owned(), "dep-b".to_owned()],
                Some("revision-one".to_owned()),
            )
            .unwrap(),
            TaskDefinitionV1::new(
                "Implement the lifecycle",
                vec!["Different criterion".to_owned()],
                Some("parent".to_owned()),
                vec!["dep-a".to_owned(), "dep-b".to_owned()],
                Some("revision-one".to_owned()),
            )
            .unwrap(),
            TaskDefinitionV1::new(
                "Implement the lifecycle",
                vec!["Transitions are CAS checked".to_owned()],
                None,
                vec!["dep-a".to_owned(), "dep-b".to_owned()],
                Some("revision-one".to_owned()),
            )
            .unwrap(),
        ] {
            assert_ne!(first.definition_digest(), changed.definition_digest());
        }
    }

    #[test]
    fn credential_shaped_text_is_refused_without_echoing_it() {
        for secret in [
            "password=hunter2",
            "Authorization: Bearer abcdef",
            "AKIAABCDEFGHIJKLMNOP",
            "https://user:pass@example.test/repo",
            "sk-abcdefghijklmnopqrstuvwxyz",
        ] {
            let error = screen_sensitive_text_v1(secret).unwrap_err();
            assert_eq!(error.to_string(), "sensitive_content_refused");
            assert!(!error.to_string().contains(secret));
        }
        screen_sensitive_text_v1("verify that password fields are rejected").unwrap();
    }

    #[test]
    fn transition_state_parsing_is_closed() {
        for state in [
            TaskStateV1::Waiting,
            TaskStateV1::Active,
            TaskStateV1::Blocked,
            TaskStateV1::Completed,
            TaskStateV1::Failed,
            TaskStateV1::Cancelled,
        ] {
            assert_eq!(TaskStateV1::parse(state.code()).unwrap(), state);
        }
        assert!(TaskStateV1::parse("done").is_err());
    }
}
