//! Non-authoritative lifecycle contracts for future execution profiles.
//!
//! The values here describe ordering only. They are deliberately not accepted
//! by the router as hit, storage, or execution authority.

use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileLifecycleStageV1 {
    ExecuteOnly,
    Candidate,
    IndependentShadow,
    Promoted,
    FreshlyValidatedHit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileLifecycleTransitionV1 {
    CompleteCandidate,
    CompleteIndependentShadow,
    PromoteExactAgreement,
    FreshlyValidate,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProfileLifecycleRefusalV1 {
    #[error("invalid_lifecycle_transition")]
    InvalidTransition,
}

/// Linear contract tracker. Its private stage prevents direct construction of
/// a promoted or hit state; each transition consumes the prior value.
#[derive(Debug, PartialEq, Eq)]
pub struct ProfileLifecycleV1 {
    stage: ProfileLifecycleStageV1,
}

impl ProfileLifecycleV1 {
    pub const fn execute_only() -> Self {
        Self {
            stage: ProfileLifecycleStageV1::ExecuteOnly,
        }
    }

    pub const fn stage(&self) -> ProfileLifecycleStageV1 {
        self.stage
    }

    pub fn transition(
        self,
        transition: ProfileLifecycleTransitionV1,
    ) -> Result<Self, ProfileLifecycleRefusalV1> {
        let stage = match (self.stage, transition) {
            (
                ProfileLifecycleStageV1::ExecuteOnly,
                ProfileLifecycleTransitionV1::CompleteCandidate,
            ) => ProfileLifecycleStageV1::Candidate,
            (
                ProfileLifecycleStageV1::Candidate,
                ProfileLifecycleTransitionV1::CompleteIndependentShadow,
            ) => ProfileLifecycleStageV1::IndependentShadow,
            (
                ProfileLifecycleStageV1::IndependentShadow,
                ProfileLifecycleTransitionV1::PromoteExactAgreement,
            ) => ProfileLifecycleStageV1::Promoted,
            (ProfileLifecycleStageV1::Promoted, ProfileLifecycleTransitionV1::FreshlyValidate) => {
                ProfileLifecycleStageV1::FreshlyValidatedHit
            }
            _ => return Err(ProfileLifecycleRefusalV1::InvalidTransition),
        };
        Ok(Self { stage })
    }
}
