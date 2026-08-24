//! Monotonic, injectable wall-clock sampling for team-cache trust boundaries.

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::team::MAX_JSON_SAFE_INTEGER;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum TeamClockError {
    #[error("system clock is before the Unix epoch")]
    BeforeUnixEpoch,
    #[error("system clock exceeds the shared JSON safe-integer range")]
    OutOfRange,
    #[error("system clock moved backwards from {previous} to {current}")]
    Rollback { previous: u64, current: u64 },
    #[cfg(test)]
    #[error("test clock has no remaining samples")]
    Exhausted,
}

/// Every trust, decrypt, and presentation boundary samples through this trait.
/// Implementations must reject backwards time so a retained capability cannot
/// regain freshness after it was checked at a later instant.
pub(crate) trait TeamClock {
    fn sample_unix_seconds(&mut self) -> Result<u64, TeamClockError>;
}

#[derive(Default)]
pub(crate) struct SystemTeamClock {
    last_sample: Option<u64>,
}

impl SystemTeamClock {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl TeamClock for SystemTeamClock {
    fn sample_unix_seconds(&mut self) -> Result<u64, TeamClockError> {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TeamClockError::BeforeUnixEpoch)?
            .as_secs();
        validate_monotonic_sample(&mut self.last_sample, current)
    }
}

fn validate_monotonic_sample(
    last_sample: &mut Option<u64>,
    current: u64,
) -> Result<u64, TeamClockError> {
    if current > MAX_JSON_SAFE_INTEGER {
        return Err(TeamClockError::OutOfRange);
    }
    if let Some(previous) = *last_sample
        && current < previous
    {
        return Err(TeamClockError::Rollback { previous, current });
    }
    *last_sample = Some(current);
    Ok(current)
}

#[cfg(test)]
pub(crate) struct SequenceTeamClock {
    samples: std::collections::VecDeque<u64>,
    last_sample: Option<u64>,
}

#[cfg(test)]
impl SequenceTeamClock {
    pub(crate) fn new(samples: impl IntoIterator<Item = u64>) -> Self {
        Self {
            samples: samples.into_iter().collect(),
            last_sample: None,
        }
    }
}

#[cfg(test)]
impl TeamClock for SequenceTeamClock {
    fn sample_unix_seconds(&mut self) -> Result<u64, TeamClockError> {
        let current = self.samples.pop_front().ok_or(TeamClockError::Exhausted)?;
        validate_monotonic_sample(&mut self.last_sample, current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_clock_accepts_equal_or_increasing_samples() {
        let mut clock = SequenceTeamClock::new([10, 10, 11]);
        assert_eq!(clock.sample_unix_seconds(), Ok(10));
        assert_eq!(clock.sample_unix_seconds(), Ok(10));
        assert_eq!(clock.sample_unix_seconds(), Ok(11));
    }

    #[test]
    fn sequence_clock_rejects_rollback_and_out_of_range_values() {
        let mut rollback = SequenceTeamClock::new([11, 10]);
        assert_eq!(rollback.sample_unix_seconds(), Ok(11));
        assert_eq!(
            rollback.sample_unix_seconds(),
            Err(TeamClockError::Rollback {
                previous: 11,
                current: 10,
            })
        );

        let mut huge = SequenceTeamClock::new([MAX_JSON_SAFE_INTEGER + 1]);
        assert_eq!(huge.sample_unix_seconds(), Err(TeamClockError::OutOfRange));
    }
}
