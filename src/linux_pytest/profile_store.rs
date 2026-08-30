//! Durable, portable control-plane storage for `linux-pytest-v1`.
//!
//! This module never launches a command. It persists only already-verified
//! EffectIR objects, keeps execute-only rows out of lookup, performs the
//! primary/shadow promotion transaction with compare-and-swap semantics, and
//! requires a freshly reconstructed observation closure before minting a
//! one-use hit. Native execution remains behind the separate Linux gate.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use super::{
    CanonicalEffectRecordV2, ClassKey, EffectRecordDispositionV2, EpochNs,
    LinuxPytestContractError, MonotonicNs, ProfileFailure, PromotedCandidateV2, PromotedLookupV2,
    PromotedPairV2, PromotionGcReportV2, PromotionStore, QuarantineCode, RecordId,
    RevalidatedObservationClosureV1, ShadowJobId, ShadowJobV2, ShadowTerminalCode, ShapeKey,
    SnapshotId, VerifiedCandidateRecordV2, VerifiedExecutionRecordV2, VerifiedSnapshotManifestV1,
};
use crate::workspace_authority::{
    ManifestDependentKindV1, ManifestDependentV1, ObservedManifestInvalidationV1, StateDigestV1,
};

const STORE_SCHEMA_V1: &str = "again.linux-pytest.profile-store.v1";
const VALIDATION_DEPENDENT_DOMAIN_V1: &[u8] = b"again linux pytest validation dependent v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteOnlyStorageReceiptV1 {
    pub(crate) record_id: RecordId,
    pub(crate) reusable: bool,
    pub(crate) candidate: bool,
    pub(crate) shadow: bool,
    pub(crate) promoted: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PytestInvalidationReportV1 {
    pub(crate) retired_promotions: u64,
}

/// A non-serializable, single-use token. A promotion row or request key alone
/// cannot construct this value.
pub(crate) struct FreshlyValidatedPytestHitV1 {
    candidate: PromotedCandidateV2,
}

/// Opaque evidence that the fixed isolated `import pytest` probe completed on
/// the same fresh validation snapshot. F1 has no production issuer; F2's
/// native connector must add the sole issuer after qualification.
pub(crate) struct FreshPythonCapabilityWitnessV1 {
    snapshot_id: SnapshotId,
}

impl FreshPythonCapabilityWitnessV1 {
    #[cfg(test)]
    pub(super) fn for_test(validation: &RevalidatedObservationClosureV1) -> Self {
        Self {
            snapshot_id: validation.snapshot().identity().snapshot_id,
        }
    }
}

impl FreshlyValidatedPytestHitV1 {
    pub(crate) fn consume(self) -> PromotedCandidateV2 {
        self.candidate
    }
}

/// Durable profile-private state. It is intentionally not exported by the
/// crate and contains no argv, process, shell, or generic execution surface.
pub(crate) struct SqlitePytestProfileStoreV1 {
    connection: Connection,
}

impl SqlitePytestProfileStoreV1 {
    pub(crate) fn open(path: &Path) -> Result<Self, ProfileFailure> {
        let connection = Connection::open(path).map_err(|_| durable_failure())?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| durable_failure())?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| durable_failure())?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| durable_failure())?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| durable_failure())?;
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS pytest_profile_metadata_v1 (
                    schema TEXT PRIMARY KEY
                ) WITHOUT ROWID;
                INSERT OR IGNORE INTO pytest_profile_metadata_v1(schema)
                    VALUES ('again.linux-pytest.profile-store.v1');

                CREATE TABLE IF NOT EXISTS pytest_records_v1 (
                    record_id BLOB PRIMARY KEY CHECK(length(record_id) = 16),
                    disposition INTEGER NOT NULL CHECK(disposition IN (1, 2, 3)),
                    shape_key BLOB NOT NULL CHECK(length(shape_key) = 32),
                    request_key BLOB NOT NULL CHECK(length(request_key) = 32),
                    primary_record_id BLOB CHECK(primary_record_id IS NULL OR length(primary_record_id) = 16),
                    record_bytes BLOB NOT NULL,
                    manifest_bytes BLOB,
                    CHECK((disposition = 1) = (manifest_bytes IS NULL)),
                    CHECK((disposition = 3) = (primary_record_id IS NOT NULL))
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS pytest_shadow_jobs_v1 (
                    job_id BLOB PRIMARY KEY CHECK(length(job_id) = 16),
                    primary_record_id BLOB NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'promoted', 'failed')),
                    failure_code INTEGER,
                    FOREIGN KEY(primary_record_id) REFERENCES pytest_records_v1(record_id)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS pytest_promotions_v1 (
                    shape_key BLOB NOT NULL CHECK(length(shape_key) = 32),
                    request_key BLOB NOT NULL CHECK(length(request_key) = 32),
                    primary_record_id BLOB NOT NULL UNIQUE,
                    shadow_record_id BLOB NOT NULL UNIQUE,
                    comparison_digest BLOB NOT NULL CHECK(length(comparison_digest) = 32),
                    class_key BLOB NOT NULL CHECK(length(class_key) = 32),
                    validation_dependent BLOB NOT NULL CHECK(length(validation_dependent) = 32),
                    promoted_monotonic_ns INTEGER NOT NULL CHECK(promoted_monotonic_ns > 0),
                    retired_reason TEXT,
                    PRIMARY KEY(shape_key, request_key),
                    FOREIGN KEY(primary_record_id) REFERENCES pytest_records_v1(record_id),
                    FOREIGN KEY(shadow_record_id) REFERENCES pytest_records_v1(record_id)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS pytest_promotions_lookup_v1
                    ON pytest_promotions_v1(shape_key, promoted_monotonic_ns DESC)
                    WHERE retired_reason IS NULL;

                CREATE TABLE IF NOT EXISTS pytest_quarantine_v1 (
                    class_key BLOB PRIMARY KEY CHECK(length(class_key) = 32),
                    first_record_id BLOB NOT NULL CHECK(length(first_record_id) = 16),
                    reason INTEGER NOT NULL
                ) WITHOUT ROWID;
                "#,
            )
            .map_err(|_| durable_failure())?;
        let schema = connection
            .query_row(
                "SELECT schema FROM pytest_profile_metadata_v1 LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| durable_failure())?;
        if schema != STORE_SCHEMA_V1 {
            return Err(ProfileFailure::Quarantined {
                code: QuarantineCode::UnknownSchema,
            });
        }
        Ok(Self { connection })
    }

    pub(crate) fn record_execute_only(
        &mut self,
        execution: &VerifiedExecutionRecordV2,
    ) -> Result<ExecuteOnlyStorageReceiptV1, ProfileFailure> {
        let VerifiedExecutionRecordV2::ExecutedOnly(canonical) = execution else {
            return Err(ProfileFailure::Shadow {
                code: ShadowTerminalCode::PrimaryIneligible,
            });
        };
        let record = canonical.record();
        if record.disposition != EffectRecordDispositionV2::ExecutedOnly
            || record.validate().is_err()
        {
            return Err(ProfileFailure::Quarantined {
                code: QuarantineCode::NoncanonicalRecord,
            });
        }
        insert_record(&self.connection, canonical, None).map_err(|_| durable_failure())?;
        Ok(ExecuteOnlyStorageReceiptV1 {
            record_id: record.record_id,
            reusable: false,
            candidate: false,
            shadow: false,
            promoted: false,
        })
    }

    pub(crate) fn retire_manifest_invalidations(
        &mut self,
        invalidations: &[ObservedManifestInvalidationV1],
    ) -> Result<PytestInvalidationReportV1, ProfileFailure> {
        self.retire_validation_dependents(
            &invalidations
                .iter()
                .flat_map(ObservedManifestInvalidationV1::dependents)
                .copied()
                .collect::<Vec<_>>(),
        )
    }

    pub(crate) fn retire_validation_dependents(
        &mut self,
        dependents: &[ManifestDependentV1],
    ) -> Result<PytestInvalidationReportV1, ProfileFailure> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| durable_failure())?;
        let mut retired = 0u64;
        for dependent in dependents
            .iter()
            .filter(|dependent| dependent.kind() == ManifestDependentKindV1::Validation)
        {
            let changed = transaction
                .execute(
                    "UPDATE pytest_promotions_v1
                     SET retired_reason = 'relevant_manifest_mutation'
                     WHERE validation_dependent = ?1 AND retired_reason IS NULL",
                    params![dependent.identity().as_bytes().as_slice()],
                )
                .map_err(|_| durable_failure())?;
            retired = retired
                .checked_add(u64::try_from(changed).map_err(|_| durable_failure())?)
                .ok_or_else(durable_failure)?;
        }
        transaction.commit().map_err(|_| durable_failure())?;
        Ok(PytestInvalidationReportV1 {
            retired_promotions: retired,
        })
    }

    pub(crate) fn freshly_validate(
        &self,
        candidate: PromotedCandidateV2,
        validation: &RevalidatedObservationClosureV1,
        capability: &FreshPythonCapabilityWitnessV1,
    ) -> Result<FreshlyValidatedPytestHitV1, ProfileFailure> {
        let record = candidate.primary().record();
        let snapshot = validation.snapshot().identity();
        let request_key = record
            .shape
            .request_key(validation.closure())
            .map_err(contract_failure)?;
        if request_key != record.request_key
            || validation.closure() != &record.observation_closure
            || snapshot.runtime_root != record.sealed_snapshot.runtime_root
            || snapshot.profile_digest != record.profile_digest
            || candidate.shadow().record().request_key != record.request_key
            || capability.snapshot_id != snapshot.snapshot_id
        {
            return Err(ProfileFailure::Quarantined {
                code: QuarantineCode::ObservationMismatch,
            });
        }
        let quarantined = self
            .connection
            .query_row(
                "SELECT 1 FROM pytest_quarantine_v1 WHERE class_key = ?1",
                params![candidate.pair().class_key().as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| durable_failure())?
            .is_some();
        if quarantined {
            return Err(ProfileFailure::Quarantined {
                code: QuarantineCode::SameRequestDifferentPair,
            });
        }
        let active = self
            .connection
            .query_row(
                "SELECT 1 FROM pytest_promotions_v1
                 WHERE shape_key = ?1 AND request_key = ?2
                   AND primary_record_id = ?3 AND shadow_record_id = ?4
                   AND comparison_digest = ?5 AND class_key = ?6
                   AND retired_reason IS NULL",
                params![
                    candidate.pair().shape_key().as_bytes().as_slice(),
                    candidate.pair().request_key().as_bytes().as_slice(),
                    candidate.pair().primary_record_id().as_bytes().as_slice(),
                    candidate.pair().shadow_record_id().as_bytes().as_slice(),
                    candidate.pair().comparison_digest().as_bytes().as_slice(),
                    candidate.pair().class_key().as_bytes().as_slice(),
                ],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| durable_failure())?
            .is_some();
        if !active {
            return Err(ProfileFailure::Quarantined {
                code: QuarantineCode::ObservationMismatch,
            });
        }
        Ok(FreshlyValidatedPytestHitV1 { candidate })
    }

    #[cfg(test)]
    pub(crate) fn corrupt_record_for_test(&self, record_id: RecordId) {
        self.connection
            .execute(
                "UPDATE pytest_records_v1 SET record_bytes = X'00' WHERE record_id = ?1",
                params![record_id.as_bytes().as_slice()],
            )
            .unwrap();
    }
}

impl PromotionStore for SqlitePytestProfileStoreV1 {
    fn record_primary(
        &mut self,
        record: &VerifiedCandidateRecordV2,
    ) -> Result<ShadowJobV2, ProfileFailure> {
        if record.record().disposition != EffectRecordDispositionV2::PrimaryCandidate {
            return Err(ProfileFailure::Shadow {
                code: ShadowTerminalCode::PrimaryIneligible,
            });
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| durable_failure())?;
        insert_candidate(&transaction, record).map_err(|_| durable_failure())?;
        let job_id = ShadowJobId::from_bytes(*Uuid::new_v4().as_bytes());
        let job = ShadowJobV2::new(job_id, record).map_err(contract_failure)?;
        transaction
            .execute(
                "INSERT INTO pytest_shadow_jobs_v1(job_id, primary_record_id, status)
                 VALUES (?1, ?2, 'pending')",
                params![
                    job_id.as_bytes().as_slice(),
                    record.record().record_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| durable_failure())?;
        transaction.commit().map_err(|_| durable_failure())?;
        Ok(job)
    }

    fn finish_shadow(
        &mut self,
        job: &ShadowJobV2,
        shadow: &VerifiedCandidateRecordV2,
    ) -> Result<PromotedPairV2, ProfileFailure> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| durable_failure())?;
        let status = transaction
            .query_row(
                "SELECT status FROM pytest_shadow_jobs_v1
                 WHERE job_id = ?1 AND primary_record_id = ?2",
                params![
                    job.job_id().as_bytes().as_slice(),
                    job.primary_record_id().as_bytes().as_slice()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| durable_failure())?;
        if status.as_deref() != Some("pending") {
            return Err(ProfileFailure::Shadow {
                code: ShadowTerminalCode::PromotionCompareAndSwapLost,
            });
        }
        let primary = load_candidate(&transaction, job.primary_record_id())?;
        let promoted_ns = MonotonicNs(
            primary
                .record()
                .created_monotonic_ns
                .0
                .max(shadow.record().created_monotonic_ns.0)
                .checked_add(1)
                .ok_or_else(durable_failure)?,
        );
        let pair = match PromotedPairV2::new(&primary, shadow, promoted_ns) {
            Ok(pair) => pair,
            Err(_) => {
                let class_key = super::identity::QuarantineClassV1::from_record(primary.record())
                    .and_then(|class| class.key())
                    .map_err(contract_failure)?;
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO pytest_quarantine_v1(
                            class_key, first_record_id, reason
                         ) VALUES (?1, ?2, ?3)",
                        params![
                            class_key.as_bytes().as_slice(),
                            primary.record().record_id.as_bytes().as_slice(),
                            QuarantineCode::ComparisonViewMismatch as u16,
                        ],
                    )
                    .map_err(|_| durable_failure())?;
                transaction
                    .execute(
                        "UPDATE pytest_shadow_jobs_v1
                         SET status = 'failed', failure_code = ?1
                         WHERE job_id = ?2 AND status = 'pending'",
                        params![
                            ShadowTerminalCode::SemanticMismatch as u16,
                            job.job_id().as_bytes().as_slice(),
                        ],
                    )
                    .map_err(|_| durable_failure())?;
                transaction.commit().map_err(|_| durable_failure())?;
                return Err(ProfileFailure::Shadow {
                    code: ShadowTerminalCode::SemanticMismatch,
                });
            }
        };
        let quarantined = transaction
            .query_row(
                "SELECT 1 FROM pytest_quarantine_v1 WHERE class_key = ?1",
                params![pair.class_key().as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| durable_failure())?
            .is_some();
        if quarantined {
            return Err(ProfileFailure::Shadow {
                code: ShadowTerminalCode::ClassAlreadyQuarantined,
            });
        }
        insert_candidate(&transaction, shadow).map_err(|_| durable_failure())?;
        let dependent = validation_dependent_v1(pair.request_key());
        transaction
            .execute(
                "INSERT INTO pytest_promotions_v1(
                    shape_key, request_key, primary_record_id, shadow_record_id,
                    comparison_digest, class_key, validation_dependent, promoted_monotonic_ns
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    pair.shape_key().as_bytes().as_slice(),
                    pair.request_key().as_bytes().as_slice(),
                    pair.primary_record_id().as_bytes().as_slice(),
                    pair.shadow_record_id().as_bytes().as_slice(),
                    pair.comparison_digest().as_bytes().as_slice(),
                    pair.class_key().as_bytes().as_slice(),
                    dependent.identity().as_bytes().as_slice(),
                    i64::try_from(pair.promoted_monotonic_ns().0).map_err(|_| durable_failure())?,
                ],
            )
            .map_err(|_| ProfileFailure::Shadow {
                code: ShadowTerminalCode::PromotionCompareAndSwapLost,
            })?;
        let changed = transaction
            .execute(
                "UPDATE pytest_shadow_jobs_v1 SET status = 'promoted'
                 WHERE job_id = ?1 AND status = 'pending'",
                params![job.job_id().as_bytes().as_slice()],
            )
            .map_err(|_| durable_failure())?;
        if changed != 1 {
            return Err(ProfileFailure::Shadow {
                code: ShadowTerminalCode::PromotionCompareAndSwapLost,
            });
        }
        transaction.commit().map_err(|_| durable_failure())?;
        Ok(pair)
    }

    fn fail_shadow(
        &mut self,
        job: &ShadowJobV2,
        reason: ShadowTerminalCode,
    ) -> Result<(), ProfileFailure> {
        let changed = self
            .connection
            .execute(
                "UPDATE pytest_shadow_jobs_v1
                 SET status = 'failed', failure_code = ?1
                 WHERE job_id = ?2 AND status = 'pending'",
                params![reason as u16, job.job_id().as_bytes().as_slice()],
            )
            .map_err(|_| durable_failure())?;
        if changed != 1 {
            return Err(ProfileFailure::Shadow {
                code: ShadowTerminalCode::PromotionCompareAndSwapLost,
            });
        }
        Ok(())
    }

    fn lookup_promoted_by_shape(
        &mut self,
        shape_key: ShapeKey,
    ) -> Result<PromotedLookupV2, ProfileFailure> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT p.primary_record_id, p.shadow_record_id, p.promoted_monotonic_ns
                 FROM pytest_promotions_v1 p
                 WHERE p.shape_key = ?1 AND p.retired_reason IS NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM pytest_quarantine_v1 q WHERE q.class_key = p.class_key
                   )
                 ORDER BY p.promoted_monotonic_ns DESC, p.request_key ASC
                 LIMIT 64",
            )
            .map_err(|_| durable_failure())?;
        let rows = statement
            .query_map(params![shape_key.as_bytes().as_slice()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| durable_failure())?;
        let stored = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| durable_failure())?;
        drop(statement);
        let mut candidates = Vec::new();
        for (primary_id, shadow_id, promoted_ns) in stored {
            let primary_id = parse_record_id(&primary_id)?;
            let shadow_id = parse_record_id(&shadow_id)?;
            let primary = match load_candidate(&self.connection, primary_id) {
                Ok(primary) => primary,
                Err(error) => {
                    quarantine_corrupt_promotion(&self.connection, primary_id)?;
                    return Err(error);
                }
            };
            let shadow = match load_candidate(&self.connection, shadow_id) {
                Ok(shadow) => shadow,
                Err(error) => {
                    quarantine_corrupt_promotion(&self.connection, primary_id)?;
                    return Err(error);
                }
            };
            let pair = match PromotedPairV2::new(
                &primary,
                &shadow,
                MonotonicNs(u64::try_from(promoted_ns).map_err(|_| durable_failure())?),
            ) {
                Ok(pair) => pair,
                Err(_) => {
                    quarantine_corrupt_promotion(&self.connection, primary_id)?;
                    return Err(ProfileFailure::Quarantined {
                        code: QuarantineCode::RecordCasCorruption,
                    });
                }
            };
            let candidate = match PromotedCandidateV2::new(pair, primary, shadow) {
                Ok(candidate) => candidate,
                Err(_) => {
                    quarantine_corrupt_promotion(&self.connection, primary_id)?;
                    return Err(ProfileFailure::Quarantined {
                        code: QuarantineCode::RecordCasCorruption,
                    });
                }
            };
            candidates.push(candidate);
        }
        PromotedLookupV2::new(shape_key, candidates).map_err(contract_failure)
    }

    fn quarantine(
        &mut self,
        class_key: ClassKey,
        first_record_id: RecordId,
        reason: QuarantineCode,
    ) -> Result<(), ProfileFailure> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO pytest_quarantine_v1(class_key, first_record_id, reason)
                 VALUES (?1, ?2, ?3)",
                params![
                    class_key.as_bytes().as_slice(),
                    first_record_id.as_bytes().as_slice(),
                    reason as u16,
                ],
            )
            .map_err(|_| durable_failure())?;
        Ok(())
    }

    fn expire(
        &mut self,
        _now_ns: EpochNs,
        _limit: u32,
    ) -> Result<PromotionGcReportV2, ProfileFailure> {
        Ok(PromotionGcReportV2::default())
    }
}

pub(crate) fn validation_dependent_v1(request_key: super::RequestKey) -> ManifestDependentV1 {
    ManifestDependentV1::new(
        ManifestDependentKindV1::Validation,
        StateDigestV1::from_domain_and_bytes(
            VALIDATION_DEPENDENT_DOMAIN_V1,
            request_key.as_bytes(),
        ),
    )
}

pub(crate) fn native_execution_gate_v1() -> Result<(), ProfileFailure> {
    #[cfg(not(target_os = "linux"))]
    {
        Err(ProfileFailure::refused(super::RefusalCode::UnsupportedOs))
    }
    #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
    {
        Err(ProfileFailure::refused(
            super::RefusalCode::UnsupportedArchitecture,
        ))
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // A matching architecture is necessary but insufficient. Only the
        // provisioned tuple qualifier may replace this refusal later.
        Err(ProfileFailure::refused(
            super::RefusalCode::KernelTupleNotEnabled,
        ))
    }
}

fn insert_candidate(
    connection: &Connection,
    candidate: &VerifiedCandidateRecordV2,
) -> rusqlite::Result<()> {
    insert_record(
        connection,
        candidate.canonical(),
        Some(candidate.manifest()),
    )
}

fn insert_record(
    connection: &Connection,
    canonical: &CanonicalEffectRecordV2,
    manifest: Option<&VerifiedSnapshotManifestV1>,
) -> rusqlite::Result<()> {
    let record = canonical.record();
    connection.execute(
        "INSERT INTO pytest_records_v1(
            record_id, disposition, shape_key, request_key, primary_record_id,
            record_bytes, manifest_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            record.record_id.as_bytes().as_slice(),
            record.disposition as u16,
            record.shape_key.as_bytes().as_slice(),
            record.request_key.as_bytes().as_slice(),
            record.primary_record_id.map(|id| id.as_bytes().to_vec()),
            canonical.canonical_bytes(),
            manifest.map(VerifiedSnapshotManifestV1::canonical_bytes),
        ],
    )?;
    Ok(())
}

fn load_candidate(
    connection: &Connection,
    record_id: RecordId,
) -> Result<VerifiedCandidateRecordV2, ProfileFailure> {
    let stored = connection
        .query_row(
            "SELECT record_bytes, manifest_bytes FROM pytest_records_v1 WHERE record_id = ?1",
            params![record_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|_| durable_failure())?
        .ok_or_else(durable_failure)?;
    VerifiedCandidateRecordV2::from_canonical_bytes(&stored.0, &stored.1).map_err(|_| {
        ProfileFailure::Quarantined {
            code: QuarantineCode::RecordCasCorruption,
        }
    })
}

fn parse_record_id(bytes: &[u8]) -> Result<RecordId, ProfileFailure> {
    let value: [u8; 16] = bytes.try_into().map_err(|_| ProfileFailure::Quarantined {
        code: QuarantineCode::RecordCasCorruption,
    })?;
    Ok(RecordId::from_bytes(value))
}

fn quarantine_corrupt_promotion(
    connection: &Connection,
    primary_record_id: RecordId,
) -> Result<(), ProfileFailure> {
    connection
        .execute(
            "INSERT OR IGNORE INTO pytest_quarantine_v1(class_key, first_record_id, reason)
             SELECT class_key, primary_record_id, ?1 FROM pytest_promotions_v1
             WHERE primary_record_id = ?2",
            params![
                QuarantineCode::RecordCasCorruption as u16,
                primary_record_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| durable_failure())?;
    Ok(())
}

fn durable_failure() -> ProfileFailure {
    ProfileFailure::Shadow {
        code: ShadowTerminalCode::DurableRecordFailed,
    }
}

fn contract_failure(_error: LinuxPytestContractError) -> ProfileFailure {
    ProfileFailure::Quarantined {
        code: QuarantineCode::NoncanonicalRecord,
    }
}
