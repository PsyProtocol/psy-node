//! Exact projection of the three closed Coordinator queue sources.
//!
//! This module accepts only candidates reconstructed by the durable artifact
//! scanner.  It validates every recoverable NATS envelope against the selected
//! generation assignment and the source's close boundary before producing the
//! driver-independent Coordinator input.  It does not own an ACK token,
//! pipeline transition, or actor invocation.

use std::{error::Error, fmt};

use psy_node_core::queue::{
    coordinator_processor_durable_capture::{
        CoordinatorProcessorDurableCaptureError,
        CoordinatorProcessorDurableCapturedGeneration,
        CoordinatorProcessorDurableCapturedItem,
        CoordinatorProcessorDurableCapturedSource,
        CoordinatorProcessorSourceKind,
    },
    recoverable_ephemeral::{
        PendingQueueBoundaryObservation, PendingQueueCaptureCandidate,
        PendingQueueCaptureContext, PendingQueueGenerationBoundary,
        PendingQueueSourceCursorView,
    },
};
use psy_node_nats::{
    recoverable_assignment::PendingQueueGenerationSegmentAssignment,
    recoverable_publish::{
        PendingQueueEnvelopeBody, PendingQueuePublishEnvelope,
        PendingQueuePublisherKind,
    },
};

#[derive(Debug)]
struct CoordinatorProcessorClosedSourceReadback {
    kind: CoordinatorProcessorSourceKind,
    candidates: Vec<PendingQueueCaptureCandidate>,
    boundary: PendingQueueGenerationBoundary,
}

impl CoordinatorProcessorClosedSourceReadback {
    fn new(
        kind: CoordinatorProcessorSourceKind,
        candidates: Vec<PendingQueueCaptureCandidate>,
        boundary: PendingQueueGenerationBoundary,
    ) -> Self {
        Self {
            kind,
            candidates,
            boundary,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoordinatorProcessorDurableProjectionError {
    IdentityMismatch,
    MalformedCompleteSource,
    Core(String),
    Envelope(String),
}

impl fmt::Display for CoordinatorProcessorDurableProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CoordinatorProcessorDurableProjectionError {}

fn project_complete_generation(
    context: PendingQueueCaptureContext,
    assignment: &PendingQueueGenerationSegmentAssignment,
    sources: Vec<CoordinatorProcessorClosedSourceReadback>,
) -> Result<
    CoordinatorProcessorDurableCapturedGeneration,
    CoordinatorProcessorDurableProjectionError,
> {
    if assignment.context() != context
        || context.key().authority()
            != psy_data::protocol::chain_context::AuthorityScope::Coordinator
        || usize::from(assignment.expected_source_count())
            != CoordinatorProcessorSourceKind::ALL.len()
        || assignment.source_quotas().len()
            != CoordinatorProcessorSourceKind::ALL.len()
        || sources.len() != CoordinatorProcessorSourceKind::ALL.len()
        || sources
            .iter()
            .map(|source| source.kind)
            .ne(CoordinatorProcessorSourceKind::ALL)
        || sources
            .iter()
            .map(|source| source.boundary.close_intent())
            .skip(1)
            .any(|close| close != sources[0].boundary.close_intent())
    {
        return Err(CoordinatorProcessorDurableProjectionError::IdentityMismatch);
    }

    let projected = sources
        .into_iter()
        .map(|source| project_complete_source(context, assignment, source))
        .collect::<Result<Vec<_>, _>>()?;
    CoordinatorProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
        context, projected,
    )
    .map_err(core)
}

fn project_complete_source(
    context: PendingQueueCaptureContext,
    assignment: &PendingQueueGenerationSegmentAssignment,
    source: CoordinatorProcessorClosedSourceReadback,
) -> Result<
    CoordinatorProcessorDurableCapturedSource,
    CoordinatorProcessorDurableProjectionError,
> {
    if source.boundary.context() != context {
        return Err(CoordinatorProcessorDurableProjectionError::IdentityMismatch);
    }
    let expected_publisher = publisher_kind(source.kind);
    let quota = assignment
        .source_quotas()
        .iter()
        .copied()
        .find(|quota| quota.publisher_kind() == expected_publisher)
        .ok_or(CoordinatorProcessorDurableProjectionError::IdentityMismatch)?;
    let mut expected_ordinal = 1_u32;
    let mut previous_subject_sequence = 0_u64;
    let mut previous_envelope_digest = [0_u8; 32];
    let mut encoded_bytes = 0_u64;
    let mut business_items = Vec::new();

    for candidate in source.candidates {
        if candidate.context() != context
            || candidate.source_identity() != source.boundary.source_identity()
        {
            return Err(CoordinatorProcessorDurableProjectionError::IdentityMismatch);
        }
        let PendingQueueSourceCursorView::NatsJetStream {
            stream_sequences, ..
        } = candidate.source().view()
        else {
            return Err(
                CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
            );
        };
        if stream_sequences.len() != candidate.items().len() {
            return Err(
                CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
            );
        }

        business_items.reserve(candidate.items().len());
        for (stream_sequence, encoded) in stream_sequences
            .iter()
            .copied()
            .zip(candidate.items())
        {
            encoded_bytes = encoded_bytes
                .checked_add(u64::try_from(encoded.len()).map_err(|_| {
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource
                })?)
                .ok_or(
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
                )?;
            let envelope = PendingQueuePublishEnvelope::decode_canonical(encoded)
                .map_err(|error| {
                    CoordinatorProcessorDurableProjectionError::Envelope(
                        error.to_string(),
                    )
                })?;
            if stream_sequence == 0
                || (previous_subject_sequence != 0
                    && stream_sequence <= previous_subject_sequence)
                || envelope.publisher_kind() != expected_publisher
                || envelope.artifact_identity() != candidate.artifact_identity()
                || envelope.segment_id() != assignment.segment_id()
                || envelope.contract_digest() != assignment.contract_digest()
                || envelope.assignment_digest() != assignment.digest()
                || envelope.member_ordinal().get() != expected_ordinal
                || envelope.previous_subject_sequence()
                    != previous_subject_sequence
                || envelope.previous_envelope_digest()
                    != previous_envelope_digest
            {
                return Err(
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
                );
            }
            let PendingQueueEnvelopeBody::Data(payload) = envelope.body() else {
                return Err(
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
                );
            };
            business_items.push(
                CoordinatorProcessorDurableCapturedItem::try_new(
                    stream_sequence,
                    *envelope.digest().as_bytes(),
                    payload.clone(),
                )
                .map_err(core)?,
            );
            expected_ordinal = expected_ordinal.checked_add(1).ok_or(
                CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
            )?;
            previous_subject_sequence = stream_sequence;
            previous_envelope_digest = *envelope.digest().as_bytes();
        }
    }

    let PendingQueueBoundaryObservation::NatsJetStream {
        seal_marker_stream_sequence,
        last_data_stream_sequence,
        ..
    } = source.boundary.observation()
    else {
        return Err(
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    };
    if *last_data_stream_sequence != previous_subject_sequence
        || *seal_marker_stream_sequence <= *last_data_stream_sequence
        || business_items.len() > quota.max_data_members() as usize
        || encoded_bytes > quota.max_data_stored_bytes()
    {
        return Err(
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    }

    CoordinatorProcessorDurableCapturedSource::try_from_exhaustive_readback(
        source.kind,
        context,
        source.boundary.source_identity().digest(),
        source.boundary.digest(),
        business_items,
    )
    .map_err(core)
}

const fn publisher_kind(
    kind: CoordinatorProcessorSourceKind,
) -> PendingQueuePublisherKind {
    match kind {
        CoordinatorProcessorSourceKind::Registration => {
            PendingQueuePublisherKind::CoordinatorRegistration
        }
        CoordinatorProcessorSourceKind::Deploy => {
            PendingQueuePublisherKind::CoordinatorDeploy
        }
        CoordinatorProcessorSourceKind::Guta => {
            PendingQueuePublisherKind::CoordinatorGuta
        }
    }
}

fn core(
    error: CoordinatorProcessorDurableCaptureError,
) -> CoordinatorProcessorDurableProjectionError {
    CoordinatorProcessorDurableProjectionError::Core(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };
    use psy_node_core::{
        queue::recoverable_ephemeral::{
            PendingQueueSourceCursor,
        },
        store::{
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationContext,
                PendingGenerationLedgerKey,
            },
            pending_generation_pipeline::PendingQueueCloseIntentDigest,
        },
    };
    use psy_node_nats::{
        recoverable_assignment::{
            PendingQueueSegmentLedgerBootstrap,
            PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
            PendingQueuePublishIntentId, PendingQueueSourceQuota,
            RecoverableNatsSourceRoute,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    struct Fixture {
        context: PendingQueueCaptureContext,
        assignment: PendingQueueGenerationSegmentAssignment,
        routes: [RecoverableNatsSourceRoute; 3],
    }

    fn fixture() -> Fixture {
        fixture_with_data_limits([127 * 1024 * 1024; 3])
    }

    fn fixture_with_data_limits(max_data_stored_bytes: [u64; 3]) -> Fixture {
        let generation_budget_bytes = max_data_stored_bytes
            .iter()
            .map(|bytes| bytes + 1024 * 1024)
            .sum::<u64>();
        let authority = AuthorityScope::Coordinator;
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
        );
        let context = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(7, 99).unwrap(),
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy",
            key,
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                1024 * 1024 * 1024,
                i64::try_from(generation_budget_bytes).unwrap(),
                3,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        let quotas = [
            PendingQueuePublisherKind::CoordinatorRegistration,
            PendingQueuePublisherKind::CoordinatorDeploy,
            PendingQueuePublisherKind::CoordinatorGuta,
        ]
        .into_iter()
        .zip(max_data_stored_bytes)
        .map(|(kind, max_data_stored_bytes)| {
            PendingQueueSourceQuota::try_new(
                kind,
                100,
                max_data_stored_bytes,
                1024 * 1024,
            )
            .unwrap()
        })
        .collect();
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            quotas,
            generation_budget_bytes,
        )
        .unwrap();
        let validated = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let assignment = match PendingQueueSegmentLedgerBootstrap::try_new(
            key,
            &validated,
            budget,
            8,
        )
        .unwrap()
        .candidate()
        .reserve_generation(context)
        .unwrap()
        {
            PendingQueueSegmentReservationPlan::Advance { assignment, .. } => {
                assignment
            }
            _ => unreachable!(),
        };
        let routes = [
            PendingQueuePublisherKind::CoordinatorRegistration,
            PendingQueuePublisherKind::CoordinatorDeploy,
            PendingQueuePublisherKind::CoordinatorGuta,
        ]
        .map(|kind| RecoverableNatsSourceRoute::try_new(context, kind, &segment).unwrap());
        Fixture {
            context,
            assignment,
            routes,
        }
    }

    fn data(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
        ordinal: u32,
        previous_sequence: u64,
        previous_digest: [u8; 32],
        payload: &[u8],
    ) -> PendingQueuePublishEnvelope {
        PendingQueuePublishEnvelope::data(
            route,
            assignment,
            PendingQueuePublishIntentId::try_new([ordinal as u8; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(ordinal).unwrap(),
            previous_sequence,
            previous_digest,
            payload.to_vec(),
        )
        .unwrap()
    }

    fn candidate(
        context: PendingQueueCaptureContext,
        route: &RecoverableNatsSourceRoute,
        sequences: &[u64],
        envelopes: &[PendingQueuePublishEnvelope],
    ) -> PendingQueueCaptureCandidate {
        PendingQueueCaptureCandidate::try_new(
            context,
            route.source_identity().clone(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], sequences).unwrap(),
            envelopes
                .iter()
                .map(PendingQueuePublishEnvelope::to_canonical_bytes)
                .collect(),
        )
        .unwrap()
    }

    fn boundary(
        context: PendingQueueCaptureContext,
        route: &RecoverableNatsSourceRoute,
        seal_sequence: u64,
        last_data_sequence: u64,
    ) -> PendingQueueGenerationBoundary {
        boundary_with_close(
            context,
            route,
            seal_sequence,
            last_data_sequence,
            9,
        )
    }

    fn boundary_with_close(
        context: PendingQueueCaptureContext,
        route: &RecoverableNatsSourceRoute,
        seal_sequence: u64,
        last_data_sequence: u64,
        close_marker: u8,
    ) -> PendingQueueGenerationBoundary {
        PendingQueueGenerationBoundary::try_from_backend_observation(
            context,
            PendingQueueCloseIntentDigest::try_new([close_marker; 32]).unwrap(),
            route.source_identity().clone(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: seal_sequence,
                last_data_stream_sequence: last_data_sequence,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap()
    }

    fn closed_source(
        fixture: &Fixture,
        kind: CoordinatorProcessorSourceKind,
        route_index: usize,
        base_sequence: u64,
        payloads: &[&[u8]],
    ) -> CoordinatorProcessorClosedSourceReadback {
        let route = &fixture.routes[route_index];
        let mut previous_sequence = 0;
        let mut previous_digest = [0; 32];
        let mut envelopes = Vec::with_capacity(payloads.len());
        let mut sequences = Vec::with_capacity(payloads.len());
        for (index, payload) in payloads.iter().enumerate() {
            let sequence = base_sequence + index as u64;
            let envelope = data(
                route,
                &fixture.assignment,
                index as u32 + 1,
                previous_sequence,
                previous_digest,
                payload,
            );
            previous_sequence = sequence;
            previous_digest = *envelope.digest().as_bytes();
            sequences.push(sequence);
            envelopes.push(envelope);
        }
        let candidates = if envelopes.is_empty() {
            Vec::new()
        } else {
            vec![candidate(
                fixture.context,
                route,
                &sequences,
                &envelopes,
            )]
        };
        CoordinatorProcessorClosedSourceReadback::new(
            kind,
            candidates,
            boundary(
                fixture.context,
                route,
                previous_sequence.saturating_add(1).max(1),
                previous_sequence,
            ),
        )
    }

    #[test]
    fn three_closed_sources_project_in_fixed_order_with_explicit_empty() {
        let fixture = fixture();
        let generation = project_complete_generation(
            fixture.context,
            &fixture.assignment,
            vec![
                closed_source(
                    &fixture,
                    CoordinatorProcessorSourceKind::Registration,
                    0,
                    10,
                    &[b"registration-1", b"registration-2"],
                ),
                closed_source(
                    &fixture,
                    CoordinatorProcessorSourceKind::Deploy,
                    1,
                    20,
                    &[],
                ),
                closed_source(
                    &fixture,
                    CoordinatorProcessorSourceKind::Guta,
                    2,
                    30,
                    &[b"guta-1"],
                ),
            ],
        )
        .unwrap();

        assert_eq!(generation.total_items(), 3);
        assert_eq!(generation.registration().items().len(), 2);
        assert!(generation.deploy().items().is_empty());
        assert_eq!(generation.guta().items().len(), 1);
        assert_ne!(generation.digest().as_bytes(), &[0; 32]);
    }

    #[test]
    fn missing_or_wrongly_ordered_source_is_rejected() {
        let fixture = fixture();
        let sources = vec![
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Deploy,
                1,
                20,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Registration,
                0,
                10,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Guta,
                2,
                30,
                &[],
            ),
        ];
        assert_eq!(
            project_complete_generation(
                fixture.context,
                &fixture.assignment,
                sources,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::IdentityMismatch,
        );
    }

    #[test]
    fn publisher_kind_chain_and_boundary_are_fail_closed() {
        let fixture = fixture();
        let wrong_kind = closed_source(
            &fixture,
            CoordinatorProcessorSourceKind::Registration,
            2,
            10,
            &[b"wrong-publisher"],
        );
        assert_eq!(
            project_complete_source(
                fixture.context,
                &fixture.assignment,
                wrong_kind,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );

        let route = &fixture.routes[0];
        let first = data(route, &fixture.assignment, 1, 0, [0; 32], b"first");
        let second = data(
            route,
            &fixture.assignment,
            2,
            9,
            *first.digest().as_bytes(),
            b"second",
        );
        let broken = CoordinatorProcessorClosedSourceReadback::new(
            CoordinatorProcessorSourceKind::Registration,
            vec![candidate(
                fixture.context,
                route,
                &[10, 11],
                &[first, second],
            )],
            boundary(fixture.context, route, 12, 11),
        );
        assert_eq!(
            project_complete_source(
                fixture.context,
                &fixture.assignment,
                broken,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    }

    #[test]
    fn cross_source_close_and_assignment_quota_are_enforced() {
        let fixture = fixture();
        let mut sources = vec![
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Registration,
                0,
                10,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Deploy,
                1,
                20,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Guta,
                2,
                30,
                &[],
            ),
        ];
        sources[2].boundary = boundary_with_close(
            fixture.context,
            &fixture.routes[2],
            1,
            0,
            7,
        );
        assert_eq!(
            project_complete_generation(
                fixture.context,
                &fixture.assignment,
                sources,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::IdentityMismatch,
        );

        let tiny = fixture_with_data_limits([
            1,
            127 * 1024 * 1024,
            127 * 1024 * 1024,
        ]);
        let oversized = closed_source(
            &tiny,
            CoordinatorProcessorSourceKind::Registration,
            0,
            10,
            &[b"larger-than-one-byte"],
        );
        assert_eq!(
            project_complete_source(tiny.context, &tiny.assignment, oversized)
                .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    }

    #[test]
    fn projection_has_no_ack_session_or_pipeline_authority() {
        let source = include_str!("coordinator_processor_durable_capture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("double_ack"));
        assert!(!production.contains("Session"));
        assert!(!production.contains("StoredPendingPipeline"));
        assert!(!production.contains("PendingPipelineWriteOutcome"));
    }
}
