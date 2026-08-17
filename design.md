# Platform Foundation design

- **Implementation status:** [Roadmap status registry](../implementation/roadmap.md#2-status-registry); this design does not maintain node state.
- **Authority:** [Integration v1 §2–3](../overall/integration-v1.md#2-identity-time-and-publication)
- **Implementation plan:** [Foundation](../implementation/plans/foundation.md)

Foundation is the Platform-owned local persistence module. It owns generic content-addressed storage (CAS), generic append logs, receipts, entry lookup, and checkpoints. Its composition root injects an explicit UTC governance clock; callers cannot supply receipt/checkpoint timestamps. The clock may repeat an instant because sequence numbers order ties, but it must not move backwards; a backward value fails with `CLOCK_NOT_MONOTONIC`. Foundation does not own Research, Validation, Promotion, Backtest, sample-consumption semantics, or status projection.

## Interface

The normative interface is [Integration v1 §3](../overall/integration-v1.md#3-foundation-contract-p00-plat-01): `put`, `read`, `append`, verified `entries` through a `LogCheckpoint` or `LogEntryRef`, and Foundation-assigned `checkpoint`. There is no `EvidenceStatusReader`; Promotion reconstructs its own status projection from generic entries.

`read()` remains structurally compatible with the Backtest-owned `ArtifactEnvelopeReader` port. Foundation performs structural Envelope/source-byte/ref and log-chain validation only. Backtest owns all Backtest decoding, hydration, semantic validation, and evidence verification.

## Publication and checkpoints

The canonical owner-log table, generic artifact publication event ID, `LogEntryRef`, receipt preimage, and hash relationships are defined once in [Integration v1 §3.1–3.2](../overall/integration-v1.md#31-canonical-owner-logs-and-entry-identity). A CAS write is addressable but not published evidence. A designated owner-log entry containing the exact canonical Envelope bytes is the publication fact.

`checkpoint(log_name=...)` has no caller-provided `as_of`: Foundation reads the injected governance clock and binds the current upper log sequence under its global lock. Foundation durably records issued checkpoint tuples, and `entries()` rejects caller-constructed tuples that were never issued. Later appends cannot enter that checkpoint, including an append with the same timestamp, because the upper sequence is authoritative. This closes the future-cutoff ambiguity while preserving the Frozen Validation pure functions, which consume the returned checkpoint cutoff as input.

## Boundary and acceptance

| Concern | Owner |
| --- | --- |
| Envelope, `ArtifactRef`, canonical encoding | Backtest Domain (`crypto_quant_domain`) |
| Backtest artifact semantics and verified evidence | Backtest Runtime (`crypto_quant_backtest`) |
| CAS, generic append, receipts, entry refs, checkpoints | Foundation |
| SampleConsumptionRecord and supplied-snapshot projection | Strategy Validation |
| EvidenceStatusEvent and current-status projection | Promotion Gate |

Foundation introduces no factory, database adapter, queue, service, Backtest decoder, schema catalog, domain-event vocabulary, or current-status projection. Its storage/failure contract and `P00-PLAT-01` acceptance are authoritative in [Integration v1 §3.3 and §9](../overall/integration-v1.md#33-storage-and-failure-contract).

Foundation implementation state and readiness are maintained only in the roadmap registry.
