# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for TrustLink.
An ADR captures a significant design choice, the context that drove it, and
the trade-offs accepted as a result.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](ADR-001-deterministic-ids.md) | Deterministic IDs instead of sequential counters | Accepted |
| [ADR-002](ADR-002-persistent-storage.md) | Persistent storage instead of temporary storage | Accepted |
| [ADR-003](ADR-003-immutable-history.md) | Immutable attestation history (no delete) | Accepted |
| [ADR-004](ADR-004-dual-indexes.md) | Separate issuer and subject indexes | Accepted |
| [ADR-005a](ADR-005-attestation-origin-enum.md) | Attestation origin enum | Accepted |
| [ADR-005b](ADR-005-prevent-admin-fee-collection.md) | Prevent admin from collecting their own fees | Accepted |
| [ADR-006](ADR-006-multisig-attestations.md) | Multi-sig attestation design (M-of-N, 7-day TTL, immutable finalization) | Accepted |

## Template

Use [ADR-000-template.md](ADR-000-template.md) when recording a new decision.

## Format

Each ADR follows this structure:

- **Status** — Proposed / Accepted / Deprecated / Superseded
- **Context** — The situation and forces that made a decision necessary
- **Decision** — What was decided and how it works
- **Consequences** — Trade-offs, benefits, and known limitations
