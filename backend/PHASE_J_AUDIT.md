# PHASE_J_AUDIT.md

## Current Architecture
The SOC Alert Triage Platform backend has been modernized to use an orchestrated pipeline driven by SQLAlchemy 2.0. 
- **Database:** SQLite (local dev & testing) and PostgreSQL 17 (production/Docker).
- **Orchestration:** `app/services/pipeline.py` orchestrates the extraction, correlation, risk assessment, MITRE mapping, AI briefing, and persistence.
- **API:** RESTful endpoints built with FastAPI, utilizing Dependency Injection for database sessions.
- **AI Briefing:** Uses Groq (`gpt-oss-120b`) for top-priority incidents, with deterministic fallbacks.

## Current Test Status
- **Total Tests:** 153 tests
- **Passed:** 123
- **Failed:** 24
- **Errors:** 6
- **Warnings:** 1 (httpx deprecation)

## Known Failures
1. **SQLite DateTime TypeError:** Integration tests (`test_api.py`, `test_ingestion.py`) fail with `StatementError` because `datetime` string representations from the dataset are being inserted directly into SQLAlchemy models without parsing into Python `datetime` objects.
2. **MITRE Sorting Invariant:** `test_mitre.py` expects alert IDs to be sorted alphabetically within MITRE contexts, but they currently retain insertion order.
3. **RiskPriority Enum Updates:** Several legacy tests in `test_mitre.py` and `test_briefing.py` still expect priority to be strings like `"Critical"` instead of the updated `RiskPriority.P1` enum.
4. **Pydantic Validation Errors:** `test_briefing.py` fails due to mock objects not aligning with the updated strongly-typed SQLAlchemy schemas and Pydantic models.
5. **Correlation Evidence Invariants:** `test_correlation.py` fails verifying correlation evidence signals.

## Missing Verification
- Complete validation of the 3000-alert dataset using the actual API or `scripts/demo.py`.
- Validation of Alembic migrations on a live PostgreSQL 17 container.
- E2E Idempotency check.
- Verification of risk calculation invariants (Asset Criticality > Alert Count).
- Full MTTT verification on human analyst workflow endpoints.
- End-to-end performance measurements.

## Planned Fixes
1. **Datetime Parsing:** Update `pipeline.py` / `ingestion.py` to parse timestamp strings into Python `datetime` objects before creating `AlertModel` instances.
2. **Enum Mapping:** Update failing tests to expect `RiskPriority.P1`/`P2`/`P3`/`P4` instead of `"Critical"`/`"High"`.
3. **Sorting Invariants:** Add sorting logic to `build_mitre_context` to satisfy deterministic presentation invariants.
4. **Mock Alignments:** Update Pydantic mocks in `test_briefing.py` and `test_correlation.py`.
5. **PostgreSQL Validation:** Spin up Docker, run alembic migrations against Postgres, and test integrity constraints.
6. **E2E Testing:** Run `demo.py` against the PostgreSQL database to collect real measurements for the final report.
