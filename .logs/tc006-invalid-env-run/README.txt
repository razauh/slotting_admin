INVALID RUN — DO NOT USE AS EVIDENCE.

Date: 2026-10-05. Cause: PostgreSQL was not reachable on 127.0.0.1:5432
(connection refused; no PostgreSQL server installed or running on the host).
All Stage 2-5 results in this directory are environment failures, not code
evidence. The full-suite classification shows 89 failing identities with 32
"only-current" because the Spring application context could not connect to the
database; none of those are real regressions. The Stage 2 RED fixture never
executed because its temporary worktree failed to attach (prunable worktree
entry) and Gradle ran in the main repository instead.

The scripts have since been fixed to preflight the database, prune/recreate the
baseline worktree, fail fast, and clear stale JUnit XML. Re-run with a live
PostgreSQL 16 to produce valid evidence.
