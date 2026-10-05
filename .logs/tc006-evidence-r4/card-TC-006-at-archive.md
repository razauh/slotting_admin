# TC-006 — Deterministic keys and early claim primitives

| Field | Value |
|---|---|
| Plan item(s) | [REM-006](../plan.md#REM-006) (part: primitives; activation in TC-008 to TC-010) |
| Audit finding(s) | AV-AUD-004 (High), §11.1, §11.2, §11.4, §11.5. |
| Priority | P0 |
| Complexity | Medium |
| Phase | 2 — Persistence correctness primitives |
| Depends on | TC-001, TC-005 |
| Blocks | TC-007, TC-008, TC-011 |
| Repo(s) | slotting_admin |
| Status | TODO |
| Decision gate | none |

## 1. Goal

Transaction-scoped early claims and deterministic ledger keys arbitrate duplicates before side effects, ready for command activation in TC-008–010.

## 2. Background and root cause

CONFIRMED (audit provenance): AV-AUD-004 §11 confirms late receipts and per-attempt random reservation/settlement keys. This is a primitive PR, not a completed command fix: claim activation must land with each transactional handler. See [plan.md#REM-006](../plan.md#REM-006) and the audit sections in the field table.

INFERRED/UNVERIFIED: proposed helper names, deployment capabilities and live-data condition are not audit facts. Step 0 must resolve these before production edits; existing passing protections remain guards rather than invented RED failures.

## 3. Scope and non-goals

- In scope: primitives; activation in TC-008 to TC-010 of REM-006; the observable goal and numbered GREEN steps below.
- In scope: tests and minimum schema/API/CI changes explicitly described below.
- Out of scope: other parts of this REM, owned by no split sibling; dependent work (TC-007, TC-008, TC-011) is not included.
- Out of scope: plan section 13, external certification, new game features, monetary/account redesign and unrelated cleanup. Preserve source comments/docstrings.

## 4. Step 0 — Codebase verification (read-only; do this before writing tests)

- [x] Read current repository AGENTS.md and nested instructions. Check nonempty graphify-out/graph.json and query this card's symbols using project-local .conda Graphify only; use local Python fallback when launcher is unavailable. Record graph freshness and scoped locations. If stale, do not silently rely on it; follow repository rules within implementation permissions.
- [x] Resolve backend unqualified gameprovider filenames below under `slotting_admin/src/main/kotlin/com/slotting/admin/gameprovider/`, ledger files under `slotting_admin/src/main/kotlin/com/slotting/admin/ledger/`, V*.sql under `slotting_admin/src/main/resources/db/migration/`, and backend gameprovider tests under `slotting_admin/src/test/kotlin/com/slotting/admin/gameprovider/`. Android paths are relative to `slotting/`. Record current lines; audit line numbers are historical.
- [x] V21__persistent_double_entry_ledger.sql, ledger/LedgerPostingService.kt and ledger/LedgerJournalStore.kt: record tenant/idempotency uniqueness, payload comparisons and joining propagation. Record the observed contract and design consequence.
- [x] V28 game_command_receipt and DurableGameWagerAndSettlementStore.kt: record existing fingerprint semantics, NOT NULL result/sequence/version and status CHECK; choose valid uncommitted claim representation before tests. Stop if plan's early receipt/late counter combination cannot be represented safely. Record the observed contract and design consequence.
- [x] Current command error enum and receipt result serializer: record exact conflict code and legacy sentinel behavior; do not invent public codes silently. Record the observed contract and design consequence.
- [x] Verify test location `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt` (new unless already present), neighboring fixtures, actual Gradle tasks and CI report paths. Record commands; new tool/task names below are proposed until implemented.
- [x] Inspect V21/V28/V29/V30 and later migrations for affected constraints, transaction joins and conflicting rows. Record migration availability (V38 existed during planning), tenant-scoped lock order and rollback boundaries.

### Verification outcome

Graph queried before source reads: `DurableGameWagerAndSettlementStore`, `LedgerPostingService`, `LedgerJournalStore`, `GameCommandReceiptRecord`. Graph is current for the working tree.

Observed contracts and design consequences:

- V21 `ledger_transaction` has `unique (tenant_id, idempotency_key)` and `unique (tenant_id, transaction_reference)`; `ledger_idempotency_receipt` has `unique (tenant_id, idempotency_key)` and a `payload_digest`. `LedgerPostingService.postTransaction` compares the payload signature before saving and throws `IdempotencyConflictException` on mismatch; the in-JVM lock key is `tenantId:idempotencyKey` and the DB unique index arbitrates across JVMs. Deterministic ledger keys therefore must be accompanied by deterministic transaction references, otherwise the payload signature changes on replay and a legitimate duplicate is misreported as a conflict. Chosen consequence: derive both the idempotency key and the transaction reference from one deterministic command key.
- V28 `game_command_receipt` already has `fingerprint` and `unique (tenant_id, command_id)`, so fingerprint reuse was chosen over adding `request_fingerprint`; `response_json` and `server_sequence_id` were NOT NULL and `status` allowed only terminal values. Chosen consequence: V40 adds `PENDING` to the status CHECK, makes `response_json`/`server_sequence_id` nullable for the transaction-private early claim, and adds a deferred constraint trigger that rejects commit while any `PENDING` receipt remains. No placeholder sequence is allocated.
- Current command conflict behavior: service throws `AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)` on fingerprint mismatch; the primitive adds the typed `CommandClaimConflictException`. Legacy receipts without a modern fingerprint are represented by a stored sentinel and are tested explicitly.
- Migrations currently end at V39 (TC-005). V40 is the next available version. Supporting hard-coded version assertions in `PostgresMigrationIntegrationTest` and the V39 migration-simulation in `AviatorCommandSequencePostgresTest` were updated to include V40. `slotting.schema.supported-version` is now 40.
- Test evidence: `./scripts/tc006-claim-tests.sh` (external PostgreSQL 16 at `slotting_admin_ci`). Compile `BUILD SUCCESSFUL`; focused suite `AviatorCommandClaimPostgresTest` green (6/6). Touched/related suites green: `AviatorCommandSequencePostgresTest` 5/0, `PostgresMigrationIntegrationTest` 4/0, `PersistentDoubleEntryLedgerContractTest` 12/0, `DurableGameWagerAndSettlementAuthorityContractTest` 11/0. The repository-wide `./gradlew test` is red with 57 failures in the clean run (1330 tests): all `*-T004` migration-certification assertions that reject `V17` and any migration above `V16`, against an already-committed V17–V39 chain.
- Baseline comparison (valid): `.scripts/tc006-baseline-full.sh` runs detached `b26bb0f` (no TC-005/TC-006 changes) in a separate database `slotting_admin_tc006_baseline`. Result `1319 tests, 57 failures`; the failure identity set is identical to the clean current run (0 only-baseline, 0 only-current). Classification: all 57 are pre-existing (same test and same underlying assertion fails on baseline), 0 introduced. `V40` appears in 0 baseline messages and 9 current messages: message drift only, no pass→fail transition. A first attempt used a second schema in the shared database, which duplicated `information_schema.tables` counts and inflated both runs to 59; that invalid attempt is preserved in `.logs/tc006-evidence-r2`, and the stray schema is dropped by `.scripts/tc006-clean-baseline-schema.sh`.
- RED-for-stated-reason was not captured and remains unavailable because the new APIs do not exist on pre-TC-006 revisions. See `TC-006-VERIFICATION-REMEDIATION-GUIDE.md`.

If verification contradicts the plan's design, stop and escalate; do not improvise. No source, test, migration, configuration or data changes belong in Step 0.

## 5. Preconditions

- Completed prerequisites: TC-001, TC-005.
- TC-001 real PostgreSQL, disposable funded/compliant fixtures and production transaction manager are available.
- Resolve Step 0 contracts and scoped acceptance inputs before encoding expectations.

## 6. RED — tests to write first

Write in this order after read-only verification. Capture actual failures. Prerequisites may turn old reproductions into passing guards, but a remaining capability/control must first fail for its stated reason. Test paths are relative to the relevant repository.

1. **GivenSameOperation_WhenKeyBuiltTwice_ThenKeysAreStableAndDomainSeparated**
   - Layer: unit.
   - File location: `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt`.
   - Setup: identical t1/game/r1/p1/hand and bet b1 across two attempts.
   - Action: Capture keys emitted by the existing service in two isolated equivalent fixtures first (reproduction), then test extracted builders against the same captured contract.
   - Expected assertions: place key bet:t1:game:r1:p1:hand; all terminal keys settle:b1; changed hand yields different place key.
   - Expected failure on CURRENT code: fresh UUID keys differ on current service path; audit §11.5.

2. **GivenSameClaim_WhenOneHundredTransactionsRace_ThenOneOwnerAndSameResult**
   - Layer: concurrency.
   - File location: `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt`.
   - Setup: real transaction wrapper; identical command/fingerprint; 100 connections/workers with bounded pool.
   - Action: claim, perform one test effect, complete; run 100 rounds.
   - Expected assertions: one owner and one debit/effect; 100 identical stored responses; no ledger rows after losing rolled-back claim.
   - Expected failure on CURRENT code: claim is currently only terminal receipt insert; duplicates pass initial read.

3. **GivenReusedCommandOrLedgerKey_WhenPayloadDiffers_ThenConflict**
   - Layer: PostgreSQL integration.
   - File location: `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt`.
   - Setup: persist original amount 60; use 61 on retry; legacy fingerprint sentinel fixture.
   - Action: claim/post again and abort owner before completion in separate case.
   - Expected assertions: typed conflict/verified error code; no second movement; rollback permits retry ownership; legacy behavior explicitly tested.
   - Expected failure on CURRENT code: request mismatch may not be compared consistently before posting.

4. **GivenUncompletedEarlyClaim_WhenTransactionCommits_ThenCommitIsRejected**
   - Layer: PostgreSQL integration.
   - File location: `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt`.
   - Setup: claim receipt without final response or sequence.
   - Action: exit owner transaction without completion.
   - Expected assertions: transaction aborts; 0 durable pending receipts, 0 money movement and counter unchanged; complete/retry succeeds.
   - Expected failure on CURRENT code: no transaction-private early-claim completion invariant exists.

5. **GivenMixedOperations_WhenLocksAreObserved_ThenGlobalOrderIsPreserved**
   - Layer: concurrency.
   - File location: `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt`.
   - Setup: TC-001 PostgreSQL; two independent connections, barriers and acquisition tracing around this card's operation and an opposing command/lifecycle writer.
   - Action: Run 2 workers for 100 seeded iterations; hold the earlier lock, then request the later lock; assert acquisition ranks and bounded completion. For primitive-only cards use caller transactions; once handlers exist run the same scenario through them.
   - Expected assertions: receipt → round → bet → player account → sequence counter, skipping unused locks; commands shared round, lifecycle exclusive; zero rank inversions or unhandled deadlocks; failed attempts leave no effects.
   - Expected failure on CURRENT code: current paths have missing or unconstrained lock boundaries; an isolated inverted-order control must be detected even if predecessors already make the runtime path pass.

6. **GivenHistoricalMoneyAndOutcomeVectors_WhenRefactoredPathRuns_ThenSemanticsStayUnchanged**
   - Layer: unit / PostgreSQL integration.
   - File location: `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt`.
   - Setup: pre-change 1.0.0 golden outputs and funded PostgreSQL fixture; wager 101 minor units, multiplier 1.2345.
   - Action: Run pure outcome vectors and, where this path posts money, reserve/cancel/cash-out/loss through production adapters.
   - Expected assertions: floor(101 × 1.2345) = 124 minor units; reservation/refund = 101; loss payout = 0; existing PLAYER/ESCROW/HOUSE entries and balanced journal unchanged; 1.0.0 outcomes byte-for-byte equal.
   - Expected failure on CURRENT code: regression guard is expected green on current code; a changed rounding/encoding control must fail. It is not counted as the initial defect reproduction.

## 7. GREEN — minimal implementation steps

1. Define deterministic builders without changing monetary values or randomly generated record IDs that are not idempotency keys.
2. Reuse fingerprint if equivalent; otherwise add request_fingerprint with safe sentinel/backfill. Add the minimum verified claim representation needed by mandatory result/sequence fields in a new migration; no guessed temporary public response or sequence. Preferred representation, subject to Step 0 confirmation: an internal transaction-private pending receipt with nullable final sequence/response and guarded completion to an existing final status; no pending receipt may commit. Use database/transaction-completion validation and a test that aborts commit of an incomplete claim. Never allocate a placeholder sequence that collides with the new unique index.
3. Provide transaction-required claim/complete/replay methods, database uniqueness arbitration and same-key/different-payload ledger rejection. Test through a real joining transaction; wire production commands only in TC-008–010.

Migration contract: Read-only query for duplicate tenant/idempotency keys and invalid/ambiguous legacy receipt fingerprints. Record existing mandatory fields and reviewed claim schema; applied V21/V28 unchanged. Add only the next available Flyway version. Run the read-only diagnostic before changes; fail with affected identities on conflict, never delete money rows. Exercise empty install and representative upgrade copies.

API/configuration contract: Preserve external contracts unless the numbered steps explicitly identify an error/status/configuration change. Internal helper names are proposals; bind to inspected modules.

## 8. REFACTOR

- Extract repeated fixtures and narrowly scoped helper naming only with all numbered tests green; tests 1–6 protect behavior.
- Remove only superseded paths described by this card; retain compatibility guards. Do not add or rewrite source comments.

## 9. Failure handling and security notes

Global lock order: **receipt → round → bet → player account → sequence counter**. Commands hold the round shared; lifecycle holds it exclusively. Skip absent locks without reversing order; lock multiple bets by stable ID. The lock-order test above must expose an inversion. Exceptions roll back all effects; bounded retries re-read durable state with the same command identity; do not infer timeout success.

Fail closed on unavailable authoritative dependencies; duplicates/retries must meet the numbered assertions. Use test identities only, preserve tenant checks at the authoritative boundary, and redact credentials, unrevealed secrets and personal data from errors, logs and artifacts.

## 10. Acceptance criteria

- [ ] RED test 0 proves: place key bet:t1:game:r1:p1:hand; all terminal keys settle:b1; changed hand yields different place key.
- [ ] RED test 1 proves: one owner and one debit/effect; 100 identical stored responses; no ledger rows after losing rolled-back claim.
- [ ] RED test 2 proves: typed conflict/verified error code; no second movement; rollback permits retry ownership; legacy behavior explicitly tested.
- [ ] RED test 3 proves: transaction aborts; 0 durable pending receipts, 0 money movement and counter unchanged; complete/retry succeeds.
- [ ] RED test 4 proves: receipt → round → bet → player account → sequence counter, skipping unused locks; commands shared round, lifecycle exclusive; zero rank inversions or unhandled deadlocks; failed attempts leave no effects.
- [ ] RED test 5 proves: floor(101 × 1.2345) = 124 minor units; reservation/refund = 101; loss payout = 0; existing PLAYER/ESCROW/HOUSE entries and balanced journal unchanged; 1.0.0 outcomes byte-for-byte equal.

## 11. Definition of done

- [ ] All RED tests written, seen failing for the stated reason, then green
- [ ] Full existing test suites for touched modules still pass
- [ ] New migrations apply from an empty database and on a copy of existing data (pre-check query run)
- [ ] No unrelated files changed; no monetary formula changes unless stated
- [ ] Card status updated in 000-INDEX.md

Record migration N/A only when this PR contains no schema change. Existing passing guards are not fabricated RED evidence.

## 12. Risks, rollback and deployment notes

Keep this PR scoped to its declared part. Roll back application changes only if compatible with durable rows/contracts already written; prefer forward repair for applied migrations. Preserve evidence and money records. Phases 2–5 require drain-to-CLOSED, stop old instances, run pre-checks/migrations, then start the new version; never mix old locking/ownership behavior with new writers. Measure round/counter contention and bound waits. Do not erase financial evidence with a down migration.

## 13. Commands and artifacts

From slotting_admin: ./gradlew test --tests 'com.slotting.admin.gameprovider.AviatorCommandClaimPostgresTest' --console=plain; then ./gradlew test. Existing backend CI uses ./gradlew compileKotlin compileTestKotlin and ./gradlew test with JDK 17. TC-001 PostgreSQL must be available; no skip counts as success.

Artifacts: JUnit XML and HTML reports, actual RED/green output, fixture seed and diagnostic/pre-check output; include lock/concurrency traces and migration logs when applicable.

Suggested commits: `test: reproduce TC-006 deterministic-keys-and-early-claim-primitives` (RED), then `fix: complete TC-006 deterministic-keys-and-early-claim-primitives` (GREEN). One reviewable PR; update card/index status only on demonstrated completion.
