# TC-006 r4 post-fix evidence inventory

This directory is the immutable r4 archive of the clean post-fix evidence produced
before the Stage 3 GREEN and Stage 4 migration verification runs. It must not be
overwritten by later Gradle runs. New runs use new directories.

## Revision identity

- Git HEAD: `b26bb0f98b3363efb40d71d73207cd58360aef70`
- HEAD subject: `feat(gameprovider): implement TC-004 round CAS transitions and row lock hierarchy`
- Working tree: uncommitted TC-005/TC-006 changes on top of HEAD.
- Tracked-change patch: `working-tree-tracked.patch`
  - sha256: `2b66dd5d887e84d7ce71a2a9c97ba685ffb4de2dbef5dbabf98d456253a2e784`
  - This patch covers tracked modifications only. The new TC-005/TC-006 files
    are untracked and are recorded below.
- Untracked new/changed source identities (sha256):
  - `src/main/kotlin/com/slotting/admin/gameprovider/AviatorCommandKeys.kt`
    `3660fa43a4ac5a802397c0d836b96111d2cc68d4888bd88dec6cb6e18dd27233`
  - `src/main/kotlin/com/slotting/admin/gameprovider/CommandSequenceDiagnostics.kt`
    `157dacc83f709fd301f86692e364285c242594e8f785b5fef4d823137624e422`
  - `src/main/resources/db/migration/V39__atomic_command_sequence_allocation.sql`
    `815f4fccbdd218f05561760a4953743c08d7e7469da9f7b9b0fae3422054cff2`
  - `src/main/resources/db/migration/V40__deterministic_command_keys_and_early_claim.sql`
    `1b8813b8991aba719afcb294457fa06695ebb3914189c38afea5564cfc76600b`
  - `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandClaimPostgresTest.kt`
    `e3ee0a1405b649a7f18fd32875e697d807a19c44239d20f7c0a9f3e06b2fe1f7`
  - `src/test/kotlin/com/slotting/admin/gameprovider/AviatorCommandSequencePostgresTest.kt`
    `01c49155690565d008825d72443f75839003f25b8df47c89a51b9e3607a63b55`

## Environment

- Runtime: OpenJDK 17.0.20 (`17.0.20+8-1-24.04-Ubuntu`)
- Gradle wrapper: repository `./gradlew`
- Database: PostgreSQL 16, external service at `jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci`
- Database credentials for the run: user `ci_runner`, ephemeral test password.
- Runner scripts: `.scripts/tc006-claim-tests.sh` (compile, focused, full),
  `.scripts/tc006-baseline-full.sh` (baseline), `.scripts/tc006-clean-baseline-schema.sh`.

## Command outcomes

| Command | Result | Exit |
|---|---|---|
| `./gradlew compileKotlin compileTestKotlin` | BUILD SUCCESSFUL | 0 |
| `./gradlew test --tests '...AviatorCommandClaimPostgresTest'` | BUILD SUCCESSFUL, `FROM-CACHE` | 0 |
| `./gradlew test` | 1,330 tests, 57 failures | 1 |

Log digests:

- `logs/tc006-compile.log` sha256 `c7303764aa30bbdea3ddec81a9fd3499cfb5be9b71d76ccdc625d77eb2f88772`
- `logs/tc006-claim-focused.log` sha256 `41ad1de25fbbfc057bee12c8c4e4baa4ae5b816140cfdb412b65bc016ab5523b`
- `logs/tc006-full.log` sha256 `2879dc27d5990ac981c906976fcb5747eb552f094c2e5ba4fe68b67ae21a9305`

The focused invocation restored `:test` from the Gradle cache. The post-fix
execution evidence for the six TC-006 tests is therefore taken from the full-suite
JUnit XML in `junit-xml/`, which records the suite as executed with 6/6 passing.

## Relevant suite counts (from `junit-xml/`, full run)

| Suite | Tests | Skipped | Failures | Errors |
|---|---:|---:|---:|---:|
| `AviatorCommandClaimPostgresTest` | 6 | 0 | 0 | 0 |
| `AviatorCommandSequencePostgresTest` | 5 | 0 | 0 | 0 |
| `PostgresMigrationIntegrationTest` | 4 | 0 | 0 | 0 |
| `PersistentDoubleEntryLedgerContractTest` | 12 | 0 | 0 | 0 |
| `DurableGameWagerAndSettlementAuthorityContractTest` | 11 | 0 | 0 | 0 |

## Full-suite failure classification

- Current failing identities: 57, listed in `failure-identities.txt`.
- Aggregate JUnit XML digest: `09a2b257e88ad5076b30af3c192f886dc45ac47093e358d9b554b3efec1fc508`.
- Corrected baseline r3 vs r4: `0 only-r3`, `0 only-r4`, `57 shared` (identical sets).
- Clean current r1 vs r4: `0 only-r1`, `0 only-r4`, `57 shared` (identical sets).
- Classification: 57 pre-existing, 0 introduced, 0 unclear.
- Message-only drift: 9 failures add `V40` to an already-failing migration
  inventory assertion (`Found illegal migrations > V16: [...]`). r3 baseline has
  0 messages containing `V40`; r1 and r4 have 9 each. No passing baseline test
  fails in the current tree.

## Contents

- `logs/` — compile, focused, and full Gradle console logs.
- `junit-xml/` — 259 JUnit XML files from the clean full-suite run.
- `reports-html/` — Gradle HTML test report from the same run.
- `failure-identities.txt` — the 57 failing class-and-method identities.
- `working-tree-tracked.patch` — tracked diff for the TC-005/TC-006 working tree.
- `card-TC-006-at-archive.md` — TC-006 card status at archive time (`TODO`).
- `index-at-archive.md` — `000-INDEX.md` status at archive time (`TODO`).

## Notes

- `.logs/tc006-evidence-r2` is retained only as the audit record of the invalid
  schema-polluted comparison and must not be used as acceptance evidence.
- This archive does not by itself close the RED-for-stated-reason gate. That
  evidence is produced separately by the baseline reproduction in Stage 2.
