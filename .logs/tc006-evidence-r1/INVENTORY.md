# TC-006 evidence inventory (run r1)

- Captured: 2026-10-05T20:24:32
- Repo: slotting_admin
- Git HEAD: b26bb0f98b3363efb40d71d73207cd58360aef70
- Working tree: DIRTY (uncommitted TC-005 + TC-006 changes)
- PostgreSQL: 16 at 127.0.0.1:5432, database slotting_admin_ci, user ci_runner
- JDK: 17 toolchain (gradle)
- Runner: .scripts/tc006-claim-tests.sh

## Observed runs (from copied logs)
- compile: BUILD SUCCESSFUL, exit 0 (.logs/tc006-compile.log)
- focused AviatorCommandClaimPostgresTest: BUILD SUCCESSFUL, exit 0, 6/0/0 (log + full-suite XML)
- full ./gradlew test: exit 1, 1330 tests, 57 failures (.logs/tc006-full.log)
  NOTE: the script ran the full suite after the focused suite, so build/test-results XML reflects the FULL run;
  the focused suite XML was overwritten. Focused per-test counts were recovered from the full-suite XML
  (AviatorCommandClaimPostgresTest tests=6 failures=0 errors=0).

## Full-suite failures (57) with V40 mention flag
total=57 with_V40_in_message=9
- [   ] com.slotting.admin.aml.AmlAlertCaseCreationTest :: AML-002-02-T004 Create AML alerts and review cases remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.aml.AuthoritativeFraudSignalTest :: AML-002-01-T004 Collect authoritative fraud signals remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.aml.DurableAccountRestrictionEnforcementTest :: AML-002-03-T004 Enforce durable account restrictions remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.aml.ImmutableAmlDecisionTest :: AML-003-02-T004 Record immutable AML decisions remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.aml.SourceOfFundsEvidenceTest :: AML-003-01-T004 Collect source-of-funds evidence remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [V40] com.slotting.admin.auth.ApiResourceOwnershipTest :: AUTHZ-002-01-T004 Enforce API resource ownership remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Found illegal migrations > V16: [V32__durable_administrative_bans.sql, V39__atomic_command_sequence_allocation.sql, V17__op
- [V40] com.slotting.admin.auth.FourEyesPrimitivesTest :: AUTHZ-003-T004 Four-eyes primitives remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Found illegal migrations > V16: [V32__durable_administrative_bans.sql, V39__atomic_command_sequence_allocation.sql, V17__op
- [V40] com.slotting.admin.auth.PlayerAdminRbacSeparationTest :: AUTHZ-002-02-T004 Enforce player and admin RBAC separation remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Found illegal migrations > V16: [V32__durable_administrative_bans.sql, V39__atomic_command_sequence_allocation.sql, V17__op
- [   ] com.slotting.admin.bonus.BonusAdministrationTest :: BONUS-003-01-T004 Migration integrity recovery and observability verification()
      org.opentest4j.AssertionFailedError: Migration version 32 exceeds V16 limit! Found: V32__durable_administrative_bans.sql
- [   ] com.slotting.admin.bonus.BonusExpiryForfeitureTest :: BONUS-002-01-T004 Migration integrity recovery and observability verification()
      org.opentest4j.AssertionFailedError: Migration version 32 exceeds V16 limit! Found: V32__durable_administrative_bans.sql
- [V40] com.slotting.admin.bonus.BonusGrantTest :: BONUS-001-01-T004 Post isolated bonus grants remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Found illegal migrations > V16: [V32__durable_administrative_bans.sql, V39__atomic_command_sequence_allocation.sql, V17__op
- [   ] com.slotting.admin.bonus.BonusRevocationAuditTest :: BONUS-003-02-T004 Migration integrity recovery and observability verification()
      org.opentest4j.AssertionFailedError: Migration version 32 exceeds V16 limit! Found: V32__durable_administrative_bans.sql
- [   ] com.slotting.admin.bonus.BonusSpendingWithdrawalRestrictionTest :: BONUS-001-02-T004 Migration integrity recovery and observability verification()
      org.opentest4j.AssertionFailedError: Migration version 32 exceeds V16 limit! Found: V32__durable_administrative_bans.sql
- [   ] com.slotting.admin.bonus.BonusStatementDisclosureTest :: BONUS-002-02-T004 Migration integrity recovery and observability verification()
      org.opentest4j.AssertionFailedError: Migration version 32 exceeds V16 limit! Found: V32__durable_administrative_bans.sql
- [   ] com.slotting.admin.crm.CommunicationPreferenceEnforcementTest :: CRM-002-02-T004 Enforce communication preferences remains compatible recoverable observable and lifecycle safe()
      org.opentest4j.AssertionFailedError: Unapproved migration V17 must not exist
- [   ] com.slotting.admin.crm.ExternalCrmContractTest :: CRM-001-T004 External CRM contract events remains compatible recoverable observable and lifecycle safe()
      org.opentest4j.AssertionFailedError: Unapproved migration V17 must not exist
- [   ] com.slotting.admin.crm.NonAuthoritativeCrmBoundaryTest :: ADR-007-02-T004 Define non-authoritative CRM integration boundary remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.crm.NonAuthoritativeVipSegmentTest :: CRM-002-03-T004 Control non-authoritative VIP tags and segments remains compatible recoverable observable and lifecycle safe()
      org.opentest4j.AssertionFailedError: Unapproved migration V17 must not exist
- [   ] com.slotting.admin.crm.PrivilegedAdminBoundaryTest :: ADR-007-01-T004 Define privileged admin integration boundary remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.crm.SupportTimelineIntegrationTest :: CRM-003-T004 Support timeline integration remains compatible recoverable observable and lifecycle safe()
      org.opentest4j.AssertionFailedError: Unapproved migration V17 must not exist
- [   ] com.slotting.admin.crm.VersionedConsentTest :: CRM-002-01-T004 Record versioned communication consent remains compatible recoverable observable and lifecycle safe()
      org.opentest4j.AssertionFailedError: Unapproved migration V17 must not exist
- [   ] com.slotting.admin.game.GamePortTest :: ADR-005-01-T004 Define provider-neutral game port remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.game.SignedGameCallbackBoundaryTest :: ADR-005-02-T004 Define signed game-callback boundary remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.gameprovider.AuthenticatedCasinoAdapterTest :: GAME-001-03-T004 Implement authenticated sandbox and production adapter remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be false.
- [   ] com.slotting.admin.gameprovider.AuthoritativeCatalogSyncTest :: GAME-002-01-T004 Synchronize authoritative provider catalog remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be false.
- [   ] com.slotting.admin.gameprovider.CanonicalCasinoProviderContractTest :: GAME-001-01-T004 Define canonical casino provider contract remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be false.
- [   ] com.slotting.admin.gameprovider.CasinoProviderFakeAdapterTest :: GAME-001-02-T004 Build casino provider fake adapter remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be false.
- [   ] com.slotting.admin.gameprovider.OperatorJurisdictionEnablementTest :: GAME-002-02-T004 Enforce operator and jurisdiction game enablement remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be false.
- [   ] com.slotting.admin.geo.GeolocationVendorEvidencePortTest :: ADR-006-02-T004 Define geolocation vendor evidence port remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [V40] com.slotting.admin.identity.AccountStateLifecycleTest :: AUTH-003-02-T004 Implement lock, suspend, and close account states remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved SQL migration beyond V16 may be introduced: [V32__durable_administrative_bans.sql, V39__atomic_command_sequen
- [   ] com.slotting.admin.identity.ConfigurableMfaChallengeTest :: AUTH-001-04-T004 Implement configurable MFA challenges remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved V17 migration should be introduced
- [V40] com.slotting.admin.identity.LoginAbuseDefenseTest :: AUTH-003-01-T004 Implement login abuse defenses remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved SQL migration beyond V16 may be introduced: [V32__durable_administrative_bans.sql, V39__atomic_command_sequen
- [   ] com.slotting.admin.identity.PlayerAccountRecoveryTest :: AUTH-001-03-T004 Implement account recovery remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved V17 migration should be introduced
- [   ] com.slotting.admin.identity.PlayerLoginLogoutLifecycleTest :: AUTH-001-02-T004 Implement login and logout lifecycle remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved V17 migration should be introduced
- [   ] com.slotting.admin.identity.PlayerRegistrationVerificationTest :: AUTH-001-01-T004 Implement player registration and contact verification remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved V17 migration should be introduced
- [V40] com.slotting.admin.identity.RefreshTokenRotationTest :: AUTH-002-02-T004 Rotate refresh-token families with reuse detection remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved SQL migration beyond V16 may be introduced: [V32__durable_administrative_bans.sql, V39__atomic_command_sequen
- [V40] com.slotting.admin.identity.ServerEligibilityPolicyTest :: AUTHZ-001-T004 Migration integrity, recovery and restart, observability and redaction()
      org.opentest4j.AssertionFailedError: Found illegal migrations > V16: [V32__durable_administrative_bans.sql, V39__atomic_command_sequence_allocation.sql, V17__op
- [V40] com.slotting.admin.identity.SessionDeviceInventoryTest :: AUTH-002-03-T004 Implement session revocation and device inventory remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved SQL migration beyond V16 may be introduced: [V32__durable_administrative_bans.sql, V39__atomic_command_sequen
- [   ] com.slotting.admin.identity.ShortLivedTokenTest :: AUTH-002-01-T004 Issue short-lived access tokens remains compatible recoverable observable and lifecycle-safe()
      org.opentest4j.AssertionFailedError: No unapproved V17 migration should be introduced
- [   ] com.slotting.admin.kyc.KycVendorEvidencePortTest :: ADR-006-01-T004 Define KYC vendor evidence port remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.ledger.LedgerDesignTest :: ADR-001-T004 Ledger design remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.locking.LockingStrategyTest :: ADR-002-T004 Locking idempotency strategy remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.outbox.RetryDeadLetterReplayPolicyTest :: ADR-003-02-T004 Decide retry, dead-letter, and replay policy remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.outbox.TransactionalOutboxTest :: ADR-003-01-T004 Decide transactional outbox contract remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.payment.AdversarialPaymentProviderFakeTest :: PAYMENT-001-02-T004 — Build adversarial payment provider fake remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be false.
- [   ] com.slotting.admin.payment.CanonicalPaymentProviderPortTest :: PAYMENT-001-01-T004 — Define canonical payment provider port remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be false.
- [   ] com.slotting.admin.payment.ChargebackDisputeTest :: PAYMENT-006-02-T004 — Manage chargeback disputes remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.ControlledFinanceReportTest :: PAYMENT-007-02-T004 — Produce controlled finance reconciliation reports remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.DepositDurableInboxTest :: PAYMENT-003-02-T004 — Persist deposit callbacks in a durable inbox remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.DepositStateMachineTest :: PAYMENT-002-T004 — Deposit state machine remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.DepositWebhookAuthenticationTest :: PAYMENT-003-01-T004 — Authenticate deposit webhook raw bodies remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.PaymentAdapterCertificationTest :: ADR-004-02-T004 Define payment-adapter certification boundary remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.payment.PaymentPortTest :: ADR-004-01-T004 Define provider-neutral payment port remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: Expected value to be true.
- [   ] com.slotting.admin.payment.ProviderLedgerReconciliationTest :: PAYMENT-007-01-T004 — Reconcile provider and ledger items remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.RefundReversalCompensationTest :: PAYMENT-006-01-T004 — Post refund and reversal compensation remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.ServerOnlyDepositCreditTest :: PAYMENT-005-T004 — Server-only deposit credit remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
- [   ] com.slotting.admin.payment.WebhookOrderingIdempotencyTest :: PAYMENT-004-T004 — Webhook ordering idempotency remains compatible, recoverable, observable, and lifecycle-safe()
      org.opentest4j.AssertionFailedError: V17 must not be created prematurely
