# Slotting administrator authority

This is the owning Kotlin/Spring boundary for `ADMIN-001-01`. The Android
applications are untrusted clients and do not authenticate or grant admin
authority.

Run the backend checks from this repository with:

```bash
./gradlew test
```

The first migration stores only redacted authentication state, audit lineage,
and an outbox record. MFA assertions are verified through `MfaVerifier` and
are never persisted or logged. Break-glass sessions expire after 30 minutes
and emit an alert. `RoleChangePolicy` requires a distinct second approver when
dual control is enabled.

The PostgreSQL migration is forward-only. Rollback must disable writers and
use compensating records; posted audit rows are never edited.

RBAC is enforced in `AdminAuthorizationService`: role permissions are defined
server-side, tenant/resource-owner mismatches fail closed, financial mutation
is not granted to any admin role, and role changes require a distinct second
approver when dual control is enabled. Authorization decisions are idempotent
and committed with redacted audit and outbox records.
