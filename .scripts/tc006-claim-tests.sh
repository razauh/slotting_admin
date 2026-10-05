#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p .logs

if [ -z "${SLOTTING_ADMIN_DATABASE_URL:-}" ]; then
  export SLOTTING_ADMIN_DATABASE_URL="jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
  export SLOTTING_ADMIN_DATABASE_USERNAME="ci_runner"
  export SLOTTING_ADMIN_DATABASE_PASSWORD="ci_test_password_ephemeral"
fi

echo "Compiling main and test sources..." | tee .logs/tc006-compile.log
./gradlew compileKotlin compileTestKotlin --console=plain >> .logs/tc006-compile.log 2>&1
compile_status=$?
echo "compile_exit=$compile_status" | tee -a .logs/tc006-compile.log

echo "Running TC-006 focused PostgreSQL suite..." | tee .logs/tc006-claim-focused.log
./gradlew test --tests 'com.slotting.admin.gameprovider.AviatorCommandClaimPostgresTest' --console=plain >> .logs/tc006-claim-focused.log 2>&1
focused_status=$?
echo "focused_exit=$focused_status" | tee -a .logs/tc006-claim-focused.log

if [ "$compile_status" -eq 0 ] && [ "$focused_status" -eq 0 ]; then
  echo "Running full backend test suite..." | tee .logs/tc006-full.log
  ./gradlew test --console=plain >> .logs/tc006-full.log 2>&1
  echo "full_exit=$?" | tee -a .logs/tc006-full.log
fi
