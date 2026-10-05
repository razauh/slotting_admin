#!/usr/bin/env bash
set -uo pipefail

REPO="/home/pc/Downloads/slot_app/slotting_admin"
LOGS="$REPO/.logs"
HOST="127.0.0.1"
PORT="5432"
PG_USER="ci_runner"
PG_PASSWORD="ci_test_password_ephemeral"
APP_DB="slotting_admin_ci"

CONDA_BASE="$(conda info --base 2>/dev/null || echo "$HOME/miniconda3")"
PG_ENV="${TC006_PG_ENV:-$CONDA_BASE/envs/tc006-pg16}"
PGDATA="${TC006_PGDATA:-/tmp/opencode/tc006-pgdata}"
PGLOG="$LOGS/tc006-ensure-postgres.log"

mkdir -p "$LOGS" /tmp/opencode

reachable() {
  (exec 3<>/dev/tcp/"$HOST"/"$PORT") 2>/dev/null
}

{
  echo "TC-006 PostgreSQL bootstrap"
  echo "Runtime UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Host/port: $HOST:$PORT"
  echo "Conda base: $CONDA_BASE"
  echo "Conda env: $PG_ENV"
  echo "Data dir: $PGDATA"
  echo "---"
} > "$PGLOG"

PGBIN=""
for candidate in "$PG_ENV/bin" "$CONDA_BASE/bin"; do
  if [ -x "$candidate/pg_ctl" ] && [ -x "$candidate/initdb" ] && [ -x "$candidate/psql" ]; then
    PGBIN="$candidate"
    break
  fi
done

if reachable; then
  echo "PostgreSQL already reachable on $HOST:$PORT." | tee -a "$PGLOG"
else
  if [ -z "$PGBIN" ]; then
    if ! command -v conda >/dev/null 2>&1; then
      echo "No PostgreSQL binaries found and conda is unavailable. Install PostgreSQL 16 or set TC006_PG_ENV." | tee -a "$PGLOG"
      exit 1
    fi
    echo "Provisioning PostgreSQL 16 into $PG_ENV via conda-forge (this can take several minutes)..." | tee -a "$PGLOG"
    if ! conda create -y -p "$PG_ENV" -c conda-forge "postgresql=16" >> "$PGLOG" 2>&1; then
      echo "conda create failed. See $PGLOG." | tee -a "$PGLOG"
      exit 1
    fi
    PGBIN="$PG_ENV/bin"
  fi

  if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "Initializing a local cluster at $PGDATA with trust authentication..." | tee -a "$PGLOG"
    rm -rf "$PGDATA"
    mkdir -p "$PGDATA"
    if ! "$PGBIN/initdb" -D "$PGDATA" -U postgres -A trust >> "$PGLOG" 2>&1; then
      echo "initdb failed. See $PGLOG." | tee -a "$PGLOG"
      exit 1
    fi
  fi

  echo "Starting PostgreSQL on $HOST:$PORT..." | tee -a "$PGLOG"
  "$PGBIN/pg_ctl" -D "$PGDATA" -l "$LOGS/tc006-postgres-server.log" \
    -o "-p $PORT -k /tmp/opencode -c listen_addresses=$HOST" start >> "$PGLOG" 2>&1

  for _ in $(seq 1 30); do
    reachable && break
    sleep 1
  done

  if ! reachable; then
    echo "PostgreSQL did not become reachable on $HOST:$PORT. See $LOGS/tc006-postgres-server.log." | tee -a "$PGLOG"
    exit 1
  fi
fi

if [ -z "$PGBIN" ]; then
  echo "PostgreSQL is reachable but no local psql client was found; cannot ensure role $PG_USER or database $APP_DB." | tee -a "$PGLOG"
  echo "The test suites use the lock-order control that requires a superuser role ($PG_USER)." | tee -a "$PGLOG"
  exit 1
fi

"$PGBIN/psql" -h "$HOST" -p "$PORT" -U postgres -tAc \
  "select 1 from pg_roles where rolname = '$PG_USER'" -d postgres 2>>"$PGLOG" | grep -q 1 \
  || "$PGBIN/createuser" -h "$HOST" -p "$PORT" -U postgres "$PG_USER" >> "$PGLOG" 2>&1

"$PGBIN/psql" -h "$HOST" -p "$PORT" -U postgres -v ON_ERROR_STOP=1 -d postgres \
  -c "alter role $PG_USER with login password '$PG_PASSWORD' createdb superuser" >> "$PGLOG" 2>&1

"$PGBIN/psql" -h "$HOST" -p "$PORT" -U postgres -tAc \
  "select 1 from pg_database where datname = '$APP_DB'" -d postgres 2>>"$PGLOG" | grep -q 1 \
  || "$PGBIN/createdb" -h "$HOST" -p "$PORT" -U postgres -O "$PG_USER" "$APP_DB" >> "$PGLOG" 2>&1

if reachable; then
  echo "PostgreSQL 16 is ready on $HOST:$PORT with superuser role $PG_USER and database $APP_DB." | tee -a "$PGLOG"
  exit 0
fi

echo "PostgreSQL bootstrap failed. See $PGLOG." | tee -a "$PGLOG"
exit 1
