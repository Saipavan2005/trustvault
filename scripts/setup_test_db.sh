#!/usr/bin/env bash
# Creates an isolated trustvault_test database on the same RDS instance.
# Usage: RDS=<endpoint> ./scripts/setup_test_db.sh    (asks for the tvadmin and migrator passwords)
set -euo pipefail
: "${RDS:?set RDS to the RDS endpoint}"
psql "host=$RDS dbname=postgres user=tvadmin sslmode=require" \
  -c "DROP DATABASE IF EXISTS trustvault_test" -c "CREATE DATABASE trustvault_test OWNER migrator"
psql "host=$RDS dbname=trustvault_test user=migrator sslmode=require" -f db/schema.sql
echo "Now export TEST_DATABASE_URL (app_user) and TEST_MIGRATOR_URL (migrator) pointing at trustvault_test."
