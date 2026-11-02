# Browser form/CSP evaluation uses actual Rust handlers and restricted PostgreSQL.
# CDP owns every navigation transport; this is not a production TLS qualification.
{
  pkgs,
  src,
  databaseTests,
  nodejsRuntime,
}:
pkgs.runCommand "aegaeon-lti-browser-consent"
  {
    nativeBuildInputs = with pkgs; [
      postgresql_18
      atlas
      python3
      coreutils
      nodejsRuntime
    ];
    AEGAEON_CHROMIUM = "${pkgs.chromium}/bin/chromium";
    AEGAEON_LTI_BROWSER_SCRIPT = "${src}/tests/lti/browser_consent.mjs";
  }
  ''
    set -euo pipefail
    mkdir -p "$out" "$TMPDIR/socket" "$TMPDIR/restricted" "$TMPDIR/browser-config"
    export CHROME_CONFIG_HOME="$TMPDIR/browser-config"
    chmod 700 "$TMPDIR/restricted"
    export PGHOST="$TMPDIR/socket" PGUSER=postgres PGDATABASE=postgres
    initdb -D "$TMPDIR/data" -U postgres --no-locale --encoding=UTF8 --auth-local=trust --auth-host=reject > "$out/initdb.log"
    trap 'pg_ctl -D "$TMPDIR/data" -w -t 20 -m immediate stop >> "$out/stop.log" 2>&1 || true' EXIT
    pg_ctl -D "$TMPDIR/data" -l "$out/postgres.log" -w -t 20 -o "-k $PGHOST -c listen_addresses=" start
    export AEGAEON_TEST_ADMIN_DATABASE_URL="postgresql://postgres@localhost/postgres?host=$PGHOST&sslmode=disable"
    export AEGAEON_TEST_DATABASE_FIXTURE_DIRECTORY="$TMPDIR/restricted"
    timeout 120 python3 ${src}/scripts/tests/subject_ownership_fixture.py prepare-runtime "$TMPDIR/restricted" > "$out/provision.log" 2>&1
    export AEGAEON_DATABASE_URL
    AEGAEON_DATABASE_URL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["urls"]["runtime"])' "$TMPDIR/restricted/suppliers.json")
    cd ${src}/crates/server
    if ! timeout --kill-after=5s 60s ${databaseTests}/libexec/aegaeon_server \
      web::lti::tests::browser::dedicated_lti_browser_consent \
      --exact --ignored --nocapture --test-threads=1 > "$out/browser.log" 2>&1; then
      cat "$out/browser.log"
      exit 1
    fi
    grep -F '1 passed; 0 failed' "$out/browser.log"
    timeout 30 python3 ${src}/scripts/tests/subject_ownership_fixture.py cleanup "$TMPDIR/restricted" > "$out/cleanup.log" 2>&1
    pg_ctl -D "$TMPDIR/data" -w -t 20 -m fast stop > "$out/stop.log"
    trap - EXIT
  ''
