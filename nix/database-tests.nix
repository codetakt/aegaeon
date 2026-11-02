args:
(import ./server-test-package.nix args) {
  pname = "aegaeon-database-tests";
  dependencyName = "aegaeon-database-test-dependencies";
  command = "cargo test --locked -p aegaeon-server --lib --test dcr_database_test --no-run";
  # Crane's dummy source omits auto-discovered integration targets. Compile the
  # same dev dependencies through the library; the final build includes both targets.
  dependencyCommand = "cargo test --locked -p aegaeon-server --lib --no-run";
  identityName = "database-test-build.json";
  buildLog = "database-build.jsonl";
  installer = "scripts/validation/database_test_package.py";
}
