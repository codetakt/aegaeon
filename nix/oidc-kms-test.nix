args:
(import ./server-test-package.nix args) {
  pname = "aegaeon-oidc-kms-test";
  dependencyName = "aegaeon-oidc-kms-test-dependencies";
  command = "cargo test --locked -p aegaeon-server --features kms-aws --lib --no-run";
  identityName = "oidc-kms-build.json";
  buildLog = "kms-build.jsonl";
  installer = "scripts/validation/oidc_kms_test_package.py";
}
