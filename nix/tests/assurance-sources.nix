let
  collect = import ../assurance-source-inventory.nix;
  source = {
    id = "rfc2119";
    edition = "RFC 2119";
    uri = "https://www.rfc-editor.org/rfc/rfc2119.txt";
    sha256 = builtins.hashString "sha256" "fixture";
  };
  run = sources: collect [ { inherit sources; } ];
  rejects = sources: !(builtins.tryEval (builtins.deepSeq (run sources) true)).success;
  lti = source // {
    id = "lti-core-1-3";
    uri = "https://www.imsglobal.org/spec/lti/v1p3/";
  };
in
assert (builtins.head (run [ lti ])).filename == "lti-core-1-3.raw";
assert
  builtins.length (run [
    lti
    (
      lti
      // {
        id = "lti-core-errata";
        uri = "https://www.imsglobal.org/spec/lti/v1p3/errata/";
      }
    )
  ]) == 2;
assert rejects [ (lti // { id = "../outside"; }) ];
assert rejects [ (lti // { uri = "https://www.imsglobal.org.evil.example/spec/lti/v1p3/"; }) ];
assert rejects [ (lti // { uri = "https://www.imsglobal.org/spec/lti/v1p3/?latest=1"; }) ];
assert rejects [ (lti // { uri = "http://www.imsglobal.org/spec/lti/v1p3/"; }) ];
assert rejects [
  lti
  (lti // { id = "different-id"; })
];
# Server/SDK overlap is shared only when the complete original pin agrees.
assert
  builtins.length (collect [
    { sources = [ source ]; }
    { sources = [ source ]; }
  ]) == 1;
assert
  builtins.length (run [
    source
    (
      source
      // {
        id = "rfc8174";
        uri = "https://www.rfc-editor.org/rfc/rfc8174.txt";
      }
    )
  ]) == 2;
assert rejects [
  source
  (source // { sha256 = builtins.hashString "sha256" "changed"; })
];
assert rejects [
  source
  (source // { edition = "another edition"; })
];
assert rejects [
  source
  (source // { id = "another-id"; })
];
assert rejects [
  source
  (
    source
    // {
      id = "collision";
      uri = "https://www.ietf.org/archive/rfc2119.txt";
    }
  )
];
assert rejects [ (source // { uri = "https://openid.net/specs/a.html?latest=1"; }) ];
assert rejects [ (source // { uri = "https://example.com/rfc2119.txt"; }) ];
assert rejects [ (source // { sha256 = ""; }) ];
true
