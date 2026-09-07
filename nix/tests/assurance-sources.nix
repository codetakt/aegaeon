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
in
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
