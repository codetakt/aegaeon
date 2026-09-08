{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [
    ps.argon2-cffi
    ps.cryptography
    ps.flask
    ps.psycopg
    ps.pyjwt
    ps.requests
  ]);
in
pkgs.runCommand "preview-review-contract" { nativeBuildInputs = [ python ]; } ''
  cp ${./review.py} review.py
  cp ${./rp.py} rp.py
  cp ${./seed.py} seed.py
  cp ${./test_review.py} test_review.py
  python3 -m unittest discover -s . -p 'test_*.py'
  touch "$out"
''
