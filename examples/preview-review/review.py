"""Run an isolated PostgreSQL/Redis/OIDC review of a prebuilt server preview."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from rp import RelyingParty, create_app, smoke
from seed import b64, seed
from werkzeug.serving import WSGIRequestHandler, make_server

SOURCE_REVISION = "4f22252f8f0f1320d20c8ce90d6476cc670a3e45"
SOURCE_NAR_HASH = "sha256-EospsV8oCnQA6M/yqt/bKltAAmE0iXavl708bgXsbgY="
FLAKE_NAME = "codetakt-inc/aegaeon"
REDIS_SURFACES = (
    "AUTH_CODE",
    "AUTH_SESSION",
    "CLIENT_ASSERTION_REPLAY",
    "DEVICE_CODE",
    "DEVICE_CSRF",
    "DEVICE_RATE_LIMIT",
    "DPOP_NONCE",
    "DPOP",
    "JWKS",
    "LOCAL_AUTH_CSRF",
    "LOCAL_LOGIN_RATE_LIMIT",
    "MANAGEMENT_LOGIN_RATE_LIMIT",
    "MANAGEMENT_SESSION",
    "OIDC_LOGOUT_SESSION",
    "PAR",
    "REQUEST_OBJECT_JTI",
    "STEPUP",
    "TOKEN_STORE",
    "UPSTREAM_AUTH",
    "UPSTREAM_LOGOUT_RELAY",
)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def validate_manifest(record, source_revision):
    identity = (
        record["version"],
        record["distribution"],
        record["repository"],
        record["attribute"],
        record["executable"],
    )
    if type(record["version"]) is not int or identity != (
        1,
        "internal-preview",
        "codetakt/aegaeon",
        "packages.x86_64-linux.server",
        "bin/aegaeon-server",
    ):
        msg = "unsupported preview manifest"
        raise ValueError(msg)
    source = record["server_source"]
    if (
        (source["owner"], source["repo"], source["rev"])
        != (
            "codetakt",
            "aegaeon",
            source_revision,
        )
        or source_revision != SOURCE_REVISION
        or source["narHash"] != SOURCE_NAR_HASH
    ):
        msg = "review migrations and server source must match the supported revision"
        raise ValueError(msg)
    if not re.fullmatch(r"[0-9a-f]{40}", record["revision"]) or not re.fullmatch(
        r"[0-9a-f]{64}", record["binary_sha256"]
    ):
        msg = "invalid revision or binary digest"
        raise ValueError(msg)
    if "flakeref_exact" in record and not re.fullmatch(
        re.escape(FLAKE_NAME) + r"/=0\.1\.[0-9]+\+rev-" + record["revision"],
        record["flakeref_exact"],
    ):
        msg = "preview reference must pin the publication revision"
        raise ValueError(msg)


def verify_output(record, output):
    resolved = output.resolve(strict=True)
    if str(resolved) != record["store_path"] or not str(resolved).startswith("/nix/store/"):
        msg = "output path differs from the preview manifest"
        raise ValueError(msg)
    executable = resolved / "bin/aegaeon-server"
    if (
        not executable.is_file()
        or not os.access(executable, os.X_OK)
        or digest(executable) != record["binary_sha256"]
    ):
        msg = "server executable differs from the preview manifest"
        raise ValueError(msg)
    paths = json.loads(
        subprocess.check_output(
            ["nix", "path-info", "--recursive", "--json", "--json-format", "1", str(resolved)]
        )
    )
    if {path: info["narHash"] for path, info in paths.items()} != record["closure"]:
        msg = "runtime closure differs from the preview manifest"
        raise ValueError(msg)
    return executable


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)


def start(stack, argv, log, env):
    output = stack.enter_context(log.open("w"))
    child = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, env=env)
    stack.callback(stop, child)
    return child


def wait_database(database_url, child):
    for _ in range(100):
        if child.poll() is not None:
            msg = "PostgreSQL exited; see postgres.log"
            raise RuntimeError(msg)
        try:
            with psycopg.connect(database_url, connect_timeout=1):
                return
        except psycopg.OperationalError:
            time.sleep(0.1)
    msg = "PostgreSQL startup timed out"
    raise TimeoutError(msg)


def certificates(state):
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegaeon review root CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegaeon local review")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    # Only the root certificate is retained; its signing key stays in memory.
    (state / "review-ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (state / "localhost.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (state / "localhost-key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def wait_http(url, ca, children):
    http = requests.Session()
    http.trust_env = False
    for _ in range(120):
        if any(child.poll() is not None for child in children):
            msg = "review process exited; inspect the private process logs"
            raise RuntimeError(msg)
        try:
            response = http.get(url, verify=str(ca), timeout=1, allow_redirects=False)
            if response.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.25)
    msg = "server readiness timed out"
    raise TimeoutError(msg)


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        # Authorization codes and state in callback URLs must not enter logs.
        pass


def prepare_inputs(args, state, evidence):
    source_revision = os.environ.get("AEGAEON_REVIEW_SOURCE_REVISION")
    migration_directory = os.environ.get("AEGAEON_REVIEW_MIGRATIONS")
    if not source_revision or not migration_directory:
        msg = (
            "AEGAEON_REVIEW_SOURCE_REVISION and AEGAEON_REVIEW_MIGRATIONS are required; "
            "run nix develop in examples/preview-review before starting the review"
        )
        raise ValueError(msg)
    record = json.loads(args.manifest.read_text())
    validate_manifest(record, source_revision)
    migrations = Path(migration_directory)
    if not (migrations / "atlas.sum").is_file():
        msg = "pinned migration inventory is missing; enter this example's Nix shell"
        raise ValueError(msg)
    tools = ("initdb", "postgres", "atlas", "redis-server", "caddy", "nix")
    for command in tools + (() if args.local_output else ("fh",)):
        if shutil.which(command) is None:
            msg = f"required tool missing: {command}"
            raise ValueError(msg)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AEGAEON_", "PG", "REDIS_", "CADDY_"))
    }
    evidence.update(
        {
            "retrieval": "local preparation" if args.local_output else "FlakeHub fetch",
            "preview_manifest_sha256": digest(args.manifest),
            "preview": record,
            "migration_inventory_sha256": digest(migrations / "atlas.sum"),
            "review_kit_sha256": {
                name: digest(Path(__file__).parent / name)
                for name in ("review.py", "rp.py", "seed.py", "flake.nix", "flake.lock")
            },
            "release_assurance": "not established",
        }
    )
    output = args.local_output
    if output is None:
        if "flakeref_exact" not in record:
            msg = "published manifest must contain an exact FlakeHub reference"
            raise ValueError(msg)
        output = state / "aegaeon"
        fetch_env = {
            **env,
            "NIX_CONFIG": env.get("NIX_CONFIG", "") + "\nmax-jobs = 0\nbuilders =\n",
        }
        with (state / "fetch.log").open("w") as log:
            subprocess.run(
                ["fh", "fetch", record["flakeref_exact"] + "#" + record["attribute"], str(output)],
                env=fetch_env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
    executable = verify_output(record, output)
    evidence["artifact_identity"] = "matched executable and complete runtime closure"
    return executable, migrations, env


def prepare_local(state, env):
    ports = dict(
        zip(
            ("postgres", "redis", "server", "issuer", "rp"), (port() for _ in range(5)), strict=True
        )
    )
    if len(set(ports.values())) != len(ports):
        msg = "port allocation collided; start again in a new state directory"
        raise RuntimeError(msg)
    password, db_password, redis_password = (secrets.token_urlsafe(24) for _ in range(3))
    kek = secrets.token_bytes(32)
    (state / "database-password").write_text(db_password)
    (state / "login.txt").write_text("Email: reviewer@example.com\nPassword: " + password + "\n")
    database_url = (
        f"postgresql://review:{db_password}@127.0.0.1:{ports['postgres']}/postgres?sslmode=disable"
    )
    issuer = f"https://localhost:{ports['issuer']}"
    rp_url = f"https://localhost:{ports['rp']}"
    with (state / "initdb.log").open("w") as log:
        subprocess.run(
            [
                "initdb",
                "-D",
                str(state / "postgres"),
                "-U",
                "review",
                "--auth=scram-sha-256",
                "--pwfile",
                str(state / "database-password"),
                "--no-locale",
                "--encoding=UTF8",
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
    certificates(state)
    return ports, password, redis_password, kek, database_url, issuer, rp_url


def serve_browser(relying_party, state, ports, rp_url):
    print(
        f"Open {rp_url}\nLocal root certificate: {state / 'review-ca.pem'}\n"
        f"Login details: {state / 'login.txt'}\nPress Ctrl-C to stop all services.",
        flush=True,
    )
    app = create_app(relying_party)
    app.config["TRUSTED_HOSTS"] = ["localhost"]
    with make_server(
        "127.0.0.1",
        ports["rp"],
        app,
        ssl_context=(str(state / "localhost.pem"), str(state / "localhost-key.pem")),
        request_handler=QuietHandler,
    ) as web:
        web.serve_forever()


def run(args, state, evidence):
    executable, migrations, env = prepare_inputs(args, state, evidence)
    ports, password, redis_password, kek, database_url, issuer, rp_url = prepare_local(state, env)
    with ExitStack() as stack:
        database = start(
            stack,
            [
                "postgres",
                "-D",
                str(state / "postgres"),
                "-k",
                "",
                "-h",
                "127.0.0.1",
                "-p",
                str(ports["postgres"]),
            ],
            state / "postgres.log",
            env,
        )
        wait_database(database_url, database)
        with (state / "migrations.log").open("w") as log:
            subprocess.run(
                [
                    "atlas",
                    "migrate",
                    "apply",
                    "--revisions-schema",
                    "public",
                    "--url",
                    database_url,
                    "--dir",
                    "file://" + str(migrations),
                ],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
        seeded = seed(database_url, urlsplit_host(issuer), password, kek)
        write_json(state / "configuration.json", seeded)
        redis_config = state / "redis.conf"
        redis_config.write_text(
            f"bind 127.0.0.1\nport {ports['redis']}\nrequirepass {redis_password}\n"
            f'save ""\nappendonly no\ndir "{state}"\n'
        )
        redis = start(stack, ["redis-server", str(redis_config)], state / "redis.log", env)
        redis_url = f"redis://:{redis_password}@127.0.0.1:{ports['redis']}/0"
        server_env = {
            **env,
            "AEGAEON_DATABASE_URL": database_url,
            "AEGAEON_RUNTIME_ISSUER_HOST": urlsplit_host(issuer),
            "AEGAEON_KEY_ENCRYPTION_KEY": b64(kek),
            "RUST_LOG": "warn",
        }
        server_env.update({f"AEGAEON_{name}_REDIS_URL": redis_url for name in REDIS_SURFACES})
        server = start(
            stack,
            [str(executable), "--host", "127.0.0.1", "--port", str(ports["server"])],
            state / "server.log",
            server_env,
        )
        caddy_config = state / "Caddyfile"
        caddy_config.write_text(
            f"{{\n admin off\n auto_https off\n}}\n{issuer} {{\n bind 127.0.0.1\n"
            f' tls "{state}/localhost.pem" "{state}/localhost-key.pem"\n'
            f" reverse_proxy 127.0.0.1:{ports['server']}\n}}\n"
        )
        proxy = start(
            stack,
            ["caddy", "run", "--config", str(caddy_config), "--adapter", "caddyfile"],
            state / "proxy.log",
            {
                **env,
                "XDG_DATA_HOME": str(state / "caddy-data"),
                "XDG_CONFIG_HOME": str(state / "caddy-config"),
            },
        )
        wait_http(
            issuer + "/.well-known/openid-configuration",
            state / "review-ca.pem",
            [database, redis, server, proxy],
        )
        relying_party = RelyingParty(issuer, rp_url + "/callback", state / "review-ca.pem")
        evidence.update(
            {
                "issuer": issuer,
                "rp": rp_url,
                "configuration_sha256": digest(state / "configuration.json"),
                "smoke": smoke(relying_party, password),
            }
        )
        evidence["status"] = "passed"
        write_json(state / "evidence.json", evidence)
        print(
            "OIDC review passed: signature, issuer, audience, nonce, "
            "UserInfo and code replay checked.",
            flush=True,
        )
        if args.serve:
            serve_browser(relying_party, state, ports, rp_url)


def urlsplit_host(url):
    return url.removeprefix("https://")


def interrupt_review(_signum, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--state-dir", type=Path, required=True, help="new private directory; must not exist"
    )
    parser.add_argument(
        "--local-output",
        type=Path,
        help="explicit pre-publication exercise; no FlakeHub retrieval claim",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="keep services and the browser RP running after smoke checks",
    )
    args = parser.parse_args()
    args.manifest = args.manifest.resolve(strict=True)
    os.umask(0o077)
    state = args.state_dir.resolve()
    if any(character in str(state) for character in ('"', "\n", "\r", "\\")):
        parser.error("state directory contains characters unsupported by the service configs")
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence = {"version": 1, "status": "failed", "started_at": datetime.now(UTC).isoformat()}
    signal.signal(signal.SIGTERM, interrupt_review)
    try:
        run(args, state, evidence)
    except KeyboardInterrupt:
        print("Review stopped; child services have been shut down.")
        if evidence["status"] != "passed":
            raise SystemExit(130) from None
    except Exception as error:
        evidence["status"] = "failed"
        evidence["failure_type"] = type(error).__name__
        raise
    finally:
        evidence["finished_at"] = datetime.now(UTC).isoformat()
        write_json(state / "evidence.json", evidence)


if __name__ == "__main__":
    main()
