"""Owned release-server/HTTPS/Tool/browser integration with finite cleanup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote, urlparse


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Fixture:
    def __init__(self, args):
        self.args = args
        self.args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="aegaeon-lti-packaged-"))
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("AEGAEON_", "PG"))
        }
        self.env["AEGAEON_CHROMIUM"] = os.environ["AEGAEON_CHROMIUM"]
        self.env["AEGAEON_KEY_ENCRYPTION_KEY"] = "V1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1c"
        self.env["CHROME_CONFIG_HOME"] = str(self.temporary / "browser-config")
        self.processes = []
        self.logs = []
        self.postgres_started = False

    def run(self, command, name, timeout=120, input_data=None, environment=None):
        with (self.args.output / name).open("wb") as log:
            result = subprocess.run(  # noqa: S603 — fixed tools and owned fixture arguments
                list(map(str, command)),
                cwd=self.args.root,
                env=self.env if environment is None else environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
                input=input_data,
            )
        if result.returncode:
            message = f"{name}: command failed with {result.returncode}"
            raise RuntimeError(message)

    def start(self, command, name, environment=None):
        log = (self.args.output / name).open("wb")
        self.logs.append(log)
        process = subprocess.Popen(  # noqa: S603 — fixed tools and owned fixture arguments
            list(map(str, command)),
            cwd=self.args.root,
            env=self.env if environment is None else environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.processes.append(process)
        return process

    def database(self):
        self.pg_port, self.redis_port, self.backend, self.public, self.tool = [
            port() for _ in range(5)
        ]
        self.password = secrets.token_urlsafe(32)
        self.run(
            [
                "initdb",
                "-D",
                self.temporary / "pg",
                "-U",
                "postgres",
                "--no-locale",
                "--encoding=UTF8",
                "--auth-local=trust",
                "--auth-host=scram-sha-256",
                "--pwfile",
                "/dev/stdin",
            ],
            "initdb.log",
            input_data=(self.password + "\n").encode(),
        )
        self.run(
            [
                "pg_ctl",
                "-D",
                self.temporary / "pg",
                "-l",
                self.args.output / "postgres.log",
                "-w",
                "-t",
                "20",
                "-o",
                f"-p {self.pg_port} -c unix_socket_directories= -c listen_addresses=127.0.0.1",
                "start",
            ],
            "start.log",
        )
        self.postgres_started = True
        redis = self.start(
            [
                "redis-server",
                "--bind",
                "127.0.0.1",
                "--port",
                self.redis_port,
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                self.temporary,
            ],
            "redis.log",
        )
        deadline = time.monotonic() + 10
        while True:
            with socket.socket() as connection:
                if connection.connect_ex(("127.0.0.1", self.redis_port)) == 0:
                    break
            if redis.poll() is not None or time.monotonic() >= deadline:
                message = "owned Redis startup failed"
                raise RuntimeError(message)
            time.sleep(0.05)

    def prepare(self):
        self.env["AEGAEON_TEST_ADMIN_DATABASE_URL"] = (
            f"postgresql://postgres:{self.password}@127.0.0.1:{self.pg_port}/postgres?sslmode=disable"
        )
        restricted = self.temporary / "restricted"
        restricted.mkdir(mode=0o700)
        self.env["AEGAEON_TEST_DATABASE_FIXTURE_DIRECTORY"] = str(restricted)
        self.env["AEGAEON_DATABASE_TEST_PACKAGE"] = str(self.args.package)
        self.run(
            [
                "python3",
                self.args.root / "scripts/tests/subject_ownership_fixture.py",
                "prepare-runtime",
                restricted,
            ],
            "provision.log",
        )
        self.env["AEGAEON_DATABASE_URL"] = json.loads((restricted / "suppliers.json").read_text())[
            "urls"
        ]["runtime"]
        self.env["AEGAEON_MANAGEMENT_DATABASE_URL"] = json.loads(
            (restricted / "suppliers.json").read_text()
        )["urls"]["management"]
        # Management origins have their own public-host contract. This fixture
        # exercises end-user login on the issuer, not a management login.
        connection = urlparse(self.env["AEGAEON_DATABASE_URL"])
        self.env.update(
            PGHOST=connection.hostname,
            PGPORT=str(connection.port),
            PGDATABASE=connection.path.removeprefix("/"),
            PGUSER=unquote(connection.username),
            PGPASSWORD=unquote(connection.password),
            PGSSLMODE="disable",
        )
        self.run(
            [
                "psql",
                "-Xq",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                (
                    "INSERT INTO aegaeon.control_plane_policies(id,management_allowed_origins) "
                    "VALUES('default',ARRAY['https://management.example.com'])"
                ),
            ],
            "control-policy.log",
        )
        for name in tuple(self.env):
            if name.startswith("PG"):
                del self.env[name]
        # Only the legacy native fixture builder needs Redis. The separate
        # release executable uses PostgreSQL sessions and SQL fault injection.
        self.env["AEGAEON_TEST_REDIS_URL"] = f"redis://127.0.0.1:{self.redis_port}/0"
        self.env["AEGAEON_REQUIRE_TLS_PROXY"] = "true"
        self.env["AEGAEON_TRUSTED_PROXIES"] = "127.0.0.1/32"
        self.env["AEGAEON_RUNTIME_ISSUER_HOST"] = f"localhost:{self.public}"
        self.env["AEGAEON_LTI_PACKAGED_FIXTURE"] = str(self.temporary)
        (self.temporary / "input.json").write_text(
            json.dumps(
                {
                    "issuer_host": f"localhost:{self.public}",
                    "tool": f"https://127.0.0.1:{self.tool}",
                }
            )
        )
        self.run(
            [
                self.args.package / "libexec/aegaeon_server",
                "web::lti::tests::browser::packaged::dedicated_lti_packaged_prepare",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ],
            "prepare.log",
        )
        if "1 passed; 0 failed" not in (self.args.output / "prepare.log").read_text():
            message = "packaged preparation selector did not execute"
            raise RuntimeError(message)

    def certificate(self):
        self.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                self.temporary / "tls.key",
                "-out",
                self.temporary / "tls.crt",
            ],
            "certificate.log",
        )
        self.run(
            [
                "openssl",
                "x509",
                "-in",
                self.temporary / "tls.crt",
                "-pubkey",
                "-noout",
                "-out",
                self.temporary / "tls-public.pem",
            ],
            "certificate-public.log",
        )
        self.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                self.temporary / "tls-public.pem",
                "-outform",
                "DER",
                "-out",
                self.temporary / "tls-public.der",
            ],
            "certificate-spki.log",
        )

    def startup_refusals(self):
        writer = self.env["AEGAEON_MANAGEMENT_DATABASE_URL"]
        wrong_database = urlparse(writer)._replace(path="/postgres").geturl()
        cases = [
            ("missing-writer", None, "LTI requires AEGAEON_MANAGEMENT_DATABASE_URL"),
            (
                "same-principal",
                self.env["AEGAEON_DATABASE_URL"],
                "distinct restricted attribute-write database principal",
            ),
            ("wrong-database", wrong_database, "database identities differ"),
        ]
        for name, url, expected in cases:
            self.startup_refusal(name, url, expected)
        self.startup_cases = [name for name, _, _ in cases]
        writer_id = '"' + unquote(urlparse(writer).username).replace('"', '""') + '"'
        connection = urlparse(writer)
        admin = self.env | {
            "PGHOST": connection.hostname,
            "PGPORT": str(connection.port),
            "PGDATABASE": unquote(connection.path.removeprefix("/")),
            "PGUSER": "postgres",
            "PGPASSWORD": self.password,
            "PGSSLMODE": "disable",
        }
        self.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1"],
            "grant-writer-bypass.log",
            input_data=f"GRANT SET ON PARAMETER session_replication_role TO {writer_id}".encode(),
            environment=admin,
        )
        try:
            self.startup_refusal(
                "writer-trigger-bypass", writer, "can bypass protected identity or audit authority"
            )
            self.startup_cases.append("writer-trigger-bypass")
        finally:
            self.run(
                ["psql", "-X", "-v", "ON_ERROR_STOP=1"],
                "revoke-writer-bypass.log",
                input_data=(
                    f"REVOKE SET ON PARAMETER session_replication_role FROM {writer_id}"
                ).encode(),
                environment=admin,
            )

        self.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1"],
            "grant-writer-admin.log",
            input_data=(
                "CREATE ROLE lti_admin_only NOLOGIN; "
                f"GRANT lti_admin_only TO {writer_id} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
            ).encode(),
            environment=admin,
        )
        try:
            self.startup_refusal(
                "writer-role-admin", writer, "must not administer role memberships"
            )
            self.startup_cases.append("writer-role-admin")
        finally:
            self.run(
                ["psql", "-X", "-v", "ON_ERROR_STOP=1"],
                "revoke-writer-admin.log",
                input_data=(
                    f"REVOKE lti_admin_only FROM {writer_id}; DROP ROLE lti_admin_only"
                ).encode(),
                environment=admin,
            )

        self.startup_authority_refusals(writer, writer_id, admin)

    def startup_authority_refusals(self, writer, writer_id, admin):
        self.run(
            ["psql", "-XAt", "-v", "ON_ERROR_STOP=1"],
            "trigger-owner.log",
            input_data=(
                b"SELECT quote_ident(pg_get_userbyid(proowner)) FROM pg_proc "
                b"WHERE oid='aegaeon.lti_immutable_record()'::regprocedure"
            ),
            environment=admin,
        )
        original_owner = (self.args.output / "trigger-owner.log").read_text().strip()
        for name, grant, revoke, expected in [
            (
                "writer-trigger-owner",
                f"ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {writer_id}",
                f"ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {original_owner}",
                "can bypass protected identity or audit authority",
            ),
            (
                "writer-host-program",
                (
                    f"GRANT pg_execute_server_program TO {writer_id} "
                    "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
                ),
                f"REVOKE pg_execute_server_program FROM {writer_id}",
                "must not administer role memberships or access server files/programs",
            ),
        ]:
            self.run(
                ["psql", "-X", "-v", "ON_ERROR_STOP=1"],
                f"grant-{name}.log",
                input_data=grant.encode(),
                environment=admin,
            )
            try:
                self.startup_refusal(name, writer, expected)
                self.startup_cases.append(name)
            finally:
                self.run(
                    ["psql", "-X", "-v", "ON_ERROR_STOP=1"],
                    f"revoke-{name}.log",
                    input_data=revoke.encode(),
                    environment=admin,
                )

    def startup_refusal(self, name, url, expected):
        environment = dict(self.env)
        environment.pop("AEGAEON_MANAGEMENT_DATABASE_URL", None)
        if url is not None:
            environment["AEGAEON_MANAGEMENT_DATABASE_URL"] = url
        process = self.start(
            [
                self.args.server / "bin/aegaeon-server",
                "--host",
                "127.0.0.1",
                "--port",
                self.backend,
            ],
            f"startup-{name}.log",
            environment,
        )
        code = process.wait(timeout=30)
        log = (self.args.output / f"startup-{name}.log").read_text()
        if not code or expected not in log:
            message = f"startup refusal not established: {name}"
            raise RuntimeError(message)

    def journey(self):
        self.startup_refusals()
        server = self.start(
            [
                self.args.server / "bin/aegaeon-server",
                "--host",
                "127.0.0.1",
                "--port",
                self.backend,
            ],
            "server.log",
        )
        deadline = time.monotonic() + 30
        while True:
            with socket.socket() as connection:
                if connection.connect_ex(("127.0.0.1", self.backend)) == 0:
                    break
            if server.poll() is not None or time.monotonic() >= deadline:
                message = "packaged server startup failed; see server.log"
                raise RuntimeError(message)
            time.sleep(0.05)
        browser = self.start(
            [
                "node",
                self.args.root / "tests/lti/packaged_browser.mjs",
                self.temporary,
                self.backend,
                self.args.output,
            ],
            "journey.log",
        )
        try:
            code = browser.wait(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(browser.pid, signal.SIGTERM)
            browser.wait(timeout=5)
            raise
        if code:
            message = "packaged browser journey failed; see journey.log"
            raise RuntimeError(message)

    def report(self):
        report = json.loads((self.args.output / "journey.json").read_text())
        if not report["passed"]:
            message = "missing successful browser result"
            raise RuntimeError(message)
        report.update(
            {
                "test_package": str(self.args.package),
                "server_package": str(self.args.server),
                "server_manifest": json.loads(
                    (self.args.server / "share/aegaeon/aegaeon-server.json").read_text()
                ),
                "test_binary_sha256": hashlib.sha256(
                    (self.args.package / "libexec/aegaeon_server").read_bytes()
                ).hexdigest(),
                "startup_refusals": self.startup_cases,
                "new_proof_discharge": 0,
                "scope": (
                    "owned loopback TLS ingress, restricted SQL sessions and release executable; "
                    "Redis only for legacy native fixture provisioning"
                ),
            }
        )
        (self.args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")

    def close(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        for log in self.logs:
            log.close()
        if self.postgres_started:
            self.run(
                [
                    "pg_ctl",
                    "-D",
                    self.temporary / "pg",
                    "-w",
                    "-t",
                    "20",
                    "-m",
                    "immediate",
                    "stop",
                ],
                "stop.log",
                timeout=30,
            )
        shutil.rmtree(self.temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    fixture = Fixture(parser.parse_args())

    def stop(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop)
    try:
        fixture.database()
        fixture.prepare()
        fixture.certificate()
        fixture.journey()
        fixture.report()
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
