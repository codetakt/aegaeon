"""Schema-guarded initialization and HTTPS OIDC on the current packaged runtime."""

from __future__ import annotations

import json
import secrets
import signal
import socket
import time
from uuid import UUID, uuid4

from browser_transport import frontend
from current_database import connect
from current_http import ConnectionFailureError, response
from current_process import check_cancellation
from delivery_journey import Management, require
from issuer_bootstrap import HOST, initialize
from issuer_configuration import client_secret, login, organization, policy, profile, register, user
from issuer_oidc import provision_key
from protocol_client import Client


class Fixture:
    def __init__(self, directory, package, connection, helpers):
        self.directory, self.package = directory, package
        self.primary, self.admin = connection
        self.root, self.env, self.run = helpers
        self.receipt = initialize(package, directory, self.primary, self.env, self.run)
        initial = self.receipt["initialization"]
        self.receipt.update(team=initial["teamId"], issuer_host=HOST)
        self.protocol_observations = []
        self.reauthentication_cutoff = 0
        self.journal = []
        self.results = []
        self.prepare()

    def prepare(self):
        deployment, generation = str(uuid4()), str(uuid4())
        with connect(self.admin) as db:
            db.execute(
                "SELECT aegaeon_lifecycle.activate_v1(%s,NULL,%s,%s)",
                (deployment, generation, uuid4()),
            )
        configuration = {
            "version": 2,
            "deployment_id": deployment,
            "generation": generation,
            "primary": {"url": self.primary, "root_cert": str(self.directory / "trusted.crt")},
            "environments": [{"id": self.receipt["environment"], "issuer": self.receipt["issuer"]}],
            "admission": {"ordinary": 32, "revocation": 2, "snapshot": 1},
        }
        self.config = self.directory / "runtime.json"
        self.config.write_text(json.dumps(configuration))
        self.env |= {
            "AEGAEON_RUNTIME_ISSUER_HOST": HOST,
            "AEGAEON_ORGANIZATION_RUNTIME_CONFIG": str(self.config),
        }

    def identity(self):
        with connect(self.admin) as db:
            row = db.execute(
                "SELECT e.id,e.issuer_host,n.environment_id,n.issuer_host "
                "FROM aegaeon.environments e JOIN aegaeon.subject_ownership_namespaces n "
                "ON n.environment_id=e.id"
            ).fetchone()
        require(
            row
            == (UUID(self.receipt["environment"]), HOST, UUID(self.receipt["environment"]), HOST),
            "immutable issuer identity",
        )
        return [str(value) for value in row]

    def ready(self, child, base):
        deadline = time.monotonic() + 40
        while True:
            check_cancellation()
            require(child.poll() is None, "packaged server exited before readiness")
            require(time.monotonic() < deadline, "packaged readiness deadline")
            try:
                if response(base, "/ready", self.directory, timeout=2) == 204:
                    break
            except (ConnectionFailureError, TimeoutError):
                pass
            time.sleep(0.05)

    def serve(self, label, action, *, restarts=False):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        base = f"http://127.0.0.1:{port}"

        values = []

        def journey(child):
            self.ready(child, base)
            api = Management(port, self.receipt)
            try:
                login(api)
                values.append(action(api))
            finally:
                self.journal.extend(api.journal)
            if not restarts:
                child.send_signal(signal.SIGTERM)

        # run_owned owns the complete process group even when the callback raises.
        result = self.run(
            [
                self.package / "bin/aegaeon-organizations-server",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            environment=self.env,
            timeout=240,
            before_wait=journey,
            private_log=self.directory / (label + ".log"),
        )
        if restarts:
            log = (self.directory / (label + ".log")).read_text()
            require(
                result.returncode == 1 and "runtime authority requested server restart" in log,
                "runtime mutation must request a controlled restart",
            )
        else:
            require(result.returncode == 0, "packaged server did not drain cleanly")
        self.results.append({"phase": label, "returncode": result.returncode})
        return values[0]

    def configure(self, api):
        policy(api)

    def enroll(self, api):
        self.user, token = user(api)
        self.organization_path = organization(api, self.registered)
        self.password = "Fixture-" + secrets.token_urlsafe(24) + "-9!"
        require(
            token["redeemUrl"].startswith(self.receipt["issuer"] + "/auth/activate"),
            "activation link uses the custom issuer",
        )
        with frontend(self, api.port) as browser:
            browser.form(
                "/auth/activate",
                {
                    "token": token["token"],
                    "password": self.password,
                    "password_confirmation": self.password,
                },
                json_response=False,
            )
        with connect(self.admin) as db:
            cutoff = db.execute(
                "SELECT organization_reauthentication_after FROM aegaeon.end_users WHERE id=%s",
                (self.user["id"],),
            ).fetchone()[0]
        self.reauthentication_cutoff = cutoff or 0

    def authorize(self, api):
        api.call("GET", self.organization_path)
        require(self.identity() == self.initial_identity, "restart preserved issuer namespace")
        deadline = time.monotonic() + 3
        while int(time.time()) <= self.reauthentication_cutoff:
            check_cancellation()
            require(time.monotonic() < deadline, "authentication cutoff deadline")
            time.sleep(0.05)
        with frontend(self, api.port) as browser:
            page = browser.form(
                "/auth/login",
                {"identifier": self.user["subject"], "password": self.password},
                json_response=False,
            )
            require("Your local sign-in succeeded" in page, "actual credential authentication")
            tokens = Client(self, browser, self.credentials).authorize(oidc=True)
            require(bool(tokens["id_token"]), "actual signed ID Token")

    def exercise(self):
        self.initial_identity = self.identity()
        self.serve(
            "oidc-key", lambda api: provision_key(api, "OIDC_ID_TOKEN_SIGNING"), restarts=True
        )
        self.serve(
            "access-key", lambda api: provision_key(api, "JWT_ACCESS_TOKEN_SIGNING"), restarts=True
        )
        self.serve("policy", self.configure, restarts=True)
        self.serve("profile", profile)
        self.registered = self.serve("client", register)
        self.credentials = self.serve(
            "client-secret", lambda api: client_secret(api, self.registered)
        )
        self.serve("enrollment", self.enroll)
        self.serve("authorization", self.authorize)
        self.serve("restart", self.authorize)
        refused = self.run(
            [
                self.package / "bin/aegaeon-organizations-server",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ],
            environment=self.env | {"AEGAEON_RUNTIME_ISSUER_HOST": "unknown.example.test"},
            timeout=30,
        )
        (self.directory / "unknown-selector.log").write_text(refused.stdout + refused.stderr)
        require(
            refused.returncode != 0
            and "organization runtime boundary refused" in refused.stderr
            and "Runtime issuer host selector unknown.example.test" in refused.stdout,
            "unregistered startup issuer must be refused for the expected reason",
        )
        return {
            "passed": True,
            "bootstrap": self.receipt,
            "identity": self.initial_identity,
            "phases": self.results,
            "management_http": self.journal,
            "protocol": self.protocol_observations,
            "unknown_selector_refused": True,
            "provider_qualification": False,
            "new_composite_discharge": 0,
        }


def exercise(directory, package, connection, helpers):
    fixture = Fixture(directory, package, connection, helpers)
    try:
        return fixture.exercise()
    finally:
        (directory / "issuer-management.json").write_text(json.dumps(fixture.journal, indent=2))
