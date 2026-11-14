"""One fixed loopback request; its parent owns the total deadline and process group."""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: PLR0913, PLR0917 - urllib interface.
        # The result must describe the requested local endpoint, not another
        # endpoint chosen by a response. HTTPError preserves the 3xx status.
        return None


def validate_request(base, path):
    parsed = urlsplit(base)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or base != f"http://127.0.0.1:{parsed.port}"
        or path not in ("/health", "/ready", "/token")
    ):
        message = "HTTP fixture requires an exact loopback URL and known path"
        raise ValueError(message)


def request_status(base, path, timeout):
    validate_request(base, path)
    request = urllib.request.Request(  # noqa: S310 - validated fixed loopback HTTP fixture.
        base + path,
        data=b"grant_type=client_credentials" if path == "/token" else None,
        headers={"X-Forwarded-Proto": "https"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as result:
            return result.status
    except urllib.error.HTTPError as error:
        error.close()
        return error.code


def main():
    base, path, timeout, output = sys.argv[1:]
    record = {"base": base, "path": path}
    try:
        record["status"] = request_status(base, path, float(timeout))
    except (OSError, urllib.error.URLError):
        # No exception text, credentials or response bodies cross this interface.
        record["error"] = "connection"
    record["completed_at"] = time.monotonic()
    with Path(output).open("x") as stream:
        json.dump(record, stream)


if __name__ == "__main__":
    main()
