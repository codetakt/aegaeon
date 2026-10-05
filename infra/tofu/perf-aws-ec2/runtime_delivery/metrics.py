"""Fixed guest delivery metrics responsibility."""

from __future__ import annotations

import json
from typing import IO, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from email.message import Message
    from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener

from runtime_delivery.common import fail, https_origin
from runtime_delivery.credentials import retrieve
from runtime_delivery.filesystem import atomic_write, prepare_directory


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(  # noqa: PLR0913, PLR0917 -- exact standard urllib callback ABI
        self, req: Request, fp: IO[bytes], code: int, msg: str, headers: Message, newurl: str
    ) -> None:
        _ = (req, fp, code, msg, headers, newurl)


METRICS_STATUS_OK = 200


def metrics(config: dict[str, Any], directory: Path, output_directory: Path) -> None:
    prepare_directory(directory)
    credential = directory / "metrics.env"
    credential.unlink(missing_ok=True)
    target = output_directory / "server.metrics.prom"
    target.unlink(missing_ok=True)
    status = output_directory / "metrics-status.json"
    atomic_write(status, b'{"status":"incomplete"}\n')
    if not config["metrics_secret_arn"]:
        atomic_write(status, b'{"status":"absent"}\n')
        return
    values = retrieve(
        "metrics",
        config["metrics_secret_arn"],
        config["metrics_secret_version"],
        config["region"],
        config["issuer_url"],
    )
    request = Request(  # noqa: S310 -- original HTTPS-origin guard and no-redirect credential boundary
        https_origin(config["issuer_url"]) + "/api/v1/operations/metrics",
        headers={"Authorization": "Bearer " + values["api_key"]},
    )
    with build_opener(NoRedirect()).open(request, timeout=30) as response:
        data = response.read(16 * 1024 * 1024 + 1)
        if (
            response.status != METRICS_STATUS_OK
            or response.headers.get_content_type() != "text/plain"
            or (not data)
            or (len(data) > 16 * 1024 * 1024)
        ):
            fail("metrics response")
    atomic_write(target, data)
    atomic_write(
        status,
        json.dumps({"status": "complete", "version": config["metrics_secret_version"]}).encode(),
    )
