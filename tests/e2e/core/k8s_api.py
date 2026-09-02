"""Raw Kubernetes API HTTP helpers for CRD surface checks (status codes only)."""

from __future__ import annotations

import base64
import json
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

from tests.e2e.core.runner import env


@dataclass(frozen=True)
class K8sApiResponse:
    status: int
    body: dict[str, Any] | list[Any] | str


@dataclass
class K8sApiClient:
    """Minimal HTTPS client for kube-apiserver using the current kubeconfig."""

    server: str
    _ssl_context: ssl.SSLContext
    _auth_header: str | None = None
    _ca_path: str | None = None

    @classmethod
    def from_kubeconfig(cls, kubeconfig: str | None = None) -> K8sApiClient:
        path = Path(kubeconfig or env("KUBECONFIG", str(Path.home() / ".kube/config")))
        cfg = yaml.safe_load(path.read_text())
        cluster = cfg["clusters"][0]["cluster"]
        user = cfg["users"][0]["user"]
        server = cluster["server"].rstrip("/")

        ca_path: str | None = None
        ctx = ssl.create_default_context()
        if ca := cluster.get("certificate-authority-data"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as ca_file:
                ca_file.write(base64.b64decode(ca))
                ca_path = ca_file.name
            ctx.load_verify_locations(cafile=ca_path)
        elif ca_file_path := cluster.get("certificate-authority"):
            ca_path = ca_file_path
            ctx.load_verify_locations(cafile=ca_path)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        auth_header: str | None = None
        if token := user.get("token"):
            auth_header = f"Bearer {token}"
        elif "client-certificate-data" in user and "client-key-data" in user:
            with (
                tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cert_file,
                tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_file,
            ):
                cert_file.write(base64.b64decode(user["client-certificate-data"]))
                key_file.write(base64.b64decode(user["client-key-data"]))
                cert_path, key_path = cert_file.name, key_file.name
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        else:
            raise RuntimeError("kubeconfig user has neither token nor client certificate")

        return cls(server=server, _ssl_context=ctx, _auth_header=auth_header, _ca_path=ca_path)

    def anonymous_client(self) -> K8sApiClient:
        """Client with cluster CA only — no bearer token and no client certificate."""
        ctx = ssl.create_default_context()
        if self._ca_path:
            ctx.load_verify_locations(cafile=self._ca_path)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return K8sApiClient(server=self.server, _ssl_context=ctx, _auth_header=None, _ca_path=self._ca_path)

    def with_bearer_token(self, token: str) -> K8sApiClient:
        """Client authenticated with a bearer token (no inherited client certificate)."""
        ctx = ssl.create_default_context()
        if self._ca_path:
            ctx.load_verify_locations(cafile=self._ca_path)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return K8sApiClient(
            server=self.server, _ssl_context=ctx, _auth_header=f"Bearer {token}", _ca_path=self._ca_path
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        content_type: str = "application/json",
    ) -> K8sApiResponse:
        url = f"{self.server}{path}"
        data = None if body is None else json.dumps(body).encode()
        headers: dict[str, str] = {}
        if self._auth_header:
            headers["Authorization"] = self._auth_header
        if data is not None:
            headers["Content-Type"] = content_type
        req = Request(url, data=data, headers=headers, method=method.upper())
        try:
            with urlopen(req, context=self._ssl_context, timeout=60) as resp:
                raw = resp.read().decode()
                parsed: dict[str, Any] | list[Any] | str
                try:
                    parsed = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    parsed = raw
                return K8sApiResponse(status=resp.status, body=parsed)
        except HTTPError as exc:
            raw = exc.read().decode()
            try:
                parsed_err: dict[str, Any] | list[Any] | str = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed_err = raw
            return K8sApiResponse(status=exc.code, body=parsed_err)
        except URLError as exc:
            raise RuntimeError(f"kube-apiserver request failed: {method} {path}: {exc}") from exc
