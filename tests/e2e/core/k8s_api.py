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
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml

from tests.e2e.core.runner import env


@dataclass(frozen=True)
class K8sApiResponse:
    status: int
    body: dict[str, Any] | list[Any] | str


def _cluster_and_user(cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    current = cfg.get("current-context")
    if not current:
        raise RuntimeError("kubeconfig has no current-context")
    contexts = {c["name"]: c["context"] for c in cfg.get("contexts") or []}
    ctx = contexts.get(current)
    if not ctx:
        raise RuntimeError(f"kubeconfig current-context {current!r} not found")
    cluster_name, user_name = ctx.get("cluster"), ctx.get("user")
    clusters = {c["name"]: c["cluster"] for c in cfg.get("clusters") or []}
    users = {u["name"]: u["user"] for u in cfg.get("users") or []}
    cluster, user = clusters.get(cluster_name), users.get(user_name)
    if cluster is None or user is None:
        raise RuntimeError(f"kubeconfig context {current!r} is missing cluster or user")
    return cluster, user


def _require_https(server: str) -> str:
    parsed = urlparse(server)
    if parsed.scheme != "https":
        raise RuntimeError(f"kube-apiserver URL must be https, got {parsed.scheme!r}")
    return server


def _ssl_context_with_ca(ca_path: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=ca_path)
    return ctx


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
        cluster, user = _cluster_and_user(cfg)
        server = _require_https(cluster["server"].rstrip("/"))

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
            raise RuntimeError("kubeconfig cluster has no certificate-authority")

        auth_header: str | None = None
        if token := user.get("token"):
            auth_header = f"Bearer {token}"
        elif "client-certificate-data" in user and "client-key-data" in user:
            cert_path = key_path = None
            try:
                with (
                    tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cert_file,
                    tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_file,
                ):
                    cert_file.write(base64.b64decode(user["client-certificate-data"]))
                    key_file.write(base64.b64decode(user["client-key-data"]))
                    cert_path, key_path = cert_file.name, key_file.name
                ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            finally:
                for tmp in (cert_path, key_path):
                    if tmp:
                        Path(tmp).unlink(missing_ok=True)
        else:
            raise RuntimeError("kubeconfig user has neither token nor client certificate")

        return cls(server=server, _ssl_context=ctx, _auth_header=auth_header, _ca_path=ca_path)

    def anonymous_client(self) -> K8sApiClient:
        """Client with cluster CA only — no bearer token and no client certificate."""
        if not self._ca_path:
            raise RuntimeError("kube-apiserver client has no CA path")
        return K8sApiClient(
            server=self.server,
            _ssl_context=_ssl_context_with_ca(self._ca_path),
            _auth_header=None,
            _ca_path=self._ca_path,
        )

    def with_bearer_token(self, token: str) -> K8sApiClient:
        """Client authenticated with a bearer token (no inherited client certificate)."""
        if not self._ca_path:
            raise RuntimeError("kube-apiserver client has no CA path")
        return K8sApiClient(
            server=self.server,
            _ssl_context=_ssl_context_with_ca(self._ca_path),
            _auth_header=f"Bearer {token}",
            _ca_path=self._ca_path,
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
