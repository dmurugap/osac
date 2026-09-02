"""Metal3 / BMO Kubernetes API surface checks (HTTP status codes only).

Portable across CI, virtual-BMH labs, and physical labs: talks only to the
kube-apiserver OpenAPI for metal3.io CRDs. Does not require free BMHs,
fulfillment, or real firmware hardware.

API reference (OCP 4.22 Provisioning APIs, Ch 2-9 and 12-13):
https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html-single/provisioning_apis/index
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Generator
from typing import Any

import pytest

from tests.e2e.core.k8s_api import K8sApiClient
from tests.e2e.core.runner import run

METAL3_GROUP = "metal3.io"
METAL3_VERSION = "v1alpha1"

# Namespaced CRDs BMaaS / Metal3 inventory commonly touches.
NAMESPACED_RESOURCES: tuple[str, ...] = (
    "baremetalhosts",
    "hardwaredata",
    "preprovisioningimages",
    "dataimages",
    "hostfirmwarecomponents",
    "hostfirmwaresettings",
    "firmwareschemas",
    "hostupdatepolicies",
    "bmceventsubscriptions",
)

# OpenShift anonymous often returns 403; some stacks return 401.
UNAUTHENTICATED_STATUSES = {401, 403}
# CRD OpenAPI rejection is usually 422; some stacks return 400.
VALIDATION_STATUSES = {400, 422}
# Unknown fields: strict apiservers reject; structural CRDs often prune → 2xx.
UNKNOWN_FIELD_REJECT = VALIDATION_STATUSES
UNKNOWN_FIELD_PRUNE = {200, 201}


def _api_path(*, resource: str, namespace: str | None = None, name: str | None = None) -> str:
    base = f"/apis/{METAL3_GROUP}/{METAL3_VERSION}"
    base = f"{base}/namespaces/{namespace}/{resource}" if namespace else f"{base}/{resource}"
    if name:
        return f"{base}/{name}"
    return base


def _bmh_missing_online(*, namespace: str, name: str) -> dict[str, Any]:
    return {
        "apiVersion": f"{METAL3_GROUP}/{METAL3_VERSION}",
        "kind": "BareMetalHost",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "bmc": {"address": "redfish://192.0.2.1", "credentialsName": "e2e-missing"},
            "bootMACAddress": "00:11:22:33:44:55",
            # intentionally omit required spec.online
        },
    }


def _hfc_missing_updates(*, namespace: str, name: str) -> dict[str, Any]:
    return {
        "apiVersion": f"{METAL3_GROUP}/{METAL3_VERSION}",
        "kind": "HostFirmwareComponents",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {},  # updates required
    }


def _hfs_missing_settings(*, namespace: str, name: str) -> dict[str, Any]:
    return {
        "apiVersion": f"{METAL3_GROUP}/{METAL3_VERSION}",
        "kind": "HostFirmwareSettings",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {},  # settings required
    }


def _dataimage_missing_url(*, namespace: str, name: str) -> dict[str, Any]:
    return {
        "apiVersion": f"{METAL3_GROUP}/{METAL3_VERSION}",
        "kind": "DataImage",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {},  # url required
    }


def _bmh_unknown_field(*, namespace: str, name: str) -> dict[str, Any]:
    return {
        "apiVersion": f"{METAL3_GROUP}/{METAL3_VERSION}",
        "kind": "BareMetalHost",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "online": False,
            "bmc": {"address": "redfish://192.0.2.1", "credentialsName": "e2e-missing"},
            "bootMACAddress": "00:11:22:33:44:55",
            "e2eUnknownField": True,
        },
    }


def _oc(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["oc", "--as", "system:admin", *args], capture_output=True, text=True, check=False
    )


@pytest.fixture(scope="module")
def k8s_api() -> K8sApiClient:
    return K8sApiClient.from_kubeconfig()


@pytest.fixture(scope="module")
def restricted_bmh_token(bmh_namespace: str, test_run_id: str) -> Generator[str, None, None]:
    """SA that can get/list/patch BMHs but not patch the status subresource."""
    sa = f"e2e-bmo-api-{test_run_id}"
    role = f"{sa}-role"
    binding = f"{sa}-binding"
    manifest = f"""
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {sa}
  namespace: {bmh_namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {role}
  namespace: {bmh_namespace}
rules:
  - apiGroups: ["{METAL3_GROUP}"]
    resources: ["baremetalhosts"]
    verbs: ["get", "list", "watch", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {binding}
  namespace: {bmh_namespace}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {role}
subjects:
  - kind: ServiceAccount
    name: {sa}
    namespace: {bmh_namespace}
"""
    subprocess.run(
        ["oc", "--as", "system:admin", "apply", "-f", "-"],
        input=manifest,
        text=True,
        check=True,
        capture_output=True,
    )
    try:
        token = run(
            "oc",
            "create",
            "token",
            sa,
            "-n",
            bmh_namespace,
            "--duration",
            "1h",
            "--as",
            "system:admin",
        )
        yield token
    finally:
        _oc("delete", "rolebinding", binding, "-n", bmh_namespace, "--ignore-not-found")
        _oc("delete", "role", role, "-n", bmh_namespace, "--ignore-not-found")
        _oc("delete", "sa", sa, "-n", bmh_namespace, "--ignore-not-found")


def test_metal3_crd_http_matrix(
    k8s_api: K8sApiClient,
    bmh_namespace: str,
    restricted_bmh_token: str,
    test_run_id: str,
) -> None:
    """HTTP status matrix for metal3 CRDs BMaaS depends on (adjusted portable AC).

    Docs: OCP 4.22 Provisioning APIs (html-single), chapters 2-9 and 12-13
    https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html-single/provisioning_apis/index

    Covered (all environments with Metal3 installed):
    - LIST each namespaced CRD → 200 (empty list OK)
    - LIST Provisioning (cluster-scoped) → 200 and ≥1 item (singleton present)
    - Unauthenticated LIST BMH → 401 or 403 (OCP often 403)
    - Named GET missing BMH → 404; GET existing BMH → 200
    - dryRun=All invalid creates → 422 (BMH missing online, HFC missing updates,
      HFS missing settings, DataImage missing url)
    - dryRun=All BMH with unknown spec field → 400/422, or 2xx with field pruned
      (Metal3 structural schemas commonly prune rather than reject)
    - Restricted SA: dryRun PATCH BMH metadata → 200; dryRun PATCH spec → 200;
      dryRun PATCH /status → 403

    Not covered here (other matrix IDs): BMI lifecycle, inventory exhaustion,
    real firmware flash, inspect field content, DataImage attach on a live host.
    """
    suffix = test_run_id
    probe = f"e2e-bmo-api-{suffix}"

    # --- LIST surface for every namespaced CRD ---
    for resource in NAMESPACED_RESOURCES:
        resp = k8s_api.request("GET", _api_path(resource=resource, namespace=bmh_namespace))
        assert resp.status == 200, f"LIST {resource}: expected 200, got {resp.status}: {resp.body}"
        assert isinstance(resp.body, dict) and "items" in resp.body

    # --- Provisioning cluster-scoped singleton ---
    prov = k8s_api.request("GET", _api_path(resource="provisionings"))
    assert prov.status == 200, f"LIST provisionings: expected 200, got {prov.status}: {prov.body}"
    assert isinstance(prov.body, dict)
    items = prov.body.get("items", [])
    assert len(items) >= 1, "expected at least one cluster-scoped Provisioning object"
    # Namespaced collection path must not pretend Provisioning is namespaced.
    namespaced_prov = k8s_api.request("GET", _api_path(resource="provisionings", namespace=bmh_namespace))
    assert namespaced_prov.status in {404, 405}, (
        f"Provisioning must not be a normal namespaced collection; got {namespaced_prov.status}"
    )

    # --- Unauthenticated ---
    anon = k8s_api.anonymous_client()
    unauth = anon.request("GET", _api_path(resource="baremetalhosts", namespace=bmh_namespace))
    assert unauth.status in UNAUTHENTICATED_STATUSES, (
        f"unauthenticated LIST BMH: expected {UNAUTHENTICATED_STATUSES}, got {unauth.status}"
    )

    # --- Named GET 404 ---
    missing = k8s_api.request(
        "GET", _api_path(resource="baremetalhosts", namespace=bmh_namespace, name="does-not-exist-xyz")
    )
    assert missing.status == 404, f"GET missing BMH: expected 404, got {missing.status}"

    # --- Validation via dryRun=All ---
    validation_cases: list[tuple[str, dict[str, Any]]] = [
        ("baremetalhosts", _bmh_missing_online(namespace=bmh_namespace, name=f"{probe}-bmh")),
        ("hostfirmwarecomponents", _hfc_missing_updates(namespace=bmh_namespace, name=f"{probe}-hfc")),
        ("hostfirmwaresettings", _hfs_missing_settings(namespace=bmh_namespace, name=f"{probe}-hfs")),
        ("dataimages", _dataimage_missing_url(namespace=bmh_namespace, name=f"{probe}-di")),
    ]
    for resource, body in validation_cases:
        path = f"{_api_path(resource=resource, namespace=bmh_namespace)}?dryRun=All"
        resp = k8s_api.request("POST", path, body=body)
        assert resp.status == 422, f"dryRun POST {resource} invalid: expected 422, got {resp.status}: {resp.body}"

    unknown = k8s_api.request(
        "POST",
        f"{_api_path(resource='baremetalhosts', namespace=bmh_namespace)}?dryRun=All",
        body=_bmh_unknown_field(namespace=bmh_namespace, name=f"{probe}-unk"),
    )
    if unknown.status in UNKNOWN_FIELD_REJECT:
        pass  # strict OpenAPI / field validation
    elif unknown.status in UNKNOWN_FIELD_PRUNE:
        assert isinstance(unknown.body, dict)
        spec = unknown.body.get("spec") or {}
        assert "e2eUnknownField" not in spec, (
            f"unknown field accepted into stored/returned BMH spec (expected prune or reject): {spec}"
        )
    else:
        raise AssertionError(
            f"unknown field: expected reject {UNKNOWN_FIELD_REJECT} or prune "
            f"{UNKNOWN_FIELD_PRUNE}, got {unknown.status}: {unknown.body}"
        )

    # --- Existing BMH GET + restricted SA RBAC ---
    listed = k8s_api.request("GET", _api_path(resource="baremetalhosts", namespace=bmh_namespace))
    assert listed.status == 200 and isinstance(listed.body, dict)
    bmh_items = listed.body.get("items", [])
    assert bmh_items, (
        f"need ≥1 BareMetalHost in {bmh_namespace} to exercise GET + RBAC "
        "(lab/CI must pre-create inventory BMHs)"
    )
    bmh_name = bmh_items[0]["metadata"]["name"]
    bmh_path = _api_path(resource="baremetalhosts", namespace=bmh_namespace, name=bmh_name)

    existing = k8s_api.request("GET", bmh_path)
    assert existing.status == 200, f"GET existing BMH: expected 200, got {existing.status}"
    assert isinstance(existing.body, dict)
    assert existing.body.get("metadata", {}).get("name") == bmh_name

    restricted = k8s_api.with_bearer_token(restricted_bmh_token)
    allowed_patch = {"metadata": {"annotations": {"osac.e2e.io/bmo-api-probe": uuid.uuid4().hex[:8]}}}
    allow_resp = restricted.request(
        "PATCH",
        f"{bmh_path}?dryRun=All",
        body=allowed_patch,
        content_type="application/merge-patch+json",
    )
    assert allow_resp.status == 200, (
        f"restricted dryRun PATCH BMH (metadata): expected 200, got {allow_resp.status}: {allow_resp.body}"
    )

    # No-op spec patch (reuse current online) so dryRun cannot change power state.
    current_online = existing.body.get("spec", {}).get("online", False)
    spec_resp = restricted.request(
        "PATCH",
        f"{bmh_path}?dryRun=All",
        body={"spec": {"online": current_online}},
        content_type="application/merge-patch+json",
    )
    assert spec_resp.status == 200, (
        f"restricted dryRun PATCH BMH (spec): expected 200, got {spec_resp.status}: {spec_resp.body}"
    )

    status_patch = {
        "apiVersion": f"{METAL3_GROUP}/{METAL3_VERSION}",
        "kind": "BareMetalHost",
        "metadata": {"name": bmh_name, "namespace": bmh_namespace},
        "status": {"errorMessage": f"e2e-forbidden-{uuid.uuid4().hex[:8]}"},
    }
    deny_resp = restricted.request(
        "PATCH",
        bmh_path + "/status?dryRun=All",
        body=status_patch,
        content_type="application/merge-patch+json",
    )
    assert deny_resp.status == 403, (
        f"restricted dryRun PATCH /status: expected 403, got {deny_resp.status}: {deny_resp.body}"
    )
