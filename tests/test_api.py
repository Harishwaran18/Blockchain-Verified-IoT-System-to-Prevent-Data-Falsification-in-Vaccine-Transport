from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from conftest import wait_until
from vchain.api import create_app
from vchain.fleet import DEVICES
from vchain.node import VirtualVaccineNode


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


def signed_readings(runtime_settings, count: int = 4):
    node = VirtualVaccineNode(DEVICES[0], runtime_settings)
    return [node.envelope() for _ in range(count)]


def test_dashboard_and_health(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "VChain" in page.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    health = client.get("/api/health").json()
    assert health["ok"] is True
    assert health["mqtt_connected"] is True


def test_snapshot_shape(client):
    snapshot = client.get("/api/snapshot").json()
    assert {"stats", "devices", "blocks", "alerts", "series", "policy", "attacks"} <= set(snapshot)
    assert len(snapshot["devices"]) == 4
    assert snapshot["stats"]["chain_height"] == 0
    assert snapshot["stats"]["chain_ok"] is True
    assert snapshot["policy"]["max_temp_c"] == 8.0
    assert len(snapshot["attacks"]) == 6


def test_ingest_audit_and_tamper_flow(client, settings):
    envelopes = signed_readings(settings, 4)
    for envelope in envelopes:
        response = client.post("/api/ingest", json=envelope)
        assert response.status_code == 200, response.text

    assert wait_until(
        lambda: client.get("/api/snapshot").json()["stats"]["readings_anchored"] >= 4, timeout=20
    )
    snapshot = client.get("/api/snapshot").json()
    assert snapshot["stats"]["chain_ok"]
    assert snapshot["blocks"][-1]["reading_count"] == 4

    digest = envelopes[0]["digest"]
    detail = client.get(f"/api/readings/{digest}").json()
    assert detail["checks"]["verified"] is True
    assert detail["proof"]["verified"] is True
    assert detail["reading"]["device_id"] == "VX-001"

    block = client.get("/api/blocks/1").json()
    assert block["checks"]["block_hash_ok"] is True
    assert block["checks"]["merkle_ok"] is True
    assert len(block["readings"]) == 4

    audit = client.post("/api/audit").json()
    assert audit["ok"] is True
    assert audit["readings_checked"] == 4

    tampered = client.post("/api/tamper/edit_temperature").json()
    assert tampered["detected"] is True
    assert any(f["kind"] == "READING_DIGEST_MISMATCH" for f in tampered["failures"])
    assert client.get("/api/snapshot").json()["stats"]["chain_ok"] is True

    export = client.get("/api/export")
    assert export.status_code == 200
    bundle = json.loads(export.text)
    assert bundle["chain_height"] == 1
    assert bundle["audit"]["ok"] is False


def test_api_error_paths(client, settings):
    assert client.get("/api/blocks/999").status_code == 404
    assert client.get("/api/readings/" + "0" * 64).status_code == 404
    assert client.post("/api/tamper/nope").status_code == 404
    assert client.post("/api/excursion", json={"device_id": "NOPE", "active": True}).status_code == 404
    bad = client.post("/api/ingest", json={"alg": "HMAC-SHA256"})
    assert bad.status_code == 422
    assert client.post("/api/excursion", json={"device_id": "VX-001", "active": True}).status_code == 200
    assert client.post("/api/excursion", json={"device_id": "VX-001", "active": False}).status_code == 200


def test_reset_endpoint(client):
    assert client.post("/api/reset").json()["ok"] is True
    snapshot = client.get("/api/snapshot").json()
    assert snapshot["stats"]["chain_ok"] is True
    assert snapshot["stats"]["chain_height"] == 0


def test_verify_chain_and_policy_endpoints(client):
    assert client.get("/api/chain/verify").json()["ok"] is True
    policy = client.get("/api/policy").json()
    assert policy["commitments"]["hash"] == "SHA-256"
    assert policy["commitments"]["quorum"] == 2
