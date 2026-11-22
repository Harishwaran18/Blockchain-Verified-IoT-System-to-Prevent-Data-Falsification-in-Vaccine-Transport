"""FastAPI service and dashboard host."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .blockchain import validate_chain
from .config import Settings
from .runtime import VChainRuntime

logger = logging.getLogger(__name__)
WEB_DIR = Path(__file__).resolve().parent / "web"


class ExcursionRequest(BaseModel):
    device_id: str = Field(min_length=2, max_length=32)
    active: bool = True


def create_app(
    settings: Settings | None = None,
    runtime: VChainRuntime | None = None,
    start_runtime: bool = True,
) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.runtime is None:
            app.state.runtime = VChainRuntime(app.state.settings)
        if app.state.start_runtime:
            await run_in_threadpool(app.state.runtime.start)
        yield
        if app.state.start_runtime:
            await run_in_threadpool(app.state.runtime.stop)

    app = FastAPI(
        title="VChain · Cold-Chain Ledger",
        version="1.0.0",
        description="Blockchain-verified IoT telemetry for vaccine transport",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.runtime = runtime
    app.state.start_runtime = start_runtime

    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    def rt() -> VChainRuntime:
        if app.state.runtime is None:
            app.state.runtime = VChainRuntime(app.state.settings)
        return app.state.runtime

    # ------------------------------------------------------------------ pages
    @app.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        index = WEB_DIR / "index.html"
        if not index.exists():
            raise HTTPException(status_code=500, detail="dashboard assets missing")
        return FileResponse(index, headers={"Cache-Control": "no-store"})

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            '<rect width="64" height="64" rx="14" fill="#0b1220"/>'
            '<path d="M18 40V24l14-8 14 8v16l-14 8-14-8z" fill="none" stroke="#22d3ee" stroke-width="3"/>'
            '<path d="M25 32l5 5 10-11" fill="none" stroke="#34d399" stroke-width="4" stroke-linecap="round"/>'
            "</svg>"
        )
        return Response(svg, media_type="image/svg+xml")

    # ------------------------------------------------------------------- API
    @app.get("/api/health")
    async def health() -> dict:
        runtime = rt()
        return {
            "ok": True,
            "mqtt_connected": runtime.gateway.connected.is_set(),
            "chain_height": runtime.store.counts()["chain_height"],
            "uptime_s": runtime.snapshot()["network"]["uptime_s"],
        }

    @app.get("/api/snapshot")
    async def snapshot() -> JSONResponse:
        payload = await run_in_threadpool(rt().snapshot)
        return JSONResponse(payload, headers={"Cache-Control": "no-store"})

    @app.get("/api/readings")
    async def readings(
        limit: int = Query(default=50, ge=1, le=500),
        device_id: str | None = Query(default=None),
        status: str | None = Query(default=None),
    ) -> dict:
        runtime = rt()
        rows = runtime.store.list_readings(limit=limit, device_id=device_id, status=status)
        from .runtime import _reading_public

        return {"readings": [_reading_public(row) for row in rows]}

    @app.get("/api/readings/{digest}")
    async def reading_detail(digest: str) -> dict:
        detail = await run_in_threadpool(rt().reading_detail, digest)
        if detail is None:
            raise HTTPException(status_code=404, detail="reading not found")
        return detail

    @app.get("/api/blocks")
    async def blocks(limit: int = Query(default=20, ge=1, le=200)) -> dict:
        runtime = rt()
        rows = runtime.store.all_blocks()[-limit:]
        from .blockchain import Block

        return {
            "blocks": [
                {**Block.from_row(row).to_public(), "mine_ms": row["mine_ms"]} for row in rows
            ]
        }

    @app.get("/api/blocks/{index}")
    async def block_detail(index: int) -> dict:
        detail = await run_in_threadpool(rt().block_detail, index)
        if detail is None:
            raise HTTPException(status_code=404, detail="block not found")
        return detail

    @app.get("/api/alerts")
    async def alerts(limit: int = Query(default=50, ge=1, le=500)) -> dict:
        rows = rt().store.list_alerts(limit=limit)
        return {
            "alerts": [
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "severity": row["severity"],
                    "device_id": row["device_id"],
                    "reading_digest": row["reading_digest"],
                    "message": row["message"],
                    "created_at": row["created_at"],
                    "block_index": row["block_index"],
                    "alert_digest": row["alert_digest"],
                }
                for row in rows
            ]
        }

    @app.post("/api/audit")
    async def run_audit() -> dict:
        runtime = rt()
        report = await run_in_threadpool(runtime.audit.run)
        runtime._chain_cache = None
        return report.to_dict()

    @app.get("/api/audit/latest")
    async def latest_audit() -> dict:
        report = rt().audit.latest()
        return {"audit": report}

    @app.get("/api/tamper")
    async def tamper_catalog() -> dict:
        runtime = rt()
        return {
            "attacks": runtime.tamper.list_attacks(),
            "events": runtime.store.list_tamper_events(limit=25),
            "stats": runtime.store.tamper_stats(),
        }

    @app.post("/api/tamper/{attack}")
    async def run_tamper(attack: str) -> dict:
        runtime = rt()
        try:
            result = await run_in_threadpool(runtime.tamper.run, attack)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        runtime._chain_cache = None
        return result

    @app.post("/api/reset")
    async def reset_demo() -> dict:
        result = await run_in_threadpool(rt().reset)
        return result

    @app.post("/api/excursion")
    async def set_excursion(request: ExcursionRequest) -> dict:
        try:
            return rt().set_excursion(request.device_id, request.active)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown device {request.device_id}") from exc

    @app.post("/api/ingest")
    async def ingest(envelope: dict = Body(...)) -> dict:
        runtime = rt()
        result = await run_in_threadpool(runtime.gateway.ingest, envelope, "http")
        if not result.accepted:
            raise HTTPException(
                status_code=422,
                detail={"reason": result.reason, "digest": result.digest},
            )
        return {
            "accepted": True,
            "digest": result.digest,
            "device_id": result.device_id,
            "violations": result.violations,
        }

    @app.get("/api/chain/verify")
    async def verify_chain() -> dict:
        runtime = rt()
        issues = await run_in_threadpool(
            validate_chain, runtime.store.all_blocks(), runtime.validators, runtime.quorum
        )
        return {
            "ok": not issues,
            "issues": [issue.to_dict() for issue in issues],
            "blocks_checked": runtime.store.block_count(),
        }

    @app.get("/api/export")
    async def export_bundle() -> Response:
        bundle = await run_in_threadpool(rt().export_bundle)
        body = json.dumps(bundle, indent=2, sort_keys=True)
        return Response(
            body,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="vchain-audit-bundle.json"'},
        )

    @app.get("/api/policy")
    async def policy() -> dict:
        runtime = rt()
        return {
            "policy": runtime.policy.to_dict(),
            "commitments": {
                "hash": "SHA-256",
                "signature": "HMAC-SHA256",
                "merkle": "SHA-256 with leaf/node domain separation",
                "difficulty": runtime.settings.difficulty,
                "validators": len(runtime.validators),
                "quorum": runtime.quorum,
            },
        }

    return app


app = create_app()
