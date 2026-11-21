"""Small local HTTP API: read the decision log, see what is active, lift a block.

Every endpoint except /health needs the bearer token from ARE_API_TOKEN. The
token is compared in constant time and never logged. The server binds to
127.0.0.1 by default; this API can lift blocks, so it is not for the lab network.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .enforcers.base import EnforcerError

MIN_TOKEN_LENGTH = 32
_MAX_DECISIONS_PER_REQUEST = 500


class UnblockRequest(BaseModel):
    ip: str = Field(max_length=64)
    who: str = Field("api", max_length=64)


def _parse_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="not a valid IP address") from None


def create_app(engine, store, adapters, token: str) -> FastAPI:
    if len(token) < MIN_TOKEN_LENGTH:
        raise ValueError(f"API token must be at least {MIN_TOKEN_LENGTH} characters")
    expected = token.encode("utf-8")

    def require_token(authorization: str | None = Header(default=None)) -> None:
        """Reject any request without the exact bearer token (constant-time compare)."""
        scheme, _, supplied = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not secrets.compare_digest(supplied.strip().encode("utf-8"), expected):
            raise HTTPException(status_code=401, detail="missing or wrong bearer token",
                                headers={"WWW-Authenticate": "Bearer"})

    app = FastAPI(title="Active Response Engine", version="1.0.0")
    auth = [Depends(require_token)]

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "driver": engine.enforcer.name, "driver_healthy": bool(engine.enforcer.health())}

    @app.get("/status", dependencies=auth)
    def status() -> dict:
        return {**engine.status(), "adapters": {a.name: dict(a.stats) for a in adapters}}

    @app.get("/decisions", dependencies=auth)
    def decisions(ip: str | None = None, limit: int = Query(50, ge=1, le=_MAX_DECISIONS_PER_REQUEST)) -> list[dict]:
        rows = store.decisions(ip=_parse_ip(ip) if ip else None, limit=limit, newest_first=True)
        return [dataclasses.asdict(d) for d in rows]

    @app.get("/decisions/{decision_id}", dependencies=auth)
    def decision(decision_id: int) -> dict:
        found = store.get_decision(decision_id)
        if found is None:
            raise HTTPException(status_code=404, detail="no such decision")
        return dataclasses.asdict(found)

    @app.get("/active", dependencies=auth)
    def active() -> dict:
        try:
            driver = [dataclasses.asdict(e) for e in engine.enforcer.list_active()]
        except EnforcerError as exc:
            driver = {"error": str(exc)}
        return {"engine": engine.active_actions(), "driver": driver}

    @app.get("/ips/{ip}", dependencies=auth)
    def ip_state(ip: str) -> dict:
        return engine.snapshot(_parse_ip(ip))

    @app.post("/unblock", dependencies=auth)
    def unblock(req: UnblockRequest) -> dict:
        lifted = engine.manual_unblock(_parse_ip(req.ip), who=req.who)
        return {"ip": req.ip, "reversed_decisions": lifted}

    return app
