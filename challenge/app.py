import asyncio
from dataclasses import asdict, dataclass, field
import html
from pathlib import Path
import secrets
import time
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent import run_turn
from levels import LEVELS
from limits import BudgetedModelClient, BudgetExhausted, IpLimiter, Settings
from model import DevScriptedModelClient, ModelError, ProxyModelClient
from store import Store
from world import World


STATIC = Path(__file__).parent / "static"
ARGUS_URL = "https://github.com/gy15901580825/Argus"


def escaped(value):
    if isinstance(value, str):
        return html.escape(value)
    if isinstance(value, list):
        return [escaped(item) for item in value]
    if isinstance(value, dict):
        return {html.escape(key): escaped(item) for key, item in value.items()}
    return value


def campaign_url(url: str, level: int) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError("Assessment URL must be an https URL")
    query = dict(parse_qsl(parts.query))
    query.update(utm_source="challenge", utm_content=f"level-{level}")
    return urlunsplit(parts._replace(query=urlencode(query)))


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    input: str = Field(min_length=1, max_length=1500)


class Consent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    consent: Literal[True]

    @field_validator("consent", mode="before")
    @classmethod
    def explicit_boolean(cls, value):
        if value is not True:
            raise ValueError("Sharing requires explicit boolean consent")
        return value


@dataclass
class LevelState:
    world: World
    submissions: int = 0
    hints_used: int = 0
    winning_turn: tuple[str, list[dict]] | None = None
    shared: bool = False


@dataclass
class Session:
    touched: float
    levels: dict[int, LevelState] = field(default_factory=dict)


class UnconfiguredModel:
    async def complete(self, messages, tools):
        raise ModelError("Configure the model proxy or enable dev scripted mode.")


def create_app(settings: Settings | None = None, model=None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.model == "scripted" and settings.environment == "production":
        raise ValueError("scripted model mode is dev only and refused in production")
    if settings.environment == "production" and not settings.model_base:
        raise ValueError("Production requires CHALLENGE_MODEL_BASE")
    campaign_url(settings.assessment_url, 1)
    if model is None:
        if settings.model == "scripted":
            model = DevScriptedModelClient()
        elif settings.model_base:
            model = ProxyModelClient(settings.model_base, model=settings.model, api_key=settings.model_key)
        else:
            model = UnconfiguredModel()
    store = Store(settings.db_path)
    budget_model = BudgetedModelClient(model, store, settings)
    limiter = IpLimiter(settings.ip_submissions)
    sessions: dict[str, Session] = {}
    lock = asyncio.Lock()
    app = FastAPI(title="Argus Challenge: break the agent", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.sessions, app.state.settings = store, sessions, settings

    @app.middleware("http")
    async def request_boundary(request: Request, call_next):
        if request.method == "POST":
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 12_000:
                    return JSONResponse({"detail": "Request body is too large."}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        if getattr(request.state, "session_id", None):
            response.set_cookie("challenge_session", request.state.session_id, httponly=True, secure=settings.environment == "production", samesite="lax", max_age=settings.session_ttl)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        return JSONResponse({"detail": "Input must be text between 1 and 1500 characters; sharing requires explicit consent."}, status_code=422)

    def level_and_state(request: Request, n: int):
        level = LEVELS.get(n)
        if level is None:
            raise HTTPException(404, "Unknown level")
        now = time.monotonic()
        for sid in list(sessions):
            if now - sessions[sid].touched >= settings.session_ttl:
                del sessions[sid]
        sid = request.cookies.get("challenge_session", "")
        if sid not in sessions:
            if len(sessions) >= 2000:
                raise HTTPException(503, "The game is busy. Please try again later.")
            sid = secrets.token_urlsafe(24)
            sessions[sid] = Session(now)
        request.state.session_id = sid
        session = sessions[sid]
        session.touched = now
        if n not in session.levels:
            session.levels[n] = LevelState(level.seed())
            store.count(n, "starts")
        return level, session.levels[n]

    def budget_response(n):
        return JSONResponse({"detail": "Today's allowance is used up. Please come back tomorrow.", "argus_url": campaign_url(ARGUS_URL, n)}, status_code=503)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/api/levels")
    async def catalog():
        return [{"id": level.id, "title": level.title, "goal": level.goal, "input_kind": level.input_kind,
                 "owasp": level.owasp, "probe_ids": level.probe_ids, "explainer": level.explainer,
                 "argus_url": campaign_url(ARGUS_URL, level.id), "assessment_url": campaign_url(settings.assessment_url, level.id),
                 "dev_mode": settings.model == "scripted"} for level in LEVELS.values()]

    @app.post("/api/levels/{n}/submit")
    async def submit(n: int, body: Submission, request: Request):
        async with lock:
            level, state = level_and_state(request, n)
            ip = request.client.host if request.client else "unknown"
            if settings.trust_proxy:
                forwarded = request.headers.get("x-forwarded-for", "").rsplit(",", 1)[-1].strip()
                if forwarded:
                    ip = forwarded
            if state.submissions >= settings.session_submissions:
                raise HTTPException(429, "Session submission limit reached for this level.")
            if not limiter.admit(ip):
                raise HTTPException(429, "Submission limit reached. Try again in ten minutes.")
            if store.spent() >= settings.daily_budget - 1e-12:
                return budget_response(n)
            state.submissions += 1
            store.count(n, "submissions")
            try:
                trace, text = await run_turn(level, state.world, body.input, budget_model)
            except BudgetExhausted:
                return budget_response(n)
            except ModelError:
                raise HTTPException(502, "The agent is temporarily unavailable. Please try again later.")
            entries = [asdict(entry) for entry in trace]
            won = level.won(state.world)
            if won and state.winning_turn is None:
                state.winning_turn = (body.input, entries)
                store.count(n, "wins")
            return escaped({"input": body.input, "trace": entries, "text": text, "won": won})

    @app.post("/api/levels/{n}/reset")
    async def reset(n: int, request: Request):
        async with lock:
            level, state = level_and_state(request, n)
            state.world = level.seed()
            state.hints_used = 0
            state.winning_turn = None
            state.shared = False
            return {"reset": True}

    @app.get("/api/levels/{n}/hint")
    async def hint(n: int, request: Request):
        async with lock:
            level, state = level_and_state(request, n)
            state.hints_used = min(3, state.hints_used + 1)
            return {"hint": level.hints[state.hints_used - 1], "used": state.hints_used}

    @app.post("/api/levels/{n}/share")
    async def share(n: int, body: Consent, request: Request):
        async with lock:
            level, state = level_and_state(request, n)
            if state.winning_turn is None:
                raise HTTPException(409, "Win this level before sharing an attack.")
            if not state.shared:
                player_input, trace = state.winning_turn
                store.share(n, player_input, trace)
                state.shared = True
            return {"shared": True}

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
