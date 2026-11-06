"""
main.py  -  FastAPI backend for the Extreme Value Risk Analytics Platform.

Run:  uvicorn main:app --host 0.0.0.0 --port 8000

Security controls implemented here
----------------------------------
* bcrypt password hashing (cost 12), constant-time-ish login (dummy hash for unknown users)
* JWT (HS256, short expiry) carrying the RBAC role; server-side role check on every route
* 100 % parameterised SQL (pyodbc "?" placeholders) - no string-built queries anywhere
* Strict allow-list validation of every upload field: ASCII ISO dates, strictly numeric floats,
  size / row caps; raw cell contents are never echoed back (no reflected XSS)
* Security response headers, CORS allow-list, generic 401 messages
"""

from __future__ import annotations

import csv
import io
import logging
import math
import os
import re
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Literal, Optional

import bcrypt
import jwt
import numpy as np
import pyodbc
from fastapi import Depends, FastAPI, File, Form, HTTPException, Path, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from blob_storage import upload_raw_csv
from config import get_connection, settings
from risk_engine import gaussian_var, hill_var

log = logging.getLogger("evt")
logging.basicConfig(level=logging.INFO)

# =========================================================================== #
# 1. PASSWORD HASHING  (bcrypt, salted, adaptive cost)
# =========================================================================== #
BCRYPT_ROUNDS = 12
MAX_PASSWORD_BYTES = 72                      # bcrypt only uses the first 72 bytes -> reject longer


def hash_password(plain: str) -> str:
    """Return a 60-char bcrypt hash. This (and only this) value is stored in dbo.Users.PasswordHash."""
    raw = plain.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError("password longer than 72 bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    raw = plain.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(raw, hashed.encode("ascii"))
    except ValueError:                       # malformed hash
        return False


# Verified against when the username does not exist, so response time does not reveal valid usernames.
_DUMMY_HASH = hash_password("dummy-password-for-timing-only")

# =========================================================================== #
# 2. JWT + ROLE-BASED ACCESS CONTROL  (Quant vs Viewer)
# =========================================================================== #
Role = Literal["Quant", "Viewer"]
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class AuthUser(BaseModel):
    user_id: int
    username: str
    role: Role


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role


def create_access_token(user_id: int, username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": username,
        "uid": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def get_current_user(token: str = Depends(oauth2_scheme)) -> AuthUser:
    unauthorised = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # algorithms is pinned: prevents "alg: none" / algorithm-confusion attacks; exp is verified.
        claims = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        if claims.get("role") not in ("Quant", "Viewer") or not isinstance(claims.get("uid"), int):
            raise unauthorised
        return AuthUser(user_id=claims["uid"], username=claims["sub"], role=claims["role"])
    except jwt.PyJWTError:
        raise unauthorised


def require_role(*allowed: Role):
    """Dependency factory: `Depends(require_role("Quant"))` -> 403 for every other role."""
    def checker(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions for this role.")
        return user
    return checker


def _get_user_record(username: str):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT u.UserID, u.Username, u.PasswordHash, r.RoleName "
            "FROM dbo.Users AS u JOIN dbo.Roles AS r ON r.RoleID = u.RoleID "
            "WHERE u.Username = ? AND u.IsActive = 1",
            username,
        )
        return cur.fetchone()


def _seed_demo_users() -> None:
    """
    Mock accounts for the demo. Passwords come from env vars (never from source code):
        DEMO_QUANT_PASSWORD, DEMO_VIEWER_PASSWORD   and   SEED_DEMO_USERS=1
    """
    for username, env_name, role in (
        ("quant_demo", "DEMO_QUANT_PASSWORD", "Quant"),
        ("viewer_demo", "DEMO_VIEWER_PASSWORD", "Viewer"),
    ):
        password = os.environ.get(env_name)
        if not password:
            continue
        with get_connection() as conn:
            conn.cursor().execute(
                "IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Username = ?) "
                "INSERT INTO dbo.Users (Username, PasswordHash, RoleID) "
                "SELECT ?, ?, RoleID FROM dbo.Roles WHERE RoleName = ?",
                username, username, hash_password(password), role,
            )
            conn.commit()
        log.info("Demo user ensured: %s (%s)", username, role)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if os.environ.get("SEED_DEMO_USERS") == "1":
        _seed_demo_users()
    yield


# Hide interactive docs in production.
_prod = os.environ.get("ENV", "").lower() == "production"
app = FastAPI(
    title="Extreme Value Risk Analytics Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if _prod else "/docs",
    redoc_url=None,
    openapi_url=None if _prod else "/openapi.json",
)

if settings.cors_origins:                    # explicit allow-list, never "*"
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

_DOC_PATHS = ("/docs", "/openapi.json")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.url.path.startswith(_DOC_PATHS):          # Swagger UI needs inline scripts
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


# =========================================================================== #
# 3. AUTH ROUTES
# =========================================================================== #
class RegisterRequest(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.\-]{3,50}$")
    password: str = Field(min_length=12, max_length=72)
    role: Role


@app.post("/api/auth/login", response_model=TokenResponse, tags=["auth"])
def login(form: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    record = _get_user_record(form.username)
    hashed = record.PasswordHash if record else _DUMMY_HASH
    password_ok = verify_password(form.password, hashed)
    if record is None or not password_ok:
        # one generic message for "no such user" and "wrong password"
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(record.UserID, record.Username, record.RoleName)
    return TokenResponse(access_token=token, role=record.RoleName)


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, tags=["auth"])
def register(body: RegisterRequest, _: AuthUser = Depends(require_role("Quant"))) -> dict:
    """Quant-only user provisioning. The password is hashed BEFORE it touches the database."""
    try:
        password_hash = hash_password(body.password)
    except ValueError:
        raise HTTPException(422, "Password must be at most 72 bytes.")
    try:
        with get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO dbo.Users (Username, PasswordHash, RoleID) "
                "SELECT ?, ?, RoleID FROM dbo.Roles WHERE RoleName = ?",
                body.username, password_hash, body.role,
            )
            conn.commit()
    except pyodbc.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists.")
    return {"username": body.username, "role": body.role}


# =========================================================================== #
# 4. ASSETS
# =========================================================================== #
TICKER_RE = re.compile(r"[A-Z0-9.\-]{1,20}")


class AssetCreate(BaseModel):
    ticker: str = Field(pattern=r"^[A-Z0-9.\-]{1,20}$")
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 .,&'()\-]+$")   # no <, >, quotes, ;
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")


def _rows_as_dicts(cur: pyodbc.Cursor) -> list[dict]:
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


@app.get("/api/assets", tags=["assets"])
def list_assets(_: AuthUser = Depends(require_role("Quant", "Viewer"))) -> list[dict]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT AssetID, Ticker, AssetName, Currency FROM dbo.Assets ORDER BY Ticker")
        return _rows_as_dicts(cur)


@app.post("/api/assets", status_code=status.HTTP_201_CREATED, tags=["assets"])
def create_asset(body: AssetCreate, _: AuthUser = Depends(require_role("Quant"))) -> dict:
    try:
        with get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO dbo.Assets (Ticker, AssetName, Currency) VALUES (?, ?, ?)",
                body.ticker, body.name, body.currency,
            )
            conn.commit()
    except pyodbc.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Ticker already exists.")
    return {"ticker": body.ticker}


# =========================================================================== #
# 5. CSV UPLOAD  (strict validation  ->  blocks SQL injection and stored/reflected XSS)
# =========================================================================== #
MAX_UPLOAD_BYTES = 5 * 1024 * 1024           # 5 MB   (10 years of daily rows is ~60 KB)
MAX_ROWS = 20_000
MIN_DATE = date(1900, 1, 1)
ALLOWED_CONTENT_TYPES = {"text/csv", "application/csv", "application/vnd.ms-excel"}

# [0-9] (not \d) so Unicode digits such as Arabic-Indic numerals are rejected.
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
FLOAT_RE = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?")


class CsvValidationError(ValueError):
    """Message contains row numbers / field names only - never the offending cell content."""


def parse_returns_csv(text: str) -> list[tuple[date, float]]:
    """
    Expected format (header required):      date,return
                                             2024-01-02,0.00412
    Every cell is checked against an allow-list pattern BEFORE conversion, so the only values that can
    ever reach SQL are a `datetime.date` and a finite `float` (bound as parameters, never concatenated).
    """
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise CsvValidationError("File is empty.")
    except csv.Error:
        raise CsvValidationError("Malformed CSV header.")
    if [h.strip().lower() for h in header] != ["date", "return"]:
        raise CsvValidationError("Header must be exactly: date,return")

    rows: list[tuple[date, float]] = []
    seen: set[date] = set()
    today = datetime.now(timezone.utc).date()

    try:
        for line_no, rec in enumerate(reader, start=2):
            if not rec:                                   # blank line
                continue
            if len(rec) != 2:
                raise CsvValidationError(f"Row {line_no}: expected exactly 2 columns.")
            d_raw, r_raw = rec[0].strip(), rec[1].strip()

            if not DATE_RE.fullmatch(d_raw):
                raise CsvValidationError(f"Row {line_no}: date must be formatted YYYY-MM-DD.")
            try:
                d = datetime.strptime(d_raw, "%Y-%m-%d").date()
            except ValueError:
                raise CsvValidationError(f"Row {line_no}: not a valid calendar date.")
            if d < MIN_DATE or d > today:
                raise CsvValidationError(f"Row {line_no}: date outside the allowed range.")
            if d in seen:
                raise CsvValidationError(f"Row {line_no}: duplicate date within the file.")

            if len(r_raw) > 32 or not FLOAT_RE.fullmatch(r_raw):
                raise CsvValidationError(f"Row {line_no}: return must be a plain decimal number.")
            value = float(r_raw)
            if not math.isfinite(value) or not (-1.0 < value < 1.0):
                raise CsvValidationError(f"Row {line_no}: return must satisfy -1 < r < 1.")

            if len(rows) >= MAX_ROWS:
                raise CsvValidationError(f"File exceeds {MAX_ROWS} rows.")
            seen.add(d)
            rows.append((d, round(value, 8)))             # DECIMAL(12,8) precision
    except csv.Error:
        raise CsvValidationError("Malformed CSV content.")

    if not rows:
        raise CsvValidationError("No data rows found.")
    return rows


def _asset_id_for(ticker: str) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT AssetID FROM dbo.Assets WHERE Ticker = ?", ticker)
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown ticker. Create the asset first.")
    return row.AssetID


@app.post("/api/upload", status_code=status.HTTP_201_CREATED, tags=["data"])
def upload_returns(
    ticker: str = Form(...),
    file: UploadFile = File(...),
    user: AuthUser = Depends(require_role("Quant")),
) -> dict:
    """Pipeline: validate envelope -> archive RAW bytes to Blob -> parse/validate -> one SQL transaction."""
    ticker = ticker.strip().upper()
    if not TICKER_RE.fullmatch(ticker):
        raise HTTPException(422, "Invalid ticker format.")
    if not (file.filename or "").lower().endswith(".csv") or file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Only .csv files are accepted.")

    raw = file.file.read(MAX_UPLOAD_BYTES + 1)            # never read more than the cap
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File too large (max 5 MB).")
    if not raw:
        raise HTTPException(422, "Empty file.")

    asset_id = _asset_id_for(ticker)

    # (a) DP-900 non-relational store: keep the untouched original BEFORE parsing.
    blob_name = upload_raw_csv(raw, ticker, user.username)

    # (b) Parse + strictly validate.
    try:
        rows = parse_returns_csv(raw.decode("utf-8-sig"))
    except UnicodeDecodeError:
        raise HTTPException(422, "File must be UTF-8 encoded text.")
    except CsvValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))

    # (c) Relational store: single transaction; any failure rolls back the whole file.
    params = [(asset_id, d, r, user.user_id) for d, r in rows]
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.fast_executemany = True
            cur.executemany(
                "INSERT INTO dbo.DailyReturns (AssetID, TradeDate, DailyReturn, UploadedBy) VALUES (?, ?, ?, ?)",
                params,
            )
            conn.commit()
    except pyodbc.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Batch rejected: it overlaps dates that already exist for this asset.")

    return {"ticker": ticker, "rows_inserted": len(rows), "raw_blob": blob_name}


# =========================================================================== #
# 6. RISK CALCULATION  (synchronous - see architecture trade-off)
# =========================================================================== #
@app.post("/api/risk/calculate/{asset_id}", status_code=status.HTTP_201_CREATED, tags=["risk"])
def calculate_risk(
    asset_id: int = Path(ge=1),
    confidence: float = Query(0.99, gt=0.95, lt=1.0),
    user: AuthUser = Depends(require_role("Quant")),
) -> dict:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT TradeDate, DailyReturn FROM dbo.DailyReturns WHERE AssetID = ? ORDER BY TradeDate",
            asset_id,
        )
        rows = cur.fetchall()
        if not rows:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "No returns stored for this asset.")

        returns = np.array([float(r.DailyReturn) for r in rows], dtype=np.float64)
        try:
            g_var = gaussian_var(returns, confidence)
            hill = hill_var(returns, confidence)
        except ValueError as exc:                          # too few observations, confidence too low, ...
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))

        cur.execute(
            "EXEC dbo.sp_LogRiskCalculation "
            "@AssetID=?, @CalculatedBy=?, @ConfidenceLevel=?, @WindowStart=?, @WindowEnd=?, "
            "@SampleSize=?, @TailK=?, @HillXi=?, @GaussianVaR=?, @HillVaR=?",
            asset_id, user.user_id, round(confidence, 5), rows[0].TradeDate, rows[-1].TradeDate,
            hill.n, hill.k, round(hill.xi, 6), round(g_var, 8), round(hill.var, 8),
        )
        metric_row = cur.fetchone()
        if metric_row is None:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Risk calculation was saved but no metric ID was returned.",
            )
        metric_id = metric_row.MetricID
        conn.commit()

    return {
        "metric_id": metric_id,
        "asset_id": asset_id,
        "confidence": confidence,
        "sample_size": hill.n,
        "tail_k": hill.k,
        "hill_xi": hill.xi,
        "tail_index_alpha": hill.tail_index,
        "gaussian_var": g_var,
        "hill_var": hill.var,
        "hill_to_gaussian_ratio": (hill.var / g_var) if g_var > 0 else None,
    }


_METRICS_SQL = (
    "SELECT TOP (?) rm.MetricID, a.Ticker, rm.CalculatedAt, rm.ConfidenceLevel, rm.WindowStart, rm.WindowEnd, "
    "rm.SampleSize, rm.TailK, rm.HillXi, rm.GaussianVaR, rm.HillVaR "
    "FROM dbo.RiskMetrics AS rm JOIN dbo.Assets AS a ON a.AssetID = rm.AssetID "
)


@app.get("/api/risk/metrics", tags=["risk"])
def list_metrics(
    asset_id: Optional[int] = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=500),
    _: AuthUser = Depends(require_role("Quant", "Viewer")),
) -> list[dict]:
    with get_connection() as conn:
        cur = conn.cursor()
        if asset_id is None:
            cur.execute(_METRICS_SQL + "ORDER BY rm.CalculatedAt DESC", limit)
        else:
            cur.execute(_METRICS_SQL + "WHERE rm.AssetID = ? ORDER BY rm.CalculatedAt DESC", limit, asset_id)
        return _rows_as_dicts(cur)


@app.get("/api/assets/{asset_id}/extreme-losses", tags=["risk"])
def extreme_losses(
    asset_id: int = Path(ge=1),
    _: AuthUser = Depends(require_role("Quant", "Viewer")),
) -> list[dict]:
    """Worst 5 % of returns for the asset (rows of vw_ExtremeLosses = the Hill exceedances)."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT LossRank, TradeDate, DailyReturn, LossMagnitude "
            "FROM dbo.vw_ExtremeLosses WHERE AssetID = ? ORDER BY LossRank",
            asset_id,
        )
        return _rows_as_dicts(cur)


@app.get("/api/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}
