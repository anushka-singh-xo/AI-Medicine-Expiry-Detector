import io
import logging
import re
import calendar
import hashlib
import hmac
import os
import secrets
import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

from config import ALLOWED_ORIGINS, APP_NAME, APP_VERSION, LOCAL_ORIGIN_REGEX

logger = logging.getLogger("medguard")
_ocr_error = None
try:
    from rapidocr import RapidOCR

    _ocr_engine = RapidOCR()
except ImportError as exc:
    _ocr_engine = None
    _ocr_error = f"OCR dependency is missing: {exc.name or exc}"
except Exception:
    # OCR is optional: a model/runtime initialization failure should not take
    # down inventory and settings endpoints too.
    logger.exception("OCR initialization failed; the rest of the API will remain available")
    _ocr_engine = None
    _ocr_error = "OCR engine could not initialize; check backend logs"

app = FastAPI(title=APP_NAME, version=APP_VERSION)
SESSION_COOKIE = "medguard_session"
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
COOKIE_SECURE = os.getenv("MEDGUARD_COOKIE_SECURE", "").lower() in {"1", "true", "yes"} or os.getenv("MEDGUARD_ENV", "").lower() == "production"
PASSWORD_SCRYPT_N = 2 ** 14
PASSWORD_SCRYPT_R = 8
PASSWORD_SCRYPT_P = 1
DB_PATH = Path(__file__).with_name("medguard.db")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL, created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS medicines (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, batch TEXT, mfg TEXT, exp TEXT NOT NULL,
            added_at TEXT NOT NULL, temp_sensitive INTEGER NOT NULL DEFAULT 0,
            temp_min REAL, temp_max REAL, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            guest_id TEXT, generic_name TEXT, strength TEXT, form TEXT, category TEXT,
            quantity INTEGER NOT NULL DEFAULT 0, unit TEXT, reorder_level INTEGER NOT NULL DEFAULT 0,
            supplier TEXT, storage_location TEXT, barcode TEXT, data_status TEXT, import_key TEXT)""")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(medicines)")}
        additions = {
            "user_id": "TEXT REFERENCES users(id) ON DELETE CASCADE", "guest_id": "TEXT",
            "generic_name": "TEXT", "strength": "TEXT", "form": "TEXT", "category": "TEXT",
            "quantity": "INTEGER NOT NULL DEFAULT 0", "unit": "TEXT",
            "reorder_level": "INTEGER NOT NULL DEFAULT 0", "supplier": "TEXT",
            "storage_location": "TEXT", "barcode": "TEXT", "data_status": "TEXT", "import_key": "TEXT",
        }
        for column, column_type in additions.items():
            if column not in columns:
                db.execute(f"ALTER TABLE medicines ADD COLUMN {column} {column_type}")
        db.execute("""CREATE TABLE IF NOT EXISTS temperature_readings (
            id TEXT PRIMARY KEY, medicine_id TEXT NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
            temp_c REAL NOT NULL, recorded_at TEXT NOT NULL, note TEXT)""")
        reading_columns = {row["name"] for row in db.execute("PRAGMA table_info(temperature_readings)")}
        if "guest_id" not in reading_columns:
            db.execute("ALTER TABLE temperature_readings ADD COLUMN guest_id TEXT")
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("""CREATE TABLE IF NOT EXISTS user_settings (
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(user_id,key))""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_medicines_user_added ON medicines(user_id,added_at DESC)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_medicines_user_guest ON medicines(user_id,guest_id)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_medicines_user_import ON medicines(user_id,import_key)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_readings_medicine_guest ON temperature_readings(medicine_id,guest_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_expiry ON sessions(user_id,expires_at)")


@app.on_event("startup")
def startup():
    init_db()
    logger.info("MedGuard API ready; database initialized at %s", DB_PATH)
    if _ocr_engine is None:
        logger.error("OCR is unavailable: %s. Install backend/requirements.txt in this Python environment.", _ocr_error)
    else:
        logger.info("OCR engine ready (RapidOCR with ONNX Runtime CPU)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=LOCAL_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def protect_cookie_requests(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method in {"POST","PUT","PATCH","DELETE"}:
        origin=request.headers.get("origin")
        if origin and origin not in ALLOWED_ORIGINS and not re.fullmatch(LOCAL_ORIGIN_REGEX,origin):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail":"Request origin is not allowed"}, status_code=403)
    response=await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"]="no-store"
    return response


@app.get("/")
def root():
    return {"status": "ok", "service": APP_NAME, "version": APP_VERSION}


@app.get("/api/health")
def health():
    return {"status": "healthy", "ocr": "available" if _ocr_engine is not None else "unavailable"}


class SignupInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ProfileInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)


def _clean_email(email: str) -> str:
    normalized = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    return normalized


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=PASSWORD_SCRYPT_N,
                            r=PASSWORD_SCRYPT_R, p=PASSWORD_SCRYPT_P, dklen=64)
    return "scrypt${}${}${}${}${}".format(PASSWORD_SCRYPT_N, PASSWORD_SCRYPT_R,
                                          PASSWORD_SCRYPT_P, salt.hex(), digest.hex())


def _verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                                n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(digest_hex)))
        return hmac.compare_digest(actual, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _user_payload(row):
    return {"id": row["id"], "name": row["name"], "email": row["email"], "created_at": row["created_at"]}


def _issue_session(db, user_id: str, response: Response):
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=SESSION_TTL_SECONDS)
    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
               (_token_hash(token),user_id,expires.isoformat(),now.isoformat()))
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS, httponly=True,
                        secure=COOKIE_SECURE, samesite="lax", path="/")


def require_user(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Please sign in to continue")
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("""SELECT u.id,u.name,u.email,u.created_at FROM sessions s
            JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?""",
            (_token_hash(token),now)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again")
    # Keep active sessions alive. Refresh both the server-side expiry and the
    # browser cookie together so they cannot drift apart during normal use.
    refreshed_at = datetime.now(timezone.utc)
    expires_at = refreshed_at + timedelta(seconds=SESSION_TTL_SECONDS)
    with get_db() as db:
        db.execute("UPDATE sessions SET expires_at=? WHERE token_hash=?",
                   (expires_at.isoformat(), _token_hash(token)))
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS, httponly=True,
                        secure=COOKIE_SECURE, samesite="lax", path="/")
    return row


@app.post("/api/auth/signup", status_code=201)
def signup(data: SignupInput, response: Response):
    name = data.name.strip()
    email = _clean_email(data.email)
    password = data.password
    if not name:
        raise HTTPException(status_code=422, detail="Name cannot be blank")
    if len(password) < 12:
        raise HTTPException(status_code=422, detail="Use a password with at least 12 characters")
    user_id = "u_" + uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    password_hash = _hash_password(password)
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        existing_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if db.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="An account with that email already exists")
        db.execute("INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?)",
                   (user_id,name,email,password_hash,created_at))
        # The first account owns inventory created before authentication existed.
        if existing_count == 0:
            db.execute("UPDATE medicines SET user_id=? WHERE user_id IS NULL", (user_id,))
            old_setting=db.execute("SELECT value FROM settings WHERE key='thresholdDays'").fetchone()
            if old_setting:
                db.execute("INSERT OR IGNORE INTO user_settings(user_id,key,value) VALUES(?,?,?)",
                           (user_id,"thresholdDays",old_setting["value"]))
                db.execute("DELETE FROM settings WHERE key='thresholdDays'")
        _issue_session(db,user_id,response)
    return {"user":{"id":user_id,"name":name,"email":email,"created_at":created_at}}


@app.post("/api/auth/login")
def login(data: LoginInput, response: Response):
    email = _clean_email(data.email)
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        valid = _verify_password(data.password,row["password_hash"]) if row else False
        if not valid:
            raise HTTPException(status_code=401, detail="Email or password is incorrect")
        # Drop expired sessions for this account whenever it signs in.
        db.execute("DELETE FROM sessions WHERE user_id=? AND expires_at<=?",
                   (row["id"],datetime.now(timezone.utc).isoformat()))
        _issue_session(db,row["id"],response)
        user = _user_payload(row)
    return {"user":user}


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    token=request.cookies.get(SESSION_COOKIE)
    if token:
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=COOKIE_SECURE, samesite="lax")


@app.get("/api/auth/me")
def current_account(user=Depends(require_user)):
    return {"user":_user_payload(user)}


@app.put("/api/auth/profile")
def update_profile(data: ProfileInput, user=Depends(require_user)):
    name=data.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Name cannot be blank")
    with get_db() as db:
        db.execute("UPDATE users SET name=? WHERE id=?", (name,user["id"]))
        row=db.execute("SELECT id,name,email,created_at FROM users WHERE id=?", (user["id"],)).fetchone()
    return {"user":_user_payload(row)}


# ── Date parsing engine ──────────────────────────────────────────────


class MedicineInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    batch: str | None = Field(default=None, max_length=100)
    mfg: date | None = None
    exp: date
    generic_name: str | None = Field(default=None, max_length=200)
    strength: str | None = Field(default=None, max_length=100)
    form: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=120)
    quantity: int = Field(default=0, ge=0, le=2147483647)
    unit: str | None = Field(default=None, max_length=80)
    reorder_level: int = Field(default=0, ge=0, le=2147483647)
    supplier: str | None = Field(default=None, max_length=200)
    storage_location: str | None = Field(default=None, max_length=200)
    barcode: str | None = Field(default=None, max_length=100)
    data_status: str | None = Field(default=None, max_length=100)
    import_key: str | None = Field(default=None, max_length=200)
    temp_sensitive: bool = False
    temp_min: float | None = Field(default=None, ge=-100, le=100)
    temp_max: float | None = Field(default=None, ge=-100, le=100)


def medicine_dict(row):
    item = dict(row)
    item.pop("user_id",None)
    item.pop("guest_id",None)
    item.pop("import_key",None)
    item["temp_sensitive"] = bool(item["temp_sensitive"])
    return item


def _is_fictional_data_status(value: str | None) -> bool:
    status = (value or "").strip().lower()
    if re.search(r"\b(?:not|non[- ]?)\s*(?:fictional|test|sample)\b", status):
        return False
    return bool(re.search(r"\b(?:fictional|fiction|test|sample)\b", status))


@app.get("/api/medicines")
def list_medicines(user=Depends(require_user)):
    with get_db() as db:
        return [medicine_dict(r) for r in db.execute("SELECT * FROM medicines WHERE user_id=? ORDER BY added_at DESC", (user["id"],))]


@app.post("/api/medicines", status_code=201)
def create_medicine(item: MedicineInput, user=Depends(require_user)):
    if not item.name.strip():
        raise HTTPException(status_code=422, detail="Medicine name cannot be blank")
    if item.mfg and item.mfg > item.exp:
        raise HTTPException(status_code=422, detail="Manufacture date must be on or before expiry date")
    if item.temp_sensitive and (item.temp_min is None or item.temp_max is None):
        raise HTTPException(status_code=422, detail="Temperature-sensitive medicines need minimum and maximum storage temperatures")
    if item.temp_min is not None and item.temp_max is not None and item.temp_min >= item.temp_max:
        raise HTTPException(status_code=422, detail="Minimum temperature must be lower than maximum temperature")
    medicine_id = "m_" + uuid.uuid4().hex[:16]
    added_at = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute("""INSERT INTO medicines
            (id,name,batch,mfg,exp,added_at,temp_sensitive,temp_min,temp_max,user_id,
             generic_name,strength,form,category,quantity,unit,reorder_level,supplier,storage_location,barcode,data_status,import_key)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (medicine_id,item.name.strip(),item.batch,item.mfg.isoformat() if item.mfg else None,
             item.exp.isoformat(),added_at,int(item.temp_sensitive),item.temp_min,item.temp_max,user["id"],
             item.generic_name,item.strength,item.form,item.category,item.quantity,item.unit,item.reorder_level,
             item.supplier,item.storage_location,item.barcode,item.data_status,None))
        row = db.execute("SELECT * FROM medicines WHERE id=? AND user_id=?", (medicine_id,user["id"])).fetchone()
        return medicine_dict(row)


@app.put("/api/medicines/{medicine_id}")
def update_medicine(medicine_id: str, item: MedicineInput, user=Depends(require_user)):
    if not item.name.strip():
        raise HTTPException(status_code=422, detail="Medicine name cannot be blank")
    if item.mfg and item.mfg > item.exp:
        raise HTTPException(status_code=422, detail="Manufacture date must be on or before expiry date")
    if item.temp_sensitive and (item.temp_min is None or item.temp_max is None):
        raise HTTPException(status_code=422, detail="Temperature-sensitive medicines need minimum and maximum storage temperatures")
    if item.temp_min is not None and item.temp_max is not None and item.temp_min >= item.temp_max:
        raise HTTPException(status_code=422, detail="Minimum temperature must be lower than maximum temperature")

    with get_db() as db:
        cursor = db.execute("""UPDATE medicines SET name=?,batch=?,mfg=?,exp=?,
            temp_sensitive=?,temp_min=?,temp_max=? WHERE id=? AND user_id=?""",
            (item.name.strip(),item.batch,item.mfg.isoformat() if item.mfg else None,
             item.exp.isoformat(),int(item.temp_sensitive),item.temp_min,item.temp_max,
             medicine_id,user["id"]))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Medicine not found")
        row = db.execute("SELECT * FROM medicines WHERE id=? AND user_id=?",
                         (medicine_id,user["id"])).fetchone()
    return medicine_dict(row)


class MedicineCsvImportInput(BaseModel):
    medicines: list[MedicineInput]

    @validator("medicines")
    def limit_csv_rows(cls, value):
        if len(value) > 5000:
            raise ValueError("A CSV import can include at most 5000 valid records")
        return value


@app.post("/api/medicines/import")
def import_medicines(data: MedicineCsvImportInput, user=Depends(require_user)):
    keys = [item.import_key for item in data.medicines]
    if any(not key for key in keys):
        raise HTTPException(status_code=422, detail="Every imported record needs an import key")
    if len(set(keys)) != len(keys):
        raise HTTPException(status_code=422, detail="This CSV contains duplicate record keys")
    for item in data.medicines:
        if not item.name.strip():
            raise HTTPException(status_code=422, detail="Medicine name cannot be blank")
        if item.mfg and item.mfg > item.exp:
            raise HTTPException(status_code=422, detail=f"{item.name}: manufacture date is after expiry date")
        if not _is_fictional_data_status(item.data_status):
            raise HTTPException(status_code=422, detail=f"{item.name}: Data Status must clearly mark this as fictional/test data")
        if item.temp_sensitive and (item.temp_min is None or item.temp_max is None):
            raise HTTPException(status_code=422, detail=f"{item.name}: temperature-sensitive medicines need minimum and maximum storage temperatures")
        if item.temp_min is not None and item.temp_max is not None and item.temp_min >= item.temp_max:
            raise HTTPException(status_code=422, detail=f"{item.name}: minimum temperature must be lower than maximum temperature")

    imported = 0
    skipped = 0
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        for item in data.medicines:
            existing = db.execute("SELECT 1 FROM medicines WHERE user_id=? AND import_key=?",
                                  (user["id"],item.import_key)).fetchone()
            if existing:
                skipped += 1
                continue
            medicine_id = "m_" + uuid.uuid4().hex[:16]
            added_at = datetime.now(timezone.utc).isoformat()
            db.execute("""INSERT INTO medicines
                (id,name,batch,mfg,exp,added_at,temp_sensitive,temp_min,temp_max,user_id,
                 generic_name,strength,form,category,quantity,unit,reorder_level,supplier,storage_location,barcode,data_status,import_key)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (medicine_id,item.name.strip(),item.batch,item.mfg.isoformat() if item.mfg else None,
                 item.exp.isoformat(),added_at,int(item.temp_sensitive),item.temp_min,item.temp_max,user["id"],
                 item.generic_name,item.strength,item.form,item.category,item.quantity,item.unit,item.reorder_level,
                 item.supplier,item.storage_location,item.barcode,item.data_status,item.import_key))
            imported += 1
    return {"imported":imported,"skipped_duplicates":skipped}


@app.delete("/api/medicines/{medicine_id}", status_code=204)
def delete_medicine(medicine_id: str, user=Depends(require_user)):
    with get_db() as db:
        cursor = db.execute("DELETE FROM medicines WHERE id=? AND user_id=?", (medicine_id,user["id"]))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Medicine not found")


class SettingsInput(BaseModel):
    thresholdDays: int = Field(default=90, ge=1, le=365)


@app.get("/api/settings")
def get_settings(user=Depends(require_user)):
    with get_db() as db:
        row = db.execute("SELECT value FROM user_settings WHERE user_id=? AND key='thresholdDays'", (user["id"],)).fetchone()
    return {"thresholdDays": int(row["value"]) if row else 90}


@app.put("/api/settings")
def put_settings(settings: SettingsInput, user=Depends(require_user)):
    with get_db() as db:
        db.execute("INSERT INTO user_settings(user_id,key,value) VALUES(?, 'thresholdDays', ?) ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value", (user["id"],str(settings.thresholdDays)))
    return {"thresholdDays": settings.thresholdDays}


class GuestMedicineInput(BaseModel):
    guest_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=200)
    batch: str | None = Field(default=None, max_length=100)
    mfg: date | None = None
    exp: date
    temp_sensitive: bool = False
    temp_min: float | None = Field(default=None, ge=-100, le=100)
    temp_max: float | None = Field(default=None, ge=-100, le=100)
    generic_name: str | None = Field(default=None, max_length=200)
    strength: str | None = Field(default=None, max_length=100)
    form: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=120)
    quantity: int = Field(default=0, ge=0, le=2147483647)
    unit: str | None = Field(default=None, max_length=80)
    reorder_level: int = Field(default=0, ge=0, le=2147483647)
    supplier: str | None = Field(default=None, max_length=200)
    storage_location: str | None = Field(default=None, max_length=200)
    barcode: str | None = Field(default=None, max_length=100)
    data_status: str | None = Field(default=None, max_length=100)
    import_key: str | None = Field(default=None, max_length=200)


class GuestReadingInput(BaseModel):
    guest_id: str = Field(min_length=1, max_length=128)
    medicine_guest_id: str = Field(min_length=1, max_length=128)
    temp_c: float = Field(ge=-100, le=100)
    recorded_at: datetime
    note: str | None = Field(default=None, max_length=500)


class GuestSyncInput(BaseModel):
    medicines: list[GuestMedicineInput]
    readings: list[GuestReadingInput] = Field(default_factory=list)
    thresholdDays: int | None = Field(default=None, ge=1, le=365)

    @validator("medicines")
    def limit_guest_medicines(cls, value):
        if len(value) > 5000:
            raise ValueError("A guest sync can include at most 5000 medicines")
        return value

    @validator("readings")
    def limit_guest_readings(cls, value):
        if len(value) > 10000:
            raise ValueError("A guest sync can include at most 10000 temperature readings")
        return value


@app.post("/api/guest-sync")
def sync_guest_workspace(data: GuestSyncInput, user=Depends(require_user)):
    """Atomically import a browser guest workspace; source IDs make retries idempotent."""
    if len({item.guest_id for item in data.medicines}) != len(data.medicines):
        raise HTTPException(status_code=422, detail="Guest inventory contains duplicate medicine IDs")
    if len({item.guest_id for item in data.readings}) != len(data.readings):
        raise HTTPException(status_code=422, detail="Guest inventory contains duplicate reading IDs")

    medicine_ids = {}
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        for item in data.medicines:
            row = db.execute("""SELECT id FROM medicines WHERE user_id=? AND
                (guest_id=? OR (? IS NOT NULL AND import_key=?)) LIMIT 1""",
                (user["id"],item.guest_id,item.import_key,item.import_key)).fetchone()
            if row:
                medicine_ids[item.guest_id] = row["id"]
                continue
            medicine_id = "m_" + uuid.uuid4().hex[:16]
            now = datetime.now(timezone.utc).isoformat()
            if item.temp_sensitive and (item.temp_min is None or item.temp_max is None):
                raise HTTPException(status_code=422, detail="Temperature-sensitive medicines need minimum and maximum storage temperatures")
            if item.temp_min is not None and item.temp_max is not None and item.temp_min >= item.temp_max:
                raise HTTPException(status_code=422, detail="Minimum temperature must be lower than maximum temperature")
            db.execute("""INSERT INTO medicines
                (id,name,batch,mfg,exp,added_at,temp_sensitive,temp_min,temp_max,user_id,guest_id,
                 generic_name,strength,form,category,quantity,unit,reorder_level,supplier,storage_location,barcode,data_status,import_key)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (medicine_id,item.name.strip(),item.batch,item.mfg.isoformat() if item.mfg else None,
                 item.exp.isoformat(),now,int(item.temp_sensitive),item.temp_min,item.temp_max,user["id"],item.guest_id,
                 item.generic_name,item.strength,item.form,item.category,item.quantity,item.unit,item.reorder_level,
                 item.supplier,item.storage_location,item.barcode,item.data_status,item.import_key))
            medicine_ids[item.guest_id] = medicine_id

        for reading in data.readings:
            medicine_id = medicine_ids.get(reading.medicine_guest_id)
            if medicine_id is None:
                raise HTTPException(status_code=422, detail="A temperature reading references a missing guest medicine")
            existing = db.execute("SELECT 1 FROM temperature_readings WHERE medicine_id=? AND guest_id=?",
                                  (medicine_id,reading.guest_id)).fetchone()
            if not existing:
                db.execute("""INSERT INTO temperature_readings
                    (id,medicine_id,temp_c,recorded_at,note,guest_id) VALUES(?,?,?,?,?,?)""",
                    ("t_"+uuid.uuid4().hex[:16],medicine_id,reading.temp_c,reading.recorded_at.isoformat(),reading.note,reading.guest_id))
        if data.thresholdDays is not None:
            db.execute("""INSERT INTO user_settings(user_id,key,value) VALUES(?, 'thresholdDays', ?)
                ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value""",
                (user["id"],str(data.thresholdDays)))
    return {"medicines":len(data.medicines),"readings":len(data.readings),"thresholdDays":data.thresholdDays}


class TemperatureInput(BaseModel):
    medicine_id: str
    temp_c: float = Field(ge=-100, le=100)
    note: str | None = Field(default=None, max_length=500)


@app.get("/api/temperature-readings")
def list_temperature_readings(user=Depends(require_user)):
    with get_db() as db:
        rows = db.execute("""SELECT r.*,m.name AS medicine_name,m.temp_min,m.temp_max
            FROM temperature_readings r JOIN medicines m ON m.id=r.medicine_id
            WHERE m.user_id=? ORDER BY r.recorded_at DESC LIMIT 100""", (user["id"],)).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/temperature-readings", status_code=201)
def create_temperature_reading(reading: TemperatureInput, user=Depends(require_user)):
    reading_id = "t_" + uuid.uuid4().hex[:16]
    recorded_at = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        medicine = db.execute("SELECT id FROM medicines WHERE id=? AND user_id=? AND temp_sensitive=1", (reading.medicine_id,user["id"])).fetchone()
        if not medicine:
            raise HTTPException(status_code=404, detail="Temperature-sensitive medicine not found")
        db.execute("INSERT INTO temperature_readings(id,medicine_id,temp_c,recorded_at,note) VALUES(?,?,?,?,?)",
                   (reading_id,reading.medicine_id,reading.temp_c,recorded_at,reading.note))
        row = db.execute("""SELECT r.*,m.name AS medicine_name,m.temp_min,m.temp_max
            FROM temperature_readings r JOIN medicines m ON m.id=r.medicine_id WHERE r.id=?""", (reading_id,)).fetchone()
    return dict(row)

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}
EXP_RE = re.compile(
    r"\b(?:EXP(?:IRY|IRES?)?\.?|USE\s*BY|BEST\s*BEFORE|BB|B\.?E\.?)\b", re.IGNORECASE
)
MFG_RE = re.compile(
    r"\b(?:MFG\.?|MFD\.?|MANUFACTURE[D]?|PKD|PACKED|MADE\s*ON)\b", re.IGNORECASE
)
BATCH_RE = re.compile(
    r"(?:B\.?\s?NO\.?|BATCH\s*NO\.?|BATCH|LOT\s*NO\.?|LOT)[:\-\.\s]*([A-Z0-9\-]{3,14})",
    re.IGNORECASE,
)
MONTH_NAME_RE = re.compile(
    r"\b(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|SEPT|OCT|NOV|DEC)[A-Z]*\.?\s*[-\/\s]?\s*(\d{2,4})\b",
    re.IGNORECASE,
)
MON_YEAR_NUM_RE = re.compile(r"\b(\d{1,2})\s*[\/\-\.]\s*(\d{2,4})\b")
FULL_DATE_RE = re.compile(r"\b(\d{1,2})\s*[\/\-\.]\s*(\d{1,2})\s*[\/\-\.]\s*(\d{2,4})\b")
ISO_DATE_RE = re.compile(r"\b(\d{4})\s*-\s*(\d{1,2})\s*-\s*(\d{1,2})\b")


def _normalize_ocr_date_digits(text: str) -> str:
    """Repair common OCR letter/digit confusions only inside date-shaped tokens."""
    date_token = re.compile(r"\b[0-9OoIl]{1,4}(?:\s*[/.\-]\s*[0-9OoIl]{1,4}){1,2}\b")
    month_year = re.compile(
        r"\b(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|SEPT|OCT|NOV|DEC)[A-Z]*\.?\s*[0-9OoIl]{2,4}\b",
        re.IGNORECASE,
    )
    translate = str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1"})
    text = date_token.sub(lambda match: match.group(0).translate(translate), text)
    return month_year.sub(lambda match: match.group(0).translate(translate), text)


def _full_year(y: int) -> int:
    if y < 100:
        return 2000 + y if y < 50 else 1900 + y
    return y


def _to_iso(d: date | None) -> str | None:
    if d is None:
        return None
    return d.isoformat()


def _find_dates(text: str):
    text = _normalize_ocr_date_digits(text)
    candidates = []

    for m in MONTH_NAME_RE.finditer(text):
        mon = MONTHS.get(m.group(1).lower())
        yr = _full_year(int(m.group(2)))
        if mon:
            last = calendar.monthrange(yr, mon)[1]
            candidates.append(
                {"index": m.start(), "date": date(yr, mon, last), "month_only": True}
            )

    for m in MON_YEAR_NUM_RE.finditer(text):
        # Ignore a month/year-looking substring inside a full DD/MM/YYYY date.
        if m.start() and text[m.start() - 1] in "/.-":
            continue
        if m.end() < len(text) and text[m.end()] in "/.-":
            continue
        mon, yr = int(m.group(1)), _full_year(int(m.group(2)))
        if 1 <= mon <= 12:
            last = calendar.monthrange(yr, mon)[1]
            candidates.append(
                {"index": m.start(), "end": m.end(), "date": date(yr, mon, last), "month_only": True}
            )

    for m in FULL_DATE_RE.finditer(text):
        a, b, yr = int(m.group(1)), int(m.group(2)), _full_year(int(m.group(3)))
        if a > 12 and b <= 12:
            day, month = a, b
        elif b > 12 and a <= 12:
            day, month = b, a
        else:
            day, month = a, b
        if 1 <= month <= 12 and 1 <= day <= 31:
            try:
                candidates.append(
                    {"index": m.start(), "date": date(yr, month, day), "month_only": False}
                )
            except ValueError:
                pass

    for m in ISO_DATE_RE.finditer(text):
        yr, mon, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if 1 <= mon <= 12 and 1 <= day <= 31:
            try:
                candidates.append(
                    {"index": m.start(), "date": date(yr, mon, day), "month_only": False}
                )
            except ValueError:
                pass

    # Associate a label only with the closest nearby date. A fixed wide context
    # incorrectly marks both manufacturing and expiry dates as EXP on compact
    # package lines (for example: "MFG 01/25 EXP 12/28").
    labels = [(m.start(), m.end(), "expiry") for m in EXP_RE.finditer(text)]
    labels.extend((m.start(), m.end(), "mfg") for m in MFG_RE.finditer(text))
    labels.sort(key=lambda label: label[0])
    date_spans = [(c["index"], c.get("end", c["index"])) for c in candidates]
    for c in candidates:
        start = max(0, c["index"] - 80)
        end = min(len(text), c.get("end", c["index"]) + 24)
        preceding = []
        following = []
        for label_start, label_end, label_type in labels:
            if label_end <= c["index"] and c["index"] - label_end <= 64:
                if not any(label_end <= ds < c["index"] for ds, _ in date_spans):
                    preceding.append((c["index"] - label_end, label_type))
            elif label_start >= c.get("end", c["index"]) and label_start - c.get("end", c["index"]) <= 16:
                if not any(c.get("end", c["index"]) <= ds < label_start for ds, _ in date_spans):
                    following.append((label_start - c.get("end", c["index"]), label_type))
        nearby = preceding or following
        c["label"] = min(nearby)[1] if nearby else None
        c["context"] = text[start:end].upper()

    candidates.sort(key=lambda c: c["index"])
    return candidates


def _extract_from_text(text: str):
    candidates = _find_dates(text)
    expiry = None
    mfg = None

    exp_labeled = [c for c in candidates if c["label"] == "expiry"]
    mfg_labeled = [c for c in candidates if c["label"] == "mfg"]

    if exp_labeled:
        expiry = max(exp_labeled, key=lambda c: c["date"])
    if mfg_labeled:
        mfg = min(mfg_labeled, key=lambda c: c["date"])

    if expiry is None:
        remaining = [c for c in candidates if c is not mfg]
        if len(remaining) == 1:
            expiry = remaining[0]
        elif len(remaining) >= 2:
            sorted_c = sorted(remaining, key=lambda c: c["date"])
            expiry = sorted_c[-1]
            if mfg is None:
                mfg = sorted_c[0]

    batch_match = BATCH_RE.search(text)
    batch = batch_match.group(1).upper() if batch_match else None

    name = _extract_name(text)

    return {
        "expiry": _to_iso(expiry["date"]) if expiry else None,
        "mfg": _to_iso(mfg["date"]) if mfg else None,
        "batch": batch,
        "name": name,
    }


def _extract_name(text: str) -> str | None:
    """Extract a plausible product name without swallowing dates or label text."""
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    form_re = re.compile(
        r"\b(TABLETS?|CAPSULES?|SYRUP|SUSPENSION|DROPS?|INJECTIONS?|OINTMENT|CREAM|GEL|POWDER|GRANULES?|SOLUTION|SPRAY|INHALER|PATCH|SUPPOSITORY|GUM)\b",
        re.IGNORECASE,
    )
    metadata_re = re.compile(
        r"\b(?:EXP(?:IRY|IRES?)?\.?|USE\s*BY|BEST\s*BEFORE|MFG\.?|MFD\.?|PKD|PACKED|BATCH|LOT|B\.?\s*NO\.?|M\.?R\.?P\.?|NET\s*(?:WT|CONTENT|WEIGHT)|STORE|KEEP|PROTECT|MANUFACTURED|MARKETED|DISTRIBUTED|PHARMACIST|COMPOSITION|DOSAGE|INDICATIONS?|WARNINGS?|CAUTION|SIDE\s*EFFECTS?|CONTRAINDICATIONS?|REG\.?\s*NO\.?)\b",
        re.IGNORECASE,
    )
    generic_only = {
        "medicine", "medicines", "tablet", "tablets", "capsule", "capsules",
        "pharma", "pharmaceutical", "batch", "expiry", "exp", "mfg", "mfd",
        "strip", "prescription", "schedule", "oral", "use", "for",
    }
    candidates = []
    for index, original in enumerate(lines):
        # OCR may join the product title and expiry/batch fields into one line.
        line = metadata_re.split(original, maxsplit=1)[0].strip(" :-.,;|")
        if not line:
            continue
        has_dose = bool(re.search(r"\b\d+(?:\.\d+)?\s*(?:mg|mcg|g|ml|iu|units?)\b", line, re.IGNORECASE))
        has_form = bool(form_re.search(line))
        line = re.sub(r"\b\d+(?:\.\d+)?\s*(?:mg|mcg|g|ml|iu|units?)\b", " ", line, flags=re.IGNORECASE)
        line = form_re.sub(" ", line)
        line = re.sub(r"\b(?:IP|BP|USP|I\.P\.?|B\.P\.?)\b", " ", line, flags=re.IGNORECASE)
        line = re.sub(r"\b\d+(?:[./-]\d+)*\b", " ", line)
        line = re.sub(r"[^\w+&'-]+", " ", line).strip(" +-_'&")
        words = [word for word in line.split() if word.casefold() not in generic_only]
        cleaned = " ".join(words)
        if len(cleaned) < 3 or not any(char.isalpha() for char in cleaned):
            continue
        if cleaned.casefold() in generic_only:
            continue
        # Prefer a concise, prominent title that contains dosage/form evidence;
        # down-rank later package copy and long manufacturer descriptions.
        score = (5 if has_dose else 0) + (4 if has_form else 0)
        score += min(sum(char.isalpha() for char in cleaned), 16) / 4
        score += max(0, 2 - index * 0.2)
        score -= max(0, len(words) - 3) * 0.8
        if len(cleaned) > 48:
            score -= 4
        candidates.append((score, index, cleaned))

    if not candidates:
        return None

    candidates.sort(key=lambda candidate: (-candidate[0], candidate[1]))
    return candidates[0][2]


# ── OCR endpoint ─────────────────────────────────────────────────────


class ScanResult(BaseModel):
    raw_text: str
    name: str | None = None
    expiry: str | None = None
    mfg: str | None = None
    batch: str | None = None


@app.post("/api/scan", response_model=ScanResult)
async def scan_image(file: UploadFile = File(...)):
    if _ocr_engine is None:
        raise HTTPException(
            status_code=500,
            detail=f"OCR is unavailable: {_ocr_error or 'engine not initialized'}",
        )

    content = await file.read()
    import numpy as np
    from PIL import Image as PILImage, ImageEnhance, ImageOps

    try:
        img = PILImage.open(io.BytesIO(content))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image file")

    # Respect phone-camera orientation and improve small, low-contrast stamped
    # dates before OCR. Keep the original aspect ratio and bound the working
    # size so a very large upload does not create an excessive inference load.
    img = ImageOps.exif_transpose(img).convert("RGB")
    longest_side = max(img.size)
    if longest_side > 2800:
        scale = 2800 / longest_side
        img = img.resize((round(img.width * scale), round(img.height * scale)), PILImage.Resampling.LANCZOS)
    elif longest_side < 1800:
        scale = min(2.0, 1800 / longest_side)
        img = img.resize((round(img.width * scale), round(img.height * scale)), PILImage.Resampling.LANCZOS)
    img = ImageOps.autocontrast(img, cutoff=0.5)
    img = ImageEnhance.Sharpness(img).enhance(1.2)

    img_array = np.array(img)
    result = _ocr_engine(img_array)
    raw_text = "\n".join(result.txts or []) if result else ""

    parsed = _extract_from_text(raw_text)

    return ScanResult(
        raw_text=raw_text.strip(),
        name=parsed["name"],
        expiry=parsed["expiry"],
        mfg=parsed["mfg"],
        batch=parsed["batch"],
    )


from fastapi.staticfiles import StaticFiles
app.mount("/app", StaticFiles(directory=Path(__file__).parent.parent / "frontend", html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
