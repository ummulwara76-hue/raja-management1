import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from .config import APP_NAME, CORS_ORIGINS, CORS_ORIGIN_REGEX, ENABLE_API_DOCS, ENVIRONMENT, JWT_SECRET, UPLOAD_DIR
from .auth import (
    verify_login, create_access_token, require_user, check_rate_limit, register_fail,
    clear_fails, client_ip, current_password_hash, STATE,
)
from .database import db, db_is_up, EMBEDDED, save_embedded
from .models import LoginRequest
from .routes import notes, modules, documents, search, security
from . import notifier

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("raja")

_ready = False


async def ensure_ready():
    """DB tayyar ho to indexes, default categories aur admin user bana deta hai."""
    global _ready
    if _ready:
        return
    if not await db_is_up():
        raise ConnectionError("MongoDB ping fail")
    await modules.seed_categories()
    await db.categories.create_index([("type", 1), ("name_key", 1)], unique=True)
    # Purana key_1 index (jo null key par bhi duplicate error deta tha) hata kar sahi index banana
    try:
        await db.notifications.drop_index("key_1")
    except Exception:
        pass
    try:
        await db.notifications.create_index(
            "key", unique=True, partialFilterExpression={"key": {"$type": "string"}})
    except Exception:
        await db.notifications.create_index("key", unique=True, sparse=True)
    await db.push_subscriptions.create_index("endpoint", unique=True)
    await db.share_links.create_index("token", unique=True)
    from .config import ADMIN_USERNAME
    # Password sirf pehli dafa .env se aata hai; baad mein "Password Badlein" se DB mein badalta hai.
    await db.users.update_one(
        {"username": ADMIN_USERNAME.lower()},
        {"$set": {"username": ADMIN_USERNAME.lower(), "role": "admin"},
         "$setOnInsert": {"password_hash": current_password_hash(), "pw_version": 1}},
        upsert=True,
    )
    user = await db.users.find_one({"username": ADMIN_USERNAME.lower()})
    STATE["pv"] = int(user.get("pw_version", 1))
    # Purane notes (jin mein fire_at nahi) ko naye system se jodna
    async for n in db.notes.find({"fire_at": {"$exists": False}}):
        if n.get("date") and n.get("time"):
            fa = f"{n['date']}T{n['time']}"
            await db.notes.update_one(
                {"_id": n["_id"]},
                {"$set": {"fire_at": fa, "notified": True, "completed": n.get("completed", False),
                          "priority": n.get("priority", "Normal")}},
            )
    _ready = True
    log.info("Database tayyar hai.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    if JWT_SECRET.startswith("change-this"):
        log.warning("JWT_SECRET default hai — .env mein lamba random secret rakhein!")
    try:
        await ensure_ready()
    except Exception as e:
        log.error("MongoDB se rabta nahi hua (%s). MongoDB start karein; backend dobara koshish karta rahega.", e)
    task = asyncio.create_task(notifier.scheduler_loop(ensure_ready))
    yield
    task.cancel()
    if EMBEDDED:
        save_embedded()


app = FastAPI(
    title=APP_NAME,
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if ENABLE_API_DOCS else None,
    redoc_url="/redoc" if ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_API_DOCS else None,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' http://localhost:5173 http://127.0.0.1:5173 ws: wss:; frame-ancestors 'none'; object-src 'none'",
    )
    if "x-powered-by" in response.headers:
        del response.headers["x-powered-by"]
    return response


# ---- Error handling: har error JSON mein aur CORS headers ke sath wapas jata hai ----
# (Pehle MongoDB band hone par 500 error bina CORS header ke aata tha, aur browser
#  usay "Failed to fetch" dikhata tha.)
@app.middleware("http")
async def catch_errors(request: Request, call_next):
    try:
        response = await call_next(request)
        if EMBEDDED and request.method in ("POST", "PUT", "DELETE", "PATCH") and response.status_code < 400:
            await asyncio.to_thread(save_embedded)  # data foran file mein mehfooz
        return response
    except (ServerSelectionTimeoutError, ConnectionError):
        return JSONResponse(
            status_code=503,
            content={"detail": "Database (MongoDB) chal nahi raha. MongoDB start karke dobara koshish karein."},
        )
    except PyMongoError:
        log.exception("Database error")
        return JSONResponse(status_code=500, content={"detail": "Data save nahi ho saka. Dobara koshish karein."})
    except Exception:
        log.exception("Unhandled error")
        return JSONResponse(status_code=500, content={"detail": "Server mein masla aa gaya. Dobara koshish karein."})


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    fields = []
    for e in exc.errors():
        loc = [str(x) for x in e.get("loc", []) if x not in ("body", "query", "form")]
        fields.append(loc[-1] if loc else "field")
    return JSONResponse(
        status_code=422,
        content={"detail": "Ye field zaroor sahi bharain: " + ", ".join(dict.fromkeys(fields)) + "."},
    )


# CORS sab se bahar rakhna zaroori hai (isliye sab se aakhir mein add hota hai)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api")
def root():
    return {"message": "Raja Management Backend Running"}


@app.get("/api/health")
async def health():
    up = await db_is_up()
    return {"status": "ok" if up else "degraded", "app": APP_NAME, "database": "connected" if up else "disconnected"}


@app.post("/api/auth/login", tags=["Auth"])
async def login(data: LoginRequest, request: Request):
    from fastapi import HTTPException
    from .config import ADMIN_USERNAME
    ip = client_ip(request)
    check_rate_limit(ip)
    doc = await db.users.find_one({"username": ADMIN_USERNAME.lower()})
    stored = doc.get("password_hash") if doc else None
    if STATE["pv"] is None and doc:
        STATE["pv"] = int(doc.get("pw_version", 1))
    if not verify_login(data.username, data.password, stored):
        register_fail(ip)
        raise HTTPException(status_code=401, detail="Password ghalat hai. Dobara koshish karein.")
    clear_fails(ip)
    return {"access_token": create_access_token(ADMIN_USERNAME, data.remember), "token_type": "bearer", "username": ADMIN_USERNAME}


@app.get("/api/auth/me", tags=["Auth"])
def get_current_user(username: str = Depends(require_user)):
    return {"username": username, "message": "User authenticated successfully."}


app.include_router(security.router)
app.include_router(notes.router)
app.include_router(modules.reminders)
app.include_router(modules.categories)
app.include_router(modules.costing)
app.include_router(modules.receivables)
app.include_router(modules.payables)
app.include_router(modules.ideas)
app.include_router(modules.calcs)
app.include_router(modules.emergency)
app.include_router(documents.router)
app.include_router(documents.wa_router)
app.include_router(documents.public_router)
app.include_router(notifier.router)
app.include_router(search.router)


# ---- Built frontend ko isi server se serve karna (phone/tunnel ke liye sirf ek port) ----
from fastapi.responses import FileResponse
from .config import FRONTEND_DIST

if (FRONTEND_DIST / "index.html").exists():
    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        from fastapi import HTTPException
        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(status_code=404, detail="Record nahi mila.")
        target = (FRONTEND_DIST / full_path).resolve()
        if full_path and FRONTEND_DIST.resolve() in target.parents and target.is_file():
            headers = {"Cache-Control": "no-cache"} if full_path in ("sw.js", "manifest.webmanifest") else {}
            return FileResponse(target, headers=headers)
        return FileResponse(FRONTEND_DIST / "index.html", headers={"Cache-Control": "no-cache"})
else:
    @app.get("/", include_in_schema=False)
    def home():
        return {"message": "Raja Management Backend Running (frontend build nahi mili)"}
