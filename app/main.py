from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.routers import auth, logs, scanner, cve_intel
from app.database import engine, Base
# Importar modelos para que Base los registre antes de create_all
from app.models import User, LogFile, LogEvent, Finding, Scan, ScanVulnerability  # noqa: F401
import os

limiter = Limiter(key_func=get_remote_address)

# Configurar orígenes CORS (sobreescribir con variable de entorno ALLOW_ORIGINS)
allow_origins_env = os.getenv("ALLOW_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
allow_origins = [o.strip() for o in allow_origins_env.split(",") if o.strip()]


def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handler 429 que incluye cabeceras CORS para no bloquear al frontend."""
    origin = request.headers.get("origin", "")
    response = JSONResponse(
        status_code=429,
        content={"detail": "Demasiadas solicitudes. Espera unos segundos e inténtalo de nuevo."}
    )
    if origin in allow_origins or "*" in allow_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


app = FastAPI(
    title="Forensic Log Analysis Platform",
    description="API para análisis forense de logs",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


app.include_router(auth.router)
app.include_router(logs.router)
app.include_router(scanner.router)
app.include_router(cve_intel.router)


@app.on_event("startup")
async def startup_event():
    """Crea todas las tablas automáticamente al arrancar el backend."""
    import time
    from sqlalchemy import text
    max_retries = 15
    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            Base.metadata.create_all(bind=engine)
            print("✅ Tablas creadas/verificadas correctamente.")
            break
        except Exception as e:
            print(f"⏳ BD no lista (intento {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(3)
            else:
                print("❌ No se pudo conectar a la BD al arrancar.")


@app.get("/")
def root():
    return {"message": "Forensic Platform API corriendo"}