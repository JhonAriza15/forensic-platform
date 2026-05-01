"""
Script para crear un usuario administrador por defecto.
Ejecutar después de create_tables.py:
    python seed_user.py
O dentro del contenedor:
    docker exec forensic_backend python seed_user.py
"""
import time
import sys
from sqlalchemy import text
from app.database import engine, SessionLocal, Base
from app.models.user import User
from app.auth import get_password_hash

# ── Credenciales por defecto (cámbialas después de iniciar sesión) ──────────
DEFAULT_EMAIL    = "admin@forensic.local"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "Admin1234!"
# ────────────────────────────────────────────────────────────────────────────


def wait_for_db(max_retries: int = 15, delay: int = 3):
    print("Esperando conexión a la base de datos...")
    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("Conexión exitosa.")
            return
        except Exception as e:
            print(f"  Intento {attempt}/{max_retries}: {e}")
            if attempt < max_retries:
                time.sleep(delay)
    print("ERROR: No se pudo conectar a la base de datos.")
    sys.exit(1)


def seed():
    wait_for_db()
    db = SessionLocal()
    try:
        existing_email = db.query(User).filter(User.email == DEFAULT_EMAIL).first()
        existing_username = db.query(User).filter(User.username == DEFAULT_USERNAME).first()
        if existing_email or existing_username:
            user = existing_email or existing_username
            print(f"Ya existe un usuario con ese email o username (id={user.id}, email={user.email}, username={user.username}).")
            print("No se creó duplicado. Usa esas credenciales para iniciar sesión.")
            return

        user = User(
            email=DEFAULT_EMAIL,
            username=DEFAULT_USERNAME,
            hashed_password=get_password_hash(DEFAULT_PASSWORD),
            is_active=True,
            is_admin=True,
        )
        db.add(user)
        db.commit()
        print("Usuario administrador creado exitosamente:")
        print(f"  Email   : {DEFAULT_EMAIL}")
        print(f"  Username: {DEFAULT_USERNAME}")
        print(f"  Password: {DEFAULT_PASSWORD}")
        print("⚠  Cambia la contraseña después de iniciar sesión.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
