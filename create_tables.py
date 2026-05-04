"""
Script para crear todas las tablas en la base de datos.
Ejecutar una sola vez al iniciar el proyecto:
    python create_tables.py
"""
import time
import sys
from sqlalchemy import text
from app.database import engine, Base

# Importar todos los modelos para que Base los registre
from app.models import User, LogFile, LogEvent, Finding, Scan, ScanVulnerability, CveData


def wait_for_db(max_retries: int = 15, delay: int = 3):
    """Espera a que PostgreSQL esté disponible antes de crear tablas."""
    print("Esperando conexión a la base de datos...")
    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("Conexión exitosa a la base de datos.")
            return
        except Exception as e:
            print(f"  Intento {attempt}/{max_retries} fallido: {e}")
            if attempt < max_retries:
                time.sleep(delay)
    print("ERROR: No se pudo conectar a la base de datos tras varios intentos.")
    sys.exit(1)


def create_all():
    wait_for_db()
    print("Creando tablas en la base de datos...")
    Base.metadata.create_all(bind=engine)
    print("Tablas creadas exitosamente:")
    for table in Base.metadata.tables.keys():
        print(f"  - {table}")


if __name__ == "__main__":
    create_all()
