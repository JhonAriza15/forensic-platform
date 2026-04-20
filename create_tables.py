"""
Script para crear todas las tablas en la base de datos.
Ejecutar una sola vez al iniciar el proyecto:
    python create_tables.py
"""
from app.database import engine, Base

# Importar todos los modelos para que Base los registre
from app.models import User, LogFile, LogEvent, Finding, Scan, ScanVulnerability


def create_all():
    print("Creando tablas en la base de datos...")
    Base.metadata.create_all(bind=engine)
    print("Tablas creadas exitosamente:")
    for table in Base.metadata.tables.keys():
        print(f"  - {table}")


if __name__ == "__main__":
    create_all()
