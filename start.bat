@echo off
echo Deteniendo RabbitMQ de Windows...
net stop RabbitMQ 2>nul

echo Iniciando contenedores Docker...
cd "C:\Users\Jhon Ariza\Videos\Proyecto\files"
docker-compose up -d

echo Esperando que los servicios inicien...
timeout /t 15 /nobreak

echo Creando tablas...
docker exec forensic_backend python create_tables.py

echo Iniciando frontend...
start cmd /k "cd C:\Users\Jhon Ariza\Videos\Proyecto\files\frontend && npm run dev"

echo.
echo Listo! Abre http://localhost:5173
pause