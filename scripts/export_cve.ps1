# ForensiLog - Exportar tabla CVE a archivo SQL
# Uso: .\scripts\export_cve.ps1

$ErrorActionPreference = "Stop"
$DumpFile = "cve_data_dump.sql"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ForensiLog - Exportar CVEs locales" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar contenedor
Write-Host "[1/3] Verificando contenedor forensic_db..." -ForegroundColor Yellow
$running = docker ps --filter "name=forensic_db" --filter "status=running" -q
if (-not $running) {
    Write-Host "ERROR: forensic_db no esta corriendo." -ForegroundColor Red
    Write-Host "       Ejecuta: docker compose up -d" -ForegroundColor Red
    exit 1
}
Write-Host "      OK - forensic_db corriendo" -ForegroundColor Green

# 2. Verificar que hay datos
Write-Host ""
Write-Host "[2/3] Contando CVEs en la base de datos..." -ForegroundColor Yellow
$count = docker exec forensic_db psql -U postgres -d forensic_db -t -c "SELECT COUNT(*) FROM cve_data;"
$count = $count.Trim()

if ($count -eq "0" -or $count -eq "") {
    Write-Host "ERROR: La tabla cve_data esta vacia." -ForegroundColor Red
    Write-Host "       Primero carga los CVEs:" -ForegroundColor Red
    Write-Host "       docker exec forensic_backend python scripts/load_cve_feeds.py --mode all" -ForegroundColor Yellow
    exit 1
}
Write-Host "      OK - $count CVEs encontrados" -ForegroundColor Green

# 3. Exportar
Write-Host ""
Write-Host "[3/3] Exportando a $DumpFile ..." -ForegroundColor Yellow
Write-Host "      (puede tardar 10-30 segundos...)" -ForegroundColor Gray

docker exec forensic_db pg_dump -U postgres -d forensic_db --table=cve_data --data-only --no-owner --no-acl -f /tmp/cve_data_dump.sql
docker cp forensic_db:/tmp/cve_data_dump.sql ./$DumpFile

$sizeMB = [math]::Round((Get-Item $DumpFile).Length / 1MB, 1)

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  EXPORTACION COMPLETADA" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Archivo : $DumpFile" -ForegroundColor White
Write-Host "  Tamanio : $sizeMB MB" -ForegroundColor White
Write-Host "  CVEs    : $count" -ForegroundColor White
Write-Host ""
Write-Host "  En la maquina de entrega:" -ForegroundColor Cyan
Write-Host "  1. Copia cve_data_dump.sql al proyecto" -ForegroundColor White
Write-Host '  2. Ejecuta: .\scripts\import_cve.ps1' -ForegroundColor White
Write-Host ""
