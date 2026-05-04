# ============================================================
# ForensiLog - Importar tabla CVE desde archivo SQL
# ============================================================
# Uso: .\scripts\import_cve.ps1
# ============================================================

$ErrorActionPreference = "Continue"
$DumpFile = "cve_data_dump.sql"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ForensiLog - Importar CVEs locales" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar que existe el archivo dump
Write-Host "[1/5] Buscando archivo $DumpFile ..." -ForegroundColor Yellow
if (-not (Test-Path $DumpFile)) {
    Write-Host "ERROR: No se encontro el archivo $DumpFile" -ForegroundColor Red
    Write-Host "       Asegurate de copiarlo en la misma carpeta del proyecto." -ForegroundColor Red
    exit 1
}
$sizeMB = [math]::Round((Get-Item $DumpFile).Length / 1MB, 1)
Write-Host "      OK - $DumpFile encontrado ($sizeMB MB)" -ForegroundColor Green

# 2. Verificar que el contenedor de BD este corriendo
Write-Host ""
Write-Host "[2/5] Verificando contenedor forensic_db..." -ForegroundColor Yellow
$running = docker ps --filter "name=forensic_db" --filter "status=running" -q
if (-not $running) {
    Write-Host "ERROR: El contenedor forensic_db no esta corriendo." -ForegroundColor Red
    Write-Host "       Ejecuta primero: docker compose up -d" -ForegroundColor Yellow
    exit 1
}
Write-Host "      OK - forensic_db corriendo" -ForegroundColor Green

# 3. Crear tabla cve_data si no existe
Write-Host ""
Write-Host "[3/5] Creando tabla cve_data si no existe..." -ForegroundColor Yellow

$createTable = @"
CREATE TABLE IF NOT EXISTS cve_data (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) UNIQUE NOT NULL,
    summary TEXT,
    cvss_score FLOAT,
    cvss_vector VARCHAR(200),
    severity VARCHAR(20),
    published_date VARCHAR(30),
    refs TEXT,
    loaded_at TIMESTAMP DEFAULT NOW()
);
"@

$createIdx1 = "CREATE INDEX IF NOT EXISTS ix_cve_data_cve_id ON cve_data(cve_id);"
$createIdx2 = "CREATE INDEX IF NOT EXISTS ix_cve_severity ON cve_data(severity);"

docker exec forensic_db psql -U postgres -d forensic_db -c $createTable 2>$null | Out-Null
docker exec forensic_db psql -U postgres -d forensic_db -c $createIdx1  2>$null | Out-Null
docker exec forensic_db psql -U postgres -d forensic_db -c $createIdx2  2>$null | Out-Null

Write-Host "      OK - tabla lista" -ForegroundColor Green

# 4. Verificar si ya hay datos
Write-Host ""
Write-Host "[4/5] Verificando datos existentes..." -ForegroundColor Yellow
$existing = docker exec forensic_db psql -U postgres -d forensic_db -t -c "SELECT COUNT(*) FROM cve_data;" 2>$null
$existing = $existing.Trim()

if ($existing -ne "0" -and $existing -ne "") {
    Write-Host "  La tabla ya tiene $existing CVEs." -ForegroundColor Yellow
    $resp = Read-Host "  Deseas reemplazar los datos existentes? (s/n)"
    if ($resp -ne "s" -and $resp -ne "S") {
        Write-Host "  Importacion cancelada. Los datos actuales se conservan." -ForegroundColor Cyan
        exit 0
    }
    Write-Host "  Limpiando datos anteriores..." -ForegroundColor Gray
    docker exec forensic_db psql -U postgres -d forensic_db -c "TRUNCATE TABLE cve_data RESTART IDENTITY;" 2>$null | Out-Null
    Write-Host "  OK - tabla limpia" -ForegroundColor Green
} else {
    Write-Host "      OK - tabla vacia, listo para importar" -ForegroundColor Green
}

# 5. Copiar archivo al contenedor e importar
Write-Host ""
Write-Host "[5/5] Importando $sizeMB MB de CVEs..." -ForegroundColor Yellow
Write-Host "      (puede tardar 30-60 segundos...)" -ForegroundColor Gray

docker cp $DumpFile forensic_db:/tmp/cve_data_dump.sql
docker exec forensic_db psql -U postgres -d forensic_db -f /tmp/cve_data_dump.sql -q
docker exec forensic_db rm /tmp/cve_data_dump.sql 2>$null

# Verificar resultado
$finalCount = docker exec forensic_db psql -U postgres -d forensic_db -t -c "SELECT COUNT(*) FROM cve_data;" 2>$null
$finalCount = $finalCount.Trim()

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  IMPORTACION COMPLETADA" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  CVEs importados : $finalCount" -ForegroundColor White
Write-Host "  Velocidad busqueda: menos de 1 ms (local)" -ForegroundColor Cyan
Write-Host ""
