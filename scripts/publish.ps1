Param(
    [string]$Username = "dante2001"
)

Set-StrictMode -Version Latest
try {
    Write-Host "Publicando imágenes a Docker Hub como $Username" -ForegroundColor Cyan

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Docker no está instalado o no está en el PATH. Aborta."
        exit 1
    }

    # Solicitar token de forma segura
    $secureToken = Read-Host -Prompt "Introduce tu token de Docker Hub (secreto)" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) | Out-Null

    # Login
    $loginProcess = "docker login --username $Username --password-stdin"
    $plainToken | docker login --username $Username --password-stdin
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Login fallido. Revisa el token o intenta 'docker login -u $Username' manualmente."
        exit 1
    }

    # Directorio actual debe ser la raíz del repo
    $root = Get-Location
    Write-Host "Directorio actual: $root"

    # Build & push backend
    Write-Host "Construyendo backend..." -ForegroundColor Green
    docker build -t $Username/forensic_backend:latest .
    if ($LASTEXITCODE -ne 0) { throw "Build backend falló." }
    docker push $Username/forensic_backend:latest
    if ($LASTEXITCODE -ne 0) { throw "Push backend falló." }

    # Build & push vuln scanner
    Write-Host "Construyendo vuln scanner..." -ForegroundColor Green
    docker build -t $Username/forensic_vuln_scanner:latest -f scanner/Dockerfile scanner
    if ($LASTEXITCODE -ne 0) { throw "Build vuln scanner falló." }
    docker push $Username/forensic_vuln_scanner:latest
    if ($LASTEXITCODE -ne 0) { throw "Push vuln scanner falló." }

    # Tag & push worker (reutiliza backend)
    Write-Host "Etiquetando y subiendo worker..." -ForegroundColor Green
    docker tag $Username/forensic_backend:latest $Username/forensic_worker:latest
    docker push $Username/forensic_worker:latest
    if ($LASTEXITCODE -ne 0) { throw "Push worker falló." }

    Write-Host "Todas las imágenes subidas correctamente." -ForegroundColor Cyan
}
catch {
    Write-Error "Error: $_"
    exit 1
}