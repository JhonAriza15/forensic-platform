#!/usr/bin/env bash
set -euo pipefail

# Automatiza build y push de imágenes a Docker Hub
# Uso:
#   DOCKERHUB_USERNAME=dante2001 DOCKERHUB_TOKEN=... ./scripts/publish.sh

USERNAME="${DOCKERHUB_USERNAME:-dante2001}"
TOKEN="${DOCKERHUB_TOKEN:-}"

if [ -z "$TOKEN" ]; then
  echo "ERROR: define la variable de entorno DOCKERHUB_TOKEN con tu token (no lo guardes en archivos)."
  echo "Ejemplo: DOCKERHUB_TOKEN=... DOCKERHUB_USERNAME=dante2001 ./scripts/publish.sh"
  exit 1
fi

echo "Iniciando sesión en Docker Hub como $USERNAME..."
echo "$TOKEN" | docker login -u "$USERNAME" --password-stdin

echo "Construyendo y subiendo: $USERNAME/forensic-backend:latest"
docker build -t "$USERNAME/forensic-backend:latest" .
docker push "$USERNAME/forensic-backend:latest"

echo "Construyendo y subiendo: $USERNAME/forensic-vuln-scanner:latest"
docker build -t "$USERNAME/forensic-vuln-scanner:latest" -f scanner/Dockerfile scanner
docker push "$USERNAME/forensic-vuln-scanner:latest"

echo "Etiquetando y subiendo worker: $USERNAME/forensic-worker:latest"
# Por simplicidad reutilizamos la imagen del backend como worker; si quieres una imagen distinta, cambia el Dockerfile o construye otra imagen.
docker tag "$USERNAME/forensic-backend:latest" "$USERNAME/forensic-worker:latest"
docker push "$USERNAME/forensic-worker:latest"

echo "Todas las imágenes subidas correctamente."
