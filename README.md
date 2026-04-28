## ForensiLog
## Plataforma de Análisis Forense de Logs Manual de Instalación y Uso


## 1. Descripción del Proyecto
ForensiLog es una plataforma web de análisis forense de logs y detección de amenazas en tiempo real. Permite a equipos de ciberseguridad subir archivos de log de sistemas, analizarlos automáticamente y detectar actividades sospechosas como ataques de fuerza bruta, escalamiento de privilegios, malware y más.


## Funcionalidades Principales

•	Subida y análisis automático de archivos de log

•	Detección de 8 tipos de amenazas de seguridad

•	Integración con AbuseIPDB para validación de IPs maliciosas

•	Score de riesgo automático del 0 al 100%

•	Escaneo de URLs para detectar vulnerabilidades web

•	Generación de informes ejecutivos en PDF con referencias CWE

•	Línea de tiempo de eventos sospechosos

•	Pipeline CI/CD con herramientas DevSecOps

## Stack Tecnológico

## Stack Tecnológico

| Componente       | Tecnología       | Puerto       |
| ---------------- | ---------------- | ------------ |
| Backend API      | FastAPI (Python) | 8000         |
| Base de Datos    | PostgreSQL 15    | 5433         |
| Cola de Mensajes | RabbitMQ         | 5672 / 15672 |
| Orquestación     | Docker Compose   | —            |

## 2. Requisitos del Sistema

⚠️ NO instalar Python ni PostgreSQL directamente en Windows. Todo corre dentro de Docker.

## ⚙️ Requisitos del Sistema

| Requisito           | Versión Mínima          | Notas                           |
| ------------------- | ----------------------- | ------------------------------- |
| Sistema Operativo   | Windows 10/11 (64 bits) | macOS o Linux también funcionan |
| Espacio en disco    | 10 GB libres            | Para imágenes Docker            |
| Git                 | 2.x o superior          | Para clonar el repositorio      |
| Docker Desktop      | 4.x o superior          | Incluye Docker Compose          |
| Node.js             | 20 LTS                  | Para el frontend React          |
| Conexión a Internet | Requerida               | Para descargar imágenes Docker  |

## 3. Instalación Paso a Paso

ℹ️ Seguir los pasos en el orden exacto indicado. No saltar ninguno.

## 1️. Instalar Git
Git es necesario para descargar el proyecto desde GitHub.

Ir a: https://git-scm.com/download/win
Verificar instalación:
git --version

✅ Resultado esperado: git version 2.x.x

## 2️. Instalar Docker Desktop

Docker ejecuta todos los servicios del proyecto.

Ir a: https://www.docker.com/products/docker-desktop/
Descargar Docker Desktop
Instalar con opciones por defecto
Abrir Docker Desktop

⚠️ Docker debe estar activo antes de ejecutar el proyecto

## 3️. Instalar Node.js

Necesario para el frontend.

Ir a: https://nodejs.org
Descargar versión LTS
Instalar con opciones por defecto
Verificar:
node --version
npm --version


## 4️. Clonar el Repositorio

cd C:\Users\TuUsuario\Documents
git clone https://github.com/JhonAriza15/forensic-platform.git

cd forensic-platform

ℹ️ Se crea la carpeta del proyecto con todo el código

## 5️. Configurar variables de entorno (.env)
Crear archivo .env en la raíz del proyecto:

DATABASE_URL=postgresql://postgres:postgres@db:5432/forensic_db

RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/


## 10. Publicar imágenes en Docker Hub (repositorios actuales)

En tu cuenta de Docker Hub ya tienes los repositorios con estos nombres: `forensic_backend`, `forensic_vuln_scanner`, `forensic_worker`.

A continuación tienes instrucciones claras y listas para PowerShell para construir y subir las imágenes exactamente a esos repositorios.

1) Crear repositorios (sólo si aún no existen)
- Entra en https://hub.docker.com → Repositories → Create repository y crea (si hace falta):
   - `dante2001/forensic_backend` (public)
   - `dante2001/forensic_vuln_scanner` (public)
   - `dante2001/forensic_worker` (public)

2) Login en Docker Hub desde PowerShell

Forma simple (interactiva):
```powershell
docker login -u dante2001
# cuando te pida la contraseña, pega tu token personal de Docker Hub
```

Forma segura (evita dejar el token en el historial):
```powershell
$token = Read-Host -Prompt "Introduce el token de Docker Hub" -AsSecureString
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)) | docker login --username dante2001 --password-stdin
```

3) Construir y subir las imágenes (PowerShell)

Ejecuta estos comandos desde la raíz del repositorio:
```powershell
# Backend (carpeta raíz)
docker build -t dante2001/forensic_backend:latest .
docker push dante2001/forensic_backend:latest

# Vulnerability scanner (Dockerfile en scanner/)
docker build -t dante2001/forensic_vuln_scanner:latest -f scanner/Dockerfile scanner
docker push dante2001/forensic_vuln_scanner:latest

# Worker (si quieres una imagen separada; aquí reutilizamos backend como ejemplo)
docker tag dante2001/forensic_backend:latest dante2001/forensic_worker:latest
docker push dante2001/forensic_worker:latest
```

4) Verificar en Docker Hub
- Tras cada `docker push`, refresca la página del repositorio en Docker Hub y mira la pestaña *Image Management* para ver el tag y el digest.

5) Errores comunes y soluciones rápidas
- `unauthorized: authentication required` o `denied`: revisa que estás logueado y que el repo existe bajo `dante2001`.
- `requested access to the resource is denied`: el nombre del repo no coincide (usa `dante2001/<repo>`).
- Errores en `docker build`: mira la salida del build para identificar la capa que falla (revisa dependencias y rutas de archivos).

Automatización con GitHub Actions
- Si prefieres automatizar, usa el workflow `.github/workflows/docker-publish.yml` y añade en GitHub Settings → Secrets los valores `DOCKERHUB_USERNAME` (`dante2001`) y `DOCKERHUB_TOKEN` (tu token). El workflow construirá y publicará cuando hagas push a `main`.

¿Quieres que cree también un script PowerShell `scripts/publish.ps1` que haga todo esto con un solo comando en PowerShell? 
ABUSEIPDB_API_KEY=eb0b7dda3b23e92a988f2fca87946db036e6055e858c4e9f0b231c94785f19347f1e9e7b8cd76abf 

ℹ️ Obtener API Key en: https://www.abuseipdb.com

## 6️. Levantar servicios con Docker
docker-compose up --build

⏳ Puede tardar 5–10 minutos la primera vez

✅ Resultado esperado:

Application startup complete
Worker esperando mensajes
⚠️ No cerrar esta terminal

## 7️. Crear tablas en la base de datos

Abrir una nueva terminal:
docker exec forensic_backend python create_tables.py
✅ Resultado esperado:

Tablas creadas exitosamente:
- users
- log_files
- log_events
- findings
  
## 8️. Ejecutar el Frontend
cd frontend
npm install
npm run dev

✅ Resultado esperado:

Local: http://localhost:5173
🌐 Acceso

Abrir en el navegador:

👉 http://localhost:5173

📌 Nota importante

Debes tener abiertas:

Terminal 1 → docker-compose up

Terminal 2 → base de datos (ya ejecutado)

Terminal 3 → npm run dev

---

## 🧑‍💻 Cómo Usar la Plataforma

---

1. Ir a: http://localhost:5173
2. Hacer clic en **"Regístrate"**
   * Email
   * Nombre de usuario
   * Contraseña
     
4. Iniciar sesión con las credenciales creadas

> ⚠️ Los tokens JWT expiran cada 15 minutos. Si la sesión se cierra, vuelve a iniciar sesión.

---

### 📂 Subir un Archivo de Log

1. En el Dashboard, seleccionar el tab **"Subir Log"**
2. Hacer clic en **"Seleccionar archivo"**
3. Subir archivo (.log, .txt, .csv, .json — máximo 10MB)
4. El archivo aparecerá con estado:

   * `pending` → `processing` → `done`
5. Visualizar eventos y hallazgos detectados

ℹ️ Formatos soportados:
`syslog`, `auth.log`, `Apache`, `Nginx`, `Windows Event`, genérico

---

### 🌐 Escanear una URL

1. Ir al tab **"Escanear URL"**
2. Ingresar la URL (ej: https://google.com)
3. Hacer clic en **"Escanear"** o presionar Enter
4. Ver resultados:

   * Headers de seguridad
   * Estado HTTPS
   * Hallazgos detectados

---

### 🔎 Ver Hallazgos

1. En la tabla de logs, hacer clic en el número de hallazgos
2. Se abrirá un modal con el detalle
3. Cada hallazgo incluye:

   * Título
   * Severidad
   * Descripción
   * Categoría
   * Nivel de confianza
   * Recomendación

Opciones adicionales:

* Ver **Timeline** de eventos
* Acceder a sección **"Hallazgos"** desde el menú lateral

---

### 📄 Generar Informe PDF

1. En la tabla de logs, hacer clic en **"Informe"**
2. Se descargará automáticamente el PDF

El informe incluye:

* Resumen ejecutivo
* Distribución de hallazgos
* Tabla detallada
* Referencias CWE
* Recomendaciones de seguridad





