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

## 🔰 Guía rápida para principiantes (paso a paso, muy sencillo)

Si no eres técnico, sigue estos pasos exactamente. Usa PowerShell en Windows.

1) Preparar el entorno (solo la primera vez)

```powershell
# Abre PowerShell como Administrador
# Ve a la carpeta del proyecto (ajusta tu usuario si hace falta)
cd "C:\Users\ADMIN\Downloads\forensic-platform-main\forensic-platform-main"
```

2) Si quieres subir imágenes a Docker Hub (opcional)

- Crea una cuenta en https://hub.docker.com (si no tienes una).
- En Docker Hub crea un repositorio (por ejemplo: `tu_usuario/forensic_backend`).
- Genera un token desde Docker Hub (Settings → Security → New Access Token).

En PowerShell, con el token en la variable `DOCKER_TOKEN` (te pedirá el token):

```powershell
# Login seguro (te pedirá token)
$token = Read-Host -Prompt "Introduce tu token de Docker Hub" -AsSecureString
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)) | docker login --username <TU_USUARIO> --password-stdin

# Construir la imagen del backend desde el código local
docker build -t <TU_USUARIO>/forensic_backend:latest .

# Subir la imagen (opcional)
docker push <TU_USUARIO>/forensic_backend:latest
```

Si no quieres subir imágenes, puedes saltarte la parte del token y ejecutar directamente Docker Compose (sigue abajo).

3) Levantar todos los servicios con Docker (recomendado)

```powershell
# Desde la carpeta raíz del proyecto
docker-compose down --remove-orphans
docker-compose up --build -d

# Verifica que los contenedores estén arriba
docker-compose ps
```

Espera unos 30 segundos a que `db` y `rabbitmq` muestren `healthy`. Si no estás seguro, espera 1 minuto.

4) Crear tablas en la base de datos (si el sistema no lo hizo automáticamente)

```powershell
docker exec forensic_backend python create_tables.py
```

5) Crear un usuario administrador (si no existe)

```powershell
docker exec forensic_backend python seed_user.py
# Si el usuario ya existe, el script no lo duplicará y te mostrará el email/usuario existente.
```

Credenciales por defecto (si creas el usuario con `seed_user.py`):

- Email: `admin@forensic.local`
- Contraseña: `Admin1234!`

6) Iniciar el frontend (en otra terminal)

```powershell
cd frontend
npm install
npm run dev
# Abre tu navegador en http://localhost:5173
```

7) Probar login (opcional desde PowerShell)

```powershell
$body = @{ username = 'admin@test.com'; password = '123456' }
Invoke-RestMethod -Uri 'http://localhost:8000/auth/login' -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -Verbose
```

8) Problemas comunes y soluciones rápidas

- Error CORS en el navegador: asegúrate de haber reiniciado el frontend (`npm run dev`) después de los cambios; si usas Docker Compose el proxy ya está configurado.
- `ERR_CONNECTION_REFUSED` en el navegador: asegúrate que `docker-compose ps` muestre `backend` con el puerto `8000:8000` y que `npm run dev` esté corriendo en el frontend.
- Tablas no creadas: ejecuta `docker exec forensic_backend python create_tables.py` o espera hasta ver `✅ Tablas creadas/verificadas correctamente.` en los logs del backend.
- Resetar contraseña: si quieres cambiar la contraseña de un usuario a `123456`, sigue estas instrucciones en PowerShell:

   1. Obtén el hash (dentro del contenedor backend):
   ```powershell
   docker exec forensic_backend python -c "from app.auth import get_password_hash; print(get_password_hash('123456'))"
   ```
   2. Copia el hash que imprima y luego actualiza la BD (ejemplo por username `admin`):
   ```powershell
   docker exec forensic_db psql -U postgres -d forensic_db -c "UPDATE users SET hashed_password = '\$2b\$...tu_hash_aqui...' WHERE username = 'admin';"
   ```

Si algo falla, copia aquí la salida de estos comandos y te ayudo con el siguiente paso.

---

Si quieres, puedo ahora:
- Generar un archivo `scripts/start.ps1` que automatice los pasos 3–6 para que solo tengas que ejecutar un script, o
- Ayudarte en vivo pegando las salidas de los comandos para guiarte hasta que todo funcione.

Dime qué prefieres y lo hago.
## 🧸 Guía paso a paso para principiantes (explicado como a un niño)

Esta guía asume que estás en Windows y usarás PowerShell. Sigue cada paso con calma; copia y pega los comandos tal cual.

1) Abre PowerShell y ve a la carpeta del proyecto

```powershell
# Abre PowerShell
cd "C:\Users\ADMIN\Downloads\forensic-platform-main\forensic-platform-main"
```

2) Asegúrate de que Docker Desktop está abierto

- Abre Docker Desktop y confirma que esté corriendo.
- Si no lo tienes, instálalo desde https://www.docker.com/products/docker-desktop/ y reinicia el equipo si hace falta.

3) Levantar toda la aplicación con Docker (paso seguro para principiantes)

```powershell
# Bajar cualquier cosa anterior
docker-compose down --remove-orphans

# Construir imágenes necesarias (tarda la primera vez)
docker-compose build --pull

# Levantar servicios en segundo plano
docker-compose up -d

# Verifica que los contenedores estén arriba
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
```

4) Espera y revisa que el backend esté listo

```powershell
docker logs -f forensic_backend
```

- Busca mensajes como `✅ Tablas creadas/verificadas correctamente.` y `Application startup complete`.
- Si ves errores (tracebacks), copia las últimas líneas aquí y te ayudo.

5) Crear tablas y usuario administrador si hace falta

```powershell
docker exec forensic_backend python create_tables.py
docker exec forensic_backend python seed_user.py
# Si el usuario ya existe, el script lo informará.
```

Credenciales por defecto (si el seed las crea):
- Email: admin@forensic.local
- Contraseña: Admin1234!

6) Iniciar el frontend (en otra terminal)

```powershell
cd frontend
npm install
npm run dev
# Abre el navegador en http://localhost:5173
```

7) Probar registro e inicio de sesión (PowerShell, copia y pega)

Registro (JSON):
```powershell
$body = @{ email='tuemail@example.com'; username='tuusuario'; password='TuPass123!' }
Invoke-RestMethod -Uri 'http://localhost:8000/auth/register' -Method Post -Body ($body | ConvertTo-Json) -ContentType 'application/json' -Verbose
```

Login (form-urlencoded):
```powershell
$body = @{ username='tuemail@example.com'; password='TuPass123!' }
Invoke-RestMethod -Uri 'http://localhost:8000/auth/login' -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -Verbose
```

8) Si obtienes `502 Bad Gateway` o `Empty reply from server`

- Paso 1: Verifica contenedores:
```powershell
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
```
- Paso 2: Revisa logs del backend (mira si hay errores al arrancar):
```powershell
docker logs --tail 300 forensic_backend
```
- Paso 3: Si ves `ModuleNotFoundError` o similar, reconstruye y levanta el backend:
```powershell
docker-compose build backend
docker-compose up -d backend
```
- Paso 4: Confirma que Vite está proxyando correctamente al backend en `frontend/vite.config.js` (debe apuntar a `http://localhost:8000`).

9) Resetear contraseña rápidamente

```powershell
# Genera hash dentro del backend
docker exec forensic_backend python -c "from app.auth import get_password_hash; print(get_password_hash('123456'))"

# Sustituye <HASH> por lo que imprima el comando anterior
docker exec forensic_db psql -U postgres -d forensic_db -c "UPDATE users SET hashed_password = '\$2b\$...<HASH>...' WHERE email = 'tuemail@example.com';"
```

10) Escanear imágenes de Docker por CVEs (opcional)

- Instala `trivy` y luego:
```powershell
trivy image --severity HIGH,CRITICAL --format table postgres:13.3
trivy image --severity HIGH,CRITICAL --format table myrepo/forensic_backend:latest
```

11) ¿Qué hago si no funciona?

- Copia la salida exacta del comando que falla y pégala aquí.
- Yo te diré exactamente qué línea causa el problema y cómo arreglarla.

---

Si quieres que lo haga automático, dime y genero `scripts/start.ps1` que ejecute los pasos 3–6 por ti.

## 📦 Usar las imágenes desde Docker Hub (opción rápida)

Las imágenes públicas están en Docker Hub bajo el usuario: https://hub.docker.com/u/inmportal19danielbermudez

Comandos para descargar y ejecutar las imágenes ya compiladas (recomendado si no quieres construir localmente):

```powershell
# Descargar las imágenes (backend, vuln_scanner, worker)
docker pull inmportal19danielbermudez/forensic_backend:latest
docker pull inmportal19danielbermudez/forensic_vuln_scanner:latest
docker pull inmportal19danielbermudez/forensic_worker:latest

# Ejecutar el backend (ejemplo simple)
docker run -d --name forensic_backend -p 8000:8000 --env-file .env inmportal19danielbermudez/forensic_backend:latest

# Ejecutar la base de datos y rabbitmq si no usas docker-compose (ejemplo rápido)
docker run -d --name forensic_db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=forensic_db -p 5432:5432 postgres:15
docker run -d --name forensic_rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management

# Luego levanta los otros servicios conectándolos a la misma red Docker si lo necesitas.
```

Usar `docker-compose` con las imágenes públicas (opción práctica):

```powershell
# Fuerza a docker-compose a usar las imágenes remotas definidas en docker-compose.yml
docker-compose pull
docker-compose up -d
```

Nota: Si tu `docker-compose.yml` usa `build:` para las imágenes locales, reemplaza temporalmente la sección `build:` por `image: inmportal19danielbermudez/forensic_backend:latest` (y análogamente para las otras imágenes) o crea un `docker-compose.override.yml` con las líneas `image: ...` para forzar el `pull`.

---

## 🛠️ Construir y ejecutar localmente (opción para desarrolladores)

Si prefieres compilar las imágenes desde el código fuente localmente, usa estos comandos:

```powershell
# Construir imagenes desde el repo local
docker build -t inmportal19danielbermudez/forensic_backend:local .
docker build -t inmportal19danielbermudez/forensic_vuln_scanner:local -f scanner/Dockerfile scanner
docker tag inmportal19danielbermudez/forensic_backend:local inmportal19danielbermudez/forensic_worker:local

# Levantar todo con docker-compose usando las imágenes locales construidas
docker-compose up --build -d

# O construir y levantar solo el backend
docker-compose build backend
docker-compose up -d backend
```

Recomendación: para usuarios que solo quieren ejecutar la plataforma sin desarrollo, usar la opción `docker pull` es la más rápida. Para desarrolladores que vayan a modificar código, usar `docker-compose up --build` es la mejor opción.

---

## Base de Datos CVE Local (consultas sin internet)

El scanner consulta CVEs desde PostgreSQL local en lugar de la API de NVD.
Esto hace las búsquedas **instantáneas (< 1 ms)** y permite trabajar sin conexión.

### Primera vez — Cargar todos los CVEs (~15 min)

```powershell
docker exec forensic_backend python scripts/load_cve_feeds.py --mode all
```

Descarga ~250,000 CVEs desde 2002 hasta hoy desde los feeds oficiales de NIST.

### Exportar CVEs para llevar a otra máquina

En la máquina donde ya tienes los CVEs cargados:

```powershell
.\scripts\export_cve.ps1
```

Genera el archivo `cve_data_dump.sql` en la raíz del proyecto (~200 MB).

### Importar CVEs en una máquina nueva

Copia `cve_data_dump.sql` a la raíz del proyecto en la máquina nueva y ejecuta:

```powershell
.\scripts\import_cve.ps1
```

Tarda ~30-60 segundos e importa todos los CVEs sin necesidad de descargar nada.

### Actualizar CVEs nuevos (semanal)

```powershell
docker exec forensic_backend python scripts/load_cve_feeds.py --mode recent
```

### Ver estadísticas de CVEs cargados

```powershell
docker exec forensic_backend python scripts/load_cve_feeds.py --mode stats
```

### Comportamiento del scanner

| Situación | Resultado |
|-----------|-----------|
| CVE en BD local | Retorna en < 1 ms, sin internet |
| CVE no en local | Consulta NVD API como fallback |
| Sin internet y no en local | Retorna CVE-ID sin descripción |






