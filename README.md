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

Ir a: https://nodejs.org Descargar versión LTS

Instalar con opciones por defecto Verificar:


<p align="center">
  <img src="worker/imagen/node.png" width="600">
</p>

<p align="center">
  <img src="worker/imagen/node2.png" width="600">
</p>

Luego de instalado verificar en una terminal cmd nueva 

node --version

npm --version

Resultado

node --version
v2--

npm --version
1---


## 4️. Clonar el Repositorio


Crea un carpeta vacia en el escritorio y luego en la misma carpeta click derecho y le dan en la opcion Open Git bash here

<p align="center">
  <img src="worker/imagen/clonar.png" width="600">
</p>

luego pegan esta linea de comando

git clone https://github.com/JhonAriza15/forensic-platform.git

debe salir algo asi:

<p align="center">
  <img src="worker/imagen/clonar2.png" width="600">
</p>

asi debe quedar

<p align="center">
  <img src="worker/imagen/clonar3.png" width="600">
</p>

ℹ️ Se crea la carpeta del proyecto con todo el código

## 5️. Configurar variables de entorno (.env)
Crear archivo .env en la raíz del proyecto:

como crearla 

Click derecho y le dan en nuevo archivo de texto 

<p align="center">
  <img src="worker/imagen/env.png" width="600">
</p>

le cambia el nombre al txt y le coloca .env solo sin el .txt y le da en si 

<p align="center">
  <img src="worker/imagen/env1.png" width="600">
</p>

luego lo abre abri en txt pero solo una vez porque si lo cambia el formato se daña 

<p align="center">
  <img src="worker/imagen/env2.png" width="600">
</p>

luego pega la esta linea en el archivo y guarda

DATABASE_URL=postgresql://postgres:postgres@localhost:5433/forensic_db

RABBITMQ_URL=amqp://guest:guest@localhost:5672/

SECRET_KEY=clave_super_secreta_cambiar_en_produccion


<p align="center">
  <img src="worker/imagen/env3.png" width="600">
</p>

## 6. luego descargar este archivo desde google drive ruta

https://drive.google.com/drive/folders/1TYrNwMKDeZGasvdBvajkW6wXLOceY4BS?usp=sharing

y dejarlo en la ruta principal de proyecto como se ve en la imagen 

<p align="center">
  <img src="worker/imagen/archivo.png" width="600">
</p>

asi debio quedar 

<p align="center">
  <img src="worker/imagen/archivo2.png" width="600">
</p>

## 7. Construir y levantar todos los servicios

Este comando construye las imagenes y levanta todos los servicios automaticamente:

Tener abierto el docker

<p align="center">
  <img src="worker/imagen/docker.png" width="600">
</p>

abrir una terminal power shell 

ingresar a la ruta donde se dejo el proyecto ejemplo la mia a es C:\Users\jhona\Desktop\Proyecto\forensic-platform

cd C:\Users\tuusuario\Desktop\Proyecto\forensic-platform

<p align="center">
  <img src="worker/imagen/docker2.png" width="600">
</p>

ejecutamos este comando 

docker compose up --build -d

<p align="center">
  <img src="worker/imagen/docker3.png" width="600">
</p>

y debe sali al finalizar esto

<p align="center">
  <img src="worker/imagen/docker4.png" width="600">
</p>

## 8. Luego en la misma terminal de power shell ejecutar esto

.\scripts\import_cve.ps1

<p align="center">
  <img src="worker/imagen/script.png" width="600">
</p>

aparece pregunta que si o no escribir S


<p align="center">
  <img src="worker/imagen/script2.png" width="600">
</p>

y deberia quedar asi

<p align="center">
  <img src="worker/imagen/script3.png" width="600">
</p>

## 9. Luego crear las tablas 

con este comando desde la misma terminal power shell

docker exec forensic_backend python seed_user.py

## 10. abri una terminal cmd como administrador importante

Ir a la ruta del proyecto a la carpeta frontend que esta en el mismo proyecto

Ejemplo
cd C:\Users\Tuusuario\Desktop\Proyecto\forensic-platform\frontend

<p align="center">
  <img src="worker/imagen/front.png" width="600">
</p>

Ejecutamos este comando 

npm install

<p align="center">
  <img src="worker/imagen/front2.png" width="600">
</p>

y luego este comando 

npm run dev

> ⚠️ Asi deberia salir no cerra terminal cmd

<p align="center">
  <img src="worker/imagen/front3.png" width="600">
</p>

Luego valida desde el navegador ingresar 

Local: http://localhost:5173

🌐 Acceso

Abrir en el navegador:

👉 http://localhost:5173

<p align="center">
  <img src="worker/imagen/pagina.png" width="600">
</p>

📌 Nota importante

Terminal 3 → npm run dev

---

## 🧑‍💻 Cómo Usar la Plataforma

---

1. Ir a: http://localhost:5173
2. Hacer clic en **"Regístrate"**
   * Email
   * Nombre de usuario
   * Contraseña
  
<p align="center">
<img src="worker/imagen/registro.png" width="600">
</p>
     
4. Iniciar sesión con las credenciales creadas

> ⚠️ Los tokens JWT expiran cada 15 minutos. Si la sesión se cierra, vuelve a iniciar sesión.

---

Para validar que funcione la herramienta vamosa subir una maquina virtual 

## 10. Paso a paso para subir maquina virutal en virtual box

Descargar la imagen de metasploitable

Link : 

https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip/download

y 

virtual box

https://www.virtualbox.org/


seguir paso para configurar el virtual box

Abrir virtual box 

<p align="center">
<img src="worker/imagen/virtual.png" width="600">
</p>

# Paso 1

<p align="center">
<img src="worker/imagen/virtual2.png" width="600">
</p>

# Paso 2

<p align="center">
<img src="worker/imagen/virtual3.png" width="600">
</p>

# Paso 3

<p align="center">
<img src="worker/imagen/virtual5.png" width="600">
</p>

# Paso 4

<p align="center">
<img src="worker/imagen/virtual4.png" width="600">
</p>

# Paso 5

<p align="center">
<img src="worker/imagen/virtual6.png" width="600">
</p>

# Paso 6

ir a donde guardaron o se descargo el archivo de metasploitable

<p align="center">
<img src="worker/imagen/virtual7.png" width="600">
</p>

# Paso 7

<p align="center">
<img src="worker/imagen/virtual8.png" width="600">
</p>


# Paso 8

<p align="center">
<img src="worker/imagen/virtual9.png" width="600">
</p>

# Paso 9

Antes de inciiar la maquina ir a configuracion para activar unos opciones en la tarjeta de red

<p align="center">
<img src="worker/imagen/virtual10.png" width="600">
</p>

# Paso 10

<p align="center">
<img src="worker/imagen/virtual11.png" width="600">
</p>

# Paso 11

Iniciar la maquina y sacar la ip de la maquina virtual para hacer el scanneo 

para sacar la ip es :

ifconfig 

<p align="center">
<img src="worker/imagen/virtual12.png" width="600">
</p>

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
2. Ingresar la URL ej: http://testphp.vulnweb.com , https://demo.testfire.net , https://owasp.org/www-project-juice-shop/
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


### Comportamiento del scanner

| Situación | Resultado |
|-----------|-----------|
| CVE en BD local | Retorna en < 1 ms, sin internet |
| CVE no en local | Consulta NVD API como fallback |
| Sin internet y no en local | Retorna CVE-ID sin descripción |






