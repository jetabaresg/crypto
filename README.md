# CryptoHackaton - Auditor TLS

Auditor de configuracion TLS para dominios o IPs.
Combina salidas de herramientas de seguridad (nmap, testssl.sh, sslscan, openssl), calcula riesgo y genera reporte HTML.

## Caracteristicas

- Analisis de uno o varios objetivos (dominio/IP)
- Score de seguridad y nivel de riesgo
- Cobertura de herramientas `x/4`
- Estado de prueba:
  - `Prueba realizada correctamente` si hay `4/4`
  - `Prueba parcial` si faltan herramientas o alguna falla
- Recomendaciones:
  - IA (OpenRouter/OpenAI compatible) cuando esta configurada
  - fallback local si no hay API o falla la llamada
- Reporte HTML por objetivo

## Estructura del proyecto

- `main.py`: entrypoint CLI
- `motores/analizadorTLS.py`: ejecucion de herramientas externas
- `motores/evaluador.py`: score, riesgo, recomendaciones y cobertura
- `motores/recomendador_ia.py`: recomendaciones por API IA
- `parsers/`: parseo de salida de cada herramienta
- `report/generator.py`: generacion de HTML
- `scripts/openssl_probe.sh`: probe via bash para openssl

## Requisitos

Python 3.10+ (libreria estandar, sin paquetes pip obligatorios)

Herramientas externas recomendadas:

- nmap
- testssl.sh
- sslscan
- openssl
- bash (Git Bash/WSL en Windows)

## Inicio rapido

### Windows (PowerShell)

1. Entrar al proyecto:

```powershell
cd C:\Users\salas.pei\Desktop\CryptoHackaton
```

2. Crear entorno virtual (si aun no existe):

```powershell
python -m venv .venv
```

3. Activar entorno virtual:

```powershell
.\.venv\Scripts\Activate.ps1
```

4. Ejecutar una prueba basica:

```powershell
python .\main.py google.com --timeout 8
```

### Linux / WSL / macOS

1. Entrar al proyecto:

```bash
cd ~/CryptoHackaton
```

2. Crear entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Ejecutar una prueba basica:

```bash
python main.py google.com --timeout 8
```

## Configuracion de testssl.sh

El proyecto intenta resolver `testssl.sh` automaticamente.

Orden de prioridad:

1. Variable de entorno `TESTSSL_PATH`
2. PATH del sistema (`testssl.sh`)
3. Rutas comunes (Linux/Windows)

En Linux/WSL/macOS, si tu carpeta es `~/testssl.sh`:

```bash
export TESTSSL_PATH=~/testssl.sh/testssl.sh
chmod +x ~/testssl.sh/testssl.sh
```

## Configuracion de recomendaciones IA (opcional)

Este proyecto usa por defecto endpoint OpenRouter compatible y modelo:

- Modelo por defecto: `openai/gpt-4o-mini`
- Endpoint por defecto: `https://openrouter.ai/api/v1/chat/completions`

Variables soportadas:

- `AI_RECOMMENDER_API_KEY` (o `OPENROUTER_API_KEY`)
- `AI_RECOMMENDER_API_URL` (opcional)
- `AI_RECOMMENDER_MODEL` (opcional)
- `OPENROUTER_REFERER` (opcional)
- `OPENROUTER_APP_NAME` (opcional)

Ejemplo (PowerShell):

```powershell
$env:AI_RECOMMENDER_API_KEY="TU_API_KEY"
$env:AI_RECOMMENDER_MODEL="openai/gpt-4o-mini"
$env:AI_RECOMMENDER_API_URL="https://openrouter.ai/api/v1/chat/completions"
```

## Uso

Analizar un objetivo:

```bash
python main.py google.com
```

Analizar varios objetivos:

```bash
python main.py 1.1.1.1 8.8.8.8 --timeout 15
```

Cambiar puerto y nombre de reporte:

```bash
python main.py google.com --puerto 443 --salida reporte_google.html --timeout 15
```

Analizar varios objetivos y generar un reporte por objetivo automaticamente:

```bash
python main.py google.com 1.1.1.1 8.8.8.8 --salida reporte_tls.html
```

Salida esperada en consola:

- Fuente de recomendaciones (IA activa o fallback local)
- Riesgo y score
- Cobertura de herramientas `x/4`
- Estado de prueba
- Ruta del reporte HTML

## Reportes

Por defecto genera `reporte_tls.html`.
Con multiples objetivos genera un archivo por objetivo (slug automatico).

## Preparar para GitHub

1. Inicializa repo:

```bash
git init
git add .
git commit -m "Initial commit"
```

2. Crea repo remoto y vincula:

```bash
git remote add origin <URL_REPO>
git branch -M main
git push -u origin main
```

## Notas

- Si faltan herramientas, no se detiene el flujo; se reportan como `No disponible`.
- Si no hay API key, las recomendaciones usan fallback local.

## Troubleshooting rapido

Verificar herramientas disponibles:

```bash
nmap --version
sslscan --version
openssl version
testssl.sh --version
```

Si `testssl.sh` no aparece:

```bash
export TESTSSL_PATH=~/testssl.sh/testssl.sh
chmod +x ~/testssl.sh/testssl.sh
```

En PowerShell (solo sesion actual):

```powershell
$env:TESTSSL_PATH="$HOME/testssl.sh/testssl.sh"
```
