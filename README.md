# Reachflow · Verificador de Dominios

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/status-active-success)

Herramienta para auditar dominios:
- Verifica **SPF / DKIM / DMARC / MX** del dominio principal
- Descubre **dominios secundarios** (variantes de marca y TLD) que la empresa pueda estar usando para **cold email**
- Detecta cuáles **redirigen al dominio principal**
- Opcional: hace **WHOIS** del dominio y sus variantes para verificar si pertenecen a la misma entidad

Funciona en dos modos:

1. **App local con UI** (recomendado para volumen): procesa un CSV completo, con N dominios en paralelo, pausar/reanudar/saltar/borrar, resumen en vivo, descarga del CSV enriquecido.
2. **API remota (opcional, deploy a Render)**: endpoints HTTP para integrar con Clay u otras herramientas.

---

## 🚀 Empezar (modo local)

### Windows

1. **Clonar el repo** (o descargar como ZIP y descomprimir):
   ```
   git clone https://github.com/Ckaox/verificador-dominios.git
   cd verificador-dominios
   ```

2. **Doble-click en `run.bat`**.

   La primera vez:
   - Crea un entorno virtual `.venv/`
   - Instala las dependencias
   - Arranca el servidor en `http://127.0.0.1:8000/ui/` y abre el navegador solo

   Tarda ~30s la primera vez. Las siguientes corre en segundos.

3. Para frenarlo: `Ctrl+C` en la consola, o cerrá la ventana.

### macOS / Linux

```bash
git clone https://github.com/Ckaox/verificador-dominios.git
cd verificador-dominios
chmod +x run.sh
./run.sh
```

### Requisitos

- **Python 3.10+** ([descargar](https://www.python.org/downloads/))
  - En Windows: durante la instalación, marcá **"Add Python to PATH"**.
- Conexión a internet (para resolver DNS y opcionalmente WHOIS).

---

## 🖥️ Cómo usar

1. **Subí tu CSV** (drag & drop o click). Acepta UTF-8 y latin-1.
2. **Elegí la columna del dominio** del dropdown (autodetecta `domain`/`website`/`url` si existe).
3. **Configurá las opciones**:

| Opción | Default | Recomendado |
|---|---|---|
| Timeout por fila | 180s | Si tu red es lenta, subí a 240s |
| Concurrencia DNS interna | 25 | Dejá 25 |
| **Dominios en paralelo** | **5** | 5-10 (ver guía abajo) |
| **Búsqueda de variantes** | **Smart cascade** | El default |
| Buscar WHOIS | off | Activá si querés el dato de propietario (lento) |

4. Click **▶ Iniciar procesamiento**. Vas a ver:
   - Cada **worker** procesando un dominio (con tiempo y paso actual en vivo)
   - **Resumen de hallazgos** actualizándose en vivo: scores de seguridad, empresas con dominios extras, redirects, cold email real, match WHOIS, etc.
   - **Tabla de resultados** con cada fila procesada
5. **Pausar/Reanudar** en cualquier momento. Las filas terminadas no se reprocesan.
6. **⏭ Skip** individual por worker si un dominio se está demorando demasiado.
7. **⬇ Descargar CSV** cuando quieras (no hace falta esperar al final). Sale ordenado por el índice original.

---

## 🧠 Modos de búsqueda de variantes

| Modo | Variantes | Tiempo / dominio | Caso de uso |
|---|---|---|---|
| **Smart cascade** ⭐ | 48 → 155 | 6–40s | **Default**. Arranca con cold; si encuentra algo, expande a completo |
| Cold email focus | 48 | 5–10s | Solo patrones cold email típicos (`getX`, `Xmail`, `X.io`, ...) |
| Completo | 155 | 25–40s | Máxima cobertura. Detecta todo el portfolio (no solo cold email) |
| Solo DNS principal | 0 | 3–5s | Solo SPF/DKIM/DMARC/MX del dominio, sin buscar variantes |

---

## ⚙️ Cuántos workers usar

El cuello de botella son los servidores DNS públicos (Cloudflare 1.1.1.1, Google 8.8.8.8).

| Workers | Queries simultáneas | Recomendación |
|---|---|---|
| 1–3 | <75 | Muy conservador. Si tu red es inestable o estás detrás de VPN. |
| **5** ⭐ | ~125 | **Balance recomendado.** Casi nunca da timeouts. |
| 7–10 | 175–250 | Rápido. Funciona bien con conexión casera buena. |
| 11–15 | 275–375 | Arriesgado. Algunos ISPs limitan DNS UDP y empezás a ver timeouts. |
| 16–20 | >400 | Solo conexión empresarial. Riesgo alto de rate-limit. |

**Regla práctica**: con **Smart cascade + 5 workers** procesás ~30k dominios en **~3–6 horas** (sin WHOIS).

---

## 📊 Columnas que agrega al CSV

Todas las columnas que añade arrancan con `rf_` (Reachflow).

| Columna | Contenido |
|---|---|
| `rf_original_index` | Índice de fila original (para ordenar) |
| `rf_status` | `ok` / `skipped` / `error` / `timeout` |
| `rf_processed_at` | Timestamp UTC |
| `rf_seconds` | Segundos que tardó la fila |
| `rf_has_mx`, `rf_mx_provider`, `rf_mx_servers` | MX records y proveedor (Google Workspace, M365, etc.) |
| `rf_has_spf`, `rf_spf_record` | SPF del dominio principal |
| `rf_has_dmarc`, `rf_dmarc_policy` | DMARC + política (`none`/`quarantine`/`reject`) |
| `rf_has_dkim` | DKIM (selectores comunes) |
| `rf_security_score` | `Poor` / `Fair` / `Good` / `Excellent` (qué tan bien configurada está la seguridad de email) |
| `rf_variants_active` | Cantidad de variantes activas detectadas |
| `rf_active_domains` | Lista con tags inline: `getfoo.com[mx dkim dmarc:reject →foo.com]` |
| `rf_cold_email_domains`, `rf_cold_email_count` | Variantes con MX configurado |
| `rf_cold_email_ready_domains`, `rf_cold_email_ready_count` | Variantes con MX + DKIM + DMARC (stack cold email real) |
| `rf_redirecting_domains`, `rf_redirecting_count` | Variantes que redirigen a cualquier destino |
| `rf_redirecting_to_main`, `rf_redirecting_to_main_count` | Variantes que redirigen al dominio principal |
| `rf_whois_main_entity`, `rf_whois_main_registrar` | (Si WHOIS está activo) propietario del main |
| `rf_whois_same_entity_count` | Variantes con la misma entidad WHOIS que el main |
| `rf_whois_all_match` | `true` si todas las variantes pertenecen al main |
| `rf_whois_data` | JSON completo con info WHOIS de cada dominio |
| `rf_error` | Mensaje de error si lo hubo |

---

## 🔄 Reanudar después de cerrar

Los trabajos viven en `./data/jobs/{job_id}/`. Al volver a abrir la UI:
- En la sidebar aparece la lista de jobs guardados
- Click en uno → si quedó interrumpido, mostrá el botón **▶ Reanudar**
- Las filas ya hechas no se reprocesan

Para borrar un job: click en el icono 🗑 junto al nombre en la sidebar.

---

## 🌐 Modo API remota (opcional)

El proyecto incluye configuración para deploy a [Render](https://render.com) con los endpoints de la API:

- `GET  /api/dns/{domain}` — verificación DNS de un dominio
- `GET  /api/discover/variants/{domain}` — variantes y dominios activos
- `GET  /api/discover/crtsh/domain/{domain}` — subdominios via Certificate Transparency
- `GET  /api/discover/crtsh/org/{org}` — dominios por organización
- `POST /api/discover/bulk` — verificación masiva de hasta 500 dominios

Documentación interactiva en `/docs`.

Para deploy: el `render.yaml` ya está configurado. Conectá el repo en Render y listo.

---

## 🛠️ Estructura del proyecto

```
verificador-dominios/
├── app/
│   ├── main.py              # FastAPI: endpoints API + endpoints jobs locales
│   ├── models.py            # Pydantic models
│   ├── utils/
│   │   ├── dns_checker.py     # SPF / DKIM / DMARC / MX
│   │   ├── domain_discovery.py # variantes + redirects + crt.sh
│   │   └── csv_processor.py    # Job manager con N workers + persistencia + WHOIS
│   └── static/              # UI Reachflow (HTML/CSS/JS + logo SVG)
├── run.bat                  # Launcher Windows
├── run.sh                   # Launcher macOS/Linux
├── run_local.py             # Script Python del launcher
├── requirements.txt         # Dependencias
├── render.yaml              # Config para deploy a Render
└── data/jobs/               # (gitignore) jobs persistidos
```

---

## 🐛 Troubleshooting

**"Python no encontrado en PATH" en Windows**
Reinstalá Python desde python.org marcando "Add Python to PATH" durante el instalador.

**Muchos timeouts en filas**
Bajá los workers a 3 o subí el timeout a 240s. Si seguís viendo timeouts, cambiá los DNS de tu sistema a 1.1.1.1 o 8.8.8.8 (suele ser más rápido que el DNS del ISP).

**WHOIS errors en la consola**
Normal. Algunos TLDs (especialmente ccTLDs europeos con GDPR) no exponen WHOIS o lo rate-limitean. La librería los reporta pero ya están silenciados. Las filas afectadas siguen procesando con la data disponible.

**El navegador queda en "Loading..."**
Refrescá la pestaña (F5). Sucede cuando el browser intenta conectarse antes de que uvicorn esté listo. El launcher ahora espera al puerto, pero si pasa, F5.

---

## 📄 Licencia

Uso libre interno y educacional. Si lo usás en producción, ojo con los rate limits de DNS público y WHOIS.
