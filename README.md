# Verificador DNS de Dominios

API REST profesional para análisis completo de registros DNS relacionados con correo electrónico empresarial.

## Características

### Verificación de Registros DNS
- Registros MX con detección automática de proveedor (Google Workspace, Microsoft 365, Zoho, ProtonMail, Yahoo)
- Validación de SPF (Sender Policy Framework)
- Verificación de DMARC (Domain-based Message Authentication) con parser detallado
- Búsqueda inteligente de registros DKIM con 20+ selectores comunes en paralelo

### Análisis de Seguridad y Reputación
- Verificación paralela en 20 blacklists principales (Spamhaus ZEN, SpamCop, Barracuda, SORBS, etc.)
- Análisis de edad del dominio vía WHOIS
- Detección de IPs de servidores MX en blacklists
- Resumen de seguridad con puntuación y recomendaciones específicas

### Rendimiento
- Verificaciones paralelas optimizadas (DKIM y Blacklists ejecutadas simultáneamente)
- WHOIS ejecutado en paralelo con verificaciones DNS
- Respuesta típica en 2-3 segundos
- API RESTful con documentación Swagger interactiva
- CORS habilitado para integración frontend

## Requisitos

- Python 3.11+
- pip

## Instalación Local

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/verificador-dns-api.git
cd verificador-dns-api

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Iniciar servidor
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

El servidor estará disponible en: `http://localhost:8000`

Documentación interactiva en: `http://localhost:8000/docs`

## Deploy en Render

### Opción 1: Deploy Automático con render.yaml

1. Sube el código a GitHub
2. Ve a [Render.com](https://render.com) y crea una cuenta
3. Click en "New +" y selecciona "Web Service"
4. Conecta tu repositorio de GitHub
5. Render detectará automáticamente `render.yaml`
6. Click en "Create Web Service"

### Opción 2: Deploy Manual

1. En Render.com, crea un nuevo "Web Service"
2. Conecta tu repositorio de GitHub
3. Configura:
   - **Name**: `verificador-dns-api`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Click en "Create Web Service"

Tu API estará disponible en: `https://tu-servicio.onrender.com`

## Endpoints de la API

### 1. Información de la API

**GET** `/`

```bash
curl https://tu-api.onrender.com/
```

### 2. Verificación DNS Completa

**GET** `/api/dns/{domain}`

Verifica todos los registros DNS de un dominio incluyendo MX, SPF, DMARC, DKIM, blacklists y edad del dominio.

**Ejemplo:**
```bash
curl https://tu-api.onrender.com/api/dns/google.com
```

**Respuesta:**
```json
{
  "domain": "google.com",
  "timestamp": "2025-10-01T16:00:00Z",
  "dns": {
    "mx": {
      "has_mx": true,
      "provider": "Google Workspace (Gmail)",
      "servers": [
        { "priority": 10, "server": "smtp.google.com" }
      ],
      "count": 1
    },
    "spf": {
      "has_spf": true,
      "valid": true,
      "record": "v=spf1 include:_spf.google.com ~all",
      "mechanisms": ["include:_spf.google.com", "~all"]
    },
    "dmarc": {
      "has_dmarc": true,
      "valid": true,
      "record": "v=DMARC1; p=reject",
      "policy": { "policy": "reject" }
    },
    "dmarc_details": {
      "policy": "reject",
      "subdomain_policy": null,
      "percentage": 100,
      "alignment_spf": "relaxed",
      "alignment_dkim": "relaxed"
    },
    "dkim": {
      "has_dkim": true,
      "valid": true,
      "count": 1
    }
  },
  "blacklists": {
    "is_blacklisted": false,
    "domain_blacklisted": false,
    "ip_blacklisted": false,
    "blacklists_checked": 80,
    "blacklists_listed": 0,
    "listed_in": [],
    "mx_ips_checked": ["142.250.0.27"]
  },
  "domain_age": {
    "has_info": true,
    "creation_date": "1997-09-15T00:00:00",
    "age_days": 10045,
    "age_years": 27.5,
    "registrar": "MarkMonitor, Inc.",
    "is_new": false
  },
  "email_security_summary": {
    "spf_configured": true,
    "dmarc_configured": true,
    "dkim_configured": true,
    "all_configured": true,
    "security_score": "Excellent",
    "recommendations": [
      "Excelente! Tu dominio tiene todas las configuraciones de seguridad recomendadas."
    ]
  },
  "success": true
}
```

### 3. Health Check

**GET** `/api/health`

```bash
curl https://tu-api.onrender.com/api/health
```

### 4. Documentación Interactiva

**GET** `/docs`

Accede a la documentación Swagger UI en: `https://tu-api.onrender.com/docs`

## Ejemplos de Uso

### cURL

```bash
# Verificar DNS de un dominio
curl https://tu-api.onrender.com/api/dns/github.com

# Health check
curl https://tu-api.onrender.com/api/health
```

### Python

```python
import requests

response = requests.get("https://tu-api.onrender.com/api/dns/github.com")
data = response.json()

print(f"Proveedor: {data['dns']['mx']['provider']}")
print(f"Seguridad: {data['email_security_summary']['security_score']}")
print(f"En blacklist: {data['blacklists']['is_blacklisted']}")
print(f"Edad (años): {data['domain_age']['age_years']}")
```

### JavaScript / Node.js

```javascript
fetch('https://tu-api.onrender.com/api/dns/github.com')
  .then(response => response.json())
  .then(data => {
    console.log('Proveedor:', data.dns.mx.provider);
    console.log('Seguridad:', data.email_security_summary.security_score);
    console.log('Blacklisted:', data.blacklists.is_blacklisted);
  });
```

## Detección de Proveedores

El API detecta automáticamente los siguientes proveedores de correo:

- Google Workspace (Gmail)
- Microsoft 365 (Outlook)
- Zoho Mail
- ProtonMail
- Yahoo Mail
- Y detecta otros proveedores automáticamente

## Blacklists Verificadas

El API verifica las 20 blacklists más importantes:

**Blacklists de dominio (5):**
- Spamhaus DBL
- SURBL Multi
- Nordspam DBL
- SORBS RHSBL
- Spam Eating Monkey

**Blacklists de IP (15):**
- Spamhaus ZEN (incluye SBL, XBL, PBL)
- SpamCop
- Barracuda Central
- SORBS DNSBL
- PSBL (Passive Spam Block List)
- MailSpike
- UCEProtect Level 1
- Spam Eating Monkey
- SpamRats
- Blocklist.de
- Abuse.ch
- Y otras

## Estructura del Proyecto

```
verificador-dns-api/
├── app/
│   ├── __init__.py
│   ├── main.py              # API FastAPI con endpoints
│   ├── models.py            # Modelos Pydantic
│   └── utils/
│       ├── __init__.py
│       └── dns_checker.py   # Lógica de verificación DNS (paralela)
├── requirements.txt         # Dependencias Python
├── Procfile                 # Configuración para Heroku/Render
├── render.yaml              # Deploy automático en Render
├── runtime.txt              # Versión de Python (3.11)
├── .gitignore              # Archivos ignorados por Git
└── README.md               # Esta documentación
```

## Solución de Problemas

### Error de DNS Timeout
Algunos dominios pueden tener servidores DNS lentos. El timeout está configurado a 5 segundos por consulta.

### Dominio no válido
Asegúrate de pasar solo el dominio (ejemplo: `example.com`) sin `http://`, `https://` o `www`

### DKIM no encontrado
DKIM requiere conocer el selector específico. El API prueba 20 selectores comunes pero algunos dominios usan selectores personalizados que no podemos detectar.

### Tiempo de respuesta largo
El primer request después de que el servicio "se duerme" en Render (plan free) puede tardar 30-60 segundos. Requests subsecuentes serán rápidos (2-3 segundos).

## Seguridad y Privacidad

- Todas las consultas son de solo lectura
- No se almacenan datos de dominios verificados
- No se requiere autenticación ni API keys
- CORS habilitado para todos los orígenes
- No se realizan modificaciones en los dominios verificados

## Limitaciones

- Plan gratuito de Render: El servicio se duerme después de 15 minutos sin actividad
- DKIM: Solo detecta selectores comunes
- WHOIS: Algunos registrars limitan consultas o no proveen información completa
- Blacklists: Solo verifica las 20 más importantes (de las 100+ existentes)

## Dependencias

- **FastAPI**: Framework web moderno y rápido
- **Uvicorn**: Servidor ASGI de alto rendimiento
- **dnspython**: Consultas DNS
- **python-whois**: Información WHOIS de dominios
- **Pydantic**: Validación de datos
- **python-dotenv**: Variables de entorno

## Contribuciones

Las contribuciones son bienvenidas. Para contribuir:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## Licencia

Este proyecto es de código abierto y está disponible bajo la licencia MIT.

## Soporte

Para reportar bugs, solicitar características o hacer preguntas:
- Abre un issue en GitHub
- Contacta al maintainer del proyecto
