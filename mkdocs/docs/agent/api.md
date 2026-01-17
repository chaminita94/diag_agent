# API REST

El Diag Agent exposa una API RESTful per integrar-se amb altres sistemes.

---

## Autenticació i Seguretat

### Restricció per IP

```python
ALLOWED_NETWORKS = []  # Configurat via --allow-from

@app.before_request
def restrict_client_ip():
    """Bloqueja peticions de IPs no autoritzades."""
    client_ip = request.remote_addr
    
    # Sempre permetre localhost
    if client_ip in ["127.0.0.1", "::1"]:
        return
    
    # Verificar contra xarxes permeses
    from ipaddress import ip_address, ip_network
    client = ip_address(client_ip)
    
    for network_str in ALLOWED_NETWORKS:
        if client in ip_network(network_str):
            return
    
    abort(403)
```

### Configuració Inicial

```bash
# Permetre només xarxa local
sudo ./setup_diag.sh 192.168.1.100 192.168.1.0/24 8080
#                     ^IP servidor  ^Xarxa permesa  ^Port
```

---

## Endpoints Disponibles

### Estat del Sistema

#### `GET /api/status`

Retorna l'estat general del sistema.

**Resposta:**
```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "hostname": "ubuntu-server",
  "vulns": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8
  },
  "cpu": 45.2,
  "memory": 62.1,
  "disk": 55.0,
  "ssh_fails": 15,
  "packages_upgradable": 23,
  "services_running": 45,
  "processes_suspicious": 0
}
```

**Exemple:**
```bash
curl http://localhost:8080/api/status | jq
```

---

### Escaneig de Vulnerabilitats

#### `POST /api/run_trivy_filtered`

Executa un escaneig Trivy amb filtres opcionals.

**Request Body:**
```json
{
  "severity": ["CRITICAL", "HIGH"],
  "limit": 100
}
```

**Resposta:**
```json
{
  "success": true,
  "scan_time": "2025-01-15T10:35:00Z",
  "duration_seconds": 45.2,
  "total_vulns": 7,
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "package": "openssl",
      "severity": "CRITICAL",
      "installed_version": "1.1.1f",
      "fixed_version": "1.1.1g",
      "title": "Buffer overflow vulnerability"
    }
  ]
}
```

#### `POST /api/vulns/refresh`

Força un refresc manual de la caché de Trivy. Útil quan s'han actualitzat paquets o es necessiten resultats actualitzats immediatament.

**Request Body:**
```json
{}
```
(Cos buit, no cal paràmetres)

**Resposta:**
```json
{
  "success": true,
  "message": "Cache refreshed"
}
```

**Exemple:**
```bash
curl -X POST http://localhost:8080/api/vulns/refresh
```

!!! info "Caché de Trivy"
    Des de la versió 2026, el Diag Agent implementa un sistema de caché global per a Trivy que redueix el temps de resposta de 30+ segons a instant després del primer escaneig. Aquest endpoint permet forçar un refresc manual de la caché.

---

### Pentesting Web (Pentest Agent)

#### `POST /api/pentest/run`
Inicia un escaneig de vulnerabilitats web en segon pla.

**Request Body:**
```json
{
  "target": "http://example.com",
  "threads": 5,
  "sqli": true,
  "xss": true,
  "max_requests": 500
}
```

#### `GET /api/pentest/status/<scan_id>`
Consulta el progrés en temps real (URLs, peticions, troballes).

#### `GET /api/pentest/results/<scan_id>`
Obté el detall complet de les vulnerabilitats detectades.

---

### Integracions i Reports

#### `GET /pentest/pdf/<scan_id>`
Genera i descarrega l'informe d'auditoria web en PDF signat.

#### `POST /api/pentest/telegram/<scan_id>`
Envia l'informe PDF directament a un Chat ID de Telegram.

**Request Body:**
```json
{
  "chat_id": "123456789"
}
```

---

## Codis de Resposta

| Codi | Significat |
|------|------------|
| `200` | Operació exitosa |
| `400` | Petició malformada o paràmetres invàlids |
| `403` | IP no autoritzada |
| `404` | Endpoint no trobat |
| `500` | Error intern del servidor |
| `504` | Timeout d'operació |

---

## Exemples d'Integració

### Python

```python
import requests

BASE_URL = "http://192.168.1.100:8080"

# Obtenir estat
response = requests.get(f"{BASE_URL}/api/status")
status = response.json()
print(f"CPU: {status['cpu']}%")

# Escaneig Nmap
scan = requests.post(
    f"{BASE_URL}/api/nmap_scan",
    json={"target": "192.168.1.1", "extra_args": "-sV"}
)
print(scan.json())
```

### Bash/cURL

```bash
#!/bin/bash
BASE="http://192.168.1.100:8080"

# Estat del sistema
curl -s "$BASE/api/status" | jq '.cpu, .memory, .disk'

# Escaneig de vulnerabilitats
curl -s -X POST "$BASE/api/run_trivy_filtered" \
  -H "Content-Type: application/json" \
  -d '{"severity": ["CRITICAL"]}' | jq '.total_vulns'
```

### JavaScript

```javascript
const BASE_URL = 'http://192.168.1.100:8080';

// Polling d'estat cada 5 segons
setInterval(async () => {
  const response = await fetch(`${BASE_URL}/api/status`);
  const data = await response.json();
  
  document.getElementById('cpu').textContent = `${data.cpu}%`;
  document.getElementById('memory').textContent = `${data.memory}%`;
  
  if (data.ssh_fails > 10) {
    alert('⚠️ Detectades múltiples fallades SSH!');
  }
}, 5000);
```

---

!!! tip "Rate Limiting"
    Actualment no hi ha rate limiting implementat. Per a entorns de producció, es recomana utilitzar un reverse proxy (nginx) amb configuració de límits.
