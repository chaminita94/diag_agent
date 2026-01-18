# SOC Dashboard

El Centre d'Operacions de Seguretat (SOC) ofereix monitoratge en temps real del sistema.

---

## Visió General

El SOC Dashboard proporciona visibilitat immediata sobre:

- **Salut del sistema**: CPU, memòria, disc
- **Tràfic de xarxa**: bytes enviats/rebuts per segon
- **Network IDS Shield**: Inspecció de paquets en temps real (motor Scapy)
- **Events de seguretat**: fallades SSH, processos sospitosos
- **Logs crítics**: últims missatges del sistema

---

## Mètriques en Temps Real

### Emmagatzematge d'Historial

```python
from collections import deque

# Store metric history (last 60 data points)
soc_history = {
    "cpu": deque(maxlen=60),
    "memory": deque(maxlen=60),
    "disk": deque(maxlen=60),
    "network_sent": deque(maxlen=60),
    "network_recv": deque(maxlen=60),
    "timestamps": deque(maxlen=60)
}

# Track previous network counters for rate calculation
soc_prev_net = {
    "bytes_sent": 0, 
    "bytes_recv": 0, 
    "timestamp": time.time()
}
```

### Funcions de Recol·lecció

#### `soc_get_system_metrics()`

Recull mètriques de salut del sistema amb llindars d'alerta.

```python
def soc_get_system_metrics():
    """
    Returns:
        {
            "cpu_percent": 45.2,
            "cpu_alert": False,      # True si > 80%
            "memory_percent": 62.1,
            "memory_alert": False,   # True si > 90%
            "disk_percent": 55.0,
            "disk_alert": False,     # True si > 85%
            "uptime_seconds": 123456,
            "uptime_human": "1d 10h 17m"
        }
    """
```

#### `soc_get_network_metrics()`

Recull estadístiques de xarxa i connexions actives.

```python
def soc_get_network_metrics():
    """
    Returns:
        {
            "bytes_sent_rate": 1234,    # bytes/sec
            "bytes_recv_rate": 5678,    # bytes/sec
            "active_connections": 42,
            "established": 30,
            "listening": 12
        }
    """
```

#### `soc_get_security_events()`

Detecta events de seguretat i processos sospitosos.

```python
def soc_get_security_events():
    """
    Returns:
        {
            "ssh_failed_attempts": 15,
            ...
        }
    """
```

---

## Network IDS Shield (Scapy Engine)

El Diag Agent inclou un motor d'inspecció de xarxa en temps real (IDS) basat en la llibreria **Scapy**. A diferència de les mètriques estàndard que llegeixen del sistema operatiu, el Shield IDS realitza una **Inspecció de Paquets (DPI)** per detectar anomalies mentre ocorren.

### Arquitectura del Monitor

El monitor corre en un fil secundari (`daemon thread`) per no bloquejar el servidor Flask:

```python
class NetworkMonitor:
    def _run_sniffer(self):
        # Captura paquets de forma asíncrona
        sniff(prn=self._packet_callback, store=0)

    def _packet_callback(self, pkt):
        # Cervell de detecció: ports, taxes, volums
        self._check_triggers(pkt)
```

### Triggers de Seguretat

| Trigger | Lògica de Detecció | Gravetat |
|---------|-------------------|----------|
| **Dangerous Ports** | Intent de connexió als ports 21, 23, 445, 3389 | ALTA |
| **Brute Force** | Més de 20 paquets per segon des de la mateixa IP | CRÍTICA |
| **Data Exfiltration** | Transferència de més de 10MB cap a un destí extern | ALTA |

### Visualització del Dashboard

1. **Live Packet Feed**: Taula actualitzada cada 3 segons amb el resum de cada paquet (Protocol, Font, Destí, Port).
2. **Top Talkers**: Gràfic de barres dinàmic que identifica les adreces IP amb més càrrega de trànsit.
3. **Advanced Traffic Analytics**: Llista granular d'**IPs Úniques** separades per protocols (TCP vs UDP). Permet identificar ràpidament actors que només realitzen trànsit UDP "estrany".
4. **AI SOC Assistant**: Motor d'anàlisi heurística que classifica els events en categories ({Port Scan, Brute Force, DoS, etc.}) i genera un resum d'analista amb evidències i accions recomanades.
5. **Control Status**: Botó interactiu per activar/desactivar el blindatge de xarxa a demanda.

> [!TIP]
> L'IDS filtra automàticament el trànsit propi de la màquina (self-traffic filtering) per evitar que les teves pròpies auditories apareguin com a atacs al dashboard.

> [!IMPORTANT]
> Aquest mòdul requereix que l'agent s'executi com a **root** (o amb capabilities de `CAP_NET_RAW`) per poder obrir sockets de baix nivell i interceptar el trànsit de la interfície.

---

## Detecció de Processos Sospitosos

El sistema utilitza heurístiques per identificar processos potencialment maliciosos:

### Criteris de Detecció

| Criteri | Descripció | Exemple |
|---------|------------|---------|
| **Ruta no estàndard** | Executable fora de /usr, /bin, /sbin | `/home/user/.hidden/malware` |
| **Patrons sospitosos** | .tmp, .sh, .py a nom d'executable | `payload.tmp.sh` |
| **Noms ocults** | Fitxers que comencen amb `.` | `/.secret_miner` |
| **Root des d'usuari** | Procés root des de /home o /tmp | `sudo /tmp/exploit` |
| **Port no estàndard** | Procés escoltant en ports inusuals | `nc -l 4444` |

### Implementació

```python
def collect_suspicious_processes(limit=200):
    """
    Heuristics:
      - Executable path not under standard system paths
      - Executable contains .tmp, .sh, .py, /tmp/, hidden names
      - Running as root from user dirs (/home, /tmp)
      - Listening network processes not from standard paths
    """
    suspicious = []
    
    # Whitelist de rutes del sistema
    SYSTEM_PATHS = [
        "/usr/", "/bin/", "/sbin/", "/lib/",
        "/opt/", "/snap/", "/var/lib/"
    ]
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
        exe = proc.info['exe'] or ""
        
        # Check if outside system paths
        if exe and not any(exe.startswith(p) for p in SYSTEM_PATHS):
            suspicious.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "exe": exe,
                "reason": "Non-standard path"
            })
    
    return suspicious[:limit]
```

---

##  Gràfiques en Temps Real

El frontend utilitza **Chart.js** per renderitzar gràfiques interactives:

```javascript
// Exemple de configuració Chart.js
const cpuChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: timestamps,
        datasets: [{
            label: 'CPU %',
            data: cpuData,
            borderColor: 'rgb(59, 130, 246)',
            fill: true,
            backgroundColor: 'rgba(59, 130, 246, 0.1)'
        }]
    },
    options: {
        responsive: true,
        scales: { y: { min: 0, max: 100 } }
    }
});
```

### Tipus de Gràfiques

| Mètrica | Tipus | Actualització |
|---------|-------|---------------|
| CPU | Línia | Cada 2s |
| Memòria | Línia | Cada 2s |
| Disc | Gauge | Cada 10s |
| Xarxa TX | Àrea | Cada 2s |
| Xarxa RX | Àrea | Cada 2s |

---

## Sistema d'Alertes

### Llindars Configurats

```python
THRESHOLDS = {
    "cpu_warning": 70,
    "cpu_critical": 90,
    "memory_warning": 80,
    "memory_critical": 95,
    "disk_warning": 80,
    "disk_critical": 90,
    "ssh_fails_warning": 10,
    "ssh_fails_critical": 50
}
```

---

## Logs Crítics

```python
def soc_get_critical_logs(lines=15):
    """
    Get critical system logs with clean formatting.
    
    Sources:
        - /var/log/syslog
        - /var/log/auth.log
        - journalctl -p err
    
    Returns:
        [
            {
                "timestamp": "2025-01-15 10:30:45",
                "level": "ERROR",
                "source": "sshd",
                "message": "Failed password for invalid user admin"
            },
            ...
        ]
    """
```

---

!!! info "Futures Millores"
    - Alertes per email/Telegram
    - Històric persistent amb SQLite
    - Dashboard multi-host
    - Integració amb Grafana
