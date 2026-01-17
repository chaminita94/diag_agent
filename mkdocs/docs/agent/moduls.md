# Mòduls de Seguretat

El Diag Agent integra múltiples eines de seguretat de codi obert en un únic tauler de control unificat.

---

## Scanner de Vulnerabilitats (Trivy)

### Descripció

**Trivy** és un escàner de vulnerabilitats complet per a contenidors, sistemes de fitxers i repositoris git.

### Configuració al Diag Agent

```python
def collect_trivy(limit=200):
    """
    Analitza el sistema de fitxers (rootfs) per detectar CVEs.
    Optimització: Omit directoris temporals per reduir temps.
    """
    cmd = "trivy fs / --skip-dirs /tmp --skip-dirs /var/cache -f json"
    result = subprocess.run(cmd, shell=True, capture_output=True, timeout=300)
    ...
```

### Funcionalitats

| Característica | Descripció |
|----------------|------------|
| **Escaneig rootfs** | Analitza tot el sistema de fitxers |
| **Filtrat per severitat** | CRITICAL, HIGH, MEDIUM, LOW |
| **Base de dades** | CVE actualitzada contínuament |
| **Optimització** | Skip de /tmp, /var/cache |
| **Límit de resultats** | Configurable (per defecte 200) |

### Sortida

```json
{
  "Results": [
    {
      "Target": "apt",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-XXXX",
          "PkgName": "openssl",
          "Severity": "HIGH",
          "Title": "Buffer overflow in...",
          "Description": "..."
        }
      ]
    }
  ]
}
```

---

## Auditoria de Xarxa (Nmap)

### Descripció

**Nmap** és l'escàner de xarxa més utilitzat, integrat amb validació d'arguments per seguretat.

### Classificació de Ports

```python
class NmapParser:
    DANGEROUS_PORTS = {
        21: "FTP - Unencrypted file transfer protocol",
        23: "Telnet - Unencrypted remote access (use SSH)",
        25: "SMTP - Mail server (check auth)",
        69: "TFTP - Trivial FTP (no auth)",
        110: "POP3 - Unencrypted mail",
        135: "MSRPC - Windows RPC",
        139: "NetBIOS - Windows shares",
        445: "SMB - Windows/Samba shares",
        512: "rexec - Remote exec",
        513: "rlogin - Remote login",
        514: "RSH - Remote shell",
        1433: "MSSQL - Database",
        1521: "Oracle - Database",
        3306: "MySQL - Database",
        3389: "RDP - Remote Desktop",
        5432: "PostgreSQL - Database",
        5900: "VNC - Remote desktop",
        6379: "Redis - Cache (no auth default)"
    }
```

### Arguments Segurs Permesos

```python
SINGLE_TOKEN_WHITELIST = {"-p-", "-Pn", "-sV", "-v", "-vv", "-A"}
T_TUNING_RE = re.compile(r"^-T[0-5]$")  # -T0 a -T5
```

!!! warning "Seguretat"
    - ❌ `--script*` rebutjat
    - ❌ Metacaràcters shell rebutjats
    - ✅ Només flags de la whitelist

### Exemple d'Ús

```bash
# Via API
curl -X POST http://localhost:8080/api/nmap_scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "extra_args": "-sV -T4"}'
```

---

## Auditoria SSH (SSH-Audit)

### Descripció

Mòdul específic que analitza la configuració del servei SSH, detectant configuracions insegures.

### Patrons de Detecció

```python
class SSHAuditParser:
    FAIL_PATTERNS = [
        r'\(fail\)',
        r'weak\s+\(',
        r'broken',
        r'vulnerable',
        r'deprecated',
        r'SHA-?1',
        r'MD5',
        r'3DES',
        r'RC4',
        r'CBC mode'
    ]
    
    SECURE_PATTERNS = [
        r'ECDH',
        r'ed25519',
        r'chacha20',
        r'gcm@openssh',
        r'umac-128'
    ]
```

### Classificació d'Algoritmes

| Nivell | Descripció | Exemples |
|--------|------------|----------|
| 🟢 **Secure** | Recomanats | Ed25519, ChaCha20, AES-GCM |
| 🟡 **Attention** | Acceptables però millorables | ECDSA, AES-CTR |
| 🔴 **Fail** | Insegurs, eliminar | 3DES, MD5, SHA1, RC4 |

### Report Generat

```python
@dataclass
class SSHAuditReport:
    banner: str = ""
    software: str = ""
    protocol_version: str = ""
    kex_secure: List[SSHAlgorithm] = field(default_factory=list)
    kex_weak: List[SSHAlgorithm] = field(default_factory=list)
    hostkey_secure: List[SSHAlgorithm] = field(default_factory=list)
    hostkey_weak: List[SSHAlgorithm] = field(default_factory=list)
    enc_secure: List[SSHAlgorithm] = field(default_factory=list)
    enc_weak: List[SSHAlgorithm] = field(default_factory=list)
    mac_secure: List[SSHAlgorithm] = field(default_factory=list)
    mac_weak: List[SSHAlgorithm] = field(default_factory=list)
    fingerprints: Dict[str, str] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    critical_issues: List[str] = field(default_factory=list)
    hardening_actions: List[str] = field(default_factory=list)
```

### Recomanacions de Hardening

L'eina genera automàticament recomanacions com:

```text
✅ Disable weak algorithms in /etc/ssh/sshd_config
✅ Use Ed25519 keys instead of RSA
✅ Set KexAlgorithms curve25519-sha256@libssh.org
✅ Set Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
✅ Set MACs hmac-sha2-512-etm@openssh.com
```

---

## Enumeració SMB (Enum4Linux)

### Descripció

Mòdul per auditar servidors Samba i entorns híbrids Windows/Linux.

### Funcionalitats

```python
def collect_enum4linux(target_str="192.168.1.1", options=None):
    """
    Executes enum4linux/enum4linux-ng against a target for SMB enumeration.
    
    Args:
        target_str: IP address or hostname
        options: dict with keys like 'users', 'shares', 'groups', 'policy'
    
    Returns:
        Structured dict with parsed results
    """
```

### Opcions d'Escaneig

| Opció | Flag | Descripció |
|-------|------|------------|
| `users` | `-U` | Enumerar usuaris |
| `shares` | `-S` | Llistar shares |
| `groups` | `-G` | Grups i membres |
| `policy` | `-P` | Política de contrasenyes |
| `rid_cycling` | `-r` | Enumerar RIDs (brute-force) |

### Sortida Parsejada

```python
def parse_enum4linux_output(raw_text, target, duration):
    return {
        "target": target,
        "duration": duration,
        "os_info": {...},
        "users": [...],
        "shares": [...],
        "groups": [...],
        "password_policy": {...},
        "domain_info": {...}
    }
```

---

## Comparativa de Mòduls

| Mòdul | Temps Típic | Risc | Invasivitat |
|-------|-------------|------|-------------|
| **Trivy** | 30-120s | Cap | Només lectura |
| **Nmap** | 10-300s | Baix | Escaneig actiu |
| **SSH-Audit** | 2-5s | Cap | Una connexió SSH |
| **Enum4Linux** | 10-60s | Baix | Queries SMB |

---

!!! tip "Bones Pràctiques"
    1. Executar Trivy primer per tenir una visió general
    2. Utilitzar Nmap amb `-sV` per detectar versions
    3. SSH-Audit per validar configuració SSH
    4. Enum4Linux només si hi ha serveis SMB
