# Instal·lació

Guia completa per instal·lar el Diag Agent en un servidor Ubuntu.

---

## Requisits Previs

### Sistema Operatiu

- **Ubuntu Server** 20.04 LTS o 22.04 LTS
- Arquitectura: x86_64 (amd64)
- RAM mínima: 2GB
- Espai en disc: 5GB

### Accés

- Accés root o sudo
- Connexió a Internet (per descarregar dependències)

---

## Instal·lació Automàtica

### Pas 1: Copiar Fitxers

```bash
# Opció A: Via SCP
scp setup_diag.sh diag_agent_single.py cshield.png user@server:/opt/diag/

# Opció B: Via USB
mount /dev/sdb1 /mnt
cp /mnt/diag/* /opt/diag/
umount /mnt
```

### Pas 2: Permisos d'Execució

```bash
cd /opt/diag
sudo chmod +x setup_diag.sh diag_agent_single.py
```

### Pas 3: Executar Instal·lador

```bash
sudo ./setup_diag.sh [IP_BIND] [XARXA_PERMESA] [PORT]
```

**Paràmetres:**

| Paràmetre | Descripció | Valor per Defecte |
|-----------|------------|-------------------|
| `IP_BIND` | IP del servidor | `hostname -I` |
| `XARXA_PERMESA` | CIDR de xarxa permesa | `IP.0/24` |
| `PORT` | Port del servei | `8080` |

**Exemple:**
```bash
sudo ./setup_diag.sh 192.168.1.100 192.168.1.0/24 8080
```

---

## 📦 Dependències Instal·lades

### Paquets APT

```bash
PKGS=(
    python3              # Python 3.x
    python3-pip          # Gestor de paquets pip
    python3-venv         # Entorns virtuals
    python3-dev          # Headers de desenvolupament
    build-essential      # Compiladors (gcc, make)
    curl jq git          # Utilitats
    nmap                 # Escàner de xarxa
    ssh-audit            # Auditoria SSH
    smbclient            # Client SMB
    samba-common-bin     # Eines Samba
    libpango-1.0-0       # Dependència WeasyPrint
    libpangocairo-1.0-0  # Dependència WeasyPrint
    libcairo2            # Renderització PDF
)
```

### Paquets Python (venv)

```bash
pip install \
    flask              # Framework web
    psutil             # Mètriques del sistema
    weasyprint         # Generació PDF
    impacket           # Protocol SMB
    ldap3              # Client LDAP
    pyyaml             # Parsing YAML
    pyhanko[crypto]    # Signatura digital PDF
    cryptography       # Criptografia
    pyhanko-certvalidator  # Validació certificats
```

### Eines Externes

**enum4linux-ng** es clona des de GitHub:
```bash
git clone https://github.com/cddmp/enum4linux-ng.git
```

---

## Certificats de Signatura

L'instal·lador genera automàticament un certificat auto-signat:

```bash
# Directori de certificats
CERT_DIR="${SCRIPT_DIR}/certs"

# Genera clau privada RSA 2048 bits
openssl genrsa -out "${CERT_DIR}/cybershield.key" 2048

# Genera certificat auto-signat (vàlid 10 anys)
openssl req -new -x509 \
    -key "${CERT_DIR}/cybershield.key" \
    -out "${CERT_DIR}/cybershield.crt" \
    -days 3650 \
    -subj "/C=ES/ST=Barcelona/L=Barcelona/O=Cybershield Solutions/OU=Security Audit Division/CN=Cybershield Solutions/emailAddress=security@cybershield.solutions"

# Protegir clau privada
chmod 600 "${CERT_DIR}/cybershield.key"
```

### Fitxers Generats

```
/opt/diag/certs/
├── cybershield.key   # Clau privada (600)
└── cybershield.crt   # Certificat públic
```

---

## Servei Systemd

L'instal·lador crea un servei systemd:

### Fitxer de Servei

```ini
# /etc/systemd/system/diag-agent.service
[Unit]
Description=Diag Agent (no-auth) - portable version
After=network.target

[Service]
Type=simple
ExecStart=/opt/diag/venv/bin/python3 /opt/diag/diag_agent_single.py --host 192.168.1.100 --port 8080 --allow-from 192.168.1.0/24
WorkingDirectory=/opt/diag
Restart=on-failure
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Gestió del Servei

```bash
# Iniciar servei
sudo systemctl start diag-agent

# Aturar servei
sudo systemctl stop diag-agent

# Reiniciar servei
sudo systemctl restart diag-agent

# Veure estat
sudo systemctl status diag-agent

# Habilitar a l'arrencada
sudo systemctl enable diag-agent

# Deshabilitar
sudo systemctl disable diag-agent
```

### Logs del Servei

```bash
# Veure logs en temps real
journalctl -u diag-agent -f

# Últimes 100 línies
journalctl -u diag-agent -n 100

# Logs des d'avui
journalctl -u diag-agent --since today
```

---

## Verificació

### Comprovar Servei

```bash
sudo systemctl status diag-agent
```

Sortida esperada:
```
● diag-agent.service - Diag Agent (no-auth) - portable version
     Loaded: loaded (/etc/systemd/system/diag-agent.service; enabled)
     Active: active (running) since Mon 2025-01-15 10:00:00 CET
   Main PID: 1234 (python3)
      Tasks: 1 (limit: 4915)
     Memory: 50.0M
```

### Comprovar Accés Web

```bash
curl -s http://localhost:8080/api/status | jq
```

O des d'un navegador:
```
http://192.168.1.100:8080/
```

---

## 🔥 Firewall

Si utilitzes `ufw`:

```bash
# Permetre el port del Diag Agent
sudo ufw allow 8080/tcp

# Verificar regles
sudo ufw status
```

---

## Desinstal·lació

Per eliminar completament el Diag Agent:

```bash
# Aturar i deshabilitar servei
sudo systemctl stop diag-agent
sudo systemctl disable diag-agent

# Eliminar fitxer de servei
sudo rm /etc/systemd/system/diag-agent.service
sudo systemctl daemon-reload

# Eliminar fitxers
sudo rm -rf /opt/diag
```

---

!!! tip "Actualitzacions"
    Per actualitzar el Diag Agent, simplement reemplaça el fitxer `diag_agent_single.py` i reinicia el servei:
    ```bash
    sudo cp diag_agent_single_new.py /opt/diag/diag_agent_single.py
    sudo systemctl restart diag-agent
    ```
