# Manual d'Usuari

## Introducció

Diag Agent és una eina d'auditoria de seguretat desenvolupada per **Cybershield Solutions, S.L.** que permet realitzar anàlisis complets de sistemes Linux Ubuntu Server.

## Accés a l'Aplicació

Un cop el servei està en funcionament, accediu a la interfície web:

```
http://<IP_DEL_SERVIDOR>:8080
```

## Pestanyes Principals

### Dashboard

La pestanya principal mostra un resum de l'estat del sistema amb targetes clares per a:

- **Vulnerabilitats**: Nombre de CVEs detectats
- **Paquets**: Paquets actualitzables
- **SSH Fails**: Intents d'accés SSH fallits
- **CPU/Memòria/Disc**: Ús de recursos del sistema

### Vulns (Vulnerabilitats)

Anàlisi de vulnerabilitats utilitzant **Trivy**:

- Escaneig del sistema de fitxers (`rootfs`)
- Detecció de CVEs crítics i d'alta prioritat
- Optimitzat per ometre directoris temporals (`/tmp`, `/var/cache`)

### Nmap

Escaneig de xarxa amb validació de seguretat:

- Escaneig de ports TCP
- Detecció de serveis i versions
- Flags permesos: `-sV`, `-Pn`, `-T4`

### Services

Llistat de serveis del sistema i el seu estat actual.

### Logs

Anàlisi dels registres del sistema per detectar anomalies.

### SSH Logs

Monitoratge específic d'accessos SSH i intents de força bruta.

## Generació d'Informes

La pestanya **Report** permet:

### Selecció Modular

L'usuari pot triar quines seccions incloure a l'informe:

- [x] Vulnerabilitats (Trivy)
- [x] Escaneig de xarxa (Nmap)
- [x] Logs del sistema
- [x] Accessos SSH
- [x] Processos sospitosos
- [x] Serveis
- [x] Paquets actualitzables

### Formats d'Exportació

| Format | Descripció |
|--------|------------|
| **PDF** | Document professional amb marca d'aigua de Cybershield Solutions, taula de resum executiu i detalls tècnics |
| **CSV** | Dades en brut per a tractament posterior en fulls de càlcul |

!!! tip "Consell"
    Per a informes executius, seleccioneu només les seccions de Vulnerabilitats i Resum. Per a informes tècnics complets, seleccioneu totes les seccions.

---

## Desinstal·lació

Per eliminar completament el Diag Agent del sistema, s'ha proporcionat un script de desinstal·lació que neteja tots els components.

### Execució

```bash
# Des del directori del Diag Agent
sudo ./uninstall_diag.sh
```

### Components Eliminats

L'script elimina els següents components:

| Component | Descripció |
|-----------|------------|
| **Servei systemd** | `diag-agent.service` - Atura i elimina el servei |
| **Entorn virtual** | `venv/` - Tot el Python virtualenv amb les dependències |
| **enum4linux-ng** | Directori clonat de GitHub |
| **Certificats** | `certs/` - Claus privades i certificats generats |
| **Paquets APT** | Opcional - `ssh-audit` i altres eines |
| **Fitxers Python** | Opcional - `diag_agent_single.py`, `pentest_agent.py`, etc. |

### Modes de Desinstal·lació

L'script ofereix diferents nivells de neteja:

1. **Desinstal·lació Parcial**: Elimina servei, venv, i components del sistema però conserva els fitxers Python (permet reinstal·lar fàcilment)

2. **Desinstal·lació Completa**: Elimina absolutament tot, incloent els fitxers Python i l'script mateix

!!! warning "Atenció"
    La desinstal·lació completa és irreversible. Assegureu-vos de tenir una còpia de seguretat dels fitxers si cal.

### Confirmació de Seguretat

Per evitar eliminacions accidentals, l'script requereix confirmació explícita:

```
Estàs segur que vols continuar? (escriu 'SI' per confirmar): SI
```

### Què NO s'elimina

Per seguretat, l'script **NO** elimina:

- Paquets essencials del sistema (`python3`, `curl`, `git`, etc.)
- Eines comunes que poden ser usades per altres aplicacions (`nmap`, `smbclient`)
- Configuracions del sistema no relacionades amb Diag Agent

