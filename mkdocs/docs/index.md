# Cybershield Solutions — Diag Agent

**Automatització d'Auditories i Pla de Millora**

---

## Benvingut a la Documentació

Aquesta documentació cobreix el projecte **Diag Agent** de Cybershield Solutions, una eina professional d'auditoria de seguretat per a sistemes Linux.

### Característiques Principals

- **Auditoria Automatitzada**: Escaneig de vulnerabilitats, ports i configuracions SSH en minuts
- **Target OS Scan**: Escaneig multi-plataforma (Windows, macOS, iOS, Linux)
- **Pentest Agent**: Mòdul d'auditoria web professional (SQLi, XSS, LFI) + Nikto/SQLMap
- **AI Security**: Anàlisi intel·ligent amb z.ai — Chat, Auditoria i Agent Autònom (beta)
- **SOC Dashboard**: Monitoratge en temps real de CPU, memòria, xarxa i events de seguretat
- **Informes Professionals**: Generació de PDF amb signatura digital i enviament via Telegram
- **API REST**: Integració segura amb sistemes externs

---

## Continguts

| Secció | Descripció |
|--------|------------|
| [**Context del Projecte**](agent/context.md) | Presentació de Cybershield Solutions i objectius |
| [**Metodologia SCRUM**](agent/scrum.md) | Organització del projecte amb metodologia àgil |
| [**Empresa Auditada**](agent/empresa-auditada.md) | Institut de l'Ebre i la seva infraestructura |
| [**Identificació d'Actius**](agent/actius.md) | Anàlisi dels actius i amenaces |
| [**Valoració del Risc**](agent/valoracio.md) | Taula de riscos i mesures preventives |
| [**Arquitectura**](agent/arquitectura.md) | Disseny tècnic del Diag Agent |
| [**Mòduls de Seguretat**](agent/moduls.md) | Trivy, Nmap, SSH-Audit, Enum4Linux |
| [**Pentest Agent**](agent/pentest.md) | Nou motor d'auditoria web (SQLi, XSS, etc.) |
| [**SOC Dashboard**](agent/soc.md) | Centre d'Operacions de Seguretat |
| [**API REST**](agent/api.md) | Documentació dels endpoints |
| [**Integracions**](agent/integracions.md) | Telegram i notificacions |
| [**Hardening**](agent/hardening.md) | Seguretat i tancament d'amenaces |
| [**OSINT Recon**](agent/osint.md) | Reconeixement passiu de dominis |
| [**Requisits**](agent/requisits.md) | Dependències del sistema |
| [**Instal·lació**](agent/installacio.md) | Guia d'instal·lació completa |
| [**Configuració**](agent/configuracio.md) | Paràmetres i systemd |
| [**Website**](agent/website/index.md) | Documentació de la landing page |
| [**Manual d'Usuari**](agent/manual/index.md) | Com utilitzar l'eina |
| [**Signatura Digital**](agent/signatura/index.md) | Certificats i signatura PDF |
| [**Conclusions**](agent/conclusions/index.md) | Conclusions i futures millores |

---

## Començar Ràpidament

```bash
# 1. Copiar fitxers al servidor
scp setup_diag.sh diag_agent_single.py user@server:/opt/diag/

# 2. Donar permisos
sudo chmod +x setup_diag.sh

# 3. Executar instal·lació
sudo ./setup_diag.sh

# 4. Accedir a la interfície
firefox http://192.168.1.100:8080
```

---

## Eines Integrades

| Eina | Funció |
|------|--------|
| **Trivy** | Escaneig de vulnerabilitats (CVEs) |
| **Nmap** | Escaneig de ports i serveis |
| **SSH-Audit** | Auditoria de configuració SSH |
| **Enum4Linux** | Enumeració de serveis SMB |
| **theHarvester** | Reconeixement OSINT passiu |
| **Subfinder** | Descobriment exhaustiu de subdominis |
| **Shodan API** | Intel·ligència d'infraestructura i CVEs |
| **Nikto** | Escàner de vulnerabilitats web |
| **SQLMap** | Detecció de SQL Injection |
| **Hydra** | Atacs de força bruta |
| **z.ai API** | Motor AI per auditoria i chat intel·ligent |
| **WeasyPrint** | Generació d'informes PDF |
| **PyHanko** | Signatura digital de documents |

---

## Fitxers Principals

| Fitxer | Línies | Descripció |
|--------|--------|------------|
| `diag_agent_single.py` | 15.275 | Agent principal amb interfície web, SOC Dashboard i Unified Scanner |
| `pentest_agent.py` | 3.281 | Motor de pentesting web professional (SQLi, XSS, LFI) |
| `audit_manager.py` | 624 | Auditoria AI amb z.ai, zero-days i CVEs |
| `autonomous_agent.py` | 147 | Agent autònom amb comandes segures |
| `os_scanner.py` | 672 | Escaneig multi-OS (Windows, macOS, iOS, Linux) |
| `setup_diag.sh` | 406 | Script d'instal·lació automatitzat |
| `uninstall_diag.sh` | 432 | Script de desinstal·lació completa |

---

!!! info "Projecte Acadèmic"
    Aquest projecte forma part del cicle formatiu ASIX amb perfil de Ciberseguretat a l'Institut de l'Ebre.

---

**Autor**: Vitaliy Domin  
**Versió**: 4.10.0 (February 2026)  
**Empresa**: Cybershield Solutions, S.L.
