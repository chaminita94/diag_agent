# Cybershield Solutions — Diag Agent

**Automatització d'Auditories i Pla de Millora**

---

## Benvingut a la Documentació

Aquesta documentació cobreix el projecte **Diag Agent** de Cybershield Solutions, una eina professional d'auditoria de seguretat per a sistemes Linux.

### Característiques Principals

- **Auditoria Automatitzada**: Escaneig de vulnerabilitats, ports i configuracions SSH en minuts
- **Pentest Agent**: Nou mòdul d'auditoria web professional (SQLi, XSS, LFI)
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
| **WeasyPrint** | Generació d'informes PDF |
| **PyHanko** | Signatura digital de documents |

---

## Fitxers Principals

| Fitxer | Línies | Descripció |
|--------|--------|------------|
| `diag_agent_single.py` | ~7.320 | Agent principal amb interfície web |
| `pentest_agent.py` | ~3.282 | Nou motor de pentesting web |
| `setup_diag.sh` | 137 | Script d'instal·lació automatitzat |
| `Website/index.html` | 1280 | Landing page corporativa |
| `Website/custom.css` | 1405 | Estils de la web |
| `Website/custom.js` | - | Interactivitat i animacions |

---

!!! info "Projecte Acadèmic"
    Aquest projecte forma part del cicle formatiu ASIX amb perfil de Ciberseguretat a l'Institut de l'Ebre.

---

**Autor**: Vitaliy Domin  
**Versió**: 2026 Professional Edition  
**Empresa**: Cybershield Solutions, S.L.
