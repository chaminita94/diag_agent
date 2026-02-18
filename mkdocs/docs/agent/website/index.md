# Website Corporativa

La pàgina web de **Cybershield Solutions** és el portal públic de l'empresa — el primer punt de contacte amb clients potencials. Accessible a [cshield.duckdns.org](https://cshield.duckdns.org), presenta els serveis d'auditoria, demostra les capacitats del Diag Agent, i converteix visitants en clients.

---

## Proposta de Valor

### Per què existeix aquesta web?

Cybershield necessitava un portal que fes tres coses alhora: **vendre**, **demostrar** i **documentar**. La web resol això amb un disseny que transmet seguretat i professionalitat des del primer segon.

| Objectiu | Com ho aconseguim |
|----------|-------------------|
| **Vendre serveis** | Seccions de serveis, tarifes i formulari de contacte |
| **Demostrar l'eina** | Carrusel amb 22 captures + demo en viu a [democshield.duckdns.org](https://democshield.duckdns.org) |
| **Generar confiança** | Disseny premium dark, terminal animat, certificacions i metodologia SCRUM |
| **Convertir** | CTAs estratègics, plans de preus comparatius i accés directe a la demo |

### Primera impressió

El visitant arriba i veu:

1. **Títol gradient animat** — "Automatització d'auditories i plans de millora"
2. **Terminal widget** — Simula comandes reals (`trivy`, `nmap`, `ssh-audit`) amb efecte typewriter
3. **Dos botons d'acció** — "Prova el Diag Agent" i "Sol·licita una auditoria"
4. **Logos de tecnologies** — Linux, Ubuntu, Docker, Python, Proxmox, Grafana

---

## Capacitats del Sistema

La web presenta les 15 funcionalitats del Diag Agent agrupades per àrea de valor:

###  Seguretat Preventiva

| Mòdul | Eina | Què fa |
|-------|------|--------|
| **Escaneig de Vulnerabilitats** | Trivy | CVEs en rootfs i Docker, filtrat per severitat |
| **Auditoria SSH** | SSH-Audit | Algoritmes KEX/MAC, classificació de seguretat |
| **Gestió de Paquets** | apt/dpkg | Detecció de paquets desactualitzats |
| **Hardening** | — | Recomanacions de reforç (SSH, TLS, permisos) |

###  Detecció Activa

| Mòdul | Eina | Què fa |
|-------|------|--------|
| **SOC Dashboard** | Scapy + Chart.js | Network IDS en temps real, Port Scan/Brute Force/DoS |
| **Monitoratge de Serveis** | psutil | Processos sospitosos, whitelist configurable |
| **Anàlisi de Logs** | syslog | auth.log, kern.log, patrons anòmals |
| **Anàlisi de Xarxa** | Nmap | Ports oberts, versions, serveis perillosos |

###  Intel·ligència

| Mòdul | Eina | Què fa |
|-------|------|--------|
| **OSINT Recon** | TheHarvester | Emails, subdominis, IPs, Certificate Transparency |
| **Shodan Threat Intel** | Shodan API | Exposició pública, CVEs, ISP/ASN/Geo |
| **AI Security** | z.ai | Audit Manager, Agent Autònom (beta), Chat, Risk Score |
| **Enum4linux** | enum4linux | SMB/NetBIOS, usuaris, shares |

###  Desplegament i Integració

| Mòdul | Què fa |
|-------|--------|
| **Pentest Agent** | Scanner web: SQLi, XSS, LFI + Nikto/SQLMap |
| **Target OS Scan** | Multi-plataforma: Windows (AD/SMB), macOS, iOS |
| **Docker USB** | 100% offline, Trivy DB pre-cached, plug & play |
| **Integrations** | Nikto, SQLMap, Hydra, Telegram Bot |

### Serveis Comercials

Tres plans presentats en targetes amb comparativa:

| Pla | Preu | Per a qui |
|-----|------|-----------|
| **Start** | €399/auditoria | Empresa que vol una primera avaluació |
| **Pro** ⭐ | €699.99/mes | Fins 5 servidors, monitoratge continu |
| **Enterprise** | A mida | Alta disponibilitat, SIEM, formació IR |

---

## Robustesa Tècnica

### Superfície d'atac zero

La web és **100% estàtica** — HTML, CSS i JavaScript purs servits per Nginx. No hi ha backend, base de dades ni processos de build. Això significa:

- ✅ Sense dependències de runtime (Node.js, PHP, etc.)
- ✅ Sense vulnerabilitats de servidor d'aplicació
- ✅ Cache agressiu amb `expires 7d` per a assets
- ✅ Servida des de Nginx amb SSL (Let's Encrypt)

### Stack

| Tecnologia | Versió | Ús |
|------------|--------|-----|
| HTML5 | 5 | Estructura semàntica (`section`, `nav`, `header`, `footer`) |
| CSS3 | 3 | Glassmorphism, gradients, animacions, variables CSS |
| JavaScript | ES6+ | Canvas API, Intersection Observer, Touch Events, Classes |
| Bootstrap | 5.3.2 | Grid, components, navbar responsive |

### API REST com a capacitat d'integració

L'aplicació (no la web) exposa **+30 endpoints** per a integració amb SIEM/SOC:

```javascript
// Exemple: estat del sistema en temps real
fetch('/api/status')
  .then(r => r.json())
  .then(data => console.log('CPU:', data.cpu + '%'));
```

!!! note "Documentació API"
    Endpoints complets a la secció [API REST](../api.md).

### Informes Professionals

- **PDF** amb signatura digital X.509 (PyHanko) i segell visible Cybershield
- **CSV** per a importació a eines d'anàlisi
- **Telegram Bot** per enviament directe al mòbil

### SEO

Títol únic, meta description, Open Graph, Twitter Cards, HTML5 semàntic, `loading="lazy"`, IDs únics.

---

## Annex Tècnic

??? info "Arquitectura de fitxers"

    ```
    Website/
    ├── index.html              ─── 1.708 línies
    ├── custom.css              ─── 1.476 línies
    ├── custom.js               ─── 765 línies
    ├── carousel.css            ─── 332 línies
    └── Assets/
        ├── logo.png, foto.jpg, shield.png, web.png
        └── Fotos Web/newfotos/  ─── 22 screenshots
    ```

    **Total:** ~4.281 línies de codi

??? info "Sistema de disseny (CSS)"

    **Paleta:**

    | Variable | Color | Ús |
    |----------|-------|-----|
    | `--bg` | `#070b1a` | Fons principal |
    | `--panel` | `#0d1426` | Targetes |
    | `--accent-neon` | `#00d4ff` | CTAs, highlights |
    | `--accent-purple` | `#9c27ff` | Gradients, accents |

    **Efectes:** Glassmorphism (`backdrop-filter: blur`), partícules Canvas, 3D Tilt (`perspective`), glow multicapa, gradients animats.

    **Responsivitat:** Desktop (>1200px), Tablet (768–1200px), Mòbil (<768px).

??? info "Motor JavaScript (custom.js — 765 línies)"

    10 sistemes independents:

    | Sistema | ~Línies | Funció |
    |---------|---------|--------|
    | Partícules antigravity | 110 | 80 partícules Canvas amb repulsió del cursor |
    | Carrusel (AppCarousel) | 120 | Autoplay, swipe, keyboard, indicadors |
    | Cookie consent RGPD | 60 | Banner amb localStorage |
    | Terminal typewriter | 55 | 11 comandes amb escriptura/esborrat |
    | Formulari | 40 | Validació, loading, toast |
    | Cursor personalitzat | 40 | Cercle exterior + punt central |
    | Reveal on scroll | 30 | Intersection Observer |
    | Counter animation | 25 | Animació numèrica KPIs |
    | Ripple effect | 25 | Ona expansiva al clic |
    | 3D tilt + magnetic + spotlight | 50 | Efectes de profunditat i seguiment |

---

## Desplegament

| Entorn | URL |
|--------|-----|
| **Web principal** | [cshield.duckdns.org](https://cshield.duckdns.org) |
| **Demo Diag Agent** | [democshield.duckdns.org](https://democshield.duckdns.org) |

!!! tip "Configuració del servidor"
    Documentació completa del proxy revers, SSL i mode demo a [Proxy Revers](proxy.md).
