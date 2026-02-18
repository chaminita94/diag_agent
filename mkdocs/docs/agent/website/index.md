# Website Corporativa — Cybershield Solutions

**Data:** Febrer 2026  
**Versió:** 3.0  
**Estat:** Producció  
**URL:** [https://cshield.duckdns.org](https://cshield.duckdns.org)

---

## Taula de Continguts

1. [Visió General](#visió-general)
2. [Stack Tecnològic](#stack-tecnològic)
3. [Arquitectura dels Fitxers](#arquitectura-dels-fitxers)
4. [Seccions de la Pàgina](#seccions-de-la-pàgina)
5. [Sistema de Disseny](#sistema-de-disseny)
6. [Motor d'Interactivitat](#motor-dinteractivitat)
7. [SEO i Metadades](#seo-i-metadades)
8. [Desplegament i Proxy Revers](#desplegament-i-proxy-revers)
9. [Accés](#accés)

---

## Visió General

La pàgina web de **Cybershield Solutions** és el portal corporatiu de l'empresa, dissenyat per transmetre confiança, professionalitat i capacitat tècnica als clients potencials. Serveix com a punt d'entrada principal per a la presentació dels serveis d'auditoria de seguretat i la demostració de l'eina **Diag Agent**.

### Objectius del Lloc Web

| Objectiu | Implementació |
|----------|---------------|
| **Presentació comercial** | Serveis, tarifes i formulari de contacte |
| **Demostració de l'eina** | Carrusel interactiu amb 22 captures de l'app |
| **Documentació tècnica** | 15 funcionalitats detallades amb especificacions |
| **Confiança visual** | Disseny premium amb efectes glassmorphism i partícules |
| **Conversió** | CTAs estratègics, plans de preus i demo en viu |

---

## Stack Tecnològic

| Tecnologia | Versió | Ús | Detalls |
|------------|--------|-----|---------|
| **HTML5** | 5 | Estructura semàntica | `<section>`, `<article>`, `<nav>`, `<header>`, `<footer>` |
| **CSS3** | 3 | Estils i animacions | Variables CSS, Glassmorphism, Gradients, Keyframes |
| **JavaScript** | ES6+ | Interactivitat | Classes, Intersection Observer, Canvas API, Touch Events |
| **Bootstrap** | 5.3.2 | Framework CSS | Grid system, components, utilities |
| **Bootstrap Icons** | 1.11.3 | Iconografia | +1.900 icones vectorials SVG |
| **Google Fonts** | — | Tipografia | Inter (text) · JetBrains Mono (codi) |

!!! tip "Sense dependències externes de build"
    El lloc web és 100% estàtic — no requereix Node.js, bundlers ni processos de compilació. Es serveix directament des de Nginx.

---

## Arquitectura dels Fitxers

```
Website/
├── index.html              # Pàgina principal ─────────── 1.708 línies
├── custom.css              # Sistema de disseny ────────── 1.476 línies
├── custom.js               # Motor d'interactivitat ───── 765 línies
├── carousel.css            # Estils del carrusel ──────── 332 línies
└── Assets/
    ├── logo.png            # Logo Cybershield (navbar + footer)
    ├── foto.jpg            # Foto professional del fundador
    ├── shield.png          # Imatge decorativa (secció About)
    ├── web.png             # Preview Open Graph (xarxes socials)
    └── Fotos Web/
        └── newfotos/       # 22 captures actualitzades de l'app
            ├── screenshot_1.png
            ├── screenshot_2.png
            ├── ...
            └── screenshot_22.png
```

**Total línies de codi:** ~4.281 línies (HTML + CSS + JS)

---

## Seccions de la Pàgina

### 1. Navegació (Navbar)

Barra de navegació fixa a la part superior amb efecte **glassmorphism** (`backdrop-filter: blur`):

| Element | Detalls |
|---------|---------|
| **Logo** | Imatge amb animació de flotació contínua (`float` keyframe) |
| **Menú** | 9 enllaços: Serveis, App, Funcionalitats, Equip, Sobre, Tarifes, Contacte, FAQ, Notícies |
| **CTA** | Botó "Comença ara" amb gradient neon que redirigeix a `#contacte` |
| **Scroll effect** | Canvia opacitat i shadow en fer scroll (`scrolled` class) |
| **Mobile** | Hamburger menu amb collapse de Bootstrap |

La barra de progrés de scroll (`#scrollProgress`) es mostra a la part superior i indica el percentatge de pàgina navegat.

---

### 2. Hero Section

La secció d'impacte inicial que els visitants veuen primer:

- **Títol**: "Automatització d'**auditories** i plans de **millora**" amb text gradient animat
- **Subtítol**: Descripció del servei amb paraules clau destacades en `<span class="text-gradient">`
- **Botons d'acció**:
    - 🔵 "Prova el Diag Agent" → `#app`
    - ⚪ "Sol·licita una auditoria" → `#contacte`
- **Indicadors de metodologia**: SCRUM · Open-Source · Resultats mesurables
- **Terminal Widget animat**: Simula comandes reals del Diag Agent amb efecte typewriter:

```bash
$ diag-agent --scan --full
$ trivy fs / --severity HIGH,CRITICAL
$ nmap -sV -sC localhost
$ ssh-audit 127.0.0.1
$ diag-agent --report --pdf --sign
$ curl /api/soc/metrics | jq .
$ theHarvester -d target.com -b crtsh
$ docker run -d -p 8080:8080 diag-agent
$ python pentest.py --target https://example.com
$ enum4linux -a 192.168.1.100
```

- **Logos de tecnologies**: Linux, Ubuntu, Proxmox, Grafana, Docker, Python

---

### 3. Serveis

Quatre targetes amb efecte *glass* i tilt 3D al hover:

| Icona | Servei | Descripció |
|-------|--------|------------|
| 🛡️ | **Auditoria de seguretat** | Anàlisi de vulnerabilitats, revisió de configuracions i mapeig d'exposició de serveis |
| 🔧 | **Hardening & millora** | Reforç de SSH, TLS, serveis, permisos i actualitzacions controlades |
| 📊 | **Monitoratge continu** | Diag Agent en mode servei 24/7 amb vigilància de processos, logs i paquets |
| 🎓 | **Resposta i formació** | Tallers per equips tècnics i procediments d'incident response |

---

### 4. App / Diag Agent

Presentació completa de l'eina organitzada en dues columnes de funcionalitats:

**Columna esquerra:**

| Mòdul | Descripció |
|-------|------------|
| **Dashboard Executiu** | Avaluació d'integritat, KPIs en temps real i AI Advisor |
| **SOC Dashboard** | Monitoratge en temps real amb Network IDS (Scapy) i alertes intel·ligents |
| **Pentest Agent** | Scanner web amb detecció de SQLi, XSS, LFI + Nikto i SQLMap |
| **OSINT Recon** | TheHarvester + Shodan + Certificate Transparency Logs |
| **AI Security** | Auditoria intel·ligent amb z.ai — Chat, Audit i Agent Autònom (beta) |

**Columna dreta:**

| Mòdul | Descripció |
|-------|------------|
| **Target OS Scan** | Escaneig multi-plataforma (Windows, macOS, iOS, Linux) |
| **Informes signats** | PDF/CSV amb signatura digital X.509 i segell visible |
| **Telegram** | Enviament d'informes PDF directament al mòbil |
| **API RESTful** | Més de 30 endpoints per a integració amb SIEM/SOC |
| **Setup automatitzat** | Instal·lació en minuts amb systemd service |

Inclou un **carrusel interactiu** amb 22 captures de pantalla de l'aplicació, amb autoplay, navegació per fletxes, indicadors i suport tàctil.

---

### 5. Funcionalitats Detallades

Quinze targetes tècniques amb icones i descripcions exhaustives de cada mòdul del Diag Agent:

#### Mòduls Core

| # | Mòdul | Eines | Característiques Clau |
|---|-------|-------|----------------------|
| 1 | **Escaneig de Vulnerabilitats** | Trivy | Rootfs, Docker/Podman, filtrat per severitat, base de dades CVE actualitzada |
| 2 | **Anàlisi de Xarxa** | Nmap | Descobriment de hosts, detecció de versions, ports perillosos, límit 250k chars |
| 3 | **Auditoria SSH** | SSH-Audit | Algoritmes KEX/MAC/Encryption, classificació de seguretat, fingerprints |
| 4 | **Gestió de Paquets** | apt/dpkg | Llistat, actualitzables, versions, historial |
| 5 | **Monitoratge de Serveis** | psutil | Processos sospitosos, whitelist, ús de recursos, serveis exposats |
| 6 | **Anàlisi de Logs** | syslog | auth.log, kern.log, filtrat temporal, patrons anòmals |

#### Mòduls Avançats

| # | Mòdul | Eines | Característiques Clau |
|---|-------|-------|----------------------|
| 7 | **SOC Dashboard** | Scapy, Chart.js | Network IDS, Port Scan/Brute Force/DoS detection, Live Packet Feed, Top Talkers |
| 8 | **Pentest Agent** | Crawler propi | SQLi (Error/Boolean/Time), XSS, LFI, Command Injection, CORS, Cookie Security |
| 9 | **OSINT Recon** | TheHarvester | Emails, subdominis, IPs, CT Logs (crt.sh), Shadow Infrastructure, email masking |
| 10 | **Shodan Threat Intel** | Shodan API | Vulnerability Search, ISP/ASN/Geo, serveis perillosos, historial de scans |
| 11 | **Enum4linux** | enum4linux | SMB/NetBIOS, usuaris, grups, shares, política de contrasenyes |

#### Mòduls Nous

| # | Mòdul | Tecnologia | Característiques Clau |
|---|-------|------------|----------------------|
| 12 | **Docker Deployment** | Docker | USB portàtil, 100% offline, Trivy DB pre-cached, plug & play |
| 13 | **AI Security** | z.ai API | Audit Manager, Autonomous Agent (beta), Chat, Risk Score 0-100 |
| 14 | **Target OS Scan** | Nmap/SSH | Multi-plataforma: Windows (SMB/AD/WinRM), macOS (AFP/Bonjour), iOS |
| 15 | **Integrations** | Nikto/SQLMap/Hydra | Scanner web, SQL Injection, força bruta, Telegram Bot |

---

### 6. Sistema d'Informes

Targeta destacada que presenta el sistema de generació d'informes professionals:

- **Formats**: PDF (WeasyPrint) i CSV
- **Signatura digital**: X.509 amb PyHanko i segell visible del logo Cybershield
- **Seccions seleccionables**: L'usuari tria quins mòduls incloure a l'informe
- **Enviament**: Via Telegram Bot directament al mòbil del client

---

### 7. API REST

Documentació interactiva de l'API amb exemples de codi:

```javascript
// Exemple: Obtenir estat del sistema en temps real
fetch('/api/status')
  .then(r => r.json())
  .then(data => {
    console.log('Vulnerabilitats:', data.vulns);
    console.log('CPU:', data.cpu + '%');
    console.log('Memòria:', data.memory + '%');
  });
```

**Endpoints destacats:**

| Mètode | Endpoint | Funció |
|--------|----------|--------|
| `GET` | `/api/status` | Estat general del sistema |
| `POST` | `/api/run_trivy_filtered` | Executa escaneig Trivy amb filtres |
| `POST` | `/api/nmap_scan` | Llança escaneig Nmap |
| `POST` | `/api/run_cmd` | Executa comandaments segurs (whitelist) |
| `GET` | `/api/soc/metrics` | Mètriques del SOC Dashboard |
| `POST` | `/api/soc/block-ip` | Bloqueig d'IPs amb iptables |

!!! note "API completa"
    La documentació completa dels +30 endpoints es troba a la secció [API REST](../api.md).

---

### 8. Equip

Presentació del fundador:

- **Nom**: Vitaliy Domin
- **Rol**: Founder · Especialista en Ciberseguretat i Infraestructures IT
- **Foto**: Professional amb efecte hover reveal
- **Descripció**: Lema corporatiu i visió del projecte

---

### 9. Sobre Cybershield

Secció informativa amb context del projecte intermodular:

- Entorns Linux Ubuntu amb VLANs i LDAP
- Informes accionables per a millora contínua
- Imatge corporativa amb efecte parallax

---

### 10. Tarifes

Tres plans de servei en targetes amb spotlight hover effect:

| Pla | Preu | Inclòs |
|-----|------|--------|
| **Start** | €399/auditoria | 1 servidor, Informe PDF/CSV, Recomanacions bàsiques |
| **Pro** ⭐ | €699.99/mes | Fins 5 servidors, Diag Agent com a servei, Sessions mensuals, Suport 24/7 |
| **Enterprise** | A mida | Alta disponibilitat, Integració SIEM, Procediments IR, Formació |

Inclou taula comparativa expandible amb checkmarks per funcionalitat i pla.

---

### 11. Contacte

Formulari de contacte amb validació en temps real:

| Camp | Tipus | Validació |
|------|-------|-----------|
| Nom | Text | Requerit |
| Empresa | Text | Opcional |
| Email | Email | Regex + feedback visual |
| Telèfon | Tel | Opcional |
| Missatge | Textarea | Requerit |
| Privacitat | Checkbox | Requerit |

**Informació de contacte:** Tortosa (Tarragona), email corporatiu, xarxes socials.

---

### 12. FAQ

Acordió amb preguntes freqüents implementat amb Bootstrap Collapse:

- Què és el Diag Agent i com funciona?
- Quins sistemes operatius són compatibles?
- Com s'instal·la i configura?
- Altres preguntes comunes dels clients

---

### 13. Notícies

Secció de notícies i actualitzacions del servei amb targetes de blog.

---

### 14. Footer

| Element | Contingut |
|---------|-----------|
| **Logo** | Logo Cybershield + descripció breu |
| **Navegació** | Enllaços a totes les seccions |
| **Social** | LinkedIn, GitHub, X (Twitter) |
| **Legal** | Copyright © amb any dinàmic via JavaScript |

---

## Sistema de Disseny

### Paleta de Colors

```css
:root {
  --bg: #070b1a;              /* Fons principal — blau molt fosc */
  --panel: #0d1426;           /* Panells i targetes */
  --text: #f8fbff;            /* Text principal — blanc suau */
  --accent: #60a5fa;          /* Accent principal — blau clar */
  --accent-neon: #00d4ff;     /* Neon cian — CTAs i highlights */
  --accent-purple: #9c27ff;   /* Porpra — gradients i accents secundaris */
}
```

### Estil Visual

| Tècnica | Implementació | Efecte |
|---------|---------------|--------|
| **Glassmorphism** | `backdrop-filter: blur(20px)` + border translúcid | Targetes i navbar semitransparents |
| **Gradients animats** | `linear-gradient` amb `@keyframes` | Text gradient i fons orgànics |
| **Partícules** | Canvas API amb 80 partícules interconnectades | Fons dinàmic amb antigravity al cursor |
| **Glow effects** | `box-shadow` amb múltiples capes rgba neon | Efecte halo en hover i focus |
| **3D Tilt** | `perspective(1000px) rotateX/Y` al `mousemove` | Targetes amb profunditat al hover |

### Tipografia

| Ús | Font | Pes |
|----|------|-----|
| Text general | Inter | 400, 600, 800 |
| Codi i terminal | JetBrains Mono | 400 |

### Responsivitat

Breakpoints implementats amb media queries:

| Dispositiu | Rang | Adaptacions |
|------------|------|-------------|
| **Desktop** | >1200px | Layout complet, efectes 3D, partícules |
| **Tablet** | 768px – 1200px | Grid reduït, tilt desactivat |
| **Mòbil** | <768px | Stack vertical, menú hamburger, partícules reduïdes |

---

## Motor d'Interactivitat

El fitxer `custom.js` (765 línies) implementa 10 sistemes d'interactivitat independents:

### Sistemes Visuals

| Sistema | Línies | Descripció |
|---------|--------|------------|
| **Cursor personalitzat** | ~40 | Cercle exterior amb lag + punt central precís, efecte `hover` en elements interactius |
| **Partícules antigravity** | ~110 | 80 partícules Canvas amb línies de connexió i repulsió del cursor |
| **Reveal on scroll** | ~30 | Intersection Observer per a animacions d'entrada (`reveal`, `reveal-fly`) |
| **Parallax** | ~10 | Efecte de profunditat a la secció Hero |

### Sistemes d'Interacció

| Sistema | Línies | Descripció |
|---------|--------|------------|
| **Terminal typewriter** | ~55 | Simulació de terminal amb 11 comandes, escriptura+esborrat automàtic |
| **Carrusel d'screenshots** | ~120 | Classe `AppCarousel` amb autoplay, swipe, keyboard, indicadors |
| **3D tilt cards** | ~20 | `perspective` + `rotateX/Y` amb reset suau al `mouseleave` |
| **Magnetic buttons** | ~15 | Botons que segueixen el cursor amb `translate` |
| **Spotlight cards** | ~15 | `radial-gradient` que segueix el mouse a les targetes de preu |
| **Ripple effect** | ~25 | Animació d'ona expansiva al clic de botons i targetes |

### Sistemes Funcionals

| Sistema | Línies | Descripció |
|---------|--------|------------|
| **Scroll progress** | ~10 | Barra de progrés a la part superior |
| **Navbar scroll** | ~10 | Canvi d'estil de la navbar en scroll |
| **Back to top** | ~5 | Botó flotant que apareix a >600px |
| **Formulari** | ~40 | Validació, loading state, toast de confirmació |
| **Cookie consent** | ~60 | Banner RGPD amb opció essencial/completa, localStorage |
| **Counter animation** | ~25 | Animació numèrica per a KPIs |

---

## SEO i Metadades

### Metadades Implementades

```html
<!-- SEO Bàsic -->
<title>Cybershield Solutions — Protect · Detect · Secure</title>
<meta name="description" content="Auditories de seguretat...">
<meta name="keywords" content="cybersecurity, auditing, diag agent...">

<!-- Open Graph (Facebook, LinkedIn) -->
<meta property="og:type" content="website">
<meta property="og:title" content="Cybershield Solutions">
<meta property="og:description" content="...">
<meta property="og:image" content="/Assets/web.png">
<meta property="og:url" content="https://cshield.duckdns.org">

<!-- Twitter Card -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Cybershield Solutions">
<meta name="twitter:image" content="/Assets/web.png">
```

### Bones Pràctiques

- ✅ Un únic `<h1>` per pàgina
- ✅ Jerarquia correcta de headings (h1 → h2 → h3)
- ✅ HTML5 semàntic (`<section>`, `<nav>`, `<header>`, `<footer>`)
- ✅ Atributs `alt` en totes les imatges
- ✅ `loading="lazy"` en imatges del carrusel
- ✅ IDs únics en tots els elements interactius

---

## Desplegament

El lloc web i la demo de l'aplicació es serveixen mitjançant **Nginx** com a proxy revers amb SSL (Let's Encrypt):

| Entorn | URL | Descripció |
|--------|-----|------------|
| **Web principal** | [cshield.duckdns.org](https://cshield.duckdns.org) | Lloc web estàtic de màrqueting |
| **Demo Diag Agent** | [democshield.duckdns.org](https://democshield.duckdns.org) | Aplicació en mode lectura (proxy) |

!!! tip "Documentació completa"
    La configuració detallada del proxy revers, SSL, mode demo i seguretat del servidor es troba a la secció [Proxy Revers](proxy.md).

---

**Última actualització:** 18 de febrer de 2026 · **Versió:** 3.0

