# Website Corporativa

La pàgina web de **Cybershield Solutions** serveix com a portal d'informació i presentació dels serveis de l'empresa. S'ha dissenyat amb un enfocament modern i professional per transmetre confiança i professionalitat als clients potencials.

## Tecnologies Utilitzades

| Tecnologia | Versió | Ús |
|------------|--------|-----|
| HTML5 | 5 | Estructura semàntica del contingut |
| CSS3 | 3 | Estils, animacions i disseny responsiu |
| JavaScript | ES6+ | Interactivitat i efectes dinàmics |
| Bootstrap | 5.3.2 | Framework CSS per a components i grid |
| Bootstrap Icons | 1.11.3 | Biblioteca d'icones |
| Google Fonts | - | Tipografia Inter per a text |

## Estructura dels Fitxers

```
Website/
├── index.html          # Pàgina principal (1280 línies)
├── custom.css          # Estils personalitzats (1405 línies)
├── custom.js           # Scripts d'interactivitat
├── carousel.css        # Estils del carrusel de captures
└── Assets/
    ├── logo.png        # Logo de Cybershield
    ├── foto.jpg        # Foto del fundador
    ├── shield.png      # Imatge decorativa
    ├── web.png         # Preview per a xarxes socials
    └── Fotos Web/      # Captures de pantalla del Diag Agent
        ├── 1.png       # Dashboard Principal
        ├── 2.png       # Escaneig de Vulnerabilitats
        ├── 3.png       # Gestió de Paquets
        ├── ...
        └── 10.png      # Exportació Professional
```

## Seccions de la Pàgina

### 1. Navegació (Navbar)

Barra de navegació fixa amb efecte *glassmorphism* que inclou:

- Logo de Cybershield amb animació de flotació
- Enllaços a totes les seccions (Serveis, App, Funcionalitats, Equip, Sobre, Tarifes, Contacte, Notícies, FAQ)
- Botó de crida a l'acció "Comença ara"
- Barra de progrés de scroll a la part superior

### 2. Hero Section

Secció principal amb:

- Títol animat: "Automatització d'**auditories** i plans de **millora**"
- Descripció del servei amb text destacat
- Botons d'acció: "Prova el Diag Agent" i "Sol·licita una auditoria"
- Indicadors de metodologia: SCRUM, Open-Source, Resultats mesurables
- **Terminal Widget animat** que simula comandes del Diag Agent:
    - `sudo ./setup_diag.sh`
    - `trivy fs / --severity HIGH,CRITICAL`
    - `nmap -sV -Pn target`
    - Més comandes amb efecte de màquina d'escriure
- Logos de tecnologies compatibles: Linux, Ubuntu, Proxmox, Grafana, Docker, Python

### 3. Serveis

Quatre targetes amb efecte *glass* que presenten els serveis:

| Servei | Descripció |
|--------|------------|
| **Auditoria de seguretat** | Anàlisi de vulnerabilitats, revisió de configuracions i exposició de serveis |
| **Hardening & millora** | SSH, TLS, serveis, permisos i actualitzacions controlades |
| **Monitoratge continu** | Diag Agent en mode servei amb vigilància de processos, logs i paquets |
| **Resposta i formació** | Tallers per equips tècnics i procediments d'incident response |

### 4. App / Diag Agent

Presentació completa de l'eina amb:

- Descripció: "Agent d'auditoria i diagnòstic complet per a sistemes Linux"
- Llista de característiques organitzada en dues columnes:
    - Dashboard en temps real amb KPI
    - Vista organitzada per pestanyes
    - Export professional PDF/CSV
    - API RESTful segura
    - Seguretat integrada amb sanitització
    - Desplegament ràpid amb systemd
- **Carrusel interactiu** amb 10 captures de pantalla de l'aplicació:
    1. Dashboard Principal
    2. Escaneig de Vulnerabilitats
    3. Gestió de Paquets
    4. Monitoratge de Serveis
    5. Anàlisi de Logs
    6. Logs SSH
    7. Escaneig Nmap
    8. SSH Audit Professional
    9. Generació d'Informes
    10. Exportació Professional

### 5. Funcionalitats Detallades

Sis targetes tècniques que expliquen cada mòdul:

1. **Escaneig de Vulnerabilitats (Trivy)**
    - Anàlisi d'imatges Docker/Podman
    - Escaneig de sistema de fitxers
    - Filtrat per severitat
    - Base de dades actualitzada
    - Informes amb descripció i fixes

2. **Anàlisi de Xarxa (Nmap)**
    - Descobriment de hosts i serveis
    - Detecció de versions
    - Identificació de ports oberts
    - Classificació de ports perillosos
    - Limitació de 250k caràcters

3. **Auditoria SSH**
    - Anàlisi d'algoritmes KEX, Host Key, Encryption, MAC
    - Classificació per nivell de seguretat
    - Detecció d'algoritmes insegurs
    - Recomanacions de hardening
    - Extracció de fingerprints

4. **Gestió de Paquets**
    - Llistat de paquets instal·lats
    - Detecció d'actualitzables
    - Informació de versions
    - Historial d'actualitzacions
    - Integració apt/dpkg

5. **Monitoratge de Serveis**
    - Llistat de processos
    - Detecció de processos sospitosos
    - Whitelist configurable
    - Ús de recursos per procés
    - Identificació de serveis exposats

6. **Anàlisi de Logs**
    - Logs de sistema (syslog, kern.log, auth.log)
    - Detecció de fallades SSH
    - Filtrat temporal i per severitat
    - Patrons de comportament anòmal
    - Exportació de logs filtrats

### 6. Sistema d'Informes

Targeta destacada amb:

- Descripció del sistema de generació d'informes
- Formats disponibles: PDF i CSV
- Seccions seleccionables per a informes personalitzats

### 7. API REST

Documentació de l'API amb exemples de codi:

```javascript
// Exemple: Obtenir estat del sistema
fetch('/api/status')
  .then(r => r.json())
  .then(data => {
    console.log('Vulnerabilitats:', data.vulns);
    console.log('CPU:', data.cpu + '%');
    console.log('Memòria:', data.memory + '%');
  });
```

Endpoints disponibles:

- `GET /api/status` - Estat general del sistema
- `POST /api/run_trivy_filtered` - Executa escaneig Trivy
- `POST /api/nmap_scan` - Llança escaneig Nmap
- `POST /api/run_cmd` - Executa comandaments segurs

### 8. Equip

Presentació del fundador amb:

- Foto professional
- Nom: Vitaliy Domin
- Rol: Founder · Especialista en Ciberseguretat i Infraestructures IT
- Descripció personal i lema corporatiu

### 9. Sobre Cybershield

Secció informativa amb:

- Descripció del projecte intermodular
- Punts clau: Entorns Linux Ubuntu, VLANs, LDAP, informes accionables
- Imatge corporativa

### 10. Tarifes

Tres plans de servei presentats en targetes:

| Pla | Preu | Característiques |
|-----|------|------------------|
| **Start** | €399/auditoria | Auditoria puntual (1 servidor), Informe PDF/CSV, Recomanacions bàsiques |
| **Pro** (Popular) | €699.99/mes | Fins 5 servidors, Diag Agent com a servei, Sessions mensuals, Suport 24/7 |
| **Enterprise** | A mida | Alta disponibilitat, Integració SIEM, Procediments IR i formació |

Inclou taula comparativa de funcionalitats per pla.

### 11. Contacte

Formulari de contacte amb:

- Camps: Nom, Empresa, Email, Telèfon, Missatge
- Checkbox de política de privacitat
- Informació de contacte: Tortosa (Tarragona), email, xarxes socials

### 12. FAQ

Acordió amb preguntes freqüents sobre:

- Què és el Diag Agent i com funciona
- Altres preguntes comunes dels clients

### 13. Notícies

Secció de notícies i actualitzacions del servei.

### 14. Footer

Peu de pàgina amb:

- Logo i descripció de l'empresa
- Enllaços de navegació
- Xarxes socials (LinkedIn, GitHub, X)
- Copyright

## Característiques de Disseny

### Estil Visual

- **Color Scheme**: Mode fosc amb accents cian i púrpura
- **Tipografia**: Inter per a text, JetBrains Mono per a codi
- **Efectes**: Glassmorphism, gradients animats, partícules de fons
- **Animacions**: Reveal on scroll, flotació, glitch en títols

### Variables CSS Principals

```css
:root {
  --bg: #070b1a;
  --panel: #0d1426;
  --text: #f8fbff;
  --accent: #60a5fa;
  --accent-neon: #00d4ff;
  --accent-purple: #9c27ff;
}
```

### Responsivitat

La pàgina és completament responsive amb breakpoints per a:

- Escriptori (>1200px)
- Tablet (768px - 1200px)
- Mòbil (<768px)

## Interactivitat (JavaScript)

El fitxer `custom.js` implementa:

1. **Cursor personalitzat** amb efecte de seguiment
2. **Animació de partícules** al fons
3. **Scroll spy** per a navegació activa
4. **Terminal widget** amb efecte de màquina d'escriure
5. **Carrusel** de captures de pantalla amb controls
6. **Reveal animations** en fer scroll
7. **Barra de progrés** de scroll
8. **Back to top** botó flotant
9. **Validació de formulari** de contacte

## SEO i Metadades

```html
<meta name="description" content="Auditories de seguretat...">
<meta property="og:type" content="website">
<meta property="og:title" content="Cybershield Solutions">
<meta property="og:image" content="/Assets/web.png">
<meta name="twitter:card" content="summary_large_image">
```

## Accés

La web està allotjada a: **https://cshield.duckdns.org**
