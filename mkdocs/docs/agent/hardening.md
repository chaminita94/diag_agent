# Hardening i Seguretat

El Diag Agent ha estat sotmès a un procés de **hardening** rigorós per garantir que l'eina d'auditoria no es converteixi en un vector d'atac per si mateixa.

---

## Mesures Implementades

S'han abordat vulnerabilitats crítiques identificades en auditories de seguretat internes:

### 1. Eliminació de RCE (Remote Code Execution)
S'ha eliminat completament l'endpoint `/api/run_cmd` que permetia l'execució de comandaments arbitraris de shell. 
- **Abans**: Qualsevol usuari amb accés a la xarxa podia executar comandes com a root.
- **Ara**: Només les funcions predefinides del sistema poden invocar processos externs, utilitzant arguments santificats.

### 2. Protecció contra XSS (Cross-Site Scripting)
Com que l'agent mostra resultats d'escanejos externs (que poden contenir codi maliciós), s'ha implementat una protecció de doble capa:
- **Server-Side**: Funció `h_esc()` en Python per escapar caràcters especials en dades renderitzades pel servidor.
- **Client-Side**: Funció `esc()` a la interfície web (JavaScript) per evitar injeccions de DOM quan es carreguen resultats dinàmicament.

### 3. Validació d'Arguments (Shell Hardening)
Per a eines com **Nmap**, s'utilitza una llista blanca estricta de paràmetres:
- Ús de `shlex.split()` per al parseig segur.
- Bloqueig de metaclasses de shell (`&`, `;`, `|`, `$`, etc.).
- Prohibició de flags perillosos com `--script`.

---

## Restriccions d'Accés

L'accés a l'aplicació està limitat per defecte:
- **Whitelisting d'IPs**: Ús de la variable `ALLOWED_NETWORKS` per permetre l'accés només des de subxarxes confiables (ex: la xarxa d'administració).
- **Interface Binding**: L'agent es pot configurar per escoltar només en `localhost` o una interfície VPN específica.

---

## Disseny de Zero-Trust

L'agent segueix el principi de **mínim privilegi**:
- Els resultats dels escanejos es guarden en estructures de dades en memòria (`deques`) amb límits de tamany per evitar atacs de denegació de servei (DoS) per esgotament de memòria.
- L'execució de binaris externs utilitza `timeout` per evitar processos zombis.

---

!!! tip "Millora de Seguretat"
    Si vols augmentar la seguretat, es recomana desplegar el Diag Agent darrere d'un proxy invers (com Nginx) amb autenticació bàsica o TLS client certificates.
