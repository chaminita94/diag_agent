# Integracions i Reports

El Diag Agent està dissenyat per facilitar la distribució dels resultats d'auditoria de manera ràpida i professional.

---

## Integració amb Telegram

L'agent permet enviar informes d'auditoria directament al teu dispositiu mòbil a través de Telegram.

### Com configurar-lo:

### Com configurar-lo:

1. **Variables d'Entorn**: Per seguretat, no guardis el token al codi. Configura'l al teu sistema:
   ```bash
   export TELEGRAM_BOT_TOKEN="el_teu_token_aquí"
   ```
2. **Executa el Bot Independent**: Copia `diagbot.py` a la teva VM de bots i executa'l.
3. **Automatització (systemd)**: Utilitza el fitxer `diagbot.service` proporcionat per mantenir el bot actiu:
   ```bash
   sudo cp diagbot.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable diagbot
   sudo systemctl start diagbot
   ```
4. **Identifica el teu Chat ID**: Envia `/start` al teu bot de Telegram. Ell et respondrà amb el teu ID personal.
5. **Configura el Diag Agent**: A la pestanya de resultats de l'eina principal, introdueix el teu ID al camp "Your Chat ID".
3. **Clica "Send"**: El bot de Cybershield t'enviarà el document PDF en pocs segons.

### Avantatges:
- **Immediatesa**: Reps l'auditoria sense haver de descarregar fitxers al PC.
- **Portabilitat**: Accés als resultats des de qualsevol lloc.
- **Privacitat**: Els informes només s'envien al ID que tu especifiquis.

---

## Informes PDF Professionals

Utilitzant el motor **WeasyPrint**, l'agent genera informes en format PDF d'alta qualitat que inclouen:

- **Resum Executiu**: Gràfiques i KPIs de l'estat del sistema.
- **Detall Tècnic**: Tota la informació de vulnerabilitats, ports i serveis.
- **Branding Personalitzat**: Inclou el logotip de Cybershield Solutions.
- **Signatura Digital**: Cada PDF està signat electrònicament per garantir-ne la integritat.

---

## Signatura Digital (PyHanko)

Tots els informes generats per l'agent porten una signatura digital verificable:

- **Autenticitat**: Confirma que l'informe prové del Diag Agent.
- **Integritat**: Qualsevol modificació posterior del PDF invalidarà la signatura.
- **Certificat**: El sistema genera un certificat de 2048 bits durant la instal·lació.

---

## Exportació CSV

Per a anàlisis posteriors o importació en altres eines (bases de dades, Excel), l'agent permet l'exportació de totes les taules en format CSV, garantint la interoperabilitat de les dades.

---

!!! info "Clau de Bot de Telegram"
    El token del bot està preconfigurat a l'agent per oferir el servei d'enviament de manera transparent a l'usuari. No cal que l'usuari creï el seu propi bot per utilitzar aquesta funcionalitat.
