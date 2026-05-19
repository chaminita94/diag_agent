# Exemple de Funcionament

Aquesta pàgina documenta un exemple complet d'ús de **Diag Agent**, una eina monolítica desenvolupada amb Python i Flask per automatitzar auditories de seguretat sobre sistemes Linux. Les captures mostren el recorregut d'un operador: revisió inicial del sistema, monitoratge SOC, escanejos tècnics, anàlisi de logs, OSINT, proves de pentest i generació d'informes finals en PDF, CSV i Telegram.

El conjunt de pantalles s'ha agrupat per mòduls per facilitar la lectura i per mostrar com cada funcionalitat aporta evidència a l'auditoria.

---

## Fitxers descarregables de mostra

A més de les captures, s'han incorporat fitxers reals generats per l'eina perquè el lector pugui descarregar-los i comprovar el format de sortida.

| Fitxer | Format | Descripció |
|---|---|---|
| [Informe complet de Diag Agent](../../assets/exemples/diag_report_exemple.pdf) | PDF | Informe tècnic generat des del mòdul Report amb resultats del sistema auditat. |
| [Informe AI Security](../../assets/exemples/ai_security_report_exemple.pdf) | PDF | Informe generat pel mòdul d'anàlisi assistida per IA. |
| [Exportació CSV](../../assets/exemples/diag_report_exemple.csv) | CSV | Dades estructurades de l'auditoria per obrir en un full de càlcul o tractar posteriorment. |

!!! note "Ús dins de MkDocs"
    MkDocs pot publicar fitxers PDF i CSV sense cap configuració especial si es troben dins de la carpeta `docs`. En aquest cas s'han ubicat a `docs/assets/exemples/` i s'enllacen com qualsevol altre recurs estàtic.

---

## 1. Vista general del sistema

La pantalla principal centralitza l'estat de seguretat del sistema auditat. Mostra un resum executiu amb el nivell d'amenaça, el nombre de vulnerabilitats, ports oberts, connexions, actualitzacions pendents i ús de recursos. També incorpora accessos ràpids als mòduls principals.

![Dashboard principal](../../assets/captures/dashboard_principal.png)

La mateixa vista també està disponible en mode clar, útil per a presentacions o captures destinades a informes acadèmics.

![Dashboard principal en mode clar](../../assets/captures/dashboard_principal_mode_clar.png)

---

## 2. SOC Dashboard

El **SOC Dashboard** ofereix monitoratge en temps real de salut del sistema, trànsit de xarxa, alertes IDS, IPs bloquejades, connexions actives i intents SSH fallits. El mòdul **Network IDS Shield** utilitza inspecció de paquets per detectar comportaments com escanejos de ports o activitat anòmala.

![SOC Dashboard amb monitoratge en temps real](../../assets/captures/soc_dashboard_monitoratge.png)

La pantalla de connexions i processos amplia la informació operativa. Permet observar connexions actives, processos sospitosos, logs crítics i alertes de xarxa.

![Connexions, processos i logs crítics del SOC](../../assets/captures/soc_connexions_processos.png)

Quan es detecta una activitat sospitosa, l'IDS genera alertes classificades. En l'exemple es mostra una alerta de **Port Scan**, amb evidències, ports detectats i recomanació d'actuació.

![Alertes IDS del SOC Dashboard](../../assets/captures/soc_alertes_ids.png)

---

## 3. Vulnerabilitats i paquets

El mòdul de vulnerabilitats utilitza **Trivy** per identificar CVEs del sistema. La taula mostra severitat, paquet afectat, versió instal·lada, versió corregida, identificador CVE i descripció.

![Vulnerabilitats detectades amb Trivy](../../assets/captures/vulnerabilitats_trivy.png)

La gestió de paquets complementa l'anàlisi de vulnerabilitats. Permet veure paquets actualitzables i una mostra de paquets instal·lats, informació necessària per planificar mesures correctores.

![Paquets actualitzables](../../assets/captures/paquets_actualitzables.png)

---

## 4. Serveis i registres del sistema

El mòdul de serveis mostra una visió resumida dels serveis del sistema i el seu estat. Aquesta informació ajuda a detectar serveis actius que no haurien d'estar exposats o que requereixen revisió.

![Resum de serveis del sistema](../../assets/captures/serveis_sistema_resum.png)

La vista detallada de serveis permet consultar llistats més amplis i verificar l'estat d'execució, habilitació i ús dels serveis.

![Llistat de serveis del sistema](../../assets/captures/serveis_sistema_llistat.png)

Els logs generals del sistema mostren esdeveniments rellevants per a diagnòstic i seguretat. Són útils per correlacionar errors, avisos del kernel, serveis fallits o comportaments inesperats.

![Logs del sistema](../../assets/captures/logs_sistema.png)

La secció **SSH Security Logs** resumeix intents fallits d'autenticació, atacants únics i entrades recents. En l'exemple es detecten intents fallits contra l'usuari `vitaliy` des de la IP `192.168.1.113`.

![Registres SSH amb intents fallits](../../assets/captures/logs_ssh_fallits.png)

---

## 5. Auditoria SSH

El mòdul **SSH-Audit** analitza la configuració criptogràfica del servei SSH. La primera vista resumeix el banner, el programari, el protocol i si la compressió està habilitada.

![Resum de l'auditoria SSH](../../assets/captures/ssh_audit_resum_host.png)

La vista d'algoritmes classifica intercanvi de claus, claus de host i xifratges en categories segures, febles o insegures. Aquesta classificació facilita decidir si cal modificar la configuració de `sshd_config`.

![Algoritmes detectats per SSH-Audit](../../assets/captures/ssh_audit_algoritmes.png)

La sortida crua conserva l'evidència tècnica original de l'eina. És útil per validar els resultats o per incloure detalls en una auditoria formal.

![Sortida crua de SSH-Audit](../../assets/captures/ssh_audit_sortida_raw.png)

---

## 6. Escaneig de xarxa amb Nmap

Diag Agent integra **Nmap** amb una interfície controlada. La configuració permet definir el target, seleccionar presets i activar opcions com detecció de versions, detecció de sistema operatiu, traceroute i escaneig de vulnerabilitats.

![Configuració d'un escaneig Nmap](../../assets/captures/nmap_configuracio.png)

Els resultats mostren ports oberts, serveis, versions i una classificació de seguretat. En l'exemple es detecten ports NetBIOS/SMB marcats com a perillosos.

![Resultats de l'escaneig Nmap](../../assets/captures/nmap_resultats.png)

El mòdul **OS Scan** ofereix una lectura orientada al sistema objectiu, mostrant tipus de sistema operatiu, ports oberts, serveis i recomanacions.

![Resultats de l'OS Scan Linux](../../assets/captures/os_scan_resultats_linux.png)

---

## 7. Escàner unificat

L'**Unified Scanner** agrupa diferents comprovacions en un únic flux. La primera captura mostra l'execució de l'escaneig i la configuració dels mòduls.

![Execució de l'Unified Scanner](../../assets/captures/unified_scanner_execucio.png)

La segona captura presenta els resultats generats, amb sortides tècniques agrupades per secció. Aquesta vista és útil quan es vol obtenir una fotografia ràpida del sistema sense executar manualment cada pestanya.

![Resultats de l'Unified Scanner](../../assets/captures/unified_scanner_resultats.png)

---

## 8. Enumeració SMB

Quan Nmap detecta serveis SMB o NetBIOS, el mòdul d'enumeració amb **enum4linux-ng** permet obtenir informació del domini o grup de treball, nom NetBIOS, FQDN, recursos compartits i política de contrasenyes.

![Resultats d'enumeració SMB amb enum4linux-ng](../../assets/captures/enum4linux_resultats.png)

Aquesta informació ajuda a identificar recursos accessibles, exposició de Samba i possibles configuracions febles en entorns mixtos Linux/Windows.

---

## 9. Pentest web

La pantalla de pentest integra eines com **Nikto** i **SQLMap**. Inclou advertiments per limitar-ne l'ús a sistemes propis o autoritzats i presenta els resultats en una taula interpretable.

![Mòdul de pentest amb Nikto i SQLMap](../../assets/captures/pentest_nikto_sqlmap.png)

El mòdul específic de Nikto mostra configuració del target, port, execució i resultats tècnics. És útil per detectar capçaleres insegures, fitxers públics, rutes sensibles i configuracions web millorables.

![Escaneig web amb Nikto](../../assets/captures/nikto_web_scanner.png)

---

## 10. OSINT i intel·ligència d'amenaces

El mòdul OSINT permet analitzar dominis amb eines com **theHarvester**. La captura mostra resultats orientats a correus, subdominis, IPs i noms relacionats amb el domini auditat.

![Reconeixement OSINT de domini](../../assets/captures/osint_reconeixement_domini.png)

La pantalla d'enviament per Telegram mostra la capacitat de distribuir l'informe generat directament a un xat, indicant el `Chat ID` i confirmant l'enviament.

![Enviament OSINT per Telegram](../../assets/captures/osint_enviament_telegram.png)

El resultat també pot arribar com a missatge resumit a Telegram, amb el nom del PDF, domini objectiu, correus, hosts, IPs i infraestructura shadow detectada.

![Informe OSINT rebut per Telegram](../../assets/captures/telegram_informe_osint.png)

El mòdul **Threat Intelligence** consulta fonts externes com Shodan per obtenir informació d'exposició pública: hostnames, organització, ISP, ASN, geolocalització, ports oberts i vulnerabilitats conegudes.

![Intel·ligència d'amenaces amb Shodan](../../assets/captures/threat_intel_shodan.png)

---

## 11. AI Security i assistent

El mòdul **AI Security** permet executar una auditoria assistida per IA sobre un target. Pot incloure anàlisi de logs, configuració, sistema de fitxers, xarxa i processos.

![Configuració d'auditoria AI Security](../../assets/captures/ai_security_auditoria.png)

La pantalla de resultats presenta la resposta generada i les conclusions de seguretat. Aquest mòdul serveix com a capa d'interpretació per ajudar l'operador a prioritzar riscos, transformar resultats tècnics en recomanacions i preparar una explicació més comprensible per a l'informe final.

![Resultats d'AI Security](../../assets/captures/ai_security_resultats.png)

L'assistent conversacional permet fer preguntes sobre l'auditoria i obtenir respostes contextualitzades. Per exemple, l'operador pot demanar quina vulnerabilitat és més crítica, quins serveis convé tancar primer o com interpretar un conjunt d'alertes. És una funcionalitat de suport, no un substitut de la validació tècnica: les respostes s'han de contrastar amb les evidències originals generades per Trivy, Nmap, SSH-Audit, logs i la resta de mòduls.

![Assistent AI de Diag Agent](../../assets/captures/assistent_ai_chat.png)

---

## 12. Generació i exportació d'informes

El mòdul d'informes permet seleccionar quines seccions s'inclouen al resultat final. Disposa de plantilles ràpides, renderitzat visual, exportació CSV i descàrrega PDF.

![Configuració i generació d'informes](../../assets/captures/informes_configuracio.png)

La vista de resum mostra seccions seleccionades, dades del host, vulnerabilitats, paquets, Nmap, SSH-Audit i altres evidències. Això permet revisar el contingut abans de descarregar-lo i decidir si l'informe serà complet, tècnic o més orientat a direcció.

![Resum de seccions de l'informe](../../assets/captures/informes_resum_seccions.png)

Quan es descarreguen fitxers, el navegador mostra l'historial de descàrregues amb els informes PDF i CSV generats. Aquesta captura evidencia la sortida múltiple de l'eina: informe general, informe d'AI Security i exportació de dades en CSV.

![Historial de descàrregues d'informes](../../assets/captures/historial_descarregues_informes.png)

El PDF final inclou portada professional, identificador d'informe, dades del sistema auditat i validació de signatura. La signatura reforça la integritat del document lliurat i permet demostrar que l'arxiu no ha estat modificat després de la seva generació.

![Informe PDF final signat](../../assets/captures/informe_pdf_signat.png)

Els fitxers generats també queden disponibles com a mostres descarregables dins d'aquesta documentació:

- [Descarregar informe complet en PDF](../../assets/exemples/diag_report_exemple.pdf)
- [Descarregar informe AI Security en PDF](../../assets/exemples/ai_security_report_exemple.pdf)
- [Descarregar exportació CSV](../../assets/exemples/diag_report_exemple.csv)

---

## Resum del flux complet

El flux complet de treball és el següent:

1. L'operador revisa el dashboard principal per obtenir una visió general.
2. El SOC Dashboard monitoritza l'activitat del sistema i la xarxa en temps real.
3. Trivy identifica vulnerabilitats i el mòdul de paquets mostra actualitzacions disponibles.
4. Els serveis i logs permeten detectar configuracions insegures i esdeveniments rellevants.
5. SSH-Audit avalua la seguretat criptogràfica del servei SSH.
6. Nmap i OS Scan identifiquen ports oberts, serveis, versions i recomanacions.
7. L'Unified Scanner agrupa comprovacions en un flux automatitzat.
8. enum4linux-ng amplia l'auditoria quan hi ha serveis SMB exposats.
9. Nikto, SQLMap, OSINT i Shodan aporten context web i d'exposició pública.
10. AI Security ajuda a interpretar resultats i generar conclusions preliminars.
11. El mòdul Report consolida les evidències en PDF, CSV i enviament per Telegram.

Aquest conjunt de captures demostra que Diag Agent no només executa eines externes, sinó que les integra en un flux coherent d'auditoria, monitoratge, anàlisi i lliurament d'evidències.
