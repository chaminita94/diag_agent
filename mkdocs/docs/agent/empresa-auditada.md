# Empresa Auditada

L'empresa auditada en aquest projecte és l'**Institut de l'Ebre**, un centre educatiu de formació professional amb una forta orientació cap a les tecnologies de la informació i la comunicació. L'auditoria s'ha centrat especialment en la seva infraestructura informàtica, amb l'objectiu d'identificar possibles vulnerabilitats i proposar millores en matèria de seguretat i eficiència del sistema.

L'Institut de l'Ebre disposa d'una infraestructura pròpia de servidors i xarxes, gestionada internament pel seu departament d'informàtica. El centre utilitza diversos serveis digitals per a la gestió acadèmica, l'allotjament de webs i aplicacions internes, i l'accés dels estudiants i docents a diferents recursos formatius. Per aquesta raó, la seguretat i la disponibilitat dels seus sistemes són aspectes crítics per garantir el bon funcionament diari del centre.

## Infraestructura tecnològica

L'entorn analitzat consta de **dos servidors principals configurats en alta disponibilitat (HA)**, basats en sistemes operatius **Linux Ubuntu Server LTS**, una plataforma escollida per la seva estabilitat, seguretat i compatibilitat amb eines d'auditoria.

Aquests servidors allotgen els principals serveis del centre, entre ells:

- Plataforma de gestió interna (bases de dades i aplicacions acadèmiques).
- Servidor web amb contingut docent i administratiu.
- Sistema d'autenticació i gestió d'usuaris (LDAP).
- Repositoris i serveis d'arxiu compartit per a docents i estudiants.
- Correu electrònic intern i eines de comunicació.

Els dos servidors funcionen en un entorn **virtualitzat**, fet que permet desplegar màquines addicionals per a proves, còpies de seguretat i desenvolupament.

En l'àmbit de xarxa, el centre disposa de **VLANs segmentades** per a cada tipus d'usuari (administració, professorat, alumnat i convidats), millorant la seguretat i el control d'accessos.

!!! info "Política de Sistemes"
    La política de sistemes del centre estableix que **tota la infraestructura informàtica ha d'estar basada exclusivament en entorns Linux**, reduint així riscos derivats de vulnerabilitats típiques d'altres plataformes.

## Objectiu de l'auditoria

L'auditoria encarregada a **Cybershield Solutions, S.L.** té com a objectiu principal **avaluar l'estat de seguretat dels servidors i serveis principals basats en Linux Ubuntu Server**, mitjançant una anàlisi tècnica i un informe amb propostes de millora.

Els punts principals de l'auditoria són:

- Verificar la configuració dels serveis crítics i la seva exposició a la xarxa.
- Detectar vulnerabilitats conegudes en paquets i serveis del sistema.
- Analitzar registres del sistema i accessos fallits per detectar intents d'intrusió.
- Avaluar l'ús de bones pràctiques en la gestió d'usuaris, permisos i actualitzacions.
- Generar un informe tècnic automatitzat amb resultats i recomanacions específiques per entorns Ubuntu.

## Abast i limitacions

L'auditoria s'ha limitat a l'anàlisi interna de la infraestructura del centre, sense accedir a informació personal o dades acadèmiques dels usuaris.

S'han revisat únicament els servidors de producció i proves, així com els principals serveis de xarxa, sistemes d'autenticació i portals interns.

!!! warning "Tipus d'Auditoria"
    No s'ha dut a terme cap prova d'intrusió externa o simulació d'atac, ja que l'objectiu d'aquesta auditoria és de tipus **preventiu i de diagnòstic**, centrada en la detecció de vulnerabilitats i l'avaluació de configuracions de seguretat.

## Durada del projecte

L'auditoria s'ha desenvolupat al llarg de **tres sprints** dins del període del projecte intermodular, amb una durada total aproximada de **sis setmanes**.

Durant aquest temps s'han dut a terme la planificació, l'anàlisi tècnica, la recopilació d'informació i la redacció de l'informe final amb les propostes de millora.
