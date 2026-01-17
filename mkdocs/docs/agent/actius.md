# Identificació d'Actius

L'anàlisi de riscos s'ha realitzat per identificar i valorar els possibles incidents que podrien afectar la infraestructura tecnològica de l'Institut de l'Ebre, amb l'objectiu de determinar el seu impacte i la probabilitat d'ocurrència. Aquesta avaluació s'ha basat en la metodologia de l'**INCIBE (Institut Nacional de Ciberseguretat d'Espanya)**, adaptada al context del centre i al seu entorn Linux.

## Actius Principals

Els principals actius analitzats durant l'auditoria han estat:

| Actiu | Descripció |
|-------|------------|
| **Servidors Ubuntu** | Dos servidors en alta disponibilitat que allotgen els serveis crítics |
| **Sistemes d'autenticació** | LDAP i gestió d'usuaris |
| **Bases de dades** | Sistemes acadèmics i de gestió interna |
| **Xarxa interna** | Segmentada per VLANs (administració, professorat, alumnat, convidats) |
| **Equips d'usuari final** | Punts d'accés de la xarxa |

## Amenaces identificades

Durant l'avaluació s'han detectat o considerat les següents amenaces potencials:

!!! danger "Amenaces Crítiques"
    - **Vulnerabilitats de programari** no actualitzat en servidors o paquets del sistema.
    - **Configuracions insegures** de serveis de xarxa (SSH, web, bases de dades).
    - **Errors humans** en la gestió de permisos o credencials.

!!! warning "Amenaces Moderades"
    - **Accés no autoritzat** des de xarxes internes o dispositius compromesos.
    - **Manca de polítiques de còpia de seguretat** o restauració deficient.
    - **Sobrecàrrega o fallada en la replicació HA**, que podria interrompre serveis essencials.
