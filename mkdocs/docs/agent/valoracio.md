# Valoració del Risc

Cada risc s'ha avaluat segons dos criteris principals:

- **Impacte**: conseqüències que tindria per a la disponibilitat, integritat o confidencialitat del sistema.
- **Probabilitat**: possibilitat que el risc es materialitzi.

La combinació d'aquests factors genera un **nivell de risc** (Baix, Mitjà o Alt).

## Taula de Valoració de Riscos

| Núm. | Risc identificat | Impacte | Probabilitat | Nivell global | Mesura preventiva |
|------|------------------|---------|--------------|---------------|-------------------|
| 1 | Vulnerabilitats en paquets obsolets d'Ubuntu | Alt | Mitjà | **Alt** | Actualitzacions periòdiques automàtiques i anàlisi amb *Trivy*. |
| 2 | Accés no autoritzat per SSH | Alt | Baix | **Mitjà** | Limitació per IP i claus SSH, monitoratge de logs. |
| 3 | Configuració insegura d'Apache o Nginx | Mitjà | Mitjà | **Mitjà** | Revisió de permisos, seguretat TLS i scripts Nmap *vuln*. |
| 4 | Error humà en la gestió d'usuaris | Mitjà | Alt | **Alt** | Polítiques de rotació de contrasenyes i auditories internes. |
| 5 | Fallada del sistema HA (replicació) | Alt | Baix | **Mitjà** | Monitoratge i proves periòdiques de failover. |
| 6 | Absència de còpies de seguretat fiables | Alt | Mitjà | **Alt** | Implementar còpies diàries i validació de restauracions. |

## Conclusions de l'anàlisi

L'avaluació dels riscos ha posat en relleu que els principals punts crítics de la infraestructura són:

!!! danger "Punts Crítics"
    - La **dependència de la disponibilitat dels servidors** (entorn HA).
    - La **necessitat d'una política d'actualitzacions i còpies de seguretat més estricta**.
    - La **importància de monitorar accessos i processos sospitosos** de manera contínua.

## Mesures Proposades

Com a resposta, **Cybershield Solutions, S.L.** proposa aplicar un conjunt de **mesures de millora** incloses en el pla de seguretat, entre les quals destaquen:

1. L'automatització d'auditories periòdiques mitjançant l'eina *Diag Agent*.
2. La implementació de scripts de supervisió constants per a serveis crítics.
3. L'establiment de polítiques de backup automatitzades amb verificació.