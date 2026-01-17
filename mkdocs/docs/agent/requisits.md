# Requisits del Sistema

Per executar l'eina Diag Agent en un entorn Ubuntu Server, calen els següents components.

## Requisits de Programari

### Python i Dependències

| Component | Versió Mínima | Descripció |
|-----------|---------------|------------|
| Python | 3.8+ | Llenguatge principal de l'aplicació |
| pip | Última versió | Gestor de paquets Python |
| Flask | 2.0+ | Framework web per la interfície |
| psutil | 5.8+ | Monitoratge de recursos del sistema |
| WeasyPrint | 52+ | Generació d'informes PDF |

### Eines Externes

| Eina | Funció |
|------|--------|
| `nmap` | Escaneig de ports i detecció de serveis |
| `trivy` | Anàlisi de vulnerabilitats (CVEs) |
| `ssh-audit` | Auditoria de configuració SSH |
| `enum4linux` | Enumeració de serveis SMB/Samba |

## Requisits de Maquinari

!!! info "Especificacions Mínimes"
    - **CPU**: 2 cores
    - **RAM**: 2 GB (recomanat 4 GB per escanejos intensius)
    - **Disc**: 1 GB d'espai lliure per logs i informes
    - **Xarxa**: Accés a la interfície de xarxa del servidor objectiu

## Instal·lació de Dependències

L'script `setup_diag.sh` automatitza la instal·lació de totes les dependències:

```bash
# Assignar permisos d'execució
chmod +x setup_diag.sh diag_agent_single.py

# Executar l'script d'instal·lació
sudo ./setup_diag.sh
```

Aquest script:

1. Instal·la Python3 i pip si no estan presents
2. Instal·la les eines externes (nmap, trivy, ssh-audit, enum4linux)
3. Instal·la les llibreries Python necessàries
4. Crea el servei systemd `diag-agent.service`
