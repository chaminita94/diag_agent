# Configuració

## Configuració Bàsica

L'agent s'executa amb privilegis elevats per poder accedir als logs del sistema i realitzar escanejos complets:

```bash
sudo python3 diag_agent_single.py --host 0.0.0.0 --port 8080
```

### Paràmetres Disponibles

| Paràmetre | Descripció | Valor per defecte |
|-----------|------------|-------------------|
| `--host` | Adreça IP d'escolta | `127.0.0.1` |
| `--port` | Port d'escolta | `8080` |

## Accés a la Interfície

Un cop iniciat, l'auditor pot accedir a la interfície web mitjançant:

- **Accés local**: `http://127.0.0.1:8080`
- **Accés remot**: `http://<IP_DEL_SERVIDOR>:8080`

!!! warning "Seguretat"
    Quan s'exposa l'agent a la xarxa (`--host 0.0.0.0`), assegureu-vos que el port 8080 estigui protegit per un firewall o només accessible des d'IPs autoritzades.

## Servei Systemd

L'script `setup_diag.sh` crea automàticament un servei systemd anomenat `diag-agent.service` que permet:

- Execució automàtica en iniciar el servidor
- Reinici automàtic en cas de fallada
- Gestió estandarditzada amb `systemctl`

### Comandes de Gestió

```bash
# Iniciar el servei
sudo systemctl start diag-agent

# Aturar el servei
sudo systemctl stop diag-agent

# Reiniciar el servei
sudo systemctl restart diag-agent

# Veure l'estat
sudo systemctl status diag-agent

# Habilitar inici automàtic
sudo systemctl enable diag-agent
```

## Post-Auditoria

!!! tip "Opcions després de l'auditoria"
    Un cop finalitzada l'auditoria, **l'eina pot romandre instal·lada al servidor del client** si així ho desitja. Aquesta opció permet que el mateix departament tècnic pugui continuar **fent monitoratges periòdics** i auditories internes de seguretat.
    
    En cas contrari, Cybershield Solutions pot procedir a la **desinstal·lació completa** dels components, deixant el sistema exactament com abans de la intervenció.
