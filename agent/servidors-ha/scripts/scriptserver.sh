#!/usr/bin/env bash
# =============================================================================
# setup_ha_lab.sh
#
# Laboratori HA vulnerable sobre Ubuntu Server
#
# Topologia:
#   ens18 -> xarxa externa / Internet (DHCP)
#   ens19 -> xarxa interna del laboratori
#
#   Primari   : 10.10.0.10
#   Secundari : 10.10.0.11
#   VIP       : 10.10.0.100
#   Domini    : lab.local
#
# ADVERTÈNCIA:
#   Aquest script instal·la configuracions insegures expressament.
#   Només per a laboratoris aïllats.
# =============================================================================

set -Eeuo pipefail

readonly LOG_FILE="/var/log/setup_ha_lab.log"

readonly EXT_IFACE="ens18"
readonly INT_IFACE="ens19"

readonly DOMAIN_NAME="lab.local"

readonly PRIMARY_IP="10.10.0.10"
readonly SECONDARY_IP="10.10.0.11"
readonly VIP_IP="10.10.0.100"

readonly DHCP_RANGE_START="10.10.0.50"
readonly DHCP_RANGE_END="10.10.0.150"
readonly DHCP_ROUTER="10.10.0.100" # VIP per garantir HA
readonly INT_NETMASK="255.255.255.0"
readonly INT_BROADCAST="10.10.0.255"

readonly LAB_USER="labuser"
readonly LAB_PASS="labpass"
readonly MYSQL_ROOT_PASS="labroot"

readonly KEEPALIVED_AUTH="LabHA123"

ROLE=""
NODE_IP=""
PEER_IP=""
NODE_HOSTNAME=""
NODE_STATE=""
NODE_PRIORITY=""

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
    local msg="[$(ts)] $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

section() {
    log ""
    log "================================================================"
    log "$*"
    log "================================================================"
}

die() {
    log "ERROR FATAL: $*"
    exit 1
}

on_error() {
    local line="$1"
    log "ERROR: fallo en la línea $line"
    exit 1
}
trap 'on_error $LINENO' ERR

check_root() {
    [[ $EUID -eq 0 ]] || die "Executa'l com a root: sudo bash $0"
}

check_ubuntu() {
    [[ -f /etc/os-release ]] || die "No s'ha pogut identificar el sistema operatiu"
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || die "Aquest script està pensat per Ubuntu Server"
}

ensure_logfile() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
}

ask_role() {
    section "Selecció del rol del node"

    echo ""
    echo "  [1] PRIMARI   -> ${PRIMARY_IP}"
    echo "  [2] SECUNDARI -> ${SECONDARY_IP}"
    echo ""
    read -rp "Aquest servidor és PRIMARI o SECUNDARI? [1/2]: " choice

    case "$choice" in
        1|[Pp]*)
            ROLE="PRIMARY"
            NODE_IP="$PRIMARY_IP"
            PEER_IP="$SECONDARY_IP"
            NODE_HOSTNAME="server1"
            NODE_STATE="MASTER"
            NODE_PRIORITY="150"
            ;;
        2|[Ss]*)
            ROLE="SECONDARY"
            NODE_IP="$SECONDARY_IP"
            PEER_IP="$PRIMARY_IP"
            NODE_HOSTNAME="server2"
            NODE_STATE="BACKUP"
            NODE_PRIORITY="100"
            ;;
        *)
            die "Opció no vàlida"
            ;;
    esac

    log "Rol: $ROLE | IP interna: $NODE_IP | Peer: $PEER_IP"
}

prepare_system() {
    section "Preparació del sistema"

    hostnamectl set-hostname "${NODE_HOSTNAME}.${DOMAIN_NAME}"

    if ! grep -q "${PRIMARY_IP}" /etc/hosts; then
        cat >> /etc/hosts <<EOF

# HA LAB
${PRIMARY_IP}    server1.${DOMAIN_NAME} server1
${SECONDARY_IP}  server2.${DOMAIN_NAME} server2
${VIP_IP}        vip.${DOMAIN_NAME} vip web.${DOMAIN_NAME} ftp.${DOMAIN_NAME} dvwa.${DOMAIN_NAME}
EOF
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >>"$LOG_FILE" 2>&1

    apt-get install -y \
        curl wget net-tools dnsutils rsync cron \
        software-properties-common apt-transport-https \
        openssh-server bind9 bind9utils bind9-doc \
        isc-dhcp-server apache2 php libapache2-mod-php php-mysql php-cli \
        mariadb-server git vsftpd keepalived iptables-persistent \
        postfix dovecot-imapd dovecot-pop3d \
        >>"$LOG_FILE" 2>&1

    if ! id "$LAB_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$LAB_USER"
        echo "${LAB_USER}:${LAB_PASS}" | chpasswd
        usermod -aG sudo "$LAB_USER"
        log "Usuari de laboratori creat: $LAB_USER"
    else
        log "L'usuari $LAB_USER ja existia"
    fi

    systemctl enable cron ssh apache2 mariadb vsftpd keepalived >>"$LOG_FILE" 2>&1 || true
}

configure_network() {
    section "Configuració de xarxa"

    local netplan_file="/etc/netplan/99-ha-lab.yaml"

    cat > "$netplan_file" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${EXT_IFACE}:
      dhcp4: true
      dhcp6: false
    ${INT_IFACE}:
      dhcp4: false
      dhcp6: false
      addresses:
        - ${NODE_IP}/24
      nameservers:
        addresses:
          - ${PRIMARY_IP}
          - ${SECONDARY_IP}
        search:
          - ${DOMAIN_NAME}
EOF

    chmod 600 "$netplan_file"
    netplan generate >>"$LOG_FILE" 2>&1
    netplan apply >>"$LOG_FILE" 2>&1 || log "AVÍS: netplan apply ha donat error"

    log "Xarxa configurada: ${EXT_IFACE}=DHCP, ${INT_IFACE}=${NODE_IP}/24"

    # Habilitar IP Forwarding (NAT per a clients interns)
    sysctl -w net.ipv4.ip_forward=1 >>"$LOG_FILE" 2>&1
    sed -i 's/#\?net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf

    # NAT (Masquerade) via iptables - sense UFW
    iptables -t nat -F
    iptables -t nat -A POSTROUTING -o "${EXT_IFACE}" -j MASQUERADE

    # Preseleccionar resposta de debconf per evitar interactivitat
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    # Guardar regles iptables perquè persisteixin entre reinicis
    netfilter-persistent save >>"$LOG_FILE" 2>&1 || true

    log "NAT actiu: ${INT_IFACE} -> ${EXT_IFACE} (Masquerade)"
}

configure_ssh() {
    section "Configuració SSH"

    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

    systemctl enable --now ssh >>"$LOG_FILE" 2>&1
    systemctl restart ssh >>"$LOG_FILE" 2>&1

    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    if [[ ! -f /root/.ssh/id_rsa ]]; then
        ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa -q
        log "Clau SSH de root generada"
    fi

    log "IMPORTANT: després d'executar el script als dos nodes, fes:"
    log "  Des del primari   -> ssh-copy-id root@${SECONDARY_IP}"
    log "  Des del secundari -> ssh-copy-id root@${PRIMARY_IP}"
}

configure_dns() {
    section "Configuració DNS (BIND9)"

    mkdir -p /etc/bind/zones

    cat > /etc/bind/named.conf.options <<EOF
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    allow-recursion { 127.0.0.1; 10.10.0.0/24; };
    listen-on { any; };
    allow-transfer { ${PEER_IP}; };
    dnssec-validation auto;
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };
    forward only;
};
EOF

    if [[ "$ROLE" == "PRIMARY" ]]; then
        configure_dns_primary
    else
        configure_dns_secondary
    fi

    named-checkconf >>"$LOG_FILE" 2>&1

    if systemctl list-unit-files | grep -q '^named\.service'; then
        systemctl enable --now named >>"$LOG_FILE" 2>&1 || true
        systemctl restart named >>"$LOG_FILE" 2>&1
    else
        systemctl start bind9 >>"$LOG_FILE" 2>&1 || true
        systemctl restart bind9 >>"$LOG_FILE" 2>&1
    fi

    log "DNS configurat com a ${ROLE}"
}

configure_dns_primary() {
    local serial
    serial="$(date +%Y%m%d)01"

    cat > /etc/bind/named.conf.local <<EOF
zone "${DOMAIN_NAME}" {
    type master;
    file "/etc/bind/zones/db.${DOMAIN_NAME}";
    allow-transfer { ${SECONDARY_IP}; };
    notify yes;
};

zone "0.10.10.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.10.10.0";
    allow-transfer { ${SECONDARY_IP}; };
    notify yes;
};
EOF

    cat > /etc/bind/zones/db.${DOMAIN_NAME} <<EOF
\$TTL 86400
@   IN  SOA server1.${DOMAIN_NAME}. admin.${DOMAIN_NAME}. (
        ${serial}
        3600
        1800
        604800
        86400
)

@           IN NS server1.${DOMAIN_NAME}.
@           IN NS server2.${DOMAIN_NAME}.

server1     IN A  ${PRIMARY_IP}
server2     IN A  ${SECONDARY_IP}
vip         IN A  ${VIP_IP}
web         IN A  ${VIP_IP}
ftp         IN A  ${VIP_IP}
dvwa        IN A  ${VIP_IP}
ns1         IN A  ${PRIMARY_IP}
ns2         IN A  ${SECONDARY_IP}
gateway     IN A  ${DHCP_ROUTER}
EOF

    cat > /etc/bind/zones/db.10.10.0 <<EOF
\$TTL 86400
@   IN  SOA server1.${DOMAIN_NAME}. admin.${DOMAIN_NAME}. (
        ${serial}
        3600
        1800
        604800
        86400
)

@   IN NS server1.${DOMAIN_NAME}.
@   IN NS server2.${DOMAIN_NAME}.

1    IN PTR gateway.${DOMAIN_NAME}.
10   IN PTR server1.${DOMAIN_NAME}.
11   IN PTR server2.${DOMAIN_NAME}.
100  IN PTR vip.${DOMAIN_NAME}.
EOF

    chown -R bind:bind /etc/bind/zones
    named-checkzone "${DOMAIN_NAME}" /etc/bind/zones/db.${DOMAIN_NAME} >>"$LOG_FILE" 2>&1
    named-checkzone "0.10.10.in-addr.arpa" /etc/bind/zones/db.10.10.0 >>"$LOG_FILE" 2>&1
}

configure_dns_secondary() {
    cat > /etc/bind/named.conf.local <<EOF
zone "${DOMAIN_NAME}" {
    type slave;
    masters { ${PRIMARY_IP}; };
    file "/var/cache/bind/db.${DOMAIN_NAME}";
};

zone "0.10.10.in-addr.arpa" {
    type slave;
    masters { ${PRIMARY_IP}; };
    file "/var/cache/bind/db.10.10.0";
};
EOF
}

configure_dhcp() {
    section "Configuració DHCP"

    sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"${INT_IFACE}\"/" /etc/default/isc-dhcp-server

    cat > /etc/dhcp/dhcpd.conf <<EOF
authoritative;
default-lease-time 3600;
max-lease-time 7200;

subnet 10.10.0.0 netmask 255.255.255.0 {
    range ${DHCP_RANGE_START} ${DHCP_RANGE_END};
    option subnet-mask ${INT_NETMASK};
    option broadcast-address ${INT_BROADCAST};
    option routers ${DHCP_ROUTER};
    option domain-name "${DOMAIN_NAME}";
    option domain-name-servers ${VIP_IP}, ${PRIMARY_IP}, ${SECONDARY_IP};
}
EOF

    systemctl enable isc-dhcp-server >>"$LOG_FILE" 2>&1
    systemctl stop isc-dhcp-server >>"$LOG_FILE" 2>&1 || true

    if [[ "$ROLE" == "PRIMARY" ]]; then
        systemctl start isc-dhcp-server >>"$LOG_FILE" 2>&1 || log "AVÍS: DHCP no ha arrancat"
        log "DHCP preparat i actiu al primari"
    else
        log "DHCP preparat al secundari, pendent de promoció per Keepalived"
    fi
}

configure_apache() {
    section "Configuració Apache i PHP"

    mkdir -p /var/www/html

    cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html lang="ca">
<head>
  <meta charset="UTF-8">
  <title>HA Lab - ${ROLE}</title>
</head>
<body>
  <h1>HA Lab - ${ROLE}</h1>
  <p>Hostname: $(hostname)</p>
  <p>IP interna: ${NODE_IP}</p>
  <p>VIP: ${VIP_IP}</p>
  <p>Data: $(date)</p>
  <p>VULNERABLE LAB CONFIGURATION - DO NOT USE IN PRODUCTION</p>
</body>
</html>
EOF

    cat > /var/www/html/status.php <<'EOF'
<?php
header('Content-Type: application/json');
echo json_encode([
  'hostname' => gethostname(),
  'server_addr' => $_SERVER['SERVER_ADDR'] ?? 'unknown',
  'time' => date('c'),
  'uptime' => trim(shell_exec('uptime -p')),
  'load' => sys_getloadavg()
], JSON_PRETTY_PRINT);
EOF

    cat > /etc/apache2/conf-available/lab-vulnerable.conf <<'EOF'
ServerTokens Full
ServerSignature On
TraceEnable On
Header always unset X-Frame-Options
Header always unset X-Content-Type-Options
Header always unset Content-Security-Policy
EOF

    a2enmod headers >>"$LOG_FILE" 2>&1 || true
    a2enconf lab-vulnerable >>"$LOG_FILE" 2>&1 || true

    systemctl enable apache2 >>"$LOG_FILE" 2>&1
    systemctl restart apache2 >>"$LOG_FILE" 2>&1 || true
}

configure_ftp() {
    section "Configuració FTP vulnerable"

    mkdir -p /srv/ftp/public
    chmod 777 /srv/ftp/public
    echo "FTP vulnerable de laboratori" > /srv/ftp/public/README.txt

    cat > /etc/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_std_format=YES
idle_session_timeout=300
data_connection_timeout=120
ftpd_banner=Welcome to HA-Lab vulnerable FTP
chroot_local_user=NO
allow_writeable_chroot=YES
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
ssl_enable=NO
anon_root=/srv/ftp/public
EOF

    systemctl enable vsftpd >>"$LOG_FILE" 2>&1
    systemctl restart vsftpd >>"$LOG_FILE" 2>&1 || true
}

configure_mariadb_dvwa() {
    section "Configuració MariaDB i DVWA"

    systemctl enable mariadb >>"$LOG_FILE" 2>&1
    systemctl restart mariadb >>"$LOG_FILE" 2>&1 || true

    mysql <<EOF >>"$LOG_FILE" 2>&1 || true
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
CREATE USER IF NOT EXISTS '${LAB_USER}'@'%' IDENTIFIED BY '${LAB_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${LAB_USER}'@'%' WITH GRANT OPTION;
CREATE DATABASE IF NOT EXISTS dvwa;
FLUSH PRIVILEGES;
EOF

    if [[ -f /etc/mysql/mariadb.conf.d/50-server.cnf ]]; then
        sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
        systemctl restart mariadb >>"$LOG_FILE" 2>&1 || true
    fi

    if [[ ! -d /var/www/html/dvwa ]]; then
        git clone --depth 1 https://github.com/digininja/DVWA.git /var/www/html/dvwa >>"$LOG_FILE" 2>&1 || true
    fi

    if [[ -d /var/www/html/dvwa ]]; then
        cp -f /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php || true
        sed -i "s/\$_DVWA\[ 'db_user' \] = 'root';/\$_DVWA[ 'db_user' ] = '${LAB_USER}';/" /var/www/html/dvwa/config/config.inc.php || true
        sed -i "s/\$_DVWA\[ 'db_password' \] = 'p@ssw0rd';/\$_DVWA[ 'db_password' ] = '${LAB_PASS}';/" /var/www/html/dvwa/config/config.inc.php || true
        chown -R www-data:www-data /var/www/html/dvwa
        chmod -R 755 /var/www/html/dvwa
        chmod -R 777 /var/www/html/dvwa/hackable/uploads
        chmod -R 777 /var/www/html/dvwa/config
    fi
}

configure_mail() {
    section "Configuració Correu (Postfix + Dovecot)"

    # Postfix: configuració mínima per al laboratori
    postconf -e "myhostname = mail.${DOMAIN_NAME}"
    postconf -e "mydestination = \$myhostname, ${DOMAIN_NAME}, localhost.localdomain, localhost"
    postconf -e "mynetworks = 127.0.0.0/8, 10.10.0.0/24"
    postconf -e "home_mailbox = Maildir/"

    # Dovecot: auth en text pla (laboratori vulnerable)
    sed -i 's/#\?disable_plaintext_auth =.*/disable_plaintext_auth = no/' /etc/dovecot/conf.d/10-auth.conf
    sed -i 's|mail_location = .*|mail_location = maildir:~/Maildir|' /etc/dovecot/conf.d/10-mail.conf

    systemctl enable postfix dovecot >>"$LOG_FILE" 2>&1
    systemctl restart postfix dovecot >>"$LOG_FILE" 2>&1

    log "Correu configurat: SMTP (25), IMAP (143), POP3 (110) a mail.${DOMAIN_NAME}"
}

configure_ha_hooks() {
    section "Configuració de scripts de promoció/retrocés HA"

    cat > /usr/local/bin/ha_promote.sh <<'EOF'
#!/bin/bash
systemctl start apache2 || true
systemctl start vsftpd || true
systemctl start isc-dhcp-server || true

if systemctl list-unit-files | grep -q '^named\.service'; then
    systemctl start named || true
else
    systemctl start bind9 || true
fi

echo MASTER > /var/run/keepalived_state
EOF

    cat > /usr/local/bin/ha_demote.sh <<'EOF'
#!/bin/bash
systemctl stop isc-dhcp-server || true
echo BACKUP > /var/run/keepalived_state
EOF

    chmod +x /usr/local/bin/ha_promote.sh /usr/local/bin/ha_demote.sh
}

configure_keepalived() {
    section "Configuració Keepalived"

    cat > /etc/keepalived/check_services.sh <<'EOF'
#!/bin/bash
systemctl is-active --quiet apache2 || exit 1
systemctl is-active --quiet vsftpd || exit 1

if systemctl list-unit-files | grep -q '^named\.service'; then
    systemctl is-active --quiet named || exit 1
else
    systemctl is-active --quiet bind9 || exit 1
fi

exit 0
EOF
    chmod +x /etc/keepalived/check_services.sh

    cat > /etc/keepalived/keepalived.conf <<EOF
global_defs {
    router_id ${NODE_HOSTNAME}_ha
    script_user root
    enable_script_security
}

vrrp_script chk_services {
    script "/etc/keepalived/check_services.sh"
    interval 5
    timeout 3
    fall 2
    rise 2
    weight -20
}

vrrp_instance VI_LAB {
    state ${NODE_STATE}
    interface ${INT_IFACE}
    virtual_router_id 51
    priority ${NODE_PRIORITY}
    advert_int 1

    unicast_src_ip ${NODE_IP}
    unicast_peer {
        ${PEER_IP}
    }

    authentication {
        auth_type PASS
        auth_pass ${KEEPALIVED_AUTH}
    }

    virtual_ipaddress {
        ${VIP_IP}/24 dev ${INT_IFACE} label ${INT_IFACE}:vip
    }

    track_script {
        chk_services
    }

    notify_master "/usr/local/bin/ha_promote.sh"
    notify_backup "/usr/local/bin/ha_demote.sh"
    notify_fault  "/usr/local/bin/ha_demote.sh"
}
EOF

    sysctl -w net.ipv4.ip_nonlocal_bind=1 >>"$LOG_FILE" 2>&1
    if ! grep -q "net.ipv4.ip_nonlocal_bind=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_nonlocal_bind=1" >> /etc/sysctl.conf
    fi

    systemctl enable --now keepalived >>"$LOG_FILE" 2>&1
    systemctl restart keepalived >>"$LOG_FILE" 2>&1
}

configure_sync() {
    section "Configuració rsync i cron"

    cat > /usr/local/bin/ha_sync.sh <<EOF
#!/bin/bash
LOG="/var/log/ha_sync.log"
PEER="${PEER_IP}"
TS=\$(date '+%Y-%m-%d %H:%M:%S')

sync_dir() {
    local src="\$1"
    local dst="\$2"
    rsync -az --delete \\
      -e "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5" \\
      "\$src" "root@\${PEER}:\${dst}" >>"\$LOG" 2>&1 && \
      echo "[\$TS] OK  \$src -> \$dst" >>"\$LOG" || \
      echo "[\$TS] ERR \$src -> \$dst" >>"\$LOG"
}

sync_dir "/var/www/html/" "/var/www/html/"
if [[ "${ROLE}" == "PRIMARY" ]]; then
    sync_dir "/etc/bind/zones/" "/etc/bind/zones/"
fi
EOF

    chmod +x /usr/local/bin/ha_sync.sh

    if [[ "$ROLE" == "PRIMARY" ]]; then
        cat > /etc/cron.d/ha_lab_sync <<'EOF'
*/5 * * * * root /usr/local/bin/ha_sync.sh
EOF
    else
        rm -f /etc/cron.d/ha_lab_sync
    fi
}

disable_ufw() {
    section "Desactivar UFW (firewall obert per a laboratori)"
    # Assegurar que UFW estigui desactivat (laboratori vulnerable)
    ufw disable >>"$LOG_FILE" 2>&1 || true
    log "UFW desactivat. Firewall: OBERT (entorn de laboratori)"
}

start_services() {
    section "Arrencada inicial de serveis"

    if [[ "$ROLE" == "PRIMARY" ]]; then
        /usr/local/bin/ha_promote.sh || true
    else
        /usr/local/bin/ha_demote.sh || true
        systemctl start apache2 || true
        systemctl start vsftpd || true
        if systemctl list-unit-files | grep -q '^named\.service'; then
            systemctl start named || true
        else
            systemctl start bind9 || true
        fi
    fi

    systemctl restart keepalived >>"$LOG_FILE" 2>&1 || true
}

print_summary() {
    section "INSTAL·LACIÓ COMPLETADA"

    log "Rol                 : $ROLE"
    log "NIC interna         : ${INT_IFACE} (${NODE_IP}/24)"
    log "Peer                : ${PEER_IP}"
    log "VIP                 : ${VIP_IP}"
    log "Failover complet    : VIP + DNS + Apache + FTP + DHCP"
    log "Log complet         : ${LOG_FILE}"
}

main() {
    ensure_logfile
    check_root
    check_ubuntu

    ask_role
    prepare_system
    configure_network
    configure_ssh
    configure_dns
    configure_dhcp
    configure_apache
    configure_ftp
    configure_mariadb_dvwa
    configure_mail
    configure_ha_hooks
    configure_keepalived
    configure_sync
    disable_ufw
    start_services
    print_summary
}

main "$@"
