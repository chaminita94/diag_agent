#!/usr/bin/env bash
# =============================================================================
# setup_raid.sh
#
# Crea un RAID 1 (mirror) software amb mdadm
# Discos: /dev/sdb + /dev/sdc  →  /dev/md0  →  /srv/raid
#
# Ús: sudo bash setup_raid.sh
# =============================================================================

set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Executa com a root: sudo bash $0"; exit 1; }

RAID_DEV="/dev/md0"
DISK1="/dev/sdb"
DISK2="/dev/sdc"
MOUNT="/srv/raid"

echo "==> Instal·lant mdadm..."
apt-get install -y mdadm > /dev/null 2>&1

echo "==> Comprovant discos $DISK1 i $DISK2..."
lsblk "$DISK1" "$DISK2"

# Si el RAID ja existeix, sortir
if mdadm --detail "$RAID_DEV" > /dev/null 2>&1; then
    echo "==> RAID $RAID_DEV ja existeix. Sortint."
    mdadm --detail "$RAID_DEV"
    exit 0
fi

echo "==> Netejant metadades anteriors..."
mdadm --zero-superblock "$DISK1" "$DISK2" 2>/dev/null || true

echo "==> Creant RAID 1..."
echo 'y' | mdadm --create "$RAID_DEV" \
    --level=1 \
    --raid-devices=2 \
    "$DISK1" "$DISK2"

echo "==> Esperant sincronització inicial..."
sleep 3
cat /proc/mdstat

echo "==> Formatant /dev/md0 amb ext4..."
mkfs.ext4 -F "$RAID_DEV"

echo "==> Muntant a $MOUNT..."
mkdir -p "$MOUNT"
mount "$RAID_DEV" "$MOUNT"

echo "==> Afegint a /etc/fstab..."
UUID=$(blkid -s UUID -o value "$RAID_DEV")
if ! grep -q "$UUID" /etc/fstab; then
    echo "UUID=${UUID}  ${MOUNT}  ext4  defaults  0  2" >> /etc/fstab
fi

echo "==> Guardant configuració mdadm..."
mdadm --detail --scan >> /etc/mdadm/mdadm.conf
update-initramfs -u

echo ""
echo "=============================="
echo " RAID 1 configurat correctament"
echo "=============================="
echo " Dispositiu : $RAID_DEV"
echo " Discos     : $DISK1  $DISK2"
echo " Muntat a   : $MOUNT"
echo " UUID       : $UUID"
echo " Espai útil : $(df -h "$MOUNT" | awk 'NR==2{print $2}')"
echo "=============================="
echo ""
cat /proc/mdstat
