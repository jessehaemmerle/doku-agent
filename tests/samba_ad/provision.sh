#!/bin/bash
# Domäne beim ersten Start anlegen, danach nur Samba starten
set -e
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf /etc/krb5.conf
  samba-tool domain provision --realm=CORP.EXAMPLE.TEST --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass='Adm1n!Passw0rd' --host-name=dc1 --use-rfc2307 \
    --option="dns forwarder = 127.0.0.1" > /tmp/provision.log 2>&1 || { cat /tmp/provision.log; exit 1; }
fi
grep -q dc1.corp.example.test /etc/hosts || echo "$(hostname -i | cut -d' ' -f1) dc1.corp.example.test dc1" >> /etc/hosts
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
exec samba --foreground --no-process-group
