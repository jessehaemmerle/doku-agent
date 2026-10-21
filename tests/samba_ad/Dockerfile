# Samba als Active-Directory-Domänencontroller – nur für die Integrationstests (nie produktiv verwenden)
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind krb5-user ldb-tools smbclient \
    && rm -rf /var/lib/apt/lists/*
COPY provision.sh setup.sh gpo_files.py /opt/
ENTRYPOINT ["/opt/provision.sh"]
