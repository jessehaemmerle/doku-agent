# Samba-AD-DC für die Integrationstests

Ein Samba-Domänencontroller (`corp.example.test`) mit den Testdaten, die `tests/test_integration_ad.py` erwartet:
OUs, Benutzer, Gruppen, Computer, Delegation, PSO, Standorte, drei GPOs mit Dateien in SYSVOL (administrative
Vorlagen, Sicherheitsvorlage, erweiterte Überwachung, Preferences mit Test-`cpassword`, Skript) und einen kleinen
Central Store. **Nur für Tests** – das Administratorkennwort steht im Skript.

```bash
docker build -t doku-samba-ad tests/samba_ad
docker run -d --name samba-ad --hostname dc1 --privileged \
  -p 127.0.0.1:1636:636 -p 127.0.0.1:1445:445 doku-samba-ad
# warten, bis Port 636 antwortet, dann einmal:
docker exec samba-ad /opt/setup.sh
docker cp samba-ad:/var/lib/samba/private/tls/ca.pem /tmp/samba-ca.pem
echo "127.0.0.1 dc1.corp.example.test" | sudo tee -a /etc/hosts   # Name passt zum Zertifikat

DOKU_IT_AD_SERVER=dc1.corp.example.test DOKU_IT_AD_PORT=1636 DOKU_IT_AD_SMB_PORT=1445 \
DOKU_IT_AD_CA=/tmp/samba-ca.pem .venv/bin/pytest tests/test_integration_ad.py
```

`--privileged` braucht Samba für die erweiterten Dateiattribute in SYSVOL (NT-ACLs).
