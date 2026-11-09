#!/bin/bash
# Testdaten für tests/test_integration_ad.py (einmal nach dem Start: docker exec samba-ad /opt/setup.sh)
set -e
A="-U Administrator%Adm1n!Passw0rd -H ldap://dc1.corp.example.test"
B="DC=corp,DC=example,DC=test"
DB=/var/lib/samba/private/sam.ldb
SV=/var/lib/samba/sysvol/corp.example.test
q() { "$@" > /dev/null; }
sid() { ldbsearch -H $DB "(sAMAccountName=$1)" objectSid | awk '/^objectSid/{print $2}'; }
uac() {  # userAccountControl setzen
  printf "dn: %s\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: %s\n" "$1" "$2" | q ldbmodify -H $DB
}

q samba-tool ou add "OU=Firma,$B"
for ou in Clients Server Benutzer Admins; do q samba-tool ou add "OU=$ou,OU=Firma,$B"; done
q samba-tool user add anna 'Anna!Passw0rd1' --given-name=Anna --surname=Admin --userou="OU=Admins,OU=Firma"
q samba-tool group addmembers "Domain Admins" anna
q samba-tool user setexpiry anna --noexpiry
q samba-tool user add bernd 'Bernd!Passw0rd1' --given-name=Bernd --surname=Benutzer --userou="OU=Benutzer,OU=Firma"
q samba-tool user add svc-sql 'Svc!Passw0rd12345' --userou="OU=Server,OU=Firma"
q samba-tool spn add MSSQLSvc/sql01.corp.example.test:1433 svc-sql
q samba-tool user setexpiry svc-sql --noexpiry
q samba-tool user add svc-old 'Svc!Passw0rd12345' --userou="OU=Server,OU=Firma"
uac "CN=svc-old,OU=Server,OU=Firma,$B" 4260352   # ohne Kerberos-Vorauthentifizierung, Kennwort läuft nie ab
q samba-tool user add doku-reader 'Reader!Passw0rd1'
q samba-tool group add Helpdesk --groupou="OU=Benutzer,OU=Firma"
q samba-tool group addmembers Helpdesk bernd
q samba-tool group add GG-Server-Admins --groupou="OU=Admins,OU=Firma"
q samba-tool group addmembers GG-Server-Admins svc-sql
q samba-tool group addmembers Administrators GG-Server-Admins
for c in srv01:Server web01:Server pc001:Clients pc002:Clients; do
  q samba-tool computer add "${c%%:*}" --computerou="OU=${c##*:},OU=Firma"
done
q samba-tool computer add pc-old
q samba-tool delegation for-any-service 'srv01$' on
q samba-tool delegation add-service 'web01$' cifs/fs01.corp.example.test
uac "CN=srv01,OU=Server,OU=Firma,$B" 528384     # aktivieren (Samba legt Computer deaktiviert an)
uac "CN=pc-old,CN=Computers,$B" 4096
uac "CN=pc001,OU=Clients,OU=Firma,$B" 4096
q samba-tool domain passwordsettings pso create PSO-Admins 10 --min-pwd-length=16 --complexity=on \
  --history-length=24 --account-lockout-threshold=5 --max-pwd-age=0 $A
q samba-tool domain passwordsettings pso apply PSO-Admins "Domain Admins" $A
q samba-tool sites create Wien
q samba-tool sites subnet create 10.1.0.0/16 Wien
q samba-tool sites subnet create 10.2.0.0/16 Default-First-Site-Name

guid() { samba-tool gpo create "$1" $A 2>/dev/null | grep -o '{[0-9A-F-]*}'; }
CLI=$(guid "Clients - Sicherheit"); SRV=$(guid "Server - Basis"); guid "Ungenutzt" > /dev/null
q samba-tool gpo setlink "OU=Clients,OU=Firma,$B" "$CLI" --enforce $A
q samba-tool gpo setlink "OU=Server,OU=Firma,$B" "$SRV" $A
q samba-tool gpo setlink "OU=Firma,$B" "$SRV" --disable $A
q samba-tool gpo setinheritance "OU=Server,OU=Firma,$B" block $A
samba-tool gpo admxload $A > /dev/null 2>&1

HD=$(sid Helpdesk); OLD=$(sid svc-old)
q samba-tool dsacl set --objectdn="OU=Benutzer,OU=Firma,$B" $A --sddl="(OA;CI;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;$HD)(OA;CI;WP;bf9679c0-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;$HD)(D;;DTSD;;;WD)"
q samba-tool dsacl set --objectdn="$B" $A --sddl="(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;$OLD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;$OLD)"
q samba-tool dsacl set --objectdn="CN=$SRV,CN=Policies,CN=System,$B" $A --sddl="(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;$HD)"

python3 /opt/gpo_files.py "$SV" "$CLI" "$SRV" "$HD"
printf 'dn: CN={A1B2C3D4-0000-1111-2222-333344445555},CN=SOM,CN=WMIPolicy,CN=System,%s\nobjectClass: msWMI-Som
msWMI-Name: Nur Windows 11\nmsWMI-Parm1: Clients mit Windows 11
msWMI-Parm2: 1;3;10;67;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.0.2%%";
msWMI-ID: {A1B2C3D4-0000-1111-2222-333344445555}\nmsWMI-Author: Administrator@corp.example.test
msWMI-ChangeDate: 20240101000000.000000-000\nmsWMI-CreationDate: 20240101000000.000000-000\n' "$B" | q ldbadd -H $DB
cat <<LDIF | q ldbmodify -H $DB
dn: CN=$CLI,CN=Policies,CN=System,$B
changetype: modify
replace: versionNumber
versionNumber: 196611
-
replace: gPCMachineExtensionNames
gPCMachineExtensionNames: [{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]
-
replace: gPCUserExtensionNames
gPCUserExtensionNames: [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F73-3407-48AE-BA88-E8213C6761F1}][{5794DAFD-BE60-433F-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]
-
replace: gPCWQLFilter
gPCWQLFilter: [corp.example.test;{A1B2C3D4-0000-1111-2222-333344445555};0]

dn: CN=$SRV,CN=Policies,CN=System,$B
changetype: modify
replace: versionNumber
versionNumber: 3
-
replace: gPCMachineExtensionNames
gPCMachineExtensionNames: [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
-
replace: flags
flags: 1
LDIF
samba-tool ntacl sysvolreset

# --- AD CS: eine verwundbare und eine sichere Vorlage plus eine CA (nur LDAP-Objekte, kein echter CA-Dienst) ---
CONF="CN=Configuration,$B"
PKI="CN=Public Key Services,CN=Services,$CONF"
DU=$(ldbsearch -H $DB "(sAMAccountName=Domain Users)" objectSid | awk '/^objectSid/{print $2}')
# msPKI-Certificate-Name-Flag 0x1 = Antragsteller bestimmt Namen; Enrollment-Flag 0 = keine Genehmigung
# Registrierungsrecht für Domain Users als ACE mit dem erweiterten Recht "Enroll" (0e10c968-...).
# (A;;LCRPLORC;;;AU) = Authentifizierte Benutzer dürfen lesen – wie im echten AD die Schema-Standard-ACL der
# Vorlagen, damit auch ein normaler Domänenbenutzer (doku-reader) Vorlagen und ZS aufzählen kann.
ldbadd -H $DB <<LDIF 2>/dev/null || true
dn: CN=VulnUserAuth,CN=Certificate Templates,$PKI
objectClass: pKICertificateTemplate
displayName: VulnUserAuth
msPKI-Certificate-Name-Flag: 1
msPKI-Enrollment-Flag: 0
msPKI-RA-Signature: 0
msPKI-Template-Schema-Version: 2
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.1.1
nTSecurityDescriptor: O:DAG:DAD:(A;;LCRPLORC;;;AU)(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;$DU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)

dn: CN=SafeTemplate,CN=Certificate Templates,$PKI
objectClass: pKICertificateTemplate
displayName: SafeTemplate
msPKI-Certificate-Name-Flag: 0
msPKI-Enrollment-Flag: 2
msPKI-RA-Signature: 0
msPKI-Template-Schema-Version: 2
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
nTSecurityDescriptor: O:DAG:DAD:(A;;LCRPLORC;;;AU)(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;$DU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)

dn: CN=corp-CA,CN=Enrollment Services,$PKI
objectClass: pKIEnrollmentService
dNSHostName: dc1.corp.example.test
certificateTemplates: VulnUserAuth
certificateTemplates: SafeTemplate
nTSecurityDescriptor: O:DAG:DAD:(A;;LCRPLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)
LDIF

# --- DNS: ein A-Eintrag (zeigt sich im DNS-Bericht und im Netbox-Abgleich) ---
# "samba-tool dns" kennt kein -H; nur anlegen, wenn er fehlt (Skript ist wiederholbar), Fehler nicht verschlucken
DNSAUTH="-U Administrator%Adm1n!Passw0rd"
samba-tool dns query dc1.corp.example.test corp.example.test app01 A $DNSAUTH > /dev/null 2>&1 \
  || q samba-tool dns add dc1.corp.example.test corp.example.test app01 A 10.1.0.50 $DNSAUTH

echo "Testdaten angelegt: Clients - Sicherheit $CLI, Server - Basis $SRV, AD CS (VulnUserAuth), DNS (app01)"
