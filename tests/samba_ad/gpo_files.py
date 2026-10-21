"""Legt die GPO-Dateien der Testdomäne in SYSVOL an (läuft im Samba-Container, ohne doku_agent).

Aufruf: python3 gpo_files.py <sysvol-domäne> <GUID Clients> <GUID Server> <SID Helpdesk>
"""

import os
import struct
import sys

SV, CLI, SRV, HD = sys.argv[1:5]
NS = 'xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"'


def write(rel: str, data) -> None:
    path = os.path.join(SV, "Policies", rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def u16(text: str) -> bytes:
    return b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le")


def pol(entries) -> bytes:
    """Registry.pol (MS-GPREG): 'PReg' + Version 1, dann [Schlüssel;Wert;Typ;Größe;Daten]."""
    def s(text):
        return text.encode("utf-16-le") + b"\x00\x00"
    out = b"PReg" + struct.pack("<I", 1)
    for key, value, kind, data in entries:
        raw = struct.pack("<I", data) if kind == 4 else s(data)
        out += (s("[")[:-2] + s(key) + s(";")[:-2] + s(value) + s(";")[:-2] + struct.pack("<I", kind)
                + s(";")[:-2] + struct.pack("<I", len(raw)) + s(";")[:-2] + raw + s("]")[:-2])
    return out


write(f"{CLI}/GPT.INI", "[General]\r\nVersion=196611\r\n")
write(f"{SRV}/GPT.INI", "[General]\r\nVersion=2\r\n")  # absichtlich ungleich zu versionNumber 3
write(f"{CLI}/Machine/Registry.pol", pol([
    (r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 4, 0),
    (r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions", 4, 4),
    (r"Software\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 4, 1),
    (r"Software\Policies\Microsoft\Windows\DeviceGuard", "**del.EnableVirtualizationBasedSecurity", 1, " "),
    (r"Software\Policies\Microsoft\WindowsFirewall\FirewallRules", "{11111111-2222-3333-4444-555555555555}", 1,
     "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|RA4=10.0.0.0/255.0.0.0|Name=RDP intern|"),
    (r"Software\Firma\Agent", "Server", 1, "agent.corp.example.test"),
]))
write(f"{CLI}/User/Registry.pol", pol([
    (r"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveTimeOut", 1, "900")]))
write(f"{CLI}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf", u16(f"""[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Event Audit]
AuditLogonEvents = 3
[Privilege Rights]
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeDenyNetworkLogonRight = *S-1-5-32-546
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = *{HD}
[Service General Setting]
"Spooler",4,""
"""))
write(f"{CLI}/Machine/Microsoft/Windows NT/Audit/audit.csv",
      "﻿Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n"
      ",System,Anmelden,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3\r\n")
write(f"{CLI}/Machine/Preferences/Groups/Groups.xml", f"""<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}"><User clsid="{{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}}"
 name="LokalAdmin" uid="{{A1}}"><Properties action="U" userName="LokalAdmin" cpassword="TESTWERT-NICHT-ECHT"
 neverExpires="1" acctDisabled="0"/></User>
<Group clsid="{{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}}" name="Administratoren (integriert)" uid="{{A2}}">
<Properties action="U" groupSid="S-1-5-32-544" groupName="Administratoren (integriert)"><Members>
<Member name="CORP\\Helpdesk" action="ADD" sid="{HD}"/></Members></Properties>
<Filters><FilterOrgUnit bool="AND" not="0" name="OU=Clients,OU=Firma,DC=corp,DC=example,DC=test"/></Filters></Group>
</Groups>""")
write(f"{CLI}/Machine/Scripts/scripts.ini", u16("[Startup]\n0CmdLine=\\\\corp.example.test\\NETLOGON\\inventar.cmd\n"
                                                 "0Parameters=/quiet\n"))
write(f"{CLI}/User/Preferences/Drives/Drives.xml", """<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}"><Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="H:"
 uid="{B1}"><Properties action="U" path="\\\\fs01\\home\\%USERNAME%" label="Home" persistent="1" letter="H"/>
</Drive></Drives>""")
write(f"{SRV}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf", u16("[System Access]\nEnableGuestAccount = 0\n"))

# Central Store: zwei ADMX-Dateien mit dateiübergreifender Kategorie, Namen auf Deutsch
write("PolicyDefinitions/dokubase.admx", f"""<policyDefinitions {NS} revision="1.0" schemaVersion="1.0">
<policyNamespaces><target prefix="base" namespace="Doku.Base"/></policyNamespaces><resources minRequiredRevision="1.0"/>
<categories><category name="WindowsComponents" displayName="$(string.WindowsComponents)"/></categories>
</policyDefinitions>""")
write("PolicyDefinitions/de-DE/dokubase.adml", f"""<policyDefinitionResources {NS} revision="1.0" schemaVersion="1.0">
<displayName/><description/><resources><stringTable><string id="WindowsComponents">Windows-Komponenten</string>
</stringTable></resources></policyDefinitionResources>""")
write("PolicyDefinitions/dokutest.admx", f"""<policyDefinitions {NS} revision="1.0" schemaVersion="1.0">
<policyNamespaces><target prefix="test" namespace="Doku.Test"/><using prefix="base" namespace="Doku.Base"/>
</policyNamespaces><resources minRequiredRevision="1.0"/>
<categories><category name="WU" displayName="$(string.WU)"><parentCategory ref="base:WindowsComponents"/></category>
<category name="Pers" displayName="$(string.Pers)"/></categories>
<policies>
<policy name="AutoUpdateCfg" class="Machine" displayName="$(string.AutoUpdateCfg)" explainText="$(string.AutoUpdateCfg)"
 presentation="$(presentation.AutoUpdateCfg)" key="Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
 valueName="NoAutoUpdate"><parentCategory ref="WU"/><enabledValue><decimal value="0"/></enabledValue>
<disabledValue><decimal value="1"/></disabledValue><elements><enum id="AutoUpdateMode" valueName="AUOptions">
<item displayName="$(string.AU2)"><value><decimal value="2"/></value></item>
<item displayName="$(string.AU4)"><value><decimal value="4"/></value></item></enum></elements></policy>
<policy name="NoLockScreenCamera" class="Machine" displayName="$(string.Cam)" explainText="$(string.Cam)"
 key="Software\\Policies\\Microsoft\\Windows\\Personalization" valueName="NoLockScreenCamera">
<parentCategory ref="Pers"/></policy>
<policy name="ScreenSaveTimeOut" class="User" displayName="$(string.SST)" explainText="$(string.SST)"
 presentation="$(presentation.SST)" key="Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop">
<parentCategory ref="Pers"/><elements><text id="Timeout" valueName="ScreenSaveTimeOut"/></elements></policy>
</policies></policyDefinitions>""")
write("PolicyDefinitions/de-DE/dokutest.adml", f"""<policyDefinitionResources {NS} revision="1.0" schemaVersion="1.0">
<displayName/><description/><resources><stringTable><string id="WU">Windows Update</string>
<string id="Pers">Personalisierung</string><string id="AutoUpdateCfg">Automatische Updates konfigurieren</string>
<string id="AU2">2 - Vor Download benachrichtigen</string>
<string id="AU4">4 - Automatisch herunterladen und laut Zeitplan installieren</string>
<string id="Cam">Aktivieren der Kamera auf dem Sperrbildschirm verhindern</string>
<string id="SST">Zeitlimit für Bildschirmschoner</string></stringTable>
<presentationTable><presentation id="AutoUpdateCfg"><dropdownList refId="AutoUpdateMode">Automatische Updates
 konfigurieren:</dropdownList></presentation><presentation id="SST"><textBox refId="Timeout"><label>Sekunden:</label>
</textBox></presentation></presentationTable></resources></policyDefinitionResources>""")
