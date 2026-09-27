# 01 – Lab-Setup (Proxmox Test-Domäne)

Aufbau einer **isolierten** AD-Testumgebung auf Proxmox für Golden-/Silver-Ticket-Angriffe.

> ⚠️ Nur für das eigene Test-Lab. Kein Routing/keine Verbindung zur Produktivumgebung.

## 1. Topologie

| Host | Rolle | OS | IP | DNS |
|------|-------|----|----|-----|
| **DC1** | Domain Controller, DNS | Windows Server 2022/2025 | `10.10.10.10/24` | `127.0.0.1` |
| **PC1** | Domänen-Client | Windows 11 | `10.10.10.20/24` (o. DHCP) | `10.10.10.10` |
| **VM1** | Angreifer | Kali Linux | `10.10.10.50/24` | `10.10.10.10` |

- **Domäne:** `lab.local`  ·  **NetBIOS:** `LAB`
- **Subnet:** `10.10.10.0/24`

### Namensauflösung & Zeit — die zwei häufigsten Fehler
- **DNS:** PC1 **und** VM1 müssen als DNS-Server **DC1 (10.10.10.10)** nutzen — sonst schlägt die
  Kerberos-Auflösung (SPNs/FQDN) fehl.
- **Zeit:** Kerberos toleriert max. **5 Minuten** Zeitdifferenz (`KRB_AP_ERR_SKEW`). DC1 ist
  Zeitquelle; PC1 synchronisiert automatisch, **VM1/Kali** muss manuell mit DC1 synchronisieren
  (siehe Abschnitt 5).

## 2. Proxmox-Netzwerk (isoliert)

1. In Proxmox eine **interne Linux-Bridge** anlegen, z. B. `vmbr1` **ohne** physischen Uplink
   (Datacenter → Node → System → Network → Create → Linux Bridge, "Bridge ports" leer lassen).
2. Alle drei VMs an `vmbr1` hängen.
3. **Für Installation/Updates** kurzzeitig eine zweite NIC an eine NAT-/Internet-Bridge hängen,
   danach wieder entfernen → Lab bleibt isoliert.
4. **Snapshots**: Nach fertigem Setup jeder VM einen Snapshot `clean` anlegen (Rollback nach Tests).

## 3. DC1 – Windows Server (DC promoten)

Nach OS-Installation als lokaler Admin (PowerShell, als Administrator):

```powershell
# Statische IP + DNS auf sich selbst
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1

# Umbenennen + Neustart
Rename-Computer -NewName "DC1" -Restart
```

Nach dem Neustart – AD DS installieren und zur neuen Gesamtstruktur promoten:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Import-Module ADDSDeployment
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -ForestMode "WinThreshold" -DomainMode "WinThreshold" `
  -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!Lab" -AsPlainText -Force) `
  -Force
# DC1 startet automatisch neu und ist danach Domänencontroller.
```

Danach: Testbenutzer, ein Service-Konto **mit SPN** (für Silver Ticket / Kerberoasting) und ein
Domänenadmin für Demozwecke anlegen — siehe [`scripts/Setup-LabDomain.ps1`](../scripts/Setup-LabDomain.ps1)
oder manuell:

```powershell
Import-Module ActiveDirectory

# Standardbenutzer
New-ADUser -Name "Max Mustermann" -SamAccountName "max" `
  -AccountPassword (ConvertTo-SecureString "User123!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# Service-Konto MIT SPN (Ziel für Silver Ticket + Kerberoasting)
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
  -AccountPassword (ConvertTo-SecureString "Sql_Svc_2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
setspn -S "MSSQLSvc/dc1.lab.local:1433" svc_sql

# Demo-Domänenadmin (nur fürs Lab)
New-ADUser -Name "labadmin" -SamAccountName "labadmin" `
  -AccountPassword (ConvertTo-SecureString "Admin_Lab_2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members labadmin
```

Domänen-SID merken (wird für beide Angriffe gebraucht):

```powershell
Get-ADDomain | Select-Object -ExpandProperty DomainSID
# z. B. S-1-5-21-1111111111-2222222222-3333333333
```

## 4. PC1 – Windows 11 (Domäne beitreten)

```powershell
# DNS auf DC1 zeigen lassen
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10

# Domäne beitreten (Neustart folgt)
Add-Computer -DomainName "lab.local" `
  -Credential (Get-Credential LAB\labadmin) -Restart
```

Danach an PC1 als `LAB\max` anmelden. PC1 ist typischer Ausgangspunkt für Credential-Dumping
und späteres Pass-the-Ticket.

## 5. VM1 – Kali (Angreifer)

```bash
# DNS auf DC1 zeigen lassen (dauerhaft je nach Netzwerk-Manager konfigurieren)
echo "nameserver 10.10.10.10" | sudo tee /etc/resolv.conf

# Auflösung testen
nslookup dc1.lab.local

# Zeit mit DC1 synchronisieren (WICHTIG gegen KRB_AP_ERR_SKEW)
sudo apt-get install -y ntpdate
sudo ntpdate 10.10.10.10

# Tools
sudo apt-get install -y python3-impacket krb5-user
# (Alternativ Rubeus/Mimikatz, falls VM1 später Windows ist)
```

`/etc/krb5.conf` – Realm für saubere Kerberos-Auth setzen:

```ini
[libdefaults]
    default_realm = LAB.LOCAL
[realms]
    LAB.LOCAL = {
        kdc = dc1.lab.local
        admin_server = dc1.lab.local
    }
[domain_realm]
    .lab.local = LAB.LOCAL
    lab.local = LAB.LOCAL
```

## 6. Checkliste vor den Angriffen

- [ ] DC1 promotet, `lab.local` erreichbar
- [ ] PC1 der Domäne beigetreten, Login mit `LAB\max` klappt
- [ ] VM1 löst `dc1.lab.local` auf und Zeit ist synchron
- [ ] Service-Konto `svc_sql` mit SPN `MSSQLSvc/dc1.lab.local:1433` existiert
- [ ] Domänen-SID notiert
- [ ] Snapshots `clean` auf allen VMs

➡️ Weiter mit [`03-golden-ticket.md`](03-golden-ticket.md) und [`04-silver-ticket.md`](04-silver-ticket.md).
