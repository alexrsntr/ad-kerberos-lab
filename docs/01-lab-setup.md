# 01 – Lab-Setup

> TODO: Aufbau der isolierten Test-Umgebung dokumentieren.

## Komponenten
- **Domain Controller** (Windows Server) — AD DS, Domäne z. B. `lab.local`
- **Domänen-Client** (Windows 10/11)
- **Angreifer-Host** (Kali / Windows mit Rubeus, Impacket, Mimikatz)

## Netzwerk
- Isoliertes internes Netz (kein Internet-Routing zur Produktivumgebung)

## Hinweise
- Keine echten Firmen-Credentials verwenden.
- Snapshots vor Angriffen anlegen.
