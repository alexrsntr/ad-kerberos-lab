# 05 – Detection & Hardening

Der **defensive Kern** des Repos. Golden-/Silver-Tickets sind schwer zu verhindern, sobald das
Schlüsselmaterial (krbtgt- bzw. Service-Hash) kompromittiert ist — daher liegt der Fokus auf
**früher Erkennung**, **Reduktion der Angriffsfläche** und **Invalidierung** bereits gefälschter
Tickets.

---

## 1. Relevante Windows-Event-IDs

| ID | Quelle | Bedeutung | Rolle bei der Erkennung |
|----|--------|-----------|-------------------------|
| **4768** | DC (KDC) | **TGT** angefordert (AS-REQ) | Fehlt bei Golden/Silver, weil das TGT nicht vom DC kam |
| **4769** | DC (KDC) | **Service-Ticket** angefordert (TGS-REQ) | Golden: 4769 **ohne** vorheriges 4768. Silver: fehlt komplett |
| **4770** | DC | TGT/TGS erneuert | Ungewöhnliche Renewals |
| **4624** | Zielhost | Erfolgreiche Anmeldung (Logon-Type 3) | Silver: Zugriff am Host **ohne** DC-Spur |
| **4672** | Zielhost | Zuweisung von Sonderrechten (admin) | „Administrator"-Logons zu ungewöhnlichen Zeiten |
| **4662** | DC | Zugriff auf AD-Objekt (mit passendem SACL) | **DCSync**-Erkennung (Replikations-GUIDs) |
| **5136/5137** | DC | AD-Objekt geändert/erstellt | krbtgt-/Service-Konto-Manipulation |

> **Voraussetzung:** „Kerberos Authentication Service" und „Kerberos Service Ticket Operations"
> müssen per **Advanced Audit Policy** auf den DCs aktiviert sein, und die Host-Logons (4624/4672)
> müssen ans SIEM gehen. Ohne dieses Logging sind die Angriffe **unsichtbar**.

---

## 2. Detection-Logik

### 2.1 Golden Ticket

1. **4769 ohne 4768** – Ein Konto fordert ein Service-Ticket an, für das es zuvor **kein** TGT vom
   DC bezogen hat. Korrelation pro Konto über ein Zeitfenster (z. B. 10 h).
2. **Unrealistische Ticket-Lebensdauer** – Fälschungs-Defaults setzen teils **10 Jahre**
   Gültigkeit. Normale Domänen-Policy: 10 h TGT / 7 Tage Renew. Ticket-Lifetime ≫ Policy = Alarm.
3. **RC4 in AES-Domäne** – 4769 mit `Ticket Encryption Type = 0x17` (RC4), obwohl die Konten AES
   können. (Feld „Ticket Encryption Type" im 4769.)
4. **Nicht existierendes / inkonsistentes Konto** – Ticket-Konto existiert nicht in AD, oder
   Account-Name/RID/Gruppen sind inkonsistent (nur mit PAC-Analyse/Tools sichtbar).
5. **DCSync-Vorstufe** – **4662** mit den Replikations-Extended-Rights (`DS-Replication-Get-Changes`
   GUID `1131f6aa-...`, `...-All` GUID `1131f6ad-...`) von einem **Nicht-DC-Konto** → jemand zieht
   gerade krbtgt/Hashes.

**Skizze (Splunk-artig):**
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| join type=outer Account_Name
    [ search index=wineventlog EventCode=4768 | fields Account_Name _time ]
| where isnull(matched_4768_time)     ' TGS ohne vorheriges TGT
| table _time, Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type
```

**Skizze (KQL / Microsoft Sentinel):**
```kql
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| join kind=leftanti (
    SecurityEvent | where EventID == 4768 | project Account, TgtTime=TimeGenerated
) on Account
| project TimeGenerated, Account, ServiceName, IpAddress, TicketEncryptionType
```

### 2.2 Silver Ticket

Das Kern-IOC ist die **Lücke**: Zugriff/Logon **am Zielhost** (4624, ggf. 4672), **ohne** dass am
DC ein passendes **4768/4769** existiert. Der KDC wurde ja umgangen.

**Skizze (Host-4624 ohne DC-4769 korrelieren):**
```spl
index=wineventlog EventCode=4624 Logon_Type=3 host=CLIENT01*
| eval user=lower(Account_Name)
| join type=outer user
    [ search index=wineventlog EventCode=4769 | eval user=lower(Account_Name)
      | fields user _time ]
| where isnull(matched_4769)          ' Host-Logon, aber KDC hat nie ein Ticket ausgestellt
| table _time, host, user, Source_Network_Address
```

Zusätzliche Silver-Indikatoren:
- **RC4** bei Diensten, deren Konto eigentlich AES beherrscht.
- Zugriffe als hochprivilegierte Namen (`Administrator`) auf **einzelne** Dienste außerhalb
  üblicher Muster / Zeiten.
- PAC ohne gültige serverseitige Signatur (mit PAC-Validierung erzwingbar, s. u.).

---

## 3. Baselining & False Positives

- **4769 ohne 4768** kann legitim sein (langlebige TGTs über Session-Grenzen, geclusterte Dienste).
  → Als **Anomalie mit Risikoscore** behandeln, nicht als Hard-Block; nach Konto/Host baseline-en.
- **RC4** kann in Legacy-Umgebungen normal sein. → Erst RC4 *unattraktiv/deaktiviert* machen
  (siehe Hardening), dann wird RC4 zum sauberen Signal.
- Service-Cluster/Load-Balancer erzeugen ungewöhnliche 4624-Muster → in die Baseline aufnehmen.

---

## 4. Härtungs-Checkliste

### 4.1 Schlüsselmaterial schützen & invalidieren
- [ ] **krbtgt-Passwort zweimal rotieren** (mit Wartezeit ≥ max. Ticket-Lebensdauer dazwischen) —
      **invalidiert alle bestehenden Golden Tickets**. Nach jedem DA-Kompromiss **Pflicht**.
      (Microsoft-Skript `New-KrbtgtKeys.ps1`.)
- [ ] **Service-Konto-Passwörter regelmäßig rotieren**; besser **gMSA/dMSA** (automatische, lange,
      zufällige Rotation) → entzieht Silver Tickets die Basis.
- [ ] **Computerkonto-Passwort-Rotation aktiv lassen** (Standard alle 30 Tage; nicht per GPO
      deaktivieren) → begrenzt Lebensdauer geklauter Maschinen-Hashes.

### 4.2 Krypto & PAC
- [ ] **RC4 (und DES) deaktivieren**, **AES erzwingen** (`msDS-SupportedEncryptionTypes`,
      GPO „Network security: Configure encryption types allowed for Kerberos"). Macht RC4-Tickets
      zum eindeutigen IOC.
- [ ] **PAC-Validierung / aktuelle Updates**: KB5008380/KB5008602 & Folge-Updates (PAC-Signaturen,
      „PAC Requestor") einspielen und in den **Enforcement**-Modus bringen → erschwert gefälschte
      PACs erheblich.

### 4.3 Angriffsfläche & Privilegien
- [ ] **Tiering / Privileged Access**: DA-Konten **nie** auf Tier-1/2-Hosts (Workstations/Server)
      interaktiv anmelden → keine DA-Credentials/TGTs im LSASS normaler Maschinen.
      *(Genau der Weg, der im Live-Lab zum Golden Ticket führen würde.)*
- [ ] **`Protected Users`**-Gruppe für alle Admin-Konten (kein RC4/NTLM, kürzere Tickets, kein
      Delegations-Missbrauch).
- [ ] **LSASS-Schutz**: Credential Guard, **RunAsPPL** (`RunAsPPL=1`), Attack-Surface-Reduction-
      Regel „Block credential stealing from LSASS" → erschwert das Ernten von Hashes/Tickets.
- [ ] **Least Privilege für Service-Konten**; keine unnötigen SPNs; keine Service-Accounts in
      `Domain Admins`.
- [ ] **Account-Policy härten** (im Live-Lab war *Lockout = None* und *Komplexität aus*):
      Lockout-Schwelle setzen, Komplexität + Mindestlänge erzwingen, **kein Passwort-Reuse**
      zwischen normalen und Admin-Konten → hätte den initialen Foothold verhindert.

### 4.4 Monitoring
- [ ] **Advanced Audit Policy** auf DCs: Kerberos-AS/TGS-Auditing **an**; Host-Auditing für
      4624/4672 **an**; alles ans **SIEM**.
- [ ] **Alerting** auf: 4662-DCSync von Nicht-DCs, 4769-RC4-Anomalien, 4769-ohne-4768,
      4624-ohne-KDC-Spur, exzessive Ticket-Lebensdauer.
- [ ] **krbtgt-Alter überwachen** (lange nicht rotiert = Risiko).

---

## 5. Bezug zum Live-Lab (`lab.local`)

| Beobachtung im Lab | Passende Härtung |
|--------------------|------------------|
| Lockout `None`, Komplexität aus, PW-Reuse (Administrator = testkerb) | 4.3 Account-Policy, kein Reuse |
| Lokaler Admin auf Domänen-VM → Maschinen-/Session-Hashes | 4.3 Tiering, LSASS-Schutz, Protected Users |
| krbtgt via DCSync → Golden möglich | 4.1 krbtgt-Doppelrotation, 4.4 DCSync-Alert (4662) |
| DC$/Service-Hash → Silver möglich | 4.1 gMSA/Rotation, 4.2 AES/PAC |
| Tickets ggf. mit RC4 | 4.2 RC4 deaktivieren → RC4 wird IOC (2.1/2.2) |
