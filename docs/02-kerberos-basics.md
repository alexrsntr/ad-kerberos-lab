# 02 – Kerberos-Grundlagen

Damit Golden- und Silver-Ticket-Angriffe *und* ihre Erkennung verständlich werden, muss der
normale Kerberos-Ablauf klar sein. Kernidee: Kerberos ist ein **Ticket-System mit einer zentralen
vertrauenswürdigen Instanz** (dem KDC auf dem Domänencontroller), die mit **symmetrischen
Schlüsseln** Tickets ausstellt und signiert. Wer einen dieser Schlüssel kennt, kann Tickets
**fälschen** — genau das ist die Grundlage beider Angriffe.

---

## 1. Beteiligte

| Begriff | Bedeutung |
|---------|-----------|
| **Client** | Der Benutzer/Rechner, der sich authentifiziert (z. B. `testkerb`). |
| **KDC** | *Key Distribution Center*, läuft auf dem DC. Besteht aus **AS** (Authentication Service) und **TGS** (Ticket Granting Service). |
| **krbtgt** | Verstecktes Dienstkonto. Sein Schlüssel signiert **alle TGTs**. → **Golden-Ticket-Schlüssel**. |
| **Service** | Der Zieldienst, adressiert über einen **SPN** (z. B. `cifs/client01`, `MSSQLSvc/...`). Läuft unter einem **Service-/Computerkonto**. |
| **TGT** | *Ticket Granting Ticket* – „Ausweis", mit `krbtgt`-Schlüssel verschlüsselt/signiert. |
| **TGS** | *Service Ticket* – Zugang zu **einem** Dienst, mit dem **Schlüssel des Service-Kontos** verschlüsselt. → **Silver-Ticket-Schlüssel**. |
| **PAC** | *Privilege Attribute Certificate* – im Ticket eingebettete Autorisierungsdaten (SIDs, Gruppen). Entscheidet, **welche Rechte** der Nutzer bekommt. |

---

## 2. Der normale Ablauf (3 Austausche)

```
  Client                                   KDC (DC)                         Service (z.B. DC/CLIENT01)
    |                                         |                                       |
    |  (1) AS-REQ  (Pre-Auth: Zeitstempel     |                                       |
    |      mit User-Schlüssel verschlüsselt)  |                                       |
    |---------------------------------------->|                                       |
    |  (2) AS-REP  { TGT }krbtgt  +           |   << Event 4768: TGT angefordert       |
    |      Session-Key (mit User-Key verschl.)|                                       |
    |<----------------------------------------|                                       |
    |                                         |                                       |
    |  (3) TGS-REQ  (TGT vorzeigen,           |                                       |
    |      SPN des Ziels nennen)              |                                       |
    |---------------------------------------->|                                       |
    |  (4) TGS-REP  { TGS }service-key         |   << Event 4769: Service-Ticket        |
    |<----------------------------------------|                                       |
    |                                         |                                       |
    |  (5) AP-REQ  { TGS }service-key vorzeigen ------------------------------------->|
    |                                         |          << Event 4624: Logon am Host  |
    |  (6) Zugriff gewährt  <----------------------------------------------------------|
```

**In Worten:**
1. **AS-REQ / AS-REP** – Der Client beweist seine Identität (Pre-Authentication: er verschlüsselt
   einen Zeitstempel mit seinem eigenen abgeleiteten Schlüssel). Der KDC antwortet mit dem **TGT**,
   das mit dem **krbtgt-Schlüssel** verschlüsselt ist — der Client kann es **nicht** lesen, nur
   vorzeigen.
2. **TGS-REQ / TGS-REP** – Der Client zeigt sein TGT vor und nennt den **SPN** des gewünschten
   Dienstes. Der KDC stellt ein **TGS** aus, verschlüsselt mit dem **Schlüssel des Service-Kontos**.
3. **AP-REQ** – Der Client präsentiert das TGS **direkt dem Dienst**. Der Dienst entschlüsselt es
   mit seinem eigenen Schlüssel, liest die **PAC** und gewährt Zugriff entsprechend der Gruppen.

**Der springende Punkt:** Der Zieldienst prüft das TGS **nur mit seinem eigenen Schlüssel** — er
fragt den KDC standardmäßig **nicht** zurück, ob das Ticket echt ist. Genau diese fehlende
Rückfrage macht das Silver Ticket möglich.

---

## 3. Wo die beiden Angriffe ansetzen

| | **Golden Ticket** | **Silver Ticket** |
|---|---|---|
| Gefälschtes Objekt | **TGT** (Schritt 2) | **TGS** (Schritt 4) |
| Benötigter Schlüssel | **krbtgt**-Hash | Hash des **Service-/Computerkontos** |
| Wer stellt normalerweise aus | KDC (AS) | KDC (TGS) |
| Beim Angriff | Angreifer **spielt KDC**, baut TGT selbst | Angreifer **spielt KDC**, baut TGS selbst |
| KDC-Kontakt beim Missbrauch | Für Folge-TGS ja (TGT wird beim DC eingelöst) | **Nein** – KDC wird komplett umgangen |
| Reichweite | **Domänenweit**, beliebige Identität/Gruppen | **Ein Dienst** auf **einem** Host |
| Kern-Spur | 4769 **ohne** vorheriges 4768; unrealistische Lebensdauer; RC4 | 4624 am Host **ohne** 4768/4769 am DC |

Merksatz: **Golden fälscht den Ausweis, Silver fälscht die Eintrittskarte.**

---

## 4. Warum die PAC so wichtig ist

Die **PAC** transportiert die SIDs/Gruppen des Nutzers. Beim Fälschen setzt der Angreifer die PAC
selbst — z. B. Mitgliedschaft in `Domain Admins` (RID 512), obwohl das Konto gar nicht drin ist
(oder gar nicht existiert). Microsofts **PAC-Validierung** (KDC-Gegenprüfung, `Pac Requestor`
seit den 2021/2022-Updates) ist deshalb eine zentrale Härtungsmaßnahme — siehe
[`05-detection-hardening.md`](05-detection-hardening.md).

---

## 5. Enc-Types (RC4 vs. AES) – klein, aber ein starkes IOC

- Historisch signiert/verschlüsselt Kerberos mit **RC4-HMAC** (Enc-Type **`0x17`**), abgeleitet aus
  dem **NTLM-Hash**.
- Moderne Domänen nutzen **AES128/256** (`0x11`/`0x12`).
- Viele Fälschungs-Tools nehmen per Default **RC4** (weil der NTLM-Hash am leichtesten zu
  beschaffen ist). Ein **RC4-Ticket in einer AES-Domäne** ist daher ein deutliches
  Anomalie-Signal (siehe Detection).

➡️ Weiter mit [`03-golden-ticket.md`](03-golden-ticket.md), [`04-silver-ticket.md`](04-silver-ticket.md)
und dem defensiven Kern [`05-detection-hardening.md`](05-detection-hardening.md).
