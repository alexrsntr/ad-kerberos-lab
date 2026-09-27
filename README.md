# ad-kerberos-lab

Lab-Repository zur **Demonstration und Absicherung** von Kerberos-Ticket-Angriffen in
Active-Directory-Umgebungen — mit Fokus auf **Golden-Ticket-** und **Silver-Ticket-**Angriffe.

Ziel ist nicht nur zu zeigen, *dass* die Angriffe funktionieren, sondern auch **wie man sie
erkennt und verhindert** (Detection & Hardening).

---

## ⚠️ Rechtlicher & ethischer Hinweis

Dieses Repository dient **ausschließlich Lern- und Verteidigungszwecken** in einer
**autorisierten Umgebung**.

- Im **eigenen Test-Lab**: uneingeschränkt nutzbar.
- Im **Firmen-AD (Produktiv)**: **nur mit schriftlicher Freigabe** der/des Verantwortlichen
  (IT-Leitung / CISO / System-Owner). Umfang, Zeitraum und Systeme vorher schriftlich festhalten.
- Kein Einsatz gegen fremde Systeme ohne ausdrückliche Genehmigung.

Der Autor übernimmt keine Haftung für missbräuchliche Nutzung.

---

## Inhalt

| Dokument | Thema |
|----------|-------|
| [`docs/01-lab-setup.md`](docs/01-lab-setup.md) | Aufbau der Test-Lab-Umgebung (DC, Client, Angreifer-VM) |
| [`docs/02-kerberos-basics.md`](docs/02-kerberos-basics.md) | Kerberos-Grundlagen: AS-REQ/REP, TGT, TGS, PAC |
| [`docs/03-golden-ticket.md`](docs/03-golden-ticket.md) | Golden Ticket: Voraussetzungen, Durchführung, Erkennung |
| [`docs/04-silver-ticket.md`](docs/04-silver-ticket.md) | Silver Ticket: Voraussetzungen, Durchführung, Erkennung |
| [`docs/05-detection-hardening.md`](docs/05-detection-hardening.md) | Detection (SIEM/Event-IDs) & Härtungsmaßnahmen |

- `scripts/` — Hilfsskripte (Lab-Setup, PoC-Automatisierung)
- `notes/`   — Arbeitsnotizen (nicht für Veröffentlichung gedacht)
- `lab/`     — lokale Lab-Konfiguration (Inhalte i. d. R. per .gitignore ausgeschlossen)

---

## Überblick der Angriffe (Kurzform)

| | Golden Ticket | Silver Ticket |
|---|---|---|
| **Fälscht** | TGT (Ticket Granting Ticket) | TGS (Service Ticket) |
| **Benötigter Schlüssel** | Hash des `krbtgt`-Kontos | Hash des Ziel-Service-Kontos / Computerkontos |
| **Reichweite** | domänenweit, quasi beliebige Identität | einzelner Dienst auf einem Host |
| **KDC-Kontakt** | nein (nach Fälschung) | nein (KDC wird umgangen) |
| **Sichtbarkeit** | tendenziell besser erkennbar | leiser / schwerer zu erkennen |

Details, Voraussetzungen und Gegenmaßnahmen: siehe `docs/`.

---

## Typische Tools (Referenz)

Rubeus, Impacket (`ticketer.py`, `getST.py`), Mimikatz — Einsatz **nur im Lab**.
Binaries werden **nicht** eingecheckt (siehe `.gitignore`).

---

## Roadmap

- [x] Lab-Setup dokumentieren (DC1 + PC1 + VM1/Kali auf Proxmox)
- [ ] Kerberos-Grundlagen ausformulieren
- [x] Golden-Ticket-PoC + Nachweis
- [x] Silver-Ticket-PoC + Nachweis
- [ ] Detection-Queries (Event-IDs 4768/4769/4624, SIEM-Regeln)
- [ ] Härtungs-Checkliste (krbtgt-Rotation, AES, PAC-Validierung, Tiering)
