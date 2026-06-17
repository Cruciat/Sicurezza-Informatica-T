# Sicurezza Informatica T (B0833) — Materiale Esame

Raccolta di materiale per l'esame di **Sicurezza Informatica T** — guide, scheletri di consegna, script e slide del corso.

> **Nota:** Questo materiale si riferisce alla **sessione estiva 2026**. La struttura dell'esame, le domande a crocetta e gli esercizi pratici potrebbero cambiare nelle sessioni successive.

---

## Struttura della repository

```
security_exam_toolkit/
├── guide/
│   ├── crocette/        # Domande a crocetta degli anni precedenti (+ sorgente LaTeX)
│   ├── pratica/         # Guida pratica all'esame (+ sorgente LaTeX + materiale Suricata)
│   ├── setup_lab/       # Guida al setup della VM in laboratorio (+ sorgente LaTeX + immagini)
│   └── teoria/          # Riassunto teorico del corso (+ sorgente LaTeX + immagini)
├── esame/
│   ├── nftables/        # Scheletri .nft per l'esercizio firewall (client, server, router, definizioni)
│   ├── nids/            # Scheletro report NIDS + file .rules per Suricata
│   ├── privesc/         # Scheletro report privilege escalation
│   ├── pwn/             # Scheletro report buffer overflow / binary exploitation
│   └── web/             # Scheletro report web security
├── scripts/
│   ├── auto_enum.sh     # Script generico di enumerazione automatica
│   ├── privesc/         # Script per l'esercizio di privilege escalation (aide_setup.sh)
│   ├── pwn/             # Script per binary exploitation (exploit.sh, payload.sh)
│   └── web/             # Script per web security (payloaderr.sh)
└── slides/              # Slide ufficiali del corso (01–26, teoria + LAB)
```

---

## Guide (`guide/`)

### Crocette (`guide/crocette/`)
Raccolta delle domande a scelta multipla degli **anni precedenti**, disponibile in formato PDF e sorgente LaTeX.

> **Consiglio pratico:** Le domande a crocetta sono storicamente quasi identiche di anno in anno. Conoscerle a memoria è la strategia più efficace per massimizzare il punteggio su quella parte dell'esame.

| File | Descrizione |
|---|---|
| `crocette_sicurezza.pdf` | Domande a crocetta con risposte |
| `crocette_sicurezza.tex` | Sorgente LaTeX |

### Teoria (`guide/teoria/`)
Riassunto teorico completo del corso (~9.5 MB PDF), con relativi sorgenti LaTeX e immagini.

> La teoria è inclusa per completezza, ma ai fini dell'esame è **largamente superflua**: le crocette coprono già tutto il necessario da memorizzare.

| File | Descrizione |
|---|---|
| `sicurezza_teoria.pdf` | Riassunto teorico del corso |
| `sicurezza_teoria.tex` | Sorgente LaTeX |

### Pratica (`guide/pratica/`)
Guida operativa alla parte pratica dell'esame, con walkthrough degli esercizi tipici e materiale per Suricata (NIDS).

| File | Descrizione |
|---|---|
| `guida_esame.pdf` | Guida pratica completa |
| `guida_esame.tex` | Sorgente LaTeX |
| `suricata/` | Materiale aggiuntivo per l'esercizio NIDS con Suricata |

### Setup Lab (`guide/setup_lab/`)
Guida illustrata per la configurazione della macchina virtuale **ParrotOS** in laboratorio tramite VirtualBox.

| File | Descrizione |
|---|---|
| `setup_lab.pdf` | Guida con screenshot passo-passo |
| `setup_lab.tex` | Sorgente LaTeX |
| `immagini/` | Screenshot utilizzati nel documento |

---

## Scheletri di consegna (`esame/`)

Contiene i file da consegnare all'esame, pre-strutturati per ciascun esercizio. **Vanno compilati durante la prova** con i risultati ottenuti.

| Cartella | File da consegnare | Descrizione |
|---|---|---|
| `nftables/` | `definizioni.nft`, `client.nft`, `server.nft`, `router.nft` | Regole firewall nftables per i diversi ruoli di rete |
| `nids/` | `nids.txt`, `exam.rules` | Report NIDS + regole Suricata personalizzate |
| `privesc/` | `privesc.txt` | Report privilege escalation |
| `pwn/` | `pwn.txt` | Report buffer overflow / binary exploitation |
| `web/` | `web.txt` | Report web security (SQLi, XSS, ecc.) |

> L'esercizio **nftables** è l'unico in cui la consegna avviene tramite file `.nft` invece di un report testuale.

---

## Script (`scripts/`)

Script Bash creati per automatizzare e velocizzare le operazioni durante la prova pratica.

| File | Esercizio | Descrizione |
|---|---|---|
| `auto_enum.sh` | Generale | Enumerazione automatica dell'host/rete target |
| `privesc/aide_setup.sh` | Privilege Escalation | Setup e configurazione di AIDE per l'integrità del filesystem |
| `pwn/exploit.sh` | PWN / Buffer Overflow | Script di exploiting automatizzato |
| `pwn/payload.sh` | PWN / Buffer Overflow | Generazione e invio del payload |
| `web/payloaderr.sh` | Web Security | Script per l'automazione dei payload web (SQLi, ecc.) |

---

## Slide del corso (`slides/`)

Tutte le slide ufficiali del corso, incluse le sessioni di laboratorio (LAB).

<details>
<summary>Mostra elenco completo (26 slide)</summary>

| # | Titolo |
|---|---|
| 01 | Intro |
| 02 | LAB Intro |
| 03 | Panoramica |
| 04 | Offensive Security |
| 05 | LAB Enumerazione |
| 06 | Autenticazione |
| 07 | Web Security |
| 08 | LAB Web Security |
| 09 | Binary Exploits |
| 10 | LAB Buffer Overflow |
| 11 | Firewall |
| 12 | Linux Packet Filter |
| 13 | Host & Cloud Security |
| 14 | Demoni di Sistema |
| 15 | Autorizzazione |
| 16 | Rilevare gli Attacchi |
| 17 | Host-Based Intrusion Detection |
| 18 | Sicurezza delle Comunicazioni |
| 19 | LAB Network Offensive Security |
| 20 | Crittografia di Base |
| 21 | Cifrari Moderni |
| 22 | LAB gpg |
| 23 | Chiavi |
| 24 | Net Security |
| 25 | OpenSSL |
| 26 | Esercizi TLS |

</details>

---

## Uso rapido

1. **Studia le crocette** → `guide/crocette/crocette_sicurezza.pdf`
2. **Leggi la guida pratica** → `guide/pratica/guida_esame.pdf`
3. **Configura la VM** → `guide/setup_lab/setup_lab.pdf`
4. **Copia gli scheletri** dalla cartella `esame/` nella cartella condivisa della VM prima dell'esame
5. **Usa gli script** da `scripts/` durante la prova per velocizzare l'esecuzione
