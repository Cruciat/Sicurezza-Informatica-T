# Report Esame: Web Security - SQL Injection (Authentication Bypass & Filter Evasion)

**FLAG:** `[INCOLLARE QUI LA FLAG TROVATA, es. SEC{...}]`

## 1. LA QUERY INIETTATA E IL PAYLOAD
**Richiesta GET (URL Esecutivo Finale):**
`[INCOLLARE QUI L'URL COMPLETO CON I PAYLOAD ENCODATI, es: http://localhost:8000/login?username=admin&password=%27%20oR%20%271%27%3E%270 ]`

**Payload in chiaro utilizzati:**
* Parametro `[NOME PARAMETRO 1, es. username]`: `[VALORE, es. admin]`
* Parametro `[NOME PARAMETRO 2, es. password]`: `[PAYLOAD, es. ' oR '1'>'0 ]`

---

## 2. DESCRIZIONE DELLA VULNERABILITÀ (Perché esiste?)
La vulnerabilità individuata nell'endpoint `[INSERIRE ENDPOINT, es. /login]` è una SQL Injection In-Band che permette il bypass dell'autenticazione. 

La falla esiste a causa di due carenze architetturali nel backend:
1. **Mancanza di Prepared Statements:** L'input dell'utente non viene parametrizzato, ma viene concatenato dinamicamente per formare la stringa della query SQL. Questo permette all'input di alterare la logica della clausola `WHERE`.
2. **Sanificazione Incompleta/Asimmetrica:** Il programmatore ha implementato controlli deboli o applicati solo parzialmente. `[OPZIONALE: Descrivere l'errore specifico, es. "Il parametro username era filtrato tramite Regex che eliminava i caratteri speciali, ma il parametro password veniva passato alla query senza alcun controllo, permettendo l'iniezione."]`

Sebbene fosse presente un rudimentale Web Application Firewall (WAF) a livello applicativo per bloccare specifiche keyword (es. `[INSERIRE FILTRI NOTATI, es. "OR" e "="]`), questo si è rivelato inefficace poiché non teneva conto della flessibilità sintattica del motore del database.

---

## 3. METODOLOGIA E PASSAGGI ESEGUITI (Come viene sfruttata)
L'obiettivo della challenge era forzare l'accesso come utente `[INSERIRE UTENTE, es. admin]` alterando la query di verifica delle credenziali, la cui struttura ipotizzata è: 
`SELECT * FROM users WHERE username = '$username' AND password = '$password'`

Per raggiungere l'obiettivo, ho eseguito i seguenti passaggi:

* **Fase 1: Fuzzing e Identificazione del punto di iniezione**
  Ho inviato un carattere metalinguistico (apice singolo `'`) nei parametri della richiesta. 
  `[SPIEGARE L'ANALISI DEGLI ERRORI, es: "Iniettando l'apice nell'username ho ricevuto un banale messaggio di 'credenziali errate', deducendo la presenza di un filtro. Iniettandolo nella password, invece, il server ha restituito un errore di sintassi SQL (OperationalError: unrecognized token), confermando che quel parametro era vulnerabile e non filtrato."]` 
  *Nota operativa:* È stato essenziale fornire un valore fittizio a tutti i parametri (es. `username=admin`) per evitare che il backend `[es. Python]` andasse in crash (KeyError) prima di eseguire la query.

* **Fase 2: Scelta dell'approccio logico**
  `[SPIEGARE LA LOGICA SCELTA. Es: "Essendo la password l'ultimo parametro della query, un semplice commento come '--' rompeva la sintassi o non veniva accettato. Ho quindi optato per un approccio Tautologico, puntando a rendere l'espressione di verifica della password sempre VERA."]`

* **Fase 3: Evasione dei Filtri Applicativi (WAF Bypass)**
  Durante l'invio del payload base, l'applicazione ha bloccato la richiesta. Ho aggirato i filtri come segue:
  * `[INSERIRE BYPASS 1, es: "Filtro su 'OR': Poiché il motore SQL è case-insensitive, ho eluso la blacklist del backend inviando la stringa in case misto 'oR'."]`
  * `[INSERIRE BYPASS 2, es: "Filtro su '=': Ho mantenuto la tautologia logica sostituendo l'operatore di uguaglianza con una disuguaglianza inconfutabile, ovvero '1'>'0'."]`

* **Fase 4: Esecuzione e Recupero Flag**
  Ho sottoposto a URL-Encoding la porzione maligna del payload per non corrompere la sintassi HTTP. 
  La query effettivamente interpretata dal database è risultata simile a:
  `SELECT * FROM users WHERE username = 'admin' AND password = '' oR '1'>'0'`
  
  Essendo l'ultima condizione sempre VERA, il database ha autorizzato il login. 
  `[AGGIUNGERE SE NECESSARIO: "Poiché l'applicazione forzava un redirect istantaneo dopo il login nascondendo l'output, ho intercettato la prima risposta HTTP grezza (tramite proxy/curl/tab Network) per catturare con successo la flag stampata a schermo."]`