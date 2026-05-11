# Report Esame: Web Security - Command Injection

**Vulnerabilità:** OS Command Injection
**Target / Endpoint:** `[Inserire IP/URL e parametro vulnerabile, es. http://10.3.3.1:5000/browse/stat?filepath=]`
**Obiettivo:** `[Es. Ottenere RCE per leggere il file /etc/passwd / Ottenere una reverse shell]`

## 1. Analisi e Identificazione
Durante l'enumerazione dell'applicativo web, è stato individuato un endpoint vulnerabile a `[URL]`. L'input fornito nel parametro `[parametro]` viene passato direttamente a una funzione di sistema (es. `system()`) senza adeguata sanificazione, permettendo l'esecuzione di comandi arbitrari.

## 2. Bypass dei Filtri (Fuzzing manuale)
Per identificare i filtri attivi, sono stati effettuati i seguenti test:
* **Tentativo 1:** `127.0.0.1 ; id`
  * *Risultato:* `[Es. Il sistema blocca il carattere ;]`
* **Tentativo 2:** `127.0.0.1 || id`
  * *Risultato:* `[Es. Esecuzione riuscita, ma i successivi tentativi con spazi falliscono]`
* **Tecnica di Bypass:** È stata utilizzata la variabile `${IFS}` per sostituire lo spazio e l'operatore `||` per concatenare il comando.

## 3. Exploit Finale e Payload
Il payload finale è stato costruito per bypassare le restrizioni sulla lunghezza e sui caratteri speciali.

**Payload utilizzato:**
```text
[INCOLLARE QUI IL PAYLOAD FINALE, ES: /etc/passwd%26%20cat%20/etc/passwd]
```

## 4. Screenshot di Conferma
Di seguito le prove visive dell'exploit riuscito:

> **[INSERIRE QUI LO SCREENSHOT DI BURP SUITE O DEL TERMINALE]**
> *Didascalia: Output del comando iniettato (es. id, cat /etc/passwd) visibile nella response.*

## 5. Mitigazione
Per correggere la vulnerabilità, si raccomanda di non utilizzare funzioni che invocano la shell del sistema operativo. In alternativa, è necessario applicare una whitelist rigorosa dei caratteri permessi o utilizzare funzioni di escaping specifiche come `escapeshellarg()`.