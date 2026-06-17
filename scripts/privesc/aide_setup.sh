#!/bin/bash

# Gestione dell'help
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	cat << 'EOF'
NAME
       aide_setup - Automazione per la configurazione e inizializzazione rapida di AIDE

SYNOPSIS
       ./aide_setup.sh /dir1 [/dir2 ...]
       ./aide_setup.sh OPTION

DESCRIPTION
       Isola la configurazione di AIDE rimuovendo i controlli di default del
       sistema operativo per velocizzare drasticamente l'inizializzazione. Aggiunge le
       directory specificate al monitoraggio con controlli completi (Full) e genera
       la baseline pulita per rilevare modifiche ai file durante i test di privilege
       escalation.

OPTIONS
       -h, --help
              Mostra questa guida, includendo i ragionamenti metodologici e i
              comandi sostituiti necessari per la stesura del report.

REPORTING (DA INSERIRE NEL REPORT)
       Non citare lo script nel report. Riporta la seguente sequenza di comandi
       e il relativo ragionamento logico:

       1. Isolamento della configurazione (Ottimizzazione)
          Comando: sed -i -E 's|^@@x_include.*/etc/aide/aide\.conf\.d.*$|# &|g' /etc/aide/aide.conf
          Ragionamento: "Ho disabilitato l'inclusione delle regole di default di AIDE
          commentando la direttiva @@x_include. Questo passaggio è stato cruciale per
          ridurre i tempi di inizializzazione a pochi secondi ed eliminare il rumore
          di fondo, concentrando il monitoraggio esclusivamente sui path dell'esercizio."

       2. Iniezione delle regole di monitoraggio
          Comando: echo "/percorso/target Full" >> /etc/aide/aide.conf
          Ragionamento: "Ho aggiunto in coda al file di configurazione i percorsi target
          da monitorare associati alla regola 'Full'. Questa macro istruisce AIDE a
          verificare permessi, ownership, inode, e a calcolare gli hash crittografici
          (MD5, SHA, ecc.), assicurando la rilevazione di qualsiasi artefatto."

       3. Generazione e attivazione della baseline
          Comandi: 
          aide -c /etc/aide/aide.conf -i
          cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
          Ragionamento: "Ho generato il database iniziale contenente lo stato pulito
          del file system prima dell'esecuzione dell'exploit, e l'ho attivato sovrascrivendo
          il db di default. In questo modo il sistema è pronto per una comparazione
          post-infezione tramite il comando 'aide -C'."

EOF
	exit 0
fi

# Controllo che vengano passate le directory da monitorare
if [ "$#" -lt 1 ]; then
    echo "Errore: Specifica almeno una directory. Uso: $0 /dir1 [/dir2 ...]"
    echo "Usa '$0 --help' per leggere il manuale e i comandi per il report."
    exit 1
fi

CONF_FILE="/etc/aide/aide.conf"
DB_FILE="/var/lib/aide/aide.db"

# 1. Backup di sicurezza del file di configurazione
sudo cp "$CONF_FILE" "${CONF_FILE}.bak"

# 2. Commenta l'intera riga specifica di include agganciata al percorso aide.conf.d
# L'uso di .*$ assicura il match e il commento di tutta la riga indipendentemente da spazi o flag finali
sudo sed -i -E 's|^@@x_include.*/etc/aide/aide\.conf\.d.*$|# &|g' "$CONF_FILE"

# 3. Appende i target passati come argomento in fondo al file
echo -e "\n# Target aggiunti per l'esame" | sudo tee -a "$CONF_FILE" > /dev/null
for dir in "$@"; do
    # FIX: Rimossa la 'f' errata. La sintassi corretta è "<percorso> <regola>"
    echo "${dir} Full" | sudo tee -a "$CONF_FILE" > /dev/null
done

# 4. Generazione del database di baseline
echo "[*] Inizializzazione database AIDE in corso (potrebbe richiedere qualche istante)..."
sudo aide -c $CONF_FILE -i

# 5. Copia e attivazione del database per i check successivi
sudo cp $DB_FILE.new $DB_FILE

echo "[+] Configurazione completata. Database AIDE pronto per il check post-infezione (usa: sudo aide -C)."
