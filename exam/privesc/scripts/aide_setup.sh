#!/bin/bash

# Controllo che vengono passate le directory da monitorare
if [ "$#" -lt 1 ]; then
    echo "Errore: Specifica almeno una directory. Uso: $0 /dir1 /dir2 ..."
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
    echo "${dir}  f  Full" | sudo tee -a "$CONF_FILE" > /dev/null
done

# 4. Generazione del database di baseline
sudo aide -c $CONF_FILE -i

# 5. Copia e attivazione del database per i check successivi
sudo cp $DB_FILE.new $DB_FILE

echo "Configurazione completata. Database AIDE pronto per il check post-infezione."
