#!/bin/bash
# web_encoder.sh - L'approccio "Tutto e Subito" per l'esame

if [ -z "$1" ]; then
    echo "Uso: $0 <stringa>"
    echo "Es: $0 \"' OR 1=1 --\""
    exit 1
fi

STR="$1"

echo -e "\n=== 🔒 ENCODING OMNICOMPRENSIVO ==="

# URL Encode
URL_ENC=$(python3 -c "import sys, urllib.parse; print(urllib.parse.quote_plus(sys.argv[1]))" "$STR")
echo -e "[+] URL Encode:\n$URL_ENC\n"

# Double URL Encode
DURL_ENC=$(python3 -c "import sys, urllib.parse; print(urllib.parse.quote_plus(sys.argv[1]))" "$URL_ENC")
echo -e "[+] Double URL Encode:\n$DURL_ENC\n"

# Base64
B64_ENC=$(echo -n "$STR" | base64 -w 0)
echo -e "[+] Base64:\n$B64_ENC\n"

# Hex (formato SQLi con 0x)
HEX_ENC=$(echo -n "$STR" | xxd -p | tr -d '\n')
echo -e "[+] Hex (SQLi):\n0x$HEX_ENC\n"


echo -e "=== 🔓 DECODING AUTOMATICO (TENTATIVI) ==="

# Tenta URL Decode se ci sono '%' o '+'
if [[ "$STR" == *%* ]] || [[ "$STR" == *+* ]]; then
    URL_DEC=$(python3 -c "import sys, urllib.parse; print(urllib.parse.unquote_plus(sys.argv[1]))" "$STR")
    echo -e "[+] Possibile URL Decode:\n$URL_DEC\n"
fi

# Tenta Base64 Decode se la stringa corrisponde al pattern base64
if echo "$STR" | grep -Eq '^[A-Za-z0-9+/]+={0,2}$'; then
    B64_DEC=$(echo -n "$STR" | base64 -d 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$B64_DEC" ]; then
        echo -e "[+] Possibile Base64 Decode:\n$B64_DEC\n"
    fi
fi

# Tenta Hex Decode se inizia con 0x o è solo esadecimale
CLEAN_HEX=$(echo "$STR" | sed 's/^0x//')
if echo "$CLEAN_HEX" | grep -Eq '^[a-fA-F0-9]+$'; then
    HEX_DEC=$(echo -n "$CLEAN_HEX" | xxd -r -p 2>/dev/null)
    if [ -n "$HEX_DEC" ]; then
        echo -e "[+] Possibile Hex Decode:\n$HEX_DEC\n"
    fi
fi