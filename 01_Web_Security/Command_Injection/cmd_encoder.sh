#!/bin/bash
# cmd_encoder.sh
# Encoder per bypass filtri command injection (A3 - Injection)
# Solo bash builtin, zero dipendenze

echo "Scegli il formato:"
echo "  1) URL encoding         es: / -> %2F"
echo "  2) Double URL encoding  es: / -> %252F"
echo "  3) Hex bash             es: / -> \$'\\x2f...'"
echo "  4) Octal bash           es: / -> \$'\\057...'"
read -p "Scelta [1-4]: " scelta
echo ""
echo "Inserisci stringhe da convertire. Invio vuoto per uscire."
echo "---"

while true; do
    read -p "Stringa: " input
    [[ -z "$input" ]] && break

    result=""
    
    for (( i=0; i<${#input}; i++ )); do
        char="${input:$i:1}"
        printf -v dec '%d' "'$char"

        case "$scelta" in
            1)
                printf -v hex '%02X' "$dec"
                result+="%$hex"
                ;;
            2)
                printf -v hex '%02X' "$dec"
                result+="%25$hex"
                ;;
            3)
                printf -v hex '%02x' "$dec"
                result+="\\x$hex"
                ;;
            4)
                printf -v oct '%03o' "$dec"
                result+="\\$oct"
                ;;
        esac
    done

    # Aggiunge il wrapper finale per le opzioni bash (3 e 4)
    if [[ "$scelta" == "3" || "$scelta" == "4" ]]; then
        result="\$'$result'"
    fi

    echo "  -> $result"
    echo ""
done

echo "Bye!"
