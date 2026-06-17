#!/bin/bash

# Gestione dell'help
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	cat << 'EOF'
NAME
       payload.sh - Fuzzer a bisezione per l'individuazione dell'offset di crash

SYNOPSIS
       ./payload.sh [-s] ./nome_binario
       ./payload.sh OPTION

DESCRIPTION
       Disabilita temporaneamente l'ASLR di sistema e automatizza la ricerca 
       dell'offset necessario per mandare in crash un eseguibile vulnerabile a 
       Buffer Overflow.

OPTIONS
       -s, --stdin
              Inietta il payload tramite Standard Input (pipe) invece che come
              argomento da riga di comando. Indispensabile per binari che 
              leggono l'input tramite funzioni come gets() o scanf().

       -h, --help
              Mostra questa guida, includendo i ragionamenti metodologici e i
              comandi sostituiti necessari per la stesura del report.

REPORTING (DA INSERIRE NEL REPORT)
       Non citare lo script nel report. Riporta la seguente sequenza di comandi
       e il relativo ragionamento logico:

       1. Disattivazione ASLR (Address Space Layout Randomization)
          Comando: sudo sysctl -w kernel.randomize_va_space=0
          Ragionamento: "Per garantire la stabilità degli indirizzi di memoria 
          durante lo sviluppo dell'exploit, ho temporaneamente disabilitato l'ASLR. 
          In questo modo, gli indirizzi dello stack e delle librerie condivise 
          rimangono statici ad ogni esecuzione."

       2. Individuazione dell'Offset di Crash
          Comando via Argomento: ./eseguibile $(perl -e 'print "A"x120')
          Comando via STDIN:     perl -e 'print "A"x120' | ./eseguibile
          Ragionamento: "Ho inviato sequenze incrementali di byte al binario
          vulnerabile per individuare il limite esatto del buffer allocato, 
          fino a causare un Segmentation Fault (SIGSEGV)."

       3. Verifica dell'Instruction Pointer in GDB
          Comando via Argomento: run $(perl -e 'print "A"x[OFFSET] . "B"x4')
          Comando via STDIN:     run < <(perl -e 'print "A"x[OFFSET] . "B"x4')
          Ragionamento: "Una volta individuato l'offset del crash, ho verificato 
          in GDB l'esatta sovrascrittura dell'Instruction Pointer (EIP/RIP) 
          appendendo 4 byte 'B' (0x42424242)."
EOF
	exit 0
fi

# Variabile di stato per la modalità STDIN
USE_STDIN=false

if [ "$1" == "-s" ] || [ "$1" == "--stdin" ]; then
	USE_STDIN=true
	shift # Rimuove l'opzione -s dai parametri posizionali
fi

if [ "$#" -ne 1 ]; then
	echo "Uso: $0 [-s] ./nome_binario"
	echo "Usa '$0 --help' per leggere il manuale e i comandi per il report."
	exit 1
fi

BINARY="$1"
LOW=1
HIGH=1000
EXACT_OFFSET=-1

# Disattivazione ASLR
echo "[*] Disattivazione ASLR..."
sudo sysctl -w kernel.randomize_va_space=0 > /dev/null

if [ $? -ne 0 ]; then
	echo "[-] Errore: Privilegi sudo richiesti per disabilitare ASLR."
	exit 1
fi

if [ "$USE_STDIN" = true ]; then
	echo "[*] Avvio bisezione tra $LOW e $HIGH byte (Input via STDIN)..."
else
	echo "[*] Avvio bisezione tra $LOW e $HIGH byte (Input via Argomento)..."
fi
echo "--------------------------------------------------"

while [ $LOW -le $HIGH ]; do
	MID=$(( (LOW + HIGH) / 2 ))
	
	echo -n "Testing offset: $MID byte (Range: $LOW-$HIGH) -> "
	
	if [ "$USE_STDIN" = true ]; then
		# Iniezione tramite Pipe (STDIN)
		perl -e "print 'A'x$MID" | "$BINARY" > /dev/null 2>&1
	else
		# Iniezione tramite Argomento
		PAYLOAD=$(perl -e "print 'A'x$MID")
		"$BINARY" "$PAYLOAD" > /dev/null 2>&1
	fi
	
	STATUS=$?
	
	if [ $STATUS -eq 139 ]; then
		echo "CRASH (SIGSEGV)"
		EXACT_OFFSET=$MID
		HIGH=$(( MID - 1 )) 
	else
		echo "OK"
		LOW=$(( MID + 1 ))  
	fi
done

echo "--------------------------------------------------"
if [ $EXACT_OFFSET -ne -1 ]; then
	echo "[+] Il binario va in Segmentation Fault a partire da: $EXACT_OFFSET byte."
	echo "[!] Lo spazio esatto prima di sovrascrivere l'Instruction Pointer (EIP/RIP) potrebbe trovarsi qualche byte prima o dopo causa padding."
	echo ""
	echo "[*] Comando generato per la verifica dell'EIP/RIP in GDB ('BBBB' = 0x42424242):"
	
	if [ "$USE_STDIN" = true ]; then
		echo "run < <(perl -e \"print 'A'x$EXACT_OFFSET . 'B'x4\")"
	else
		echo "run \$(perl -e \"print 'A'x$EXACT_OFFSET . 'B'x4\")"
	fi
else
	echo "[-] Nessun crash rilevato nel range selezionato (1-1000)."
fi
