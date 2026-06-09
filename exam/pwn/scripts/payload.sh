#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "Uso: $0 ./nome_binario"
	exit 1
	fi
	
	BINARY="$1"
	LOW=1
	HIGH=1000
	EXACT_OFFSET=-1
	
	# Disattivazione ASLR
	echo "Disattivazione ASLR..."
	sudo sysctl -w kernel.randomize_va_space=0 > /dev/null
	
	if [ $? -ne 0 ]; then
		echo "Errore: Privilegi sudo richiesti."
		exit 1
		fi
		
		echo "Avvio bisezione tra $LOW e $HIGH byte (Input via Argomento)..."
		echo "--------------------------------------------------"
		
		while [ $LOW -le $HIGH ]; do
			MID=$(( (LOW + HIGH) / 2 ))
			
			echo -n "Testing offset: $MID byte (Range: $LOW-$HIGH) -> "
			
			PAYLOAD=$(perl -e "print 'A'x$MID")
			
			sh -c "\"$BINARY\" \"$PAYLOAD\"" > /dev/null 2>&1
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
						echo "Il binario va in Segmentation Fault a partire da: $EXACT_OFFSET byte come argomento."
						echo "Lo spazio esatto prima di sovrascrivere l'Instruction Pointer (EIP/RIP) potrebbe trovarsi qualche byte prima o dopo."
						echo ""
						# [Certain] Stampa del comando Perl pre-formattato per il copia-incolla immediato in GDB
						echo "Comando generato per la verifica dell'EIP/RIP in GDB ('BBBB' = 0x42424242):"
						echo "run \$(perl -e \"print 'A'x$EXACT_OFFSET . 'B'x4\")"
						else
							echo "Nessun crash rilevato nel range selezionato."
							fi

