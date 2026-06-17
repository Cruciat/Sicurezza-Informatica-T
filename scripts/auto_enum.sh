#!/bin/bash

# Gestione dell'help
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	cat << 'EOF'
NAME
       auto_enum - Automazione progressiva per network discovery ed enumerazione

SYNOPSIS
       ./auto_enum.sh SUBNET
       ./auto_enum.sh OPTION

DESCRIPTION
       Esegue una scansione a imbuto sulla rete specificata per identificare
       host attivi, individuare le porte TCP aperte e scansionare in profondità
       esclusivamente i servizi in ascolto, ignorando gli IP locali e di routing
       (tipicamente .1 e .254).

OPTIONS
       -h, --help
              Mostra questa guida, includendo i ragionamenti metodologici e i
              comandi sostituiti necessari per la stesura del report.

REPORTING (DA INSERIRE NEL REPORT)
       Non citare lo script nel report. Riporta la seguente sequenza di comandi
       e il relativo ragionamento logico:

       1. Host Discovery
          Comando: nmap -sn <subnet>
          Ragionamento: "Ho evitato di eseguire subito una scansione delle
          porte sull'intera subnet per ottimizzare i tempi. Ho lanciato prima
          un Ping Scan (-sn) per individuare esclusivamente gli host attivi (UP)
          che rispondono a ICMP/ARP, disabilitando il port scanning."

       2. All TCP Ports Scan
          Comando: nmap -sT -p- <target_ip>
          Ragionamento: "Sui bersagli vivi, ho lanciato una scansione completa
          sui 65535 port con TCP Connect (-sT) per eseguire un three-way
          handshake completo, evitando la necessità di privilegi di root.
          L'obiettivo era ottenere la lista esatta delle porte aperte per
          restringere il campo successivo."

       3. Deep Service Enumeration
          Comando: nmap -p <porte_aperte> -A -sV -sC -oA "enum_<ip>" <ip>
          Ragionamento: "Avendo isolato le porte in ascolto, ho lanciato
          l'enumerazione mirata, risparmiando tempo. Ho usato -sV (versioning),
          -sC (script NSE) e -A (OS fingerprinting). Ho salvato l'output in
          tutti i formati con -oA per mantenere l'evidenza."

EOF
	exit 0
fi

# Controllo argomenti
if [ -z "$1" ]; then
	echo "Uso: $0 <subnet> [es. ./auto_enum.sh 192.168.56.0/24]"
	echo "Usa '$0 --help' per leggere il manuale e i comandi per il report."
	exit 1
fi

SUBNET=$1

# Estrae dinamicamente tutti gli IP IPv4 della tua macchina e li formatta
# con un pipe (es. 127.0.0.1|192.168.56.101) per l'esclusione regex.
OWN_IPS=$(ip -4 addr | grep inet | awk '{print $2}' | cut -d '/' -f 1 | tr '\n' '|' | sed 's/|$//')

echo "[*] I tuoi IP rilevati: $(echo $OWN_IPS | tr '|' ' ')"
echo "[*] Step 1: Eseguo Host Discovery su $SUBNET..."

# Il grep finale esclude gli IP locali, gli indirizzi .1 e .254
TARGETS=$(nmap -sn $SUBNET | grep "Nmap scan report for" | awk '{print $NF}' | tr -d '()' | grep -vE "($OWN_IPS|\.1$|\.254$)")

if [ -z "$TARGETS" ]; then
	echo "[-] Nessun target valido trovato."
	exit 1
fi

for IP in $TARGETS; do
	echo "------------------------------------------------"
	echo "[+] Target identificato: $IP"
	
	echo "[*] Step 2: Scansione veloce di TUTTE le porte TCP (65535)..."
	OPEN_PORTS=$(nmap -sT -p- $IP | grep '/tcp' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
	
	if [ -z "$OPEN_PORTS" ]; then
		echo "[-] Nessuna porta TCP aperta trovata su $IP."
		continue
	fi
	
	echo "[+] Porte aperte trovate su $IP: $OPEN_PORTS"
	
	echo "[*] Step 3: Scansione profonda sui servizi..."
	nmap -p $OPEN_PORTS -A -sV -sC -oA "enum_${IP}" $IP
done

echo "------------------------------------------------"
echo "[*] Enumerazione completata."
