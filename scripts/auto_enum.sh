#!/bin/bash

# Controllo argomenti
if [ -z "$1" ]; then
	echo "Uso: $0 <subnet> [es. ./auto_enum.sh 192.168.56.0/24]"
	exit 1
fi

SUBNET=$1

# Estrae il prefisso della rete (es. 192.168.56) per trovare l'IP corretto sull'interfaccia giusta
PREFIX=$(echo $SUBNET | cut -d '.' -f 1-3)
OWN_IP=$(ip a | grep "inet $PREFIX" | awk '{print $2}' | cut -d '/' -f 1)

echo "[*] Il tuo IP rilevato sulla rete $PREFIX: $OWN_IP"
echo "[*] Step 1: Eseguo Host Discovery su $SUBNET..."

TARGETS=$(nmap -sn $SUBNET | grep "Nmap scan report for" | awk '{print $NF}' | tr -d '()' | grep -vE "($OWN_IP|\.1$|\.254$)")

if [ -z "$TARGETS" ]; then
	echo "[-] Nessun target valido trovato."
	exit 1
fi

for IP in $TARGETS; do
	echo "------------------------------------------------"
	echo "[+] Target identificato: $IP"
	
	echo "[*] Step 2: Scansione veloce di TUTTE le porte TCP (65535)..."
	# Uso un approccio blindato con awk per estrarre solo il numero delle porte
	OPEN_PORTS=$(nmap -sT -p- $IP | grep '/tcp' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
	
	if [ -z "$OPEN_PORTS" ]; then
		echo "[-] Nessuna porta TCP aperta."
		continue
	fi
	
	echo "[+] Porte aperte trovate: $OPEN_PORTS"
	
	echo "[*] Step 3: Scansione profonda sui servizi..."
	nmap -p $OPEN_PORTS -A -sV -sC -oA "enum_${IP}" $IP
done

echo "------------------------------------------------"
echo "[*] Enumerazione completata."