#!/bin/bash
# Check each domain for /__/firebase/init.json Firebase config

INPUT="/root/.claude/uploads/a929f025-6b4d-5412-a164-94538e881361/f57eeb53-ALL_domains_scanned_unique.txt"
OUTPUT="/home/user/asdw/fire.txt"
> "$OUTPUT"

check_domain() {
    local domain="$1"
    for scheme in https http; do
        body=$(curl -s -k --max-time 8 -L \
            -H "User-Agent: Mozilla/5.0" \
            "${scheme}://${domain}/__/firebase/init.json" 2>/dev/null)
        if echo "$body" | grep -q '"apiKey"' && echo "$body" | grep -q '"authDomain"'; then
            echo "$domain" >> "$OUTPUT"
            return
        fi
    done
}

export -f check_domain
export OUTPUT

cat "$INPUT" | xargs -n1 -P100 -I{} bash -c 'check_domain "$@"' _ {}
