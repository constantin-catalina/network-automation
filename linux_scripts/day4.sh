#!/bin/bash
# ========================================================
# Day 4 - Extract Unique Services from /etc/services
# ========================================================

OUTPUT_FILE=~/uniqueservices.txt

echo "[INFO] Extragem toate serviciile unice din /etc/services..."

# 1. Luăm doar liniile care încep cu litere (nume servicii)
# 2. Extragem prima coloană (nume serviciu)
# 3. Sortăm și eliminăm duplicate
grep -E '^[a-zA-Z]' /etc/services | awk '{print $1}' | sort -u > "$OUTPUT_FILE"

# 4. Numărăm câte servicii unice există
COUNT=$(wc -l < "$OUTPUT_FILE")

echo "[INFO] Număr de servicii unice: $COUNT"
echo "[INFO] Lista salvată în: $OUTPUT_FILE"

# 5. Afișăm primele 20 ca preview
echo
echo "Primele 20 de servicii:"
head -n 20 "$OUTPUT_FILE"
