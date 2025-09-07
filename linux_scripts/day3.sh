#!/bin/bash
# ========================================================
# Day 3 - Backup și arhivare loguri
# ========================================================

ARCHIVE_DIR=~/archive
BACKUP_DIR=~/backup
LOG_TAR=$ARCHIVE_DIR/log.tar

echo "[INFO] Creăm directoarele necesare..."
mkdir -p "$ARCHIVE_DIR"
mkdir -p "$BACKUP_DIR"

echo "[INFO] Arhivăm fișierele *.log din /var/log..."
tar -cvf "$LOG_TAR" /var/log/*.log

echo "[INFO] Verificăm conținutul arhivei:"
tar -tvf "$LOG_TAR"

echo "[INFO] Copiem fișierele ascunse de tip log în backup..."
cp /var/log/.*log* "$BACKUP_DIR" 2>/dev/null

echo "[INFO] Fișiere în backup:"
ls -l "$BACKUP_DIR"

echo "[INFO] Conținutul final al arhivei:"
tar -tf "$LOG_TAR"
