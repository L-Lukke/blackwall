#!/usr/bin/env bash
set -euo pipefail

rm -f runtime/gateway/*.db runtime/gateway/*.db-shm runtime/gateway/*.db-wal
rm -f runtime/issuer/*.db runtime/issuer/*.db-shm runtime/issuer/*.db-wal
rm -f runtime/wallet/*.db runtime/wallet/*.db-shm runtime/wallet/*.db-wal
rm -f scenarios/.logs/*.log
