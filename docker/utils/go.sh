#!/usr/bin/env bash
set -e

if [[ "$1" == "template" ]]; then
  echo "[+] extracting template files to $PWD"
  cp -r /snapchange/fuzzer_template/{.[!.]*,*} "$TEMPLATE_OUT"
  exit 0
fi

if [[ -n "$SNAPSHOT_INPUT" ]]; then
  if [[ -z "$(ls "$SNAPSHOT_INPUT")" ]]; then
    echo "[ERROR] No files provided for snapshot root filesystem in (copy to $SNAPSHOT_INPUT)" 
  fi
fi

cd /snapchange/
echo "[+] building target image"
./build.sh
echo "[+] creating snapshot"
./snapshot.sh
echo "[+] done"
