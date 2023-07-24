#!/bin/bash

if [[ -z "$SNAPSHOT_OUTPUT" ]]; then
  # Directory to output snapshot files
  OUTPUT=/snapshot/
else
  OUTPUT="$SNAPSHOT_OUTPUT"
fi
if [[ -z "$SNAPSHOT_IMGTYPE" ]]; then
    # IMGTYPE="disk"
    IMGTYPE="initramfs"
else
    IMGTYPE="$SNAPSHOT_IMGTYPE"
fi
if [[ -z "$SNAPSHOT_USER" ]]; then
    USER=root
else
    USER="$SNAPSHOT_USER"
fi
if [[ -z "$SNAPSHOT_KERNEL_IMG" ]]; then
  SNAPSHOT_KERNEL_IMG=""
fi
if [[ -z "$SNAPSHOT_KERNEL_ELF" ]]; then
  SNAPSHOT_KERNEL_ELF=""
fi
if [[ -z "$LIBFUZZER" ]]; then 
    LIBFUZZER=0
fi
if [[ -z "$QEMU_MEM" ]]; then
    QEMU_MEM="4G"
fi
if [[ -z "$KASAN" ]]; then
    KASAN=0
fi
if [[ -z "$SNAPSHOT_ENTRYPOINT" ]]; then
    echo "[ERROR] reuqire setting a SNAPSHOT_ENTRYPOINT"
    exit 1
fi
  
RELEASE="harness"
D9P="/tmp/mnt.9p"  # directory for 9pfs

set -eu -o pipefail

function start_vm {
  QEMU="/snapchange/QEMU/build/qemu-system-x86_64"
  KERNEL="/snapchange/linux.bzImage"
  if [[ -n "$SNAPSHOT_KERNEL_IMG" ]]; then
    KERNEL="$SNAPSHOT_KERNEL_IMG"
  elif [[ "$KASAN" -eq 1 ]]; then
    KERNEL="/snapchange/linux.kasan.bzImage"
  fi

  if ! command -v "$QEMU"; then
      echo "[ERROR] No qemu found!"
      exit 1
  fi
  if [[ ! -e "$KERNEL" ]]; then
      echo "[ERROR] no kernel found! ('$KERNEL')"
      exit 1
  fi

  rm -rf "$D9P" || true
  mkdir -p "$D9P"
  D9P="$(realpath "$D9P")"

  echo "[snapshot.sh] launching qemu"

  if [[ "$IMGTYPE" = "disk" ]]; then
     "$QEMU" \
        -m "$QEMU_MEM" \
        -smp 1 \
        -kernel "$KERNEL" \
        -append "console=ttyS0 root=/dev/sda earlyprintk=serial init=/init mitigations=off" \
        -drive "file=/snapchange/$RELEASE.img" \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
        -net nic,model=e1000 \
        -virtfs "local,path=$D9P,mount_tag=snapchange_mnt,security_model=mapped" \
        -nographic \
        -pidfile vm.pid \
        2>&1 | tee vm.log
  elif [[ "$IMGTYPE" = "initramfs" ]]; then
      "$QEMU" \
          -m "$QEMU_MEM" \
          -smp 1 \
          -kernel "$KERNEL" \
          -initrd "/snapchange/$RELEASE.initramfs.lz4" \
          -append "console=ttyS0 earlyprintk=serial mitigations=off" \
          -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
          -net nic,model=e1000 \
          -virtfs "local,path=$D9P,mount_tag=snapchange_mnt,security_model=mapped" \
          -nographic \
          -pidfile vm.pid \
          2>&1 | tee vm.log
  else
      echo "[snapshot.sh][ERROR] invalid IMGTYPE=$IMGTYPE"
      exit 1 
  fi
}

function kill_vm {
    if [[ -e vm.pid ]]; then
        kill -9 "$(cat vm.pid)" || true
    fi
}

function check_vm_halted {
    if [[ -e vm.pid ]]; then
        if ps -p "$(cat vm.pid)" >/dev/null; then
            return 1
        else
            return 0
        fi
    else
        return 0
    fi
}

function extract_output { 

  DIR="$D9P"

  echo "[snapshot.sh] VM returned data:"
  ls -al "$DIR"

  # Copy over the files written by `gdbsnapshot.py`
  mv "$DIR/gdb.vmmap" .
  mv "$DIR/gdb.modules" .
  mv "$DIR/gdb.symbols" .

  # Copy over the root symbols and, if found, move the user symbols to .symbols in order to
  # combine the symbols into one gdb.symbols
  if [ -f "$DIR/gdb.symbols.root" ]; then
      echo "Combining root and user symbols"
      mv "$DIR/gdb.symbols.root" .
      mv gdb.symbols gdb.symbols.user 
      python3 combine_symbols.py
  fi

  # Ensure the files are the current user and not root anymore
  if [ -f gdb.symbols.root ]; then 
      chown `id -u`:`id -g` gdb.symbols.root
  fi
  chown `id -u`:`id -g` gdb.symbols
  chown `id -u`:`id -g` gdb.modules
  chown `id -u`:`id -g` gdb.vmmap

  # copy the saved working dir from the snapshot
    cp -r "$DIR/cwd" "$OUTPUT/" || true

    cp  "$DIR"/guestkernel* "$OUTPUT" || true
}


# Create the output directory
mkdir -p $OUTPUT || true

if [[ -n "$SNAPSHOT_KERNEL_IMG" ]]; then
  cp "$SNAPSHOT_KERNEL_IMG" "$OUTPUT/vmlinux.bzimg"
  if [[ -n "$SNAPSHOT_KERNEL_ELF" ]]; then
    cp "$SNAPSHOT_KERNEL_ELF" "$OUTPUT/vmlinux"
  else
    echo "[WARNING] couldn't find vmlinux corresponding to bootable kernel image '$SNAPSHOT_KERNEL_IMG'."
    echo "[WARNING] please set the variable SNAPSHOT_KERNEL_ELF for kernel symbols!"
  fi
else
  # Copy over the `vmlinux` into the output directory
  if [[ "$KASAN" -eq 1 ]]; then
      cp /snapchange/vmlinux.kasan "$OUTPUT/vmlinux"
  else
      cp /snapchange/vmlinux "$OUTPUT/vmlinux"
  fi
fi

# Start the VM
start_vm &

sleep 1

# While the VM is booting, wait for the login prompt. Once the login prompt is shown,
# extarct the gdb output and kill the VM
while true; do
    # Login prompt signals that the /etc/rc.local script executed and can extract output
    # Status code of 0 means the login prompt was found in the vm.log
    if grep -e "\(linux login:\|snapshot done\)" vm.log 2>&1 >/dev/null || check_vm_halted; then
        echo "[snapshot.sh] Finished booting.. extracting gdb output";
        extract_output

        echo "[snapshot.sh] Moving the snapshot data into $OUTPUT"
        mv fuzzvm.* $OUTPUT
        mv gdb.* $OUTPUT

        echo "[snapshot.sh] Found the following files"
        ls -la $OUTPUT

        echo "[snapshot.sh] Found this SNAPSHOT output from the vm log"
        grep SNAPSHOT vm.log || true

        echo "[snapshot.sh] Killing the VM"
        kill_vm

        echo "[snapshot.sh] (almost) done!"
        break
    fi

    echo "[snapshot.sh] Waiting for login prompt.."
    sleep 2
done

cp vm.log "$OUTPUT/"


if [[ "$LIBFUZZER" -eq 1 ]]; then 
    echo "[snapshot.sh] patching physmem"
    BYTES="$(cat /tmp/libfuzzer.bytes.bak)"
    # Restore the original bytes at the LLVMFuzzerTestOneInput bytes
    r2 -w -q -c "/x cc0f01c1cdcdcdcdcdcdcdcdcdcdcdcd ; wx $BYTES @@ hit0*" "$OUTPUT/fuzzvm.physmem"
fi

# Create the reset script for the snapshot
cp ./reset_snapshot.sh $OUTPUT/reset.sh

echo "[snapshot.sh] creating coverage breakpoints with ghidra"
# Create the coverage breakpoints and analysis
BIN_NAME="$(basename "$SNAPSHOT_ENTRYPOINT")"

# Get the base address of the example from the module list
BASE="$(grep "$BIN_NAME" "$OUTPUT/gdb.modules" | cut -d' ' -f1)"

# Use ghidra to find the coverage basic blocks
python3 ./ghidra_basic_blocks.py --base-addr "$BASE" "$OUTPUT/$BIN_NAME.bin"


# finally just chown to something more sensible
chown -R "$SNAPSHOT_CHOWN_TO" "$OUTPUT" || true
