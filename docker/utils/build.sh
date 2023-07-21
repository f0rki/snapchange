#!/usr/bin/env bash

# make sure env vars have sensible default if not set:

if [[ -z "$SNAPSHOT_INPUT" ]]; then
    DIR=/image/
else
    DIR="$SNAPSHOT_INPUT"
fi
if [[ -z "$SNAPSHOT_OUTPUT" ]]; then
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
if [[ -z "$LIBFUZZER" ]]; then 
    LIBFUZZER=0
fi
if [[ -z "$SNAPSHOT_EXTRACT" ]]; then
  SNAPSHOT_EXTRACT=""
fi

RELEASE=harness

if [[ -z "$SNAPSHOT_ENTRYPOINT" ]]; then
    echo "[ERROR] reuqire setting a SNAPSHOT_ENTRYPOINT"
    exit 1
fi
if [[ -z "$SNAPSHOT_ENTRYPOINT_ARGUMENTS" ]]; then
    SNAPSHOT_ENTRYPOINT_ARGUMENTS=""
fi
if [[ -z "$SNAPSHOT_ENTRYPOINT_CWD" ]]; then
    SNAPSHOT_ENTRYPOINT_CWD=""
fi

set -eu -o pipefail
set -x

BIN="$DIR/$SNAPSHOT_ENTRYPOINT"

cp "$BIN" "$OUTPUT/$(basename "$BIN").bin"
if ! [[ -z "$SNAPSHOT_EXTRACT" ]]; then
  mkdir -p "$OUTPUT/image"
  for file in $SNAPSHOT_EXTRACT; do
    echo "$file"
    dest="$OUTPUT/image/$file"
    mkdir -p "$(dirname "$dest")" || true
    cp -r "$DIR/$file" "$dest"
  done
fi

if [[ "$LIBFUZZER" -eq 1 ]]; then 

    if ! nm "$BIN" | grep LLVMFuzzerTestOneInput; then
        echo "LLVMFuzzerTestOneInput not found in $BIN."
        exit 1
    fi
    
    # If LIBFUZZER, dump the first 16 bytes of LLVMFuzzerTestOneInput to restore
    # after taking the snapshot. These bytes are corrupted 
    r2 -q -c 'p8 16 @ sym.LLVMFuzzerTestOneInput' $BIN > /tmp/libfuzzer.bytes.bak
fi

 
if [[ $USER = 'root' ]]; then
    HOMEDIR=/root/
else
    HOMEDIR="/home/$USER"
fi

# Make the directory to hold the original binary to copy into the snapshot directory
mkdir -p "$DIR/$HOMEDIR"

RC_LOCAL="$DIR/etc/rc.local"

# Remove previous snapshot script
rm "$RC_LOCAL" || true

# Init the rc.local script
cat > "$RC_LOCAL" <<EOF
#!/bin/sh -ex

export SNAPSHOT=1

echo "[+] snapshotting program: $SNAPSHOT_ENTRYPOINT $SNAPSHOT_ENTRYPOINT_ARGUMENTS"

EOF

if [[ -z "$SNAPSHOT_ENTRYPOINT_CWD" ]]; then
    echo "cd $HOMEDIR || true" >> "$RC_LOCAL"
else
    echo "cd $SNAPSHOT_ENTRYPOINT_CWD || true" >> "$RC_LOCAL"
fi


# If user is not root, run gdb under gdb in order to gain kernel symbols as root
if [ $USER != 'root' ]; then
    cat > "$RC_LOCAL" <<EOF
echo "[+] obtaining kernel symbols by running gdb under gdb"
gdb --command=$HOMEDIR/gdbcmds --args gdb
mv /tmp/gdb.symbols /tmp/gdb.symbols.root
rm /tmp/gdb.modules
rm /tmp/gdb.vmmap

EOF
fi

# If user is not root, run gdb under the given user
if [ $USER != 'root' ]; then
    echo "su $USER -c '" >> $RC_LOCAL
fi

# Create the script to start on boot
echo -n "gdb --batch --command=$HOMEDIR/gdbcmds --args "$SNAPSHOT_ENTRYPOINT" $SNAPSHOT_ENTRYPOINT_ARGUMENTS"  >> $RC_LOCAL

# If user is not root, close the command executed
if [ $USER != 'root' ]; then
    echo "'" >> $RC_LOCAL
fi

# Add a newline
echo "" >> $RC_LOCAL

# Ensure the output files are actually written to the image
echo "sync" >> $RC_LOCAL

# Status check after GDB exits to see if the files are written
echo "ls -la" >> $RC_LOCAL


cat >> "$RC_LOCAL" <<EOF

echo "[+] Trying to mount 9pfs"
mount -t 9p -o trans=virtio snapchange_mnt /mnt/ -oversion=9p2000.L
echo "mounting 9pfs success? => \$?"

echo "[+] extracting logs to 9pfs"
cp -r /tmp/gdb.* /mnt/
if [ "\$PWD" != "/" ]; then
    cp -r . "/mnt/cwd"
fi
cat /proc/modules > /mnt/guestkernel.modules
cat /proc/kallsyms > /mnt/guestkernel.kallsyms

# Ensure the output files are actually written to the image
sync

echo "[+] ok. kthxbye."
# a trigger for the snapchange scripts that we are done with execution.
echo ""
echo "snapshot done"
echo ""
EOF


# Make the script executable and owned by root
chmod +x $RC_LOCAL
chown root:root $RC_LOCAL

# Add newline to thes script
echo "" >> $RC_LOCAL

# Copy in the gdbsnapshot.py
cp gdbsnapshot.py $DIR$HOMEDIR/gdbsnapshot.py

# Try to remove the old gdbcmds since we are writing a new one below
rm $DIR$HOMEDIR/gdbcmds || true

# Execute to the first int3, execute the gdbsnapshot, execute vmcall, then exit
if [[ "$LIBFUZZER" -eq 1 ]]; then
    echo "LIBFUZZER SNAPSHOT DETECTED"
    echo "Taking a snapshot at LLVMFuzzerTestOneInput"
    cat > "$DIR$HOMEDIR/gdbcmds" <<EOF
# Ignore leak detection. 
set environment ASAN_OPTIONS=detect_leaks=0

# Stop at the first chance in the target in order to enable the breakpoint on LLVMFuzzerTestOneInput
start
del *
x/16xb LLVMFuzzerTestOneInput

# Remove all coverage trace from libfuzzer since we are using breakpoint coverage in Snapchange
set {unsigned char}(__sanitizer_cov_trace_cmp1)=0xc3
set {unsigned char}(__sanitizer_cov_trace_cmp2)=0xc3
set {unsigned char}(__sanitizer_cov_trace_cmp4)=0xc3
set {unsigned char}(__sanitizer_cov_trace_cmp8)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp1)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp2)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp4)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp8)=0xc3
set {unsigned char}(__sanitizer_cov_trace_div4)=0xc3
set {unsigned char}(__sanitizer_cov_trace_div8)=0xc3
set {unsigned char}(__sanitizer_cov_trace_gep)=0xc3
set {unsigned char}(__sanitizer_cov_trace_pc_guard)=0xc3
set {unsigned char}(__sanitizer_cov_trace_pc_guard_init)=0xc3
set {unsigned char}(__sanitizer_cov_trace_pc_indir)=0xc3
set {unsigned char}(__sanitizer_cov_trace_switch)=0xc3

# Insert (int3 ; vmcall) on the LLVMFuzzerTestOneInput 
set {unsigned char}(LLVMFuzzerTestOneInput+0x0)=0xcc
set {unsigned char}(LLVMFuzzerTestOneInput+0x1)=0x0f
set {unsigned char}(LLVMFuzzerTestOneInput+0x2)=0x01
set {unsigned char}(LLVMFuzzerTestOneInput+0x3)=0xc1
set {unsigned char}(LLVMFuzzerTestOneInput+0x4)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x5)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x6)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x7)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x8)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x9)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xa)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xb)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xc)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xd)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xe)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xf)=0xcd

# Continue execution until the LLVMFuzzerTestOneInput and take the snapshot as normal
continue
source $HOMEDIR/gdbsnapshot.py
ni
ni
quit

EOF
else
    cat > "$DIR$HOMEDIR/gdbcmds" <<EOF
set pagination off
run
source $HOMEDIR/gdbsnapshot.py
ni
ni
quit

EOF
fi


# e.g., if we are in initramfs we need a script to run `/etc/rc.local`
if [[ ! -e "$DIR/init" ]]; then
  cat > "$DIR/init" <<EOF
#!/bin/sh

export PATH=\$PATH:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

echo "[+] Mounting /dev /proc /sys"
mount -t devtmpfs dev /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys

echo "[+] bringing up loopback netdevice"
ip link set up dev lo

# for interactive use - enable shell prompt
# /sbin/getty -n -l /bin/sh 115200 /dev/console

echo "[+] Starting rc.local commands"
/etc/rc.local
echo "[+] rc.local finished with \$?"
if [ \$? -ne 0 ]; then
    echo "[ERROR] rc.local error"
fi


echo "[+] poweroff"
poweroff -f

EOF
    chmod +x "$DIR/init"
fi


echo "!!! Sanity check the root directory !!!"
ls -la $DIR
echo "!!! Sanity check the root directory !!!"

# Sanity check the script was written properly
echo "!!! Sanity check the startup script !!!"
cat $RC_LOCAL
echo "!!! Sanity check the startup script !!!"

# Display the home directory as a sanity check
echo "!!! Sanity check the home directory !!!"
ls -la $DIR$HOMEDIR
echo "!!! Sanity check the home directory !!!"


if [[ "$IMGTYPE" = "initramfs" ]]; then
    pushd "$DIR"
    find . -print0 \
        | cpio --null --create --owner root:root --format=newc \
        | lz4c -l \
        > "/snapchange/$RELEASE.initramfs.lz4"
    popd
elif [[ "$IMGTYPE" = "disk" ]]; then
    # Build a disk image
    virt-make-fs "$DIR" "/snapchange/$RELEASE.img"
else
    echo "[ERROR] invalid IMGTYPE=$IMGTYPE"
    exit 1
fi
