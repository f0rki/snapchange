#!/bin/bash

# Build the raw image itself
if [ ! -d ./fuzzer_template ]; then
  cp -r -L ../fuzzer_template .

  pushd fuzzer_template/qemu_snapshot/IMAGE
  sed -i 's/ext4/ext2/' create-image.sh
  ./create-image.sh
  sudo rm -rf chroot
  popd
fi

# Compress the image to make the docker image a bit smaller
echo "Compressing the raw linux image"
pigz fuzzer_template/qemu_snapshot/IMAGE/bookworm.img

# Build the docker container
docker build -t snapchange .