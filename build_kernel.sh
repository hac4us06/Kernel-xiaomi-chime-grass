#/bin/bash
set -e

[ ! -e "scripts/packaging/pack.sh" ] && git submodule init && git submodule update
[ ! -e "toolchain" ] && echo "Make toolchain avaliable at $(pwd)/toolchain"

# Patch for 4.14
sed -i 's/#ifdef CONFIG_KPROBES/#if 0/g' KernelSU/kernel/ksu.c

export KBUILD_BUILD_USER=Ash
export KBUILD_BUILD_HOST=GrassLand

PATH=$PWD/toolchain/bin:$PATH

rm -rf out
make O=out CROSS_COMPILE=aarch64-linux-gnu- LLVM=1 -j$(nproc) vendor/chime_defconfig
make O=out CROSS_COMPILE=aarch64-linux-gnu- LLVM=1 -j$(nproc)
