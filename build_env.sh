#!/bin/bash
# Source this in every new terminal before building optee_examples (or your own TAs):
#   source build_env.sh
#
# It does three things:
#   1. Loads the ST cross-compile SDK (compiler, sysroot, PATH)
#   2. Points the OP-TEE build at your built optee_client (host side) and optee_os TA dev kit (TA side)
#   3. Works around a libgcc path bug in this SDK's TA link step

# --- 1. ST SDK environment (compiler, sysroot) ---
source /opt/st/stm32mp1/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi

# --- 2. OP-TEE build variables ---
export TEEC_EXPORT=~/myboot/optee_client/export
#
# IMPORTANT: use ST's pre-built TA dev kit, NOT your own locally-built optee_os.
# Your board runs ST's stock OP-TEE OS (flashed by the official OpenSTLinux image),
# which trusts ST's signing key. A TA dev kit built from the upstream optee_os repo
# uses a different (mismatched) default key, so TAs signed with it get rejected by
# the board's OP-TEE with TEEC_Opensession failed ... origin 0x3 even though
# everything else about the build is correct.
export TA_DEV_KIT_DIR=/opt/st/stm32mpu-sdk/sysroots/cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi/usr/include/optee/export-user_ta
export CROSS_COMPILE=arm-ostl-linux-gnueabi-
export CROSS_COMPILE32=arm-ostl-linux-gnueabi-
export CROSS_COMPILE_ta_arm32=arm-ostl-linux-gnueabi-

# --- 3. libgcc path fix ---
# gcc.mk's -print-libgcc-file-name returns a bare filename ("libgcc.a") instead of
# a full path on this SDK, so the TA linker can't find it. Override with the real path.
export LIBGCC_PATH=/opt/st/stm32mp1/sysroots/cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi/lib/arm-ostl-linux-gnueabi/13.4.0/libgcc.a

echo "OP-TEE build environment loaded."
echo "  TEEC_EXPORT=$TEEC_EXPORT"
echo "  TA_DEV_KIT_DIR=$TA_DEV_KIT_DIR"
echo "  CROSS_COMPILE=$CROSS_COMPILE"
echo ""
echo "Build any example with:"
echo "  make libgccta_arm32=\$LIBGCC_PATH"
