#ifndef SECURE_MANAGER_TA_H
#define SECURE_MANAGER_TA_H

#define TA_SECURE_MANAGER_UUID \
    { 0x7e1a5d1e, 0xc3bc, 0x4556, \
      { 0x84, 0x89, 0x3e, 0x15, 0x39, 0x8c, 0xe9, 0x32 } }

/* Commands */
#define CMD_HASH_FILE    0
#define CMD_VERIFY_FILE  1

/*
 * CMD_HASH_FILE
 *   param[0] memref input  : buffer to hash
 *   param[1] memref output : 32-byte SHA256 digest
 *   param[2] unused
 *   param[3] unused
 *
 * CMD_VERIFY_FILE
 *   param[0] memref input  : buffer to verify
 *   param[1] memref input  : expected 32-byte SHA256 digest
 *   param[2] unused
 *   param[3] unused
 *   returns TEE_SUCCESS if match, TEE_ERROR_SECURITY if mismatch
 */

#endif /* SECURE_MANAGER_TA_H */
