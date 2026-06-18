#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "secure_manager_ta.h"
#include "secure_manager.h"

#define SHA256_DIGEST_SIZE 32

TEE_Result ta_hash_file(uint32_t param_types, TEE_Param params[4])
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res;
    uint32_t digest_len = SHA256_DIGEST_SIZE;

    uint32_t exp = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[1].memref.size < SHA256_DIGEST_SIZE)
        return TEE_ERROR_SHORT_BUFFER;

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed: 0x%x", res);
        return res;
    }

    TEE_DigestUpdate(op, params[0].memref.buffer, params[0].memref.size);

    res = TEE_DigestDoFinal(op, NULL, 0,
                            params[1].memref.buffer, &digest_len);
    if (res != TEE_SUCCESS)
        EMSG("TEE_DigestDoFinal failed: 0x%x", res);
    else
        params[1].memref.size = digest_len;

    TEE_FreeOperation(op);
    return res;
}

TEE_Result ta_verify_file(uint32_t param_types, TEE_Param params[4])
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res;
    uint8_t computed[SHA256_DIGEST_SIZE];
    uint32_t digest_len = SHA256_DIGEST_SIZE;

    uint32_t exp = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[1].memref.size != SHA256_DIGEST_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed: 0x%x", res);
        return res;
    }

    TEE_DigestUpdate(op, params[0].memref.buffer, params[0].memref.size);

    res = TEE_DigestDoFinal(op, NULL, 0, computed, &digest_len);
    TEE_FreeOperation(op);

    if (res != TEE_SUCCESS) {
        EMSG("TEE_DigestDoFinal failed: 0x%x", res);
        return res;
    }

    /* Constant-time compare to avoid timing side-channel */
    if (TEE_MemCompare(computed, params[1].memref.buffer, SHA256_DIGEST_SIZE) != 0) {
        EMSG("Hash mismatch — image verification FAILED");
        return TEE_ERROR_SECURITY;
    }

    IMSG("Image verification passed");
    return TEE_SUCCESS;
}
