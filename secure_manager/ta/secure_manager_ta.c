#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "secure_manager_ta.h"
#include "secure_manager.h"

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("Secure Manager TA created");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("Secure Manager TA destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param __unused params[4],
                                    void __unused **sess_ctx)
{
    uint32_t exp = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    IMSG("Secure Manager session opened");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
    IMSG("Secure Manager session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    switch (cmd_id) {
    case CMD_HASH_FILE:
        return ta_hash_file(param_types, params);
    case CMD_VERIFY_FILE:
        return ta_verify_file(param_types, params);
    default:
        EMSG("Unknown command 0x%x", cmd_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
