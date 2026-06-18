#ifndef SECURE_MANAGER_H
#define SECURE_MANAGER_H

#include <tee_internal_api.h>

TEE_Result ta_hash_file(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_verify_file(uint32_t param_types, TEE_Param params[4]);

#endif /* SECURE_MANAGER_H */
