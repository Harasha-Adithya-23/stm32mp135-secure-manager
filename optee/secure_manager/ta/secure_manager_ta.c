
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


#include "secure_manager_ta.h"

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptype,
                                    TEE_Param param[4],
                                    void **session_id_ptr)
{
    /* Check client identity, and alloc/init some session resources if any */
    
	
    /* Return with a status */
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ptr)
{
    /* check client and handle session resource release, if any */
    
}


static TEE_Result get_version(uint32_t parameters_type,TEE_Param parameters[4])
{
	uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE);

	if(parameters_type != expected)
	{
		return TEE_ERROR_BAD_PARAMETERS;
	}

	parameters[0].value.a = 1;

	return TEE_SUCCESS;
}

static TEE_Result echo(uint32_t parameters_type, TEE_Param parameters[4])
{
    uint32_t expected = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (parameters_type != expected)
        return TEE_ERROR_BAD_PARAMETERS;

    char *input = parameters[0].memref.buffer;
    char *output = parameters[1].memref.buffer;
    uint32_t size = parameters[0].memref.size;

    if (parameters[1].memref.size < size)
        return TEE_ERROR_SHORT_BUFFER;

    TEE_MemMove(output, input, size);
    parameters[1].memref.size = size;

    return TEE_SUCCESS;
}

static TEE_Result hash(uint32_t parameters_type , TEE_Param parameters[4])
{
	uint32_t expected = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (parameters_type != expected)
		return TEE_ERROR_BAD_PARAMETERS;

	if (parameters[1].memref.size < 32)     //output size
		return TEE_ERROR_SHORT_BUFFER;


	TEE_OperationHandle op; // op to create a crypto function
	TEE_Result res;	  // to call and get response 

	res = TEE_AllocateOperation(
		&op,
		TEE_ALG_SHA256,				  // Calling algo sha 256
		TEE_MODE_DIGEST,			  // purpose making a digest/hash - one way
		0
    );                                 // operation to create a crypto api 

	if (res != TEE_SUCCESS)
	{
		return 	res;
	}


	TEE_DigestUpdate(
		op,
		parameters[0].memref.buffer,
		parameters[0].memref.size
	);                                       // digest data gives data to the crypto api

	uint32_t hash_size = 32;


	TEE_DigestDoFinal(
		op,							   //  op
		NULL,                          //  data: NULL because data already sent via digest update
		0,
		parameters[1].memref.buffer,
		&hash_size
	);                      // Finish hashing and get the result


	parameters[1].memref.size = 32;

	TEE_FreeOperation(op);
	
	return TEE_SUCCESS;
}


TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t cmd_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4])
{
    /* Decode the command and process execution of the target service */

    switch(cmd_id)
    {
    	case CMD_GET_VERSION:
    		return get_version(parameters_type,parameters);

    	case CMD_ECHO:
    	    return echo(parameters_type, parameters);

    	case CMD_HASH:
    		return hash(parameters_type , parameters);

    	default:
    		return TEE_ERROR_BAD_PARAMETERS;
    }
    

    /* Return with a status */
    return TEE_SUCCESS;
}
