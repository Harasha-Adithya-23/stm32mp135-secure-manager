#include <stdio.h>
#include<string.h>  // for memset
	
// tee_client_api.h for accessing TEEC functions
#include <tee_client_api.h>

// for uuid and command ids
#include "../ta/include/secure_manager_ta.h"



int main(void)
{
    TEEC_Context ctx;                               //Connection to OPTEE
    TEEC_Session sess;                              // Connection to TA
    TEEC_UUID uuid = TA_SECURE_MANAGER_UUID;        // UUID for which TA to load
    TEEC_Result res;								
    uint32_t origin;

    TEEC_Operation op;                              // operation to take place

    res = TEEC_InitializeContext(NULL, &ctx);                  // Connects linux to optee
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return 1;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid,                                 // TA connection 
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x origin: 0x%x\n", res, origin);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    printf("Entered secure world — session open\n");

    memset(&op,0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT , TEEC_NONE , TEEC_NONE , TEEC_NONE );

    res = TEEC_InvokeCommand(&sess,CMD_GET_VERSION,&op,&origin);
    	
    	if (res != TEEC_SUCCESS) {
    	
    	    printf("InvokeCommand failed: 0x%x origin: 0x%x\n",
    	            res, origin);
    	
    	    TEEC_CloseSession(&sess);
    	    TEEC_FinalizeContext(&ctx);
    	
    	    return 1;
    	}
    

    printf("Secure Manager version = %u\n",
           op.params[0].value.a);

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    printf("Back in normal world\n");
    return 0;

}
