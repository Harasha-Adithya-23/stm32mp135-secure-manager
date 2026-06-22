#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "../ta/include/secure_manager_ta.h"

static TEEC_Context ctx;         //connection to optee
static TEEC_Session sess;        // connection to ta
static TEEC_UUID uuid = TA_SECURE_MANAGER_UUID;  // uuid to search .ta file
static TEEC_Result res;
static uint32_t origin;
static TEEC_Operation op;

static void start(void)
{
    res = TEEC_InitializeContext(NULL, &ctx);                 //connects linux to optee
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid,                     
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);                   // connects linux to ta
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x origin: 0x%x\n", res, origin);
        TEEC_FinalizeContext(&ctx);
        return;
    }

    printf("Entered secure world — session open\n");
}

static void get_version(void)
{
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&sess, CMD_GET_VERSION, &op, &origin);
    if (res != TEEC_SUCCESS) {
        printf("get_version failed: 0x%x origin: 0x%x\n", res, origin);
        return;
    }

    printf("Secure Manager version = %u\n", op.params[0].value.a);
}

static void echo(void)
{
    char input[20];
    char output[20];

    printf("Enter word: ");
    scanf("%19s", input);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,
        TEEC_NONE);

    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = strlen(input) + 1;
    op.params[1].tmpref.buffer = output;
    op.params[1].tmpref.size = sizeof(output);

    res = TEEC_InvokeCommand(&sess, CMD_ECHO, &op, &origin);
    if (res != TEEC_SUCCESS) {
        printf("echo failed: 0x%x origin: 0x%x\n", res, origin);
        return;
    }

    printf("TA echoed: %s\n", output);
}

static void hashTest(void)
{
    char input[20];
    char hash[32];

    printf("Enter word: ");
    scanf("%19s", input);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,
        TEEC_NONE);

    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = strlen(input) + 1;
    op.params[1].tmpref.buffer = hash;
    op.params[1].tmpref.size = sizeof(hash);

    res = TEEC_InvokeCommand(&sess, CMD_HASH, &op, &origin);
    if (res != TEEC_SUCCESS){
    	printf("hash failed 0x%x\n" , res);
    }

    printf("hash returned\n");

    printf("SHA256: ");

    for(int i = 0; i < 32; i++)
    {
        printf("%02x", hash[i]);
    }

    printf("\n");

    
        	
}

static void stop(void)
{
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    printf("Back in normal world\n");
}

int main(void)
{
    start();
    if (res != TEEC_SUCCESS) return 1;

    get_version();
    echo();
    hashTest();

    stop();
    return 0;
}
