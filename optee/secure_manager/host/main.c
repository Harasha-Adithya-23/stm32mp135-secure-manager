#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include<time.h>
#include <tee_client_api.h>
#include "../ta/include/secure_manager_ta.h"
#include "../ta/include/public_key.h"

typedef struct
{
    uint8_t n[256];
    uint32_t n_size;

    uint8_t e[8];
    uint32_t e_size;

} public_key_blob;


static TEEC_Context ctx;         //connection to optee
static TEEC_Session sess;        // connection to ta
static TEEC_UUID uuid = TA_SECURE_MANAGER_UUID;  // uuid to search .ta file
static TEEC_Result res;
static uint32_t origin;
static TEEC_Operation op;

#define HASH_SIZE 32
#define SIG_SIZE  256

static unsigned char hash[HASH_SIZE];


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

static void setFirmwareVersion(uint32_t version)
{
	memset(&op , 0 , sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT , TEEC_NONE , TEEC_NONE , TEEC_NONE);

	op.params[0].value.a = version;

	res = TEEC_InvokeCommand(&sess , CMD_SET_FW_VERSION , &op , &origin);

	if(res != TEEC_SUCCESS)
	{
	    printf("Version set failed 0x%x origin=0x%x\n",
	           res,
	           origin);
	    return;
	}

	printf("Firmware version set to %u\n", version);
}

static void getFirmwareVersion(void)
{
	memset(&op , 0 , sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT , TEEC_NONE , TEEC_NONE , TEEC_NONE);
	res = TEEC_InvokeCommand(&sess , CMD_GET_FW_VERSION , &op , &origin);	

	if(res != TEEC_SUCCESS)
	{
	    printf("Version get failed 0x%x origin=0x%x\n",
	           res,
	           origin);
	    return;
	}
		
    printf("Current firmware version = %u\n",
           op.params[0].value.a);
}

static void writeAuditLog(const	char *file , const char *sender , int version , const char *result)
{
	FILE *log;

	char timebuf[64];

	time_t now = time(NULL);

	struct tm *t =  localtime(&now);

	strftime( timebuf , sizeof(timebuf) , "%Y-%m-%d %H:%M:%S",t);

	log =  fopen("/var/log/secure_manager.log" , "a");

	if (log == NULL)
	{
		printf("Cannot open log\n");
		return;
	}

	fprintf( log , "[%s] FILE = %s SENDER = %s VERSION = %d RESULT = %s\n" , timebuf , file , sender , version , result);
	fclose(log);
	
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

static void storeKey()
{
	memset(&op , 0 , sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(
						TEEC_MEMREF_TEMP_INPUT,
						TEEC_NONE,
						TEEC_NONE,
						TEEC_NONE
					);

	public_key_blob key;

	memset(&key , 0 , sizeof(key));

	memcpy(key.n , rsa_n , sizeof(rsa_n));
	key.n_size = RSA_N_SIZE;

	memcpy(key.e , rsa_e , sizeof(rsa_e));
	key.e_size = RSA_E_SIZE;

	op.params[0].tmpref.buffer = &key;
	op.params[0].tmpref.size = sizeof(key);

	
	res = TEEC_InvokeCommand(&sess , CMD_STORE_KEY , &op , &origin);
	if (res != TEEC_SUCCESS)
	{
		printf("Public Key store failed 0x%x\n",res);
		return;
	}

	printf("Public Key stored in secured storage");
}

static void readKey()
{
	public_key_blob key;

	memset(&op , 0 , sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES( TEEC_MEMREF_TEMP_OUTPUT , TEEC_NONE , TEEC_NONE , TEEC_NONE);

	op.params[0].tmpref.buffer = &key;
	op.params[0].tmpref.size = sizeof(key);

	res = TEEC_InvokeCommand(&sess , CMD_READ_KEY , &op , &origin);

	if(res==TEEC_SUCCESS)
	    printf("Read key from secure storage OK\n");
	else
	    printf("Read failed 0x%x\n",res);
}

static void hashFile(const char *filename)
{
    FILE *fp;
    unsigned char buffer[4096];
    size_t n;

    fp = fopen(filename, "rb");

    if (!fp) {
        printf("Cannot open file: %s\n", filename);
        return;
    }

    memset(&op, 0, sizeof(op));

    res = TEEC_InvokeCommand(&sess,
                             CMD_HASH_START,
                             &op,
                             &origin);

    if (res != TEEC_SUCCESS) {
        printf("HASH_START failed\n");
        fclose(fp);
        return;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {

        memset(&op, 0, sizeof(op));

        op.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_NONE,
                TEEC_NONE,
                TEEC_NONE);

        op.params[0].tmpref.buffer = buffer;
        op.params[0].tmpref.size   = n;

        res = TEEC_InvokeCommand(&sess,
                                 CMD_HASH_UPDATE,
                                 &op,
                                 &origin);

        if (res != TEEC_SUCCESS) {
            printf("HASH_UPDATE failed\n");
            fclose(fp);
            return;
        }
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_NONE,
            TEEC_NONE,
            TEEC_NONE);

    op.params[0].tmpref.buffer = hash;
    op.params[0].tmpref.size   = HASH_SIZE;

    res = TEEC_InvokeCommand(&sess,
                             CMD_HASH_CLOSE,
                             &op,
                             &origin);

    if (res != TEEC_SUCCESS) {
        printf("HASH_CLOSE failed\n");
        fclose(fp);
        return;
    }

    fclose(fp);

    printf("SHA256: ");

    for (int i = 0; i < HASH_SIZE; i++)
        printf("%02x", hash[i]);

    printf("\n");
}


static void move_file(const char *src,
                      const char *folder)
{
    char dst[512];

    const char *name = strrchr(src, '/');

    if (name)
        name++;
    else
        name = src;

    snprintf(dst,
             sizeof(dst),
             "%s/%s",
             folder,
             name);

    if (rename(src, dst) != 0)
        printf("Failed moving %s\n", src);
}



static void verifyFile(const char *file_path,
                       const char *sig_path)
{
    uint8_t sig[SIG_SIZE];

    FILE *fp = fopen(sig_path, "rb");

    if (!fp) {
        printf("Cannot open signature: %s\n",
               sig_path);
        return;
    }

    size_t n = fread(sig, 1, sizeof(sig), fp);

    fclose(fp);

    if (n == 0) {
        printf("Signature file empty\n");
        return;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_NONE);

    op.params[0].tmpref.buffer = hash;
    op.params[0].tmpref.size   = HASH_SIZE;

    op.params[1].tmpref.buffer = sig;
    op.params[1].tmpref.size   = n;

    res = TEEC_InvokeCommand(&sess,
                             CMD_VERIFY_FILE,
                             &op,
                             &origin);

    if (res == TEEC_SUCCESS) {

        printf("Signature Verified\n");

        move_file(file_path,
                  "./approved");

        move_file(sig_path,
                  "./approved");

        writeAuditLog(file_path , "default_sender" , 1 , "APPROVED");
    }
    else {

        printf("Signature Invalid\n");

        move_file(file_path,
                  "./rejected");

        move_file(sig_path,
                  "./rejected");

        writeAuditLog(file_path , "default_sender" , 1 , "REJECTED");
    }
}




static void stop(void)
{
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    printf("Back in normal world\n");
}

int main(int argc, char *argv[])
{
  /* if (argc != 3) {
        printf("Usage:\n");
        printf("%s <file.bin> <file.sig>\n",
               argv[0]);
        return 1;
    }
    
*/
    start();

    if(res != TEEC_SUCCESS){
        return 1;    	
    }

	storeKey();
	readKey();

	//setFirmwareVersion(3);
	getFirmwareVersion();

    //hashFile(argv[1]);

    //verifyFile(argv[1], argv[2]);


    stop();

    return 0;
}
