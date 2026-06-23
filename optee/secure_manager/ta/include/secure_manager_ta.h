#ifndef SECURE_MANAGER_TA_H
#define SECURE_MANAGER_TA_H

#define TA_SECURE_MANAGER_UUID \
    { 0x9407a4d1, 0x33a0, 0x4b9b, \
      { 0xa5, 0x68, 0xf1, 0x84, 0xdd, 0xf8, 0xb6, 0x5c } }

#define CMD_GET_VERSION 0
#define CMD_ECHO 1  
#define CMD_HASH 2     
#define CMD_HASH_START 3
#define CMD_HASH_UPDATE 4
#define CMD_HASH_CLOSE 5
#define CMD_VERIFY_FILE 6

#endif
