

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#define TA_UUID \
    { 0x9407a4d1 , 0x33a0, 0x4b9b, \
        { 0xa5, 0x68, 0xf1, 0x84, 0xdd, 0xf8, 0xb6, 0x5c} }

#define TA_FLAGS                    (TA_FLAG_EXEC_DDR | \
                        TA_FLAG_SINGLE_INSTANCE | \
                        TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE                       (2 * 1024)
#define TA_DATA_SIZE                        (32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, "Foo TA for some purpose." }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0100 } }

#endif /* USER_TA_HEADER_DEFINES_H */

