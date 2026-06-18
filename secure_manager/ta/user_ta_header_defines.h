#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include "secure_manager_ta.h"

#define TA_UUID TA_SECURE_MANAGER_UUID

#define TA_FLAGS          (TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE)
#define TA_STACK_SIZE     (2 * 1024)
#define TA_DATA_SIZE      (32 * 1024)

#define TA_VERSION        "1.0"
#define TA_DESCRIPTION    "Secure Manager TA"

#endif /* USER_TA_HEADER_DEFINES_H */
