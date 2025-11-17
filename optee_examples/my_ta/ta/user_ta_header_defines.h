/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <my_ta.h>

#define TA_UUID                MY_TA_UUID

/* Multi-instance TA, no special flags */
#define TA_FLAGS               TA_FLAG_EXEC_DDR

/* Stack / Heap sizes */
#define TA_STACK_SIZE          (2 * 1024)
#define TA_DATA_SIZE           (32 * 1024)

/* TA metadata */
#define TA_VERSION    "1.0"
#define TA_DESCRIPTION "My TA for VA → PA test"

#endif /* USER_TA_HEADER_DEFINES_H */