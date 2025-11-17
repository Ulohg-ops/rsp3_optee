#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "my_ta.h"

int main(void)
{
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    /* 初始化 context */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return 1;
    }

    /* 開啟 session 到 TA */
    TEEC_UUID uuid = MY_TA_UUID;
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x\n", res);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    /* 設定 operation */
    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    /* 呼叫 TA：CMD_GET_PA */
    
    res = TEEC_InvokeCommand(&sess, CMD_GET_PA, &op, &err_origin);
    uint64_t pa = 0;
    if (res != TEEC_SUCCESS) {
        printf("Invoke CMD_GET_PA failed: 0x%x (origin 0x%x)\n", res, err_origin);
    } else {
        pa = op.params[0].value.a;
        printf("TA returned PA = 0x%08x\n", (uint32_t)pa);
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return 0;
}