// my_ta.c
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <my_ta.h>        // 內含 MY_TA_UUID, CMD_GET_SECRET, CMD_GET_PA 等定義
#include <pta_va2pa.h>    // 你自己的 pta_va2pa.h, 內含 PTA_VA2PA_UUID / PTA_CMD_VA2PA

#define SECRET_SIZE 32

/* Secure World 中要被 DMA 攻擊的祕密 */
static uint8_t g_secret[SECRET_SIZE] = {
    0x10, 0x11, 0x12, 0x13,
    0x20, 0x21, 0x22, 0x23,
    0x30, 0x31, 0x32, 0x33,
    0x40, 0x41, 0x42, 0x43,
    0x50, 0x51, 0x52, 0x53,
    0x60, 0x61, 0x62, 0x63,
    0x70, 0x71, 0x72, 0x73,
    0x80, 0x81, 0x82, 0x83
};

/*
 * 利用 PTA_VA2PA，將 g_secret 的 VA 轉成實體位址 PA。
 *
 * 假設 pta_va2pa 介面如下：
 *   - UUID: PTA_VA2PA_UUID
 *   - CMD:  PTA_CMD_VA2PA
 *   - param[0]: VALUE_INOUT，其中
 *         a = VA (輸入, 32-bit)
 *         b = PA (輸出, 32-bit)
 */
static TEE_Result get_pa_of_g_secret(uint64_t *out_pa)
{
    TEE_Result res;
    TEE_TASessionHandle sess;
    TEE_UUID pta_uuid = PTA_VA2PA_UUID;
    uint32_t ret_origin;
    TEE_Param params[4];
    uint32_t param_types;
    uint32_t va32, pa32;
    uint64_t va = (uint64_t)g_secret;

    if (!out_pa)
        return TEE_ERROR_BAD_PARAMETERS;

    IMSG("[TA] get_pa_of_g_secret: VA=%p", (void *)g_secret);

    /* 開 session 給 pta_va2pa */
    res = TEE_OpenTASession(&pta_uuid, 0, 0, NULL, &sess, &ret_origin);
    if (res != TEE_SUCCESS) {
        EMSG("[TA] TEE_OpenTASession(pta_va2pa) failed: 0x%x (origin 0x%x)",
             res, ret_origin);
        return res;
    }

    TEE_MemFill(params, 0, sizeof(params));

    /* ⚠ 只用一個 VALUE_INOUT，跟 PTA 完全對齊 */
    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE);

    va32 = (uint32_t)va;   // 在 RPi3 上 VA < 4GB，32-bit 足夠
    params[0].value.a = va32;
    params[0].value.b = 0;

    res = TEE_InvokeTACommand(sess, 0, PTA_CMD_VA2PA,
                              param_types, params, &ret_origin);
    if (res != TEE_SUCCESS) {
        EMSG("[TA] TEE_InvokeTACommand(PTA_CMD_VA2PA) failed: 0x%x (origin 0x%x)",
             res, ret_origin);
        TEE_CloseTASession(sess);
        return res;
    }

    pa32 = params[0].value.b;
    TEE_CloseTASession(sess);

    *out_pa = (uint64_t)pa32;
    IMSG("[TA] VA=%p -> PA=0x%08" PRIx32 " (0x%016llX as 64-bit)",
         (void *)g_secret, pa32, (unsigned long long)*out_pa);

    return TEE_SUCCESS;
}

/* ===================================================================== */
/*  Command handlers                                                     */
/* ===================================================================== */

/*
 * CMD_GET_SECRET:
 *   params[0] : MEMREF_OUTPUT，用來把 g_secret 拷貝給 Normal World
 *
 *   Normal World: TEEC_MEMREF_TEMP_OUTPUT
 */
static TEE_Result cmd_get_secret(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    void *out_buf;
    size_t out_size;

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) {
        EMSG("cmd_get_secret: bad param_types: 0x%x", param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    out_buf  = params[0].memref.buffer;
    out_size = params[0].memref.size;

    if (!out_buf || out_size < SECRET_SIZE) {
        EMSG("cmd_get_secret: buffer too small (got %zu, need %u)",
             out_size, SECRET_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    TEE_MemMove(out_buf, g_secret, SECRET_SIZE);
    params[0].memref.size = SECRET_SIZE;

    IMSG("cmd_get_secret: returned %u bytes", SECRET_SIZE);
    return TEE_SUCCESS;
}

/*
 * CMD_GET_PA:
 *   TA 端: params[0] : MEMREF_OUTPUT (TEE_PARAM_TYPE_MEMREF_OUTPUT)
 *          buffer 至少要 8 bytes，用來存 uint64_t PA
 *
 *   CA 端程式：
 *      uint64_t secret_pa;
 *      op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
 *                                       TEEC_NONE, TEEC_NONE, TEEC_NONE);
 *      op.params[0].tmpref.buffer = &secret_pa;
 *      op.params[0].tmpref.size   = sizeof(secret_pa);
 */
static TEE_Result cmd_get_pa(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types;
    uint8_t *out_buf;
    size_t out_size;
    uint64_t pa;
    TEE_Result res;

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) {
        EMSG("cmd_get_pa: bad param_types: 0x%x", param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    out_buf  = (uint8_t *)params[0].memref.buffer;
    out_size = params[0].memref.size;

    if (!out_buf || out_size < sizeof(uint64_t)) {
        EMSG("cmd_get_pa: buffer too small (got %zu, need %zu)",
             out_size, sizeof(uint64_t));
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* 透過 PTA 取得 g_secret 的實體位址 */
    res = get_pa_of_g_secret(&pa);
    if (res != TEE_SUCCESS) {
        EMSG("cmd_get_pa: get_pa_of_g_secret failed: 0x%x", res);
        return res;
    }

    TEE_MemMove(out_buf, &pa, sizeof(uint64_t));
    params[0].memref.size = sizeof(uint64_t);

    IMSG("cmd_get_pa: returned PA = 0x%016llX", (unsigned long long)pa);

    return TEE_SUCCESS;
}

/* ===================================================================== */
/*  TA entry points                                                      */
/* ===================================================================== */

TEE_Result TA_CreateEntryPoint(void)
{
    IMSG("my_ta: TA_CreateEntryPoint");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    IMSG("my_ta: TA_DestroyEntryPoint");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx)
{
    (void)param_types;
    (void)params;
    (void)sess_ctx;

    IMSG("my_ta: TA_OpenSessionEntryPoint");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)sess_ctx;
    IMSG("my_ta: TA_CloseSessionEntryPoint");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)sess_ctx;

    switch (cmd_id) {
    case CMD_GET_SECRET:
        return cmd_get_secret(param_types, params);

    case CMD_GET_PA:
        return cmd_get_pa(param_types, params);

    default:
        EMSG("Unknown command ID: %u", cmd_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
