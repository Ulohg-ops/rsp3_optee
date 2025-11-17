// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <my_ta.h>
#include <pta_va2pa.h>

static const TEE_UUID pta_va2pa_uuid = PTA_VA2PA_UUID;

static TEE_Result cmd_get_secret(uint32_t param_types, TEE_Param params[4]);
static TEE_Result cmd_get_pa(uint32_t param_types, TEE_Param params[4]);

static uint8_t g_secret[32] = {
    0x11,0x22,0x33,0x44,
    0x55,0x66,0x77,0x88,
    0x99,0xAA,0xBB,0xCC,
    0xDD,0xEE,0xFF,0x00,
    0x01,0x02,0x03,0x04,
    0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,
    0x0D,0x0E,0x0F,0x10,
};


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

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("MY TA Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	IMSG("Goodbye!\n");
}

TEE_Result cmd_get_secret(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    // 確認 buffer 大小足夠
    if (params[0].memref.size < sizeof(g_secret))
        return TEE_ERROR_SHORT_BUFFER;

    // 然後把 g_secret 複製出去
    memcpy(params[0].memref.buffer, g_secret, sizeof(g_secret));
    params[0].memref.size = sizeof(g_secret);

    return TEE_SUCCESS;
}

static TEE_Result cmd_get_pa(uint32_t param_types, TEE_Param params[4])
{
    /* Normal world 用 VALUE_OUTPUT 拿回 PA */
    uint32_t exp = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    /* User TA 是 32-bit VA → g_secret 的 VA 直接轉成 uint32_t */
    uint32_t va = (uint32_t)(uintptr_t)g_secret;

    IMSG("[TA] g_secret VA = %p (0x%x)", g_secret, va);

    /* 打開 PTA session */
    TEE_TASessionHandle sess;
    uint32_t origin = 0;
    TEE_Result res;

    TEE_Param none[4] = { 0 };

    res = TEE_OpenTASession(&pta_va2pa_uuid,
                            0,
                            TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE),
                            none,
                            &sess,
                            &origin);
    if (res != TEE_SUCCESS) {
        EMSG("Open PTA session failed: 0x%x", res);
        return res;
    }

    /* 組要傳給 PTA 的參數 */
    TEE_Param p[4];
    memset(p, 0, sizeof(p));

    uint32_t pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INOUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    p[0].value.a = va;   /* VA 直接帶進去 */
    p[0].value.b = 0;    /* 不用 64bit */

    /* 呼叫 PTA → VA2PA */
    res = TEE_InvokeTACommand(sess, 0, PTA_CMD_VA2PA, pt, p, &origin);
    if (res != TEE_SUCCESS) {
        EMSG("PTA invoke failed: 0x%x", res);
        TEE_CloseTASession(sess);
        return res;
    }

    /* 取回物理位址（32-bit PA） */
    uint32_t pa = p[0].value.a;

    /* 回傳給 Normal World */
    params[0].value.a = pa;
    params[0].value.b = 0;

    IMSG("[TA] g_secret VA 0x%x → PA 0x%x", va, pa);

    TEE_CloseTASession(sess);
    return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd_id) {
	case CMD_GET_SECRET:
		return cmd_get_secret(param_types, params);
	case CMD_GET_PA:                   
        return cmd_get_pa(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
