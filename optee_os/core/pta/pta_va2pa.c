// SPDX-License-Identifier: BSD-2-Clause
/*
 * Simple PTA to translate current user TA VA -> PA
 */
#include <kernel/pseudo_ta.h>
#include <kernel/ts_manager.h>
#include <kernel/user_ta.h>
#include <mm/vm.h>
#include <pta_va2pa.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <types_ext.h>

#define TA_NAME "pta_va2pa"

static TEE_Result pta_cmd_va2pa(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct ts_session *ts_sess;
	struct user_ta_ctx *utc;
	vaddr_t va;
	paddr_t pa;
	TEE_Result res;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* VA 從 a 帶進來 */
	va = (vaddr_t)params[0].value.a;

	/* 拿到目前呼叫這個 PTA 的 user TA context */
	ts_sess = ts_get_calling_session();
	if (!ts_sess)
		return TEE_ERROR_BAD_STATE;

	utc = to_user_ta_ctx(ts_sess->ctx);
	if (!utc)
		return TEE_ERROR_BAD_STATE;
	
	DMSG("pta_va2pa: input VA = 0x%lx", (unsigned long)va);

	/* 把 user TA 的 VA 轉成 PA */
	res = vm_va2pa(&utc->uctx, (void *)va, &pa);
	if (res != TEE_SUCCESS)
		return res;

	params[0].value.a = (uint32_t)pa;
	params[0].value.b = 0;

	DMSG("VA 0x%lx -> PA 0x%lx",
	     (unsigned long)va, (unsigned long)pa);

	return TEE_SUCCESS;
}

static TEE_Result pta_va2pa_invoke(void *session_ctx __unused,
				   uint32_t cmd_id,
				   uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_CMD_VA2PA:
		return pta_cmd_va2pa(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_VA2PA_UUID,
		   .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = pta_va2pa_invoke);
