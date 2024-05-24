// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 *
 */
#include <crypto/crypto.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <tee/cache.h>
#include <tsi_cmd.h>
#include <io.h>
#include <string.h>
#include <trng_pta_client.h>

#define PTA_NAME "nvt_trng.pta"

#define USE_GEN_NONCE
#define TRNG_BUSY_TIMEOUT	2000

/*---------------------------------------------------------------------*/
/*  MA35 Series TRNG registers                                         */
/*---------------------------------------------------------------------*/
#define CTRL			(trng_base + 0x000)
#define CTRL_CMD_OFFSET			(0)
#define CTRL_CMD_MASK			(0xf << 0)

#define MODE			(trng_base + 0x004)
#define MODE_SEC_ALG			(0x1 << 0)
#define MODE_PRED_RESET			(0x1 << 3)
#define MODE_ADDIN_PRESENT		(0x1 << 4)
#define MODE_KAT_VEC_OFFSET		(5)
#define MODE_KAT_VEC_MASK		(0x3 << 5)
#define MODE_KAT_SEL_OFFSET		(7)
#define MODE_KAT_SEL_MASK		(0x3 << 7)

#define SMODE			(trng_base + 0x008)
#define SMODE_NONCE			(0x1 << 0)
#define SMODE_MISSION_MODE		(0x1 << 1)
#define SMODE_MAX_REJECTS_OFFSET	(2)
#define SMODE_MAX_REJECTS_MASK		(0xff << 2)
#define SMODE_INDIV_HT_DISABLE_OFFSET	(16)
#define SMODE_INDIV_HT_DISABLE_MASK	(0xff << 16)
#define SMODE_NOISE_COLLECT		(0x1 << 31)

#define STAT			(trng_base + 0x00C)
#define STAT_LAST_CMD_OFFSET		(0)
#define STAT_LAST_CMD_MASK		(0xf << 0)
#define STAT_SEC_ALG			(0x1 << 4)
#define STAT_NONCE_MODE			(0x1 << 5)
#define STAT_MISSION_MODE		(0x1 << 6)
#define STAT_DRBG_STATE_OFFSET		(7)
#define STAT_DRBG_STATE_MASK		(0x3 << 7)
#define STAT_STARTUP_TEST_STUCK		(0x1 << 9)
#define STAT_STARTUP_TEST_IN_PROG	(0x1 << 10)
#define STAT_BUSY			(0x1 << 31)

#define IE			(trng_base + 0x010)
#define IE_ZEROIZED			(0x1 << 0)
#define IE_KAT_COMPLETED		(0x1 << 1)
#define IE_NOISE_RDY			(0x1 << 2)
#define IE_ALARMS			(0x1 << 3)
#define IE_DONE				(0x1 << 4)
#define IE_GLBL				(0x1 << 31)

#define ISTAT			(trng_base + 0x014)
#define ISTAT_ZEROIZED			(0x1 << 0)
#define ISTAT_KAT_COMPLETED		(0x1 << 1)
#define ISTAT_NOISE_RDY			(0x1 << 2)
#define ISTAT_ALARMS			(0x1 << 3)
#define ISTAT_DONE			(0x1 << 4)

#define ALARMS			(trng_base + 0x018)
#define ALARMS_FAILED_TEST_ID_OFFSET	(0)
#define ALARMS_FAILED_TEST_ID_MASK	(0xf << 0)
#define ALARMS_ILLEGAL_CMD_SEQ		(0x1 << 4)
#define ALARMS_FAILED_SEED_ST_HT	(0x1 << 5)

#define COREKIT_REL		(trng_base + 0x01C)
#define COREKIT_REL_REL_NUM_OFFSET	(0)
#define COREKIT_REL_REL_NUM_MASK	(0xffff << 0)
#define COREKIT_REL_EXT_VER_OFFSET	(16)
#define COREKIT_REL_EXT_VER_MASK	(0xff << 16)
#define COREKIT_REL_EXT_ENUM_OFFSET	(28)
#define COREKIT_REL_EXT_ENUM_MASK	(0xf << 28)

#define FEATURES		(trng_base + 0x020)
#define FEATURES_SECURE_RST_STATE	(0x1 << 0)
#define FEATURES_DIAG_LEVEL_ST_HLT_OFFSET (1)
#define FEATURES_DIAG_LEVEL_ST_HLT_MASK	(0x7 << 1)
#define FEATURES_DIAG_LEVEL_CLP800_OFFSET (4)
#define FEATURES_DIAG_LEVEL_CLP800_MASK	(0x7 << 4)
#define FEATURES_DIAG_LEVEL_NS		(0x1 << 7)
#define FEATURES_PS_PRESENT		(0x1 << 8)
#define FEATURES_AES_256		(0x1 << 9)
#define RAND(x)			(trng_base + 0x024 + ((x) * 0x04))
#define RAND_WCNT			4
#define NPA_DATA(x)		(trng_base + 0x034 + ((x) * 0x04))
#define NPA_DATA_WCNT			16
#define SEED(x)			(trng_base + 0x074 + ((x) * 0x04))
#define SEED_WCNT			12
#define TIME_TO_SEED		(trng_base + 0x0d0)
#define BUILD_CFG0		(trng_base + 0x0f0)
#define BUILD_CFG1		(trng_base + 0x0f4)

/*
 *  CTL CMD[3:0]  commands
 */
#define TCMD_NOP		0x0       /* Execute a NOP */
#define TCMD_GEN_NOISE		0x1       /* Generate ful-entropy seed from noise  */
#define TCMD_GEN_NONCE		0x2       /* Generate seed from host written nonce */
#define TCMD_CREATE_STATE	0x3       /* Move DRBG to create state  */
#define TCMD_RENEW_STATE	0x4       /* Move DRBG to renew state   */
#define TCMD_REFRESH_ADDIN	0x5       /* Move DRBG to refresh addin */
#define TCMD_GEN_RANDOM		0x6       /* Generate a random number   */
#define TCMD_ADVANCE_STATE	0x7       /* Advance DRBG state         */
#define TCMD_RUN_KAT		0x8       /* Run KAT on DRBG or entropy source */
#define TCMD_ZEROIZE		0xf       /* Zeroize                    */

static int ma35_trng_wait_busy_clear(vaddr_t trng_base)
{
	TEE_Time  t_start, t_cur;
	uint32_t  mytime;

	tee_time_get_sys_time(&t_start);
	while (io_read32(STAT) & STAT_BUSY) {
		tee_time_get_sys_time(&t_cur);
		mytime = (t_cur.seconds - t_start.seconds) * 1000 +
		    (int)t_cur.millis - (int)t_start.millis;

		if (mytime > TRNG_BUSY_TIMEOUT)
			return -1;
	}
	return 0;
}

static int ma35_trng_issue_command(vaddr_t trng_base, int cmd)
{
	TEE_Time  t_start, t_cur;
	uint32_t  mytime;

	if (ma35_trng_wait_busy_clear(trng_base) != 0)
		return TEE_ERROR_TRNG_BUSY;

	io_write32(CTRL, (io_read32(CTRL) & ~CTRL_CMD_MASK) | (cmd << CTRL_CMD_OFFSET));

	tee_time_get_sys_time(&t_start);
	while (!(io_read32(ISTAT) & ISTAT_DONE)) {
		tee_time_get_sys_time(&t_cur);
		mytime = (t_cur.seconds - t_start.seconds) * 1000 +
			 (int)t_cur.millis - (int)t_start.millis;

		if (mytime > TRNG_BUSY_TIMEOUT) {
			EMSG("TRNG command %d timeout! ISTAT=0x%x, SMODE=0x%x.\n",
			     cmd, io_read32(ISTAT), io_read32(SMODE));
			return TEE_ERROR_TRNG_COMMAND;
		}
	}
	return 0;
}

static int ma35_trng_gen_nonce(vaddr_t trng_base, uint32_t *nonce)
{
	int   i, j, loop, ret;

	io_write32(SMODE, io_read32(SMODE) | SMODE_NONCE);

	if (io_read32(MODE) & MODE_SEC_ALG)
		loop = 3;
	else
		loop = 2;

	for (i = 0; i < loop; i++) {
		if (ma35_trng_wait_busy_clear(trng_base) != 0)
			return TEE_ERROR_TRNG_BUSY;

		for (j = 0; j < 16; j++)
			io_write32(NPA_DATA(j), nonce[j]);

		ret = ma35_trng_issue_command(trng_base, TCMD_GEN_NONCE);
		if (ret != 0)
			return TEE_ERROR_TRNG_GEN_NOISE;
	}
	return 0;
}

static int ma35_trng_create_state(vaddr_t trng_base)
{
	if (ma35_trng_wait_busy_clear(trng_base) != 0)
		return TEE_ERROR_TRNG_BUSY;

	return ma35_trng_issue_command(trng_base, TCMD_CREATE_STATE);
}

static TEE_Result ma35_trng_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t nonce[64] = { 0xc47b0294, 0xdbbbee0f, 0xec4757f2, 0x2ffeee35,
			       0x87ca4730, 0xc3d33b69, 0x1df38bab, 0x63ac0a6b,
			       0xd38da3ab, 0x584a50ea, 0xb93f2603, 0x09a5c691,
			       0x09a5c691, 0x024f91ac, 0x6063ce20, 0x229160d9,
			       0x49e00388, 0x1ab6b0cd, 0xe657cb40, 0x87c5aa81,
			       0xd611eab8, 0xa7ae6d1c, 0x3a181a28, 0x9391bbec,
			       0x22186179, 0xb6476813, 0x67e64213, 0x47cc0c01,
			       0xf53bc314, 0x73545902, 0xd8a14864, 0xb31262d1,
			       0x2bf77bc3, 0xd81c9e3a, 0xa0657c50, 0x51a2fe50,
			       0x91ff8818, 0x6de4dc00, 0xba468631, 0x7601971c,
			       0xdec69b2f, 0x336e9662, 0xef73d94a, 0x618226a3,
			       0x3cdd3154, 0xf361b408, 0x55d394b4, 0xfc3d7775,
			       0x8b35e0ef, 0xa221fe17, 0x0d498127, 0x641719f1,
			       0x4e5197b1, 0x7c84d929, 0xab60aa80, 0x08889570,
			       0xee42614d, 0x73c2ace4, 0xbaed0e9c, 0x9a12145d,
			       0xed66a951, 0xeac1e50f, 0x690c563b, 0x5dccdc9d
			       };
	vaddr_t trng_base = core_mmu_get_va(TRNG_BASE, MEM_AREA_IO_SEC, TRNG_REG_SIZE);
	vaddr_t tsi_base = core_mmu_get_va(TSI_BASE, MEM_AREA_IO_SEC, TSI_REG_SIZE);
	int ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

#if defined(PLATFORM_FLAVOR_MA35D1)
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC, SYS_REG_SIZE);

	if (!(io_read32(sys_base + SYS_CHIPCFG) & TSIEN)) {

		ret = ma35d1_tsi_init();
		if (ret != 0)
			return ret;

		ret = TSI_TRNG_Init(0, 0); //(uint32_t)((uint64_t)nonce));
		if (ret == ST_WAIT_TSI_SYNC) {
			if (TSI_Sync() != ST_SUCCESS)
				return TEE_ERROR_TRNG_BUSY;
			ret = TSI_TRNG_Init(0, 0); // (uint32_t)((uint64_t)nonce));
		}
		if (ret != ST_SUCCESS)
			return TEE_ERROR_TRNG_GEN_NOISE;

		return TEE_SUCCESS;
	}
#endif

	/* enable TRNG engine clock */
	io_write32(tsi_base + 0x20c, io_read32(tsi_base + 0x20c) |
		   (1 << 25));

	if (ma35_trng_wait_busy_clear(trng_base) != 0)
		return TEE_ERROR_TRNG_BUSY;

	if (io_read32(STAT) & (STAT_STARTUP_TEST_STUCK |
		STAT_STARTUP_TEST_IN_PROG)) {
		/* TRNG startup in progress state! */
		return TEE_ERROR_TRNG_BUSY;
	}

	/* SELECT_ALG_AES_256 */
	io_write32(MODE, io_read32(MODE) | MODE_SEC_ALG);

	ret = ma35_trng_gen_nonce(trng_base, nonce);
	if (ret != 0)
		return ret;

	ret = ma35_trng_create_state(trng_base);
	if (ret != 0)
		return ret;

	params[0].value.a = io_read32(STAT);
	params[0].value.b = io_read32(ISTAT);

	FMSG("TRNG init done.\n");
	return TEE_SUCCESS;
}

static TEE_Result ma35_trng_read(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t *rdata = NULL;
	uint32_t rq_size = 0, get_size = 0;
	vaddr_t trng_base = core_mmu_get_va(TRNG_BASE, MEM_AREA_IO_SEC, TRNG_REG_SIZE);
	int	i, ret;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	rq_size = params[0].memref.size;

	if (rq_size % 4)	/* must be multiple of words */
		return TEE_ERROR_NOT_SUPPORTED;

	rdata = (uint32_t *)params[0].memref.buffer;
	if (!rdata)
		return TEE_ERROR_BAD_PARAMETERS;

#if defined(PLATFORM_FLAVOR_MA35D1)
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_SEC, SYS_REG_SIZE);

	if (!(io_read32(sys_base + SYS_CHIPCFG) & TSIEN)) {
		/*
		 * TSI enabled. Invoke TSI command and return here.
		 */
		cache_operation(TEE_CACHEINVALIDATE, rdata, rq_size);

		ret = TSI_TRNG_Gen_Random(rq_size / 4, (uint32_t)virt_to_phys(rdata));
		if (ret != ST_SUCCESS)
			return TEE_ERROR_TRNG_FAILED;

		return 0;
	}
#endif

	while (rq_size >= 4) {
		if (ma35_trng_wait_busy_clear(trng_base) != 0)
			return TEE_ERROR_TRNG_BUSY;

		ret = ma35_trng_issue_command(trng_base, TCMD_GEN_RANDOM);
		if (ret != 0)
			return ret;

		for (i = 0; i < 4; i++) {
			if (rq_size < 4)
				break;
			*rdata = io_read32(RAND(i));
			rdata++;
			rq_size -= 4;
			get_size += 4;
		}
	}
	params[0].memref.size = get_size;
	FMSG("reqsize = %d, get_size=%d\n", rq_size, get_size);
	return 0;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (nCommandID) {
	case PTA_CMD_TRNG_INIT:
		return ma35_trng_init(nParamTypes, pParams);
	
	case PTA_CMD_TRNG_READ:
		return ma35_trng_read(nParamTypes, pParams);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_TRNG_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
