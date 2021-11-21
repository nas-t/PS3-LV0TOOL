/* An imlementation of 50nyWantToFuckHackersButTheyCannot(tm) cryptographic algorithm */

#include "crypt.h"
#include "tables.h"
#include "util.h"

typedef struct {
	uint8_t erk[SFC_KEY_SIZE];
	uint8_t riv[SFC_BLOCK_SIZE];
} sfc_context_prv_t;

#define SFC_NUM_ROUNDS   5
#define SFC_CONTEXT_SIZE sizeof(sfc_context_prv_t)

#define RCTRL_V1_SHIFT 0
#define RCTRL_V2_SHIFT 5
#define RCTRL_V_MASK   0x1F
#define RCTRL_X_BIT    (1 << 10)
#define RCTRL_T_BIT    (1 << 11)

#define RCTRL_S(_idx)         (((_idx) & RCTRL_V_MASK) << RCTRL_V1_SHIFT)
#define RCTRL_X(_idx1, _idx2) (RCTRL_X_BIT | (((_idx1) & RCTRL_V_MASK) << RCTRL_V1_SHIFT) | (((_idx2) & RCTRL_V_MASK) << RCTRL_V2_SHIFT))
#define RCTRL_T(_idx)         (RCTRL_T_BIT | (((_idx) & RCTRL_V_MASK) << RCTRL_V1_SHIFT))

#define RCTRL_V1(_val) (((_val) >> RCTRL_V1_SHIFT) & RCTRL_V_MASK)
#define RCTRL_V2(_val) (((_val) >> RCTRL_V2_SHIFT) & RCTRL_V_MASK)

#define GET_MATRIX_ELEMENT(_matrix, _i, _j) _matrix[((_i) & 3) * 4 + ((_j) & 3)]
#define GET_NTH_BYTE(_val, _idx) (((_val) >> 8 * (4 - (_idx) - 1)) & 0xFF)

/* TODO: rewrite */
#if !defined(CRYPTO_PPU) && defined(CRYPTO_SPU)
	const uint8_t FT[16] = {
		0x00, 0x05, 0x0A, 0x0F, 0x04, 0x09, 0x0E, 0x03, 0x08, 0x0D, 0x02, 0x07, 0x0C, 0x01, 0x06, 0x0B
	};
#elif !defined(CRYPTO_SPU) && defined(CRYPTO_PPU)
	const uint8_t FT[16] = {
		0x05, 0x0A, 0x0F, 0x00, 0x09, 0x0E, 0x03, 0x04, 0x0D, 0x02, 0x07, 0x08, 0x01, 0x06, 0x0B, 0x0C
	};
#endif

#if !defined(CRYPTO_PPU) && defined(CRYPTO_SPU)
#	define B_START 0x0
#elif !defined(CRYPTO_SPU) && defined(CRYPTO_PPU)
#	define B_START 0x9000 /* TODO: rewrite */
#endif

/* TODO: rewrite */
const uint16_t phase1_ctrl[16] = {
	RCTRL_S( 5), RCTRL_S(12), RCTRL_T( 6), RCTRL_X( 4,  9),
	RCTRL_S( 9), RCTRL_S( 0), RCTRL_T( 7), RCTRL_X( 8, 13),
	RCTRL_S(13), RCTRL_S( 4), RCTRL_T( 4), RCTRL_X(12,  1),
	RCTRL_S( 1), RCTRL_S( 8), RCTRL_T( 7), RCTRL_X( 0,  5)
};
const uint16_t phase2_ctrl1[4] = {
	RCTRL_X(15, 15), RCTRL_X( 3,  3), RCTRL_X( 7,  7), RCTRL_X(11, 11)
};
const uint16_t phase2_ctrl2[4] = {
	RCTRL_X(10,  4), RCTRL_X(14,  5), RCTRL_X( 2,  6), RCTRL_X( 6,  7)
};

int calculate_key(const uint8_t *box, const uint8_t *iv, uint8_t key[SFC_BLOCK_SIZE]) {
	uint8_t ctx[SFC_BLOCK_SIZE];
	uint32_t s[16];
	uint32_t t[8];
	uint32_t x[16];
	uint32_t p[4];
	uint32_t n[4];
	uint32_t state_matrix[16];

	int round;
	int i, j;

	memset(key, 0, SFC_BLOCK_SIZE);
	memset(ctx, 0, SFC_BLOCK_SIZE);

	/* initialize the context with IV */
	const uint32_t *ku = (const uint32_t *)box;
	for (i = 0; i < 16; ++i) {
		ctx[i] = T1[i * 256 + iv[i]] ^ box[i];
	}

	/* round loop */
	for (round = 0; round < SFC_NUM_ROUNDS; ++round, ku += 8) {
		for (i = 0; i < 8; ++i) {
			t[i] = swap32(ku[i]);
		}

		#if !defined(CRYPTO_PPU) && defined(CRYPTO_SPU)
			for (i = 0; i < 16; ++i) {
				s[i] = swap32(B[ctx[i] + i * 256]);
			}
		#elif !defined(CRYPTO_SPU) && defined(CRYPTO_PPU)
			for (i = 0; i < 16; ++i) {
				s[i] = swap32(B[ctx[i] + i * 256 + round * 0x2000]); /* TODO: rewrite */
			}
		#endif

		for (i = 0; i < 16; ++i) {
			uint16_t ctrl = phase1_ctrl[i];
			if ((ctrl & RCTRL_T_BIT) == RCTRL_T_BIT) {
				x[i] = t[RCTRL_V1(ctrl)];
			} else if ((ctrl & RCTRL_X_BIT) == RCTRL_X_BIT) {
				x[i] = s[RCTRL_V1(ctrl)] ^ s[RCTRL_V2(ctrl)];
			} else {
				x[i] = s[RCTRL_V1(ctrl)];
			}
		}

		for (i = 0; i < 4; ++i) {
			assert((phase2_ctrl1[i] & RCTRL_X_BIT) == RCTRL_X_BIT);
			assert((phase2_ctrl2[i] & RCTRL_X_BIT) == RCTRL_X_BIT);

			uint16_t ctrl1 = phase2_ctrl1[i];
			uint16_t ctrl2 = phase2_ctrl2[i];

			uint32_t x1 = s[RCTRL_V1(ctrl1)] ^ x[RCTRL_V2(ctrl1)];
			uint32_t x2 = s[RCTRL_V1(ctrl2)] ^ t[RCTRL_V2(ctrl2)];

			p[i] = x1 ^ x2;
		}

		for (i = 0; i < 4; ++i) {
			n[i] = swap32(ku[i + 8]);
		}

		if (round < SFC_NUM_ROUNDS - 1) {
			/* update the context */
			#if !defined(CRYPTO_PPU) && defined(CRYPTO_SPU)
				for (i = 0; i < 4; ++i) {
					for (j = 0; j < 4; ++j) {
						state_matrix[i * 4 + j] = swap32(B[GET_NTH_BYTE(p[i], j) + i * 1024 + j * 256]);
					}
				}
			#elif !defined(CRYPTO_SPU) && defined(CRYPTO_PPU)
				for (i = 0; i < 4; ++i) {
					for (j = 0; j < 4; ++j) {
						state_matrix[i * 4 + j] = swap32(B[GET_NTH_BYTE(p[i], j) + i * 1024 + j * 256 + ((round * 2 + 1) << 12)]); /* TODO: rewrite */
					}
				}
			#endif

			for (i = 0; i < 4; ++i) {
				uint32_t x1 = GET_MATRIX_ELEMENT(state_matrix, i + 0, 0);
				uint32_t x2 = GET_MATRIX_ELEMENT(state_matrix, i + 1, 1);
				uint32_t x3 = GET_MATRIX_ELEMENT(state_matrix, i + 2, 2);
				uint32_t x4 = GET_MATRIX_ELEMENT(state_matrix, i + 3, 3);
				uint32_t xxx = x1 ^ x2 ^ x3 ^ x4 ^ n[i];

				for (j = 0; j < 4; ++j) {
					ctx[i * 4 + j] = GET_NTH_BYTE(xxx, j);
				}
			}
		} else {
			/* final round */
			for (i = 0; i < 4; ++i) {
				for (j = 0; j < 4; ++j) {
					ctx[i * 4 + j] = GET_NTH_BYTE(p[i], j);
				}
			}
		}
	}

	/* final step */
	for (i = 0; i < 4; ++i) {
		uint32_t a = swap32(B[ctx[FT[i * 4 + 0]] + FT[i * 4 + 0] * 256 + B_START]) & 0xFF000000;
		uint32_t b = swap32(B[ctx[FT[i * 4 + 1]] + FT[i * 4 + 1] * 256 + B_START]) & 0xFF0000;
		uint32_t c = swap32(B[ctx[FT[i * 4 + 2]] + FT[i * 4 + 2] * 256 + B_START]) & 0xFF00;
		uint32_t d = swap32(B[ctx[FT[i * 4 + 3]] + FT[i * 4 + 3] * 256 + B_START]) & 0xFF;
		uint32_t f = n[i] ^ a ^ b ^ c ^ d;

		#if !defined(CRYPTO_PPU) && defined(CRYPTO_SPU)
			for (j = 0; j < 4; ++j) {
				key[(i * 4 + j) & 15] = T2[GET_NTH_BYTE(f, j) + i * 1024 + j * 256];
			}
		#elif !defined(CRYPTO_SPU) && defined(CRYPTO_PPU)
			for (j = 0; j < 4; ++j) {
				key[((i + 1) * 4 + j) & 15] = T2[GET_NTH_BYTE(f, j) + i * 1024 + j * 256];
			}
		#endif
	}

	return 0;
}

sfc_context_t * sfc_create_context(const uint8_t erk[SFC_KEY_SIZE], const uint8_t riv[SFC_BLOCK_SIZE]) {
	sfc_context_prv_t *real_ctx;

	if (erk != NULL && riv != NULL) {
		real_ctx = (sfc_context_prv_t *)malloc(SFC_CONTEXT_SIZE);
		memset(real_ctx, 0, SFC_CONTEXT_SIZE);
		memcpy(real_ctx->erk, erk, SFC_KEY_SIZE);
		memcpy(real_ctx->riv, riv, SFC_BLOCK_SIZE);
		return (sfc_context_t *)real_ctx;
	} else {
		return NULL;
	}
}

int sfc_process_data(sfc_context_t *ctx, const uint8_t *in, uint8_t *out, uint32_t size) {
	sfc_context_prv_t *real_ctx;
	uint8_t final_key[SFC_BLOCK_SIZE];
	uint32_t num_blocks;
	uint32_t i, j;

	if (ctx == NULL || in == NULL || out == NULL)
		return SFC_ERROR_INVALID_ARG;

	real_ctx = (sfc_context_prv_t *)ctx;

	num_blocks = (uint32_t)(size / SFC_BLOCK_SIZE);
	for (i = 0; i < num_blocks; ++i) {
		calculate_key(real_ctx->erk, real_ctx->riv, final_key);

		for (j = 0; j < SFC_BLOCK_SIZE; ++j)
			out[j] = in[j] ^ final_key[j];

		for (j = SFC_BLOCK_SIZE - 1; j >= 0; --j) {
			real_ctx->riv[j]++;
			if (real_ctx->riv[j])
				break;
		}

		in += SFC_BLOCK_SIZE;
		out += SFC_BLOCK_SIZE;
	}

	return SFC_ERROR_OK;
}

void sfc_destroy_context(sfc_context_t *ctx) {
	sfc_context_prv_t *real_ctx;

	if (ctx != NULL) {
		real_ctx = (sfc_context_prv_t *)ctx;
		free(real_ctx);
	}
}
