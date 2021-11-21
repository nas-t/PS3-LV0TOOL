#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SFC_KEY_SIZE   (11 * 16)
#define SFC_BLOCK_SIZE 16

#define SFC_ERROR_OK          ( 0)
#define SFC_ERROR_INVALID_ARG (-1)

typedef struct {
	void *unused;
} sfc_context_t;

/*
 * create a new context.
 */
sfc_context_t * sfc_create_context(const uint8_t erk[SFC_KEY_SIZE], const uint8_t riv[SFC_BLOCK_SIZE]);

/*
 * process a data.
 */
int sfc_process_data(sfc_context_t *ctx, const uint8_t *in, uint8_t *out, uint32_t size);

/*
 * destroy a context.
 */
void sfc_destroy_context(sfc_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
