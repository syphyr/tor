/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2025, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_crypto_cgo.c
 * \brief Implementation for counter galois onion encryption.
 **/

#define RELAY_CRYPTO_CGO_PRIVATE
#define USE_AES_RAW

#include "orconfig.h"
#include "lib/crypt_ops/aes.h"
#include "ext/polyval/polyval.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/log/util_bug.h"
#include "lib/arch/bytes.h"
#include "ext/polyval/polyval.h"
#include "core/crypto/relay_crypto_cgo.h"

#if 0
// XXXX debugging.
#include "lib/encoding/binascii.h"
#include <stdio.h>
#endif

#include <string.h>


/** Initialize an instance of the tweakable block cipher,
 * using an 'aesbits'-bit AES key.
 *
 * The total key material used from 'key' will be
 * (aesbits / 8) + 16.
 *
 * This will be initialized for encryption or decryption depending
 * on the value of 'encrypt'
 */
STATIC int
cgo_et_init(cgo_et_t *et, int aesbits, bool encrypt,
            const uint8_t *key)
{
  size_t aes_key_bytes = aesbits / 8;
  et->kb = aes_raw_new(key, aesbits, encrypt);
  if (et->kb == NULL)
    return -1;
  polyval_key_init(&et->ku, key + aes_key_bytes);
  return 0;
}
/** Replace the key on an existing, already initialized cgo_et_t.
 *
 * Does fewer allocations than a clear+init. */
STATIC void
cgo_et_set_key(cgo_et_t *et, int aesbits, bool encrypt,
               const uint8_t *key)
{
  size_t aes_key_bytes = aesbits / 8;
  aes_raw_set_key(&et->kb, key, aesbits, encrypt);
  polyval_key_init(&et->ku, key + aes_key_bytes);
}

/** Helper: Compute polyval(KU, H | CMD | X_R). */
static inline void
compute_et_mask(polyval_key_t *pvk, const et_tweak_t tweak, uint8_t *t_out) {
  // block 0: tweak.h
  // block 1: one byte of command, first 15 bytes of x_r
  // block 2...: remainder of x_r, zero-padded.
  polyval_t pv;
  uint8_t block1[16];
  block1[0] = tweak.uiv.cmd;
  memcpy(block1+1, tweak.x_r, 15);
  polyval_init_from_key(&pv, pvk);
  polyval_add_block(&pv, tweak.uiv.h);
  polyval_add_block(&pv, block1);
  polyval_add_zpad(&pv, tweak.x_r + 15, ET_TWEAK_LEN_X_R - 15);
  polyval_get_tag(&pv, t_out);
}
/** XOR the 16 byte block from inp into out. */
static void
xor_block(uint8_t *out, const uint8_t *inp)
{
  for (int i = 0; i < 16; ++i)
    out[i] ^= inp[i];
}

/**
 * Encrypt the 16-byte block in 'block'.
 */
STATIC void
cgo_et_encrypt(cgo_et_t *et, const et_tweak_t tweak,
               uint8_t *block)
{
  uint8_t mask[16];
  compute_et_mask(&et->ku, tweak, mask);
  xor_block(block, mask);
  aes_raw_encrypt(et->kb, block);
  xor_block(block, mask);
}
/**
 * Decrypt the 16-byte b lock in 'block'
 */
STATIC void
cgo_et_decrypt(cgo_et_t *et, const et_tweak_t tweak,
               uint8_t *block)
{
  uint8_t mask[16];
  compute_et_mask(&et->ku, tweak, mask);
  xor_block(block, mask);
  aes_raw_decrypt(et->kb, block);
  xor_block(block, mask);
}
/**
 * Release any storage held in 'et'.
 *
 * This _doesn't_ wipe 'et'; that's done from a higher-level function.
 */
STATIC void
cgo_et_clear(cgo_et_t *et)
{
  aes_raw_free(et->kb);
}

/**
 * Initialize a psedorandom function from a given key.
 * Uses an internal 'aesbits'-bit AES key.
 *
 * The total key material used from 'key' will be
 * (aesbits / 8) + 16.
 */
STATIC int
cgo_prf_init(cgo_prf_t *prf, int aesbits,
             const uint8_t *key)
{
  size_t aes_key_bytes = aesbits / 8;
  memset(prf,0, sizeof(*prf));
  prf->k = aes_raw_new(key, aesbits, true);
  polyval_key_init(&prf->b, key + aes_key_bytes);
  return 0;
}
/** Replace the key on an existing cgo_prf_t.
 *
 * Does fewer allocations than a clear+init. */
STATIC void
cgo_prf_set_key(cgo_prf_t *prf, int aesbits,
                const uint8_t *key)
{
  size_t aes_key_bytes = aesbits / 8;
  aes_raw_set_key(&prf->k, key, aesbits, true);
  polyval_key_init(&prf->b, key + aes_key_bytes);
}
/**
 * Compute the PRF's results on 'input', for position t=0,
 * XOR it into 'data'.
 *
 * 'input' must be PRF_INPUT_LEN bytes long.
 *
 * 'data' must be PRF_T0_DATA_LEN bytes long.
 */
STATIC void
cgo_prf_xor_t0(cgo_prf_t *prf, const uint8_t *input,
               uint8_t *data)
{
  uint8_t hash[16];
  polyval_t pv;
  polyval_init_from_key(&pv, &prf->b);
  polyval_add_block(&pv, input);
  polyval_get_tag(&pv, hash);
  hash[15] &= 0xC0; // Clear the low six bits.

  aes_raw_counter_xor(prf->k, hash, 0, data, PRF_T0_DATA_LEN);
}
/**
 * Generate 'n' bytes of the PRF's results on 'input', for position t=1,
 * and store them into 'buf'.
 *
 * 'input' must be PRF_INPUT_LEN bytes long.
 */
STATIC void
cgo_prf_gen_t1(cgo_prf_t *prf, const uint8_t *input,
               uint8_t *buf, size_t n)
{
  #define T1_OFFSET 31
  uint8_t hash[16];
  polyval_t pv;
  polyval_init_from_key(&pv, &prf->b);
  polyval_add_block(&pv, input);
  polyval_get_tag(&pv, hash);
  hash[15] &= 0xC0; // Clear the low six bits.

  memset(buf, 0, n);
  aes_raw_counter_xor(prf->k, hash, T1_OFFSET, buf, n);
}
/**
 * Release any storage held in 'prf'.
 *
 * This _doesn't_ wipe 'prf'; that's done from a higher-level function.
 */
STATIC void
cgo_prf_clear(cgo_prf_t *prf)
{
  aes_raw_free(prf->k);
}

/**
 * Initialize the 'uiv' wide-block cipher, using 'aesbits'-bit
 * AES keys internally.
 *
 * Initializes for encryption or decryption depending on the value of
 * 'encrypt'.
 *
 * The total key material used from 'key' will be
 * (aesbits / 8) * 2 + 32.
 */
STATIC int
cgo_uiv_init(cgo_uiv_t *uiv, int aesbits, bool encrypt,
             const uint8_t *key)
{
  size_t aes_key_bytes = aesbits / 8;
  if (cgo_et_init(&uiv->j, aesbits, encrypt, key) < 0)
    return -1;
  if (cgo_prf_init(&uiv->s, aesbits, key + aes_key_bytes + POLYVAL_KEY_LEN)<0)
    return -1;
#ifdef TOR_UNIT_TESTS
  /* Testing only: copy the keys so we can test UIV_UPDATE function. */
  size_t total_key_len = aes_key_bytes * 2 + POLYVAL_KEY_LEN * 2;
  tor_assert(total_key_len <= sizeof(uiv->uiv_keys_));
  memset(uiv->uiv_keys_, 0, sizeof(uiv->uiv_keys_));
  memcpy(uiv->uiv_keys_, key, total_key_len);
#endif
  return 0;
}
/**
 * Encrypt 'cell_body', with the provided tweak.
 *
 * The cell body must be UIV_BLOCK_LEN bytes long.
 */
STATIC void
cgo_uiv_encrypt(cgo_uiv_t *uiv, const uiv_tweak_t tweak, uint8_t *cell_body)
{
  uint8_t *X_L = cell_body;
  uint8_t *X_R = cell_body + 16;

  const et_tweak_t et_tweak = {
    .uiv = tweak,
    .x_r = X_R,
  };
  cgo_et_encrypt(&uiv->j, et_tweak, X_L);
  cgo_prf_xor_t0(&uiv->s, X_L, X_R);
}
/**
 * Decrypt 'cell_body', with the provided tweak.
 *
 * The cell body must be UIV_BLOCK_LEN bytes long.
 */
STATIC void
cgo_uiv_decrypt(cgo_uiv_t *uiv, const uiv_tweak_t tweak, uint8_t *cell_body)
{
  uint8_t *X_L = cell_body;
  uint8_t *X_R = cell_body + 16;

  const et_tweak_t et_tweak = {
    .uiv = tweak,
    .x_r = X_R,
  };
  cgo_prf_xor_t0(&uiv->s, X_L, X_R);
  cgo_et_decrypt(&uiv->j, et_tweak, X_L);
}
/**
 * Irreversibly ransform the keys of this UIV+, and the provided nonce,
 * using the nonce as input.
 *
 * The nonce must be 16 bytes long.
 */
STATIC void
cgo_uiv_update(cgo_uiv_t *uiv, int aesbits, bool encrypt, uint8_t *nonce)
{
  size_t aes_bytes = aesbits / 8;
  size_t single_key_len = aes_bytes + POLYVAL_KEY_LEN;
  size_t total_key_len = single_key_len * 2 + 16;
  // Note: We could store this on the stack, but stack-protector
  // wouldn't like that.
  uint8_t *new_keys = tor_malloc(total_key_len);

  cgo_prf_gen_t1(&uiv->s, nonce, new_keys, total_key_len);

  cgo_et_set_key(&uiv->j, aesbits, encrypt, new_keys);
  cgo_prf_set_key(&uiv->s, aesbits, new_keys + single_key_len);

  memcpy(nonce, new_keys + single_key_len * 2, 16);

#ifdef TOR_UNIT_TESTS
  /* Testing only: copy the keys so we can test UIV_UPDATE function. */
  memset(uiv->uiv_keys_, 0, sizeof(uiv->uiv_keys_));
  memcpy(uiv->uiv_keys_, new_keys, total_key_len);
#endif

  // This is key material, so we should really discard it.
  memwipe(new_keys, 0, total_key_len);
  tor_free(new_keys);
}
/**
 * Release any storage held in 'prf'.
 *
 * This _doesn't_ wipe 'prf'; that's done from a higher-level function.
 */
STATIC void
cgo_uiv_clear(cgo_uiv_t *uiv)
{
  cgo_et_clear(&uiv->j);
  cgo_prf_clear(&uiv->s);
}

// XXXX temporarily suppress unused-function warnings
void temporary(void);
void temporary(void)
{
  (void)cgo_et_init;
  (void)cgo_et_encrypt;
  (void)cgo_et_decrypt;
  (void)cgo_et_clear;

  (void)cgo_prf_init;
  (void)cgo_prf_xor_t0;
  (void)cgo_prf_gen_t1;
  (void)cgo_prf_clear;

  (void)cgo_uiv_init;
  (void)cgo_uiv_encrypt;
  (void)cgo_uiv_decrypt;
  (void)cgo_uiv_update;
  (void)cgo_uiv_clear;
}
