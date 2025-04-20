/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Implements a minimal interface to counter-mode AES. */

#ifndef TOR_AES_H
#define TOR_AES_H

/**
 * \file aes.h
 * \brief Headers for aes.c
 */

#include "lib/cc/torint.h"
#include "lib/malloc/malloc.h"
#include "lib/testsupport/testsupport.h"

typedef struct aes_cnt_cipher_t aes_cnt_cipher_t;

aes_cnt_cipher_t* aes_new_cipher(const uint8_t *key, const uint8_t *iv,
                                 int key_bits);
void aes_cipher_free_(aes_cnt_cipher_t *cipher);
#define aes_cipher_free(cipher) \
  FREE_AND_NULL(aes_cnt_cipher_t, aes_cipher_free_, (cipher))
void aes_crypt_inplace(aes_cnt_cipher_t *cipher, char *data, size_t len);

int evaluate_evp_for_aes(int force_value);
int evaluate_ctr_for_aes(void);

#ifdef USE_AES_RAW
typedef struct aes_raw_t aes_raw_t;

aes_raw_t *aes_raw_new(const uint8_t *key, int key_bits, bool encrypt);
void aes_raw_free_(aes_raw_t *cipher);
#define aes_raw_free(cipher) \
  FREE_AND_NULL(aes_raw_t, aes_raw_free_, (cipher))
void aes_raw_encrypt(const aes_raw_t *cipher, uint8_t *block);
void aes_raw_decrypt(const aes_raw_t *cipher, uint8_t *block);

void aes_raw_counter_xor(const aes_raw_t *aes,
                         const uint8_t *iv, uint32_t iv_offset,
                         uint8_t *data, size_t n);
#endif

#ifdef TOR_AES_PRIVATE
#include "lib/arch/bytes.h"

/** Increment the big-endian 128-bit counter in 'iv' by 'offset'. */
static inline void
aes_ctr_add_iv_offset(uint8_t *iv, uint32_t offset)
{

  uint64_t h_hi = tor_ntohll(get_uint64(iv + 0));
  uint64_t h_lo = tor_ntohll(get_uint64(iv + 8));
  h_lo += offset;
  h_hi += (h_lo < offset);
  set_uint64(iv + 0, tor_htonll(h_hi));
  set_uint64(iv + 8, tor_htonll(h_lo));
}
#endif

#endif /* !defined(TOR_AES_H) */
