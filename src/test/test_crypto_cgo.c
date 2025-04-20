/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define RELAY_CRYPTO_CGO_PRIVATE
#define USE_AES_RAW

#include "orconfig.h"
#include "core/or/or.h"
#include "test/test.h"
#include "lib/cc/compat_compiler.h"
#include "lib/crypt_ops/aes.h"
#include "ext/polyval/polyval.h"
#include "core/crypto/relay_crypto_cgo.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"

#include "test/cgo_vectors.inc"

static const int AESBITS[] = { 128, 192, 256 };

static void
test_crypto_cgo_et_roundtrip(void *arg)
{
  (void)arg;
  uint8_t key[32 + 16]; // max
  uint8_t tweak_h[16];
  uint8_t tweak_x_r[493];
  uint8_t block[16], block_orig[16];
  cgo_et_t et1, et2;
  memset(&et1, 0, sizeof(et1));
  memset(&et2, 0, sizeof(et2));

  et_tweak_t tweak = {
    .uiv = {
      .h = tweak_h,
      .cmd = 7,
    },
    .x_r = tweak_x_r,
  };

  for (int bi = 0; bi < (int) ARRAY_LENGTH(AESBITS); ++bi) {
    const int aesbits = AESBITS[bi];

    for (int i = 0; i < 16; ++i) {
      crypto_rand((char*)key, sizeof(key));
      crypto_rand((char*)tweak_h, sizeof(tweak_h));
      crypto_rand((char*)tweak_x_r, sizeof(tweak_x_r));
      crypto_rand((char*)block_orig, sizeof(block_orig));
      memcpy(block, block_orig, 16);
      cgo_et_init(&et1, aesbits, true, key);
      cgo_et_init(&et2, aesbits, false, key);

      // encrypt-then-decrypt should round-trip.
      cgo_et_encrypt(&et1, tweak, block);
      tt_mem_op(block, OP_NE, block_orig, 16);
      cgo_et_decrypt(&et2, tweak, block);
      tt_mem_op(block, OP_EQ, block_orig, 16);

      // decrypt-then-encrypt should round-trip.
      cgo_et_decrypt(&et2, tweak, block);
      tt_mem_op(block, OP_NE, block_orig, 16);
      cgo_et_encrypt(&et1, tweak, block);
      tt_mem_op(block, OP_EQ, block_orig, 16);

      cgo_et_clear(&et1);
      cgo_et_clear(&et2);
    }
  }
 done:
  cgo_et_clear(&et1);
  cgo_et_clear(&et2);
}

static void
test_crypto_cgo_uiv_roundtrip(void *arg)
{
  (void)arg;
  uint8_t key[64 + 32]; // max
  uint8_t tweak_h[16];
  uint8_t cell[509], cell_orig[509];
  cgo_uiv_t uiv1, uiv2;
  memset(&uiv1, 0, sizeof(uiv1));
  memset(&uiv2, 0, sizeof(uiv2));

  uiv_tweak_t tweak = {
    .h = tweak_h,
    .cmd = 4,
  };

  for (int bi = 0; bi < (int) ARRAY_LENGTH(AESBITS); ++bi) {
    const int aesbits = AESBITS[bi];

    for (int i = 0; i < 16; ++i) {
      crypto_rand((char*)key, sizeof(key));
      crypto_rand((char*)tweak_h, sizeof(tweak_h));
      crypto_rand((char*)cell_orig, sizeof(cell_orig));
      memcpy(cell, cell_orig, sizeof(cell_orig));

      cgo_uiv_init(&uiv1, aesbits, true, key);
      cgo_uiv_init(&uiv2, aesbits, false, key);

      // encrypt-then-decrypt should round-trip.
      cgo_uiv_encrypt(&uiv1, tweak, cell);
      tt_mem_op(cell, OP_NE, cell_orig, sizeof(cell));
      cgo_uiv_decrypt(&uiv2, tweak, cell);
      tt_mem_op(cell, OP_EQ, cell_orig, sizeof(cell));

      // decrypt-then-encrypt should round-trip.
      cgo_uiv_decrypt(&uiv2, tweak, cell);
      tt_mem_op(cell, OP_NE, cell_orig, sizeof(cell));
      cgo_uiv_encrypt(&uiv1, tweak, cell);
      tt_mem_op(cell, OP_EQ, cell_orig, sizeof(cell));

      cgo_uiv_clear(&uiv1);
      cgo_uiv_clear(&uiv2);
    }
  }
 done:
  cgo_uiv_clear(&uiv1);
  cgo_uiv_clear(&uiv2);
}

#define UNHEX(out,inp) STMT_BEGIN {                                     \
    size_t inplen = strlen(inp);                                        \
    tt_int_op(sizeof(out), OP_EQ, inplen / 2);                          \
    int r = base16_decode((char*)(out), sizeof(out), inp, inplen);      \
    tt_int_op(r, OP_EQ, sizeof(out));                                   \
  } STMT_END

static void
test_crypto_cgo_et_testvec(void *arg)
{
  (void)arg;
  cgo_et_t et;
  memset(&et, 0, sizeof(et));

  for (int i = 0; i < (int)ARRAY_LENGTH(ET_TESTVECS); ++i) {
    const struct et_testvec *tv = &ET_TESTVECS[i];
    uint8_t keys[32];
    uint8_t tweaks[16 + 1 + 493];
    uint8_t block[16], expect[16];
    UNHEX(keys, tv->keys);
    UNHEX(tweaks, tv->tweaks);
    UNHEX(block, tv->block);
    UNHEX(expect, tv->expect);

    et_tweak_t tweak = {
      .uiv = {
        .h = tweaks,
        .cmd = tweaks[16],
      },
      .x_r = tweaks + 17,
    };

    cgo_et_init(&et, 128, tv->encrypt, keys);
    if (tv->encrypt) {
      cgo_et_encrypt(&et, tweak, block);
    } else {
      cgo_et_decrypt(&et, tweak, block);
    }
    cgo_et_clear(&et);

    tt_mem_op(block, OP_EQ, expect, 16);
  }

 done:
  cgo_et_clear(&et);
}

static void
test_crypto_cgo_prf_testvec(void *arg)
{
  (void)arg;
  cgo_prf_t prf;
  memset(&prf, 0, sizeof(prf));

  for (int i = 0; i < (int)ARRAY_LENGTH(PRF_TESTVECS); ++i) {
    const struct prf_testvec *tv = &PRF_TESTVECS[i];
    uint8_t keys[32];
    uint8_t input[16];
    uint8_t expect_t0[493];
    uint8_t expect_t1[80];
    uint8_t output[493]; // max
    UNHEX(keys, tv->keys);
    UNHEX(input, tv->input);

    cgo_prf_init(&prf, 128, keys);
    if (tv->t == 0) {
      UNHEX(expect_t0, tv->expect);
      memset(output, 0, sizeof(output));
      cgo_prf_xor_t0(&prf, input, output);
      tt_mem_op(output, OP_EQ, expect_t0, PRF_T0_DATA_LEN);
    } else {
      tt_int_op(tv->t, OP_EQ, 1);
      UNHEX(expect_t1, tv->expect);
      cgo_prf_gen_t1(&prf, input, output, sizeof(expect_t1));
      tt_mem_op(output, OP_EQ, expect_t1, sizeof(expect_t1));
    }
    cgo_prf_clear(&prf);
  }
 done:
  cgo_prf_clear(&prf);
}

static void
test_crypto_cgo_uiv_testvec(void *arg)
{
  (void)arg;
  cgo_uiv_t uiv;
  memset(&uiv, 0, sizeof(uiv));

  for (int i = 0; i < (int)ARRAY_LENGTH(UIV_TESTVECS); ++i) {
    const struct uiv_testvec *tv = &UIV_TESTVECS[i];
    uint8_t keys[64];
    uint8_t tweaks[17];
    uint8_t x_l[16], x_r[493];
    uint8_t y_l[16], y_r[493];
    uint8_t cell[509];
    UNHEX(keys, tv->keys);
    UNHEX(tweaks, tv->tweaks);
    UNHEX(x_l, tv->x_l);
    UNHEX(x_r, tv->x_r);
    UNHEX(y_l, tv->y.y_l);
    UNHEX(y_r, tv->y.y_r);

    uiv_tweak_t tweak = {
      .h = tweaks,
      .cmd = tweaks[16]
    };
    memcpy(cell, x_l, 16);
    memcpy(cell+16, x_r, 493);

    cgo_uiv_init(&uiv, 128, tv->encrypt, keys);
    if (tv->encrypt) {
      cgo_uiv_encrypt(&uiv, tweak, cell);
    } else {
      cgo_uiv_decrypt(&uiv, tweak, cell);
    }
    cgo_uiv_clear(&uiv);

    tt_mem_op(cell, OP_EQ, y_l, 16);
    tt_mem_op(cell+16, OP_EQ, y_r, 493);
  }

 done:
  cgo_uiv_clear(&uiv);
}

static void
test_crypto_cgo_uiv_update_testvec(void *arg)
{
  (void)arg;
  cgo_uiv_t uiv;
  cgo_uiv_t uiv2;
  memset(&uiv, 0, sizeof(uiv));
  memset(&uiv2, 0, sizeof(uiv2));

  uint8_t tw[16];
  memset(tw, 42, sizeof(tw));
  uiv_tweak_t tweak = {
      .h = tw,
      .cmd = 42
  };

  for (int i = 0; i < (int)ARRAY_LENGTH(UIV_UPDATE_TESTVECS); ++i) {
    const struct uiv_update_testvec *tv = &UIV_UPDATE_TESTVECS[i];
    uint8_t keys[64];
    uint8_t nonce[16];
    uint8_t new_keys[64];
    uint8_t new_nonce[16];
    UNHEX(keys, tv->keys);
    UNHEX(nonce, tv->nonce);
    UNHEX(new_keys, tv->output.new_keys);
    UNHEX(new_nonce, tv->output.new_nonce);

    cgo_uiv_init(&uiv, 128, true, keys);
    cgo_uiv_update(&uiv, 128, true, nonce);
    // Make sure that the recorded keys are what we expect.
    tt_mem_op(uiv.uiv_keys_, OP_EQ, new_keys, 64);
    tt_mem_op(nonce, OP_EQ, new_nonce, 16);

    // Construct a new UIV from these keys and make sure it acts like this one.
    uint8_t cell[509], cell2[509];
    crypto_rand((char*)cell, sizeof(cell));
    memcpy(cell2, cell, 509);
    cgo_uiv_init(&uiv2, 128, true, uiv.uiv_keys_);
    cgo_uiv_encrypt(&uiv, tweak, cell);
    cgo_uiv_encrypt(&uiv2, tweak, cell2);
    tt_mem_op(cell, OP_EQ, cell2, 509);

    cgo_uiv_clear(&uiv);
    cgo_uiv_clear(&uiv2);
  }
 done:
  cgo_uiv_clear(&uiv);
  cgo_uiv_clear(&uiv2);
}

struct testcase_t crypto_cgo_tests[] = {
  { "et_roundtrip", test_crypto_cgo_et_roundtrip, 0, NULL, NULL },
  { "et_testvec", test_crypto_cgo_et_testvec, 0, NULL, NULL },
  { "prf_testvec", test_crypto_cgo_prf_testvec, 0, NULL, NULL },
  { "uiv_roundtrip", test_crypto_cgo_uiv_roundtrip, 0, NULL, NULL },
  { "uiv_testvec", test_crypto_cgo_uiv_testvec, 0, NULL, NULL },
  { "uiv_update_testvec", test_crypto_cgo_uiv_update_testvec, 0, NULL, NULL },
  END_OF_TESTCASES
};
