/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file aes_openssl.c
 * \brief Use OpenSSL to implement AES_CTR.
 **/

#define USE_AES_RAW
#define TOR_AES_PRIVATE

#include "orconfig.h"
#include "lib/crypt_ops/aes.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/log/util_bug.h"
#include "lib/arch/bytes.h"

#ifdef _WIN32 /*wrkard for dtls1.h >= 0.9.8m of "#include <winsock.h>"*/
  #include <winsock2.h>
  #include <ws2tcpip.h>
#endif

#include "lib/crypt_ops/compat_openssl.h"
#include <openssl/opensslv.h>
#include "lib/crypt_ops/crypto_openssl_mgt.h"

DISABLE_GCC_WARNING("-Wredundant-decls")

#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/modes.h>

ENABLE_GCC_WARNING("-Wredundant-decls")

#include "lib/log/log.h"
#include "lib/ctime/di_ops.h"

#ifdef OPENSSL_NO_ENGINE
/* Android's OpenSSL seems to have removed all of its Engine support. */
#define DISABLE_ENGINES
#endif

/* We have five strategies for implementing AES counter mode.
 *
 * Best with x86 and x86_64: Use EVP_aes_*_ctr() and EVP_EncryptUpdate().
 * This is possible with OpenSSL 1.0.1, where the counter-mode implementation
 * can use bit-sliced or vectorized AES or AESNI as appropriate.
 *
 * Otherwise: Pick the best possible AES block implementation that OpenSSL
 * gives us, and the best possible counter-mode implementation, and combine
 * them.
 */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_NOPATCH(1,1,0)

/* With newer OpenSSL versions, the older fallback modes don't compile.  So
 * don't use them, even if we lack specific acceleration. */

#define USE_EVP_AES_CTR

#elif OPENSSL_VERSION_NUMBER >= OPENSSL_V_NOPATCH(1,0,1) &&               \
  (defined(__i386) || defined(__i386__) || defined(_M_IX86) ||          \
   defined(__x86_64) || defined(__x86_64__) ||                          \
   defined(_M_AMD64) || defined(_M_X64) || defined(__INTEL__))

#define USE_EVP_AES_CTR

#endif /* OPENSSL_VERSION_NUMBER >= OPENSSL_V_NOPATCH(1,1,0) || ... */

/* Cached values of our EVP_CIPHER items.  If we don't pre-fetch them,
 * then EVP_CipherInit calls EVP_CIPHER_fetch itself,
 * which is surprisingly expensive.
 */
static const EVP_CIPHER *aes128ctr = NULL;
static const EVP_CIPHER *aes192ctr = NULL;
static const EVP_CIPHER *aes256ctr = NULL;
static const EVP_CIPHER *aes128ecb = NULL;
static const EVP_CIPHER *aes192ecb = NULL;
static const EVP_CIPHER *aes256ecb = NULL;

#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_NOPATCH(3,0,0) \
  && !defined(LIBRESSL_VERSION_NUMBER)
#define RESOLVE_CIPHER(c) \
  EVP_CIPHER_fetch(NULL, OBJ_nid2sn(EVP_CIPHER_get_nid(c)), "")
#else
#define RESOLVE_CIPHER(c) (c)
#endif

/**
 * Pre-fetch the versions of every AES cipher with its associated provider.
 */
static void
init_ciphers(void)
{
  aes128ctr = RESOLVE_CIPHER(EVP_aes_128_ctr());
  aes192ctr = RESOLVE_CIPHER(EVP_aes_192_ctr());
  aes256ctr = RESOLVE_CIPHER(EVP_aes_256_ctr());
  aes128ecb = RESOLVE_CIPHER(EVP_aes_128_ecb());
  aes192ecb = RESOLVE_CIPHER(EVP_aes_192_ecb());
  aes256ecb = RESOLVE_CIPHER(EVP_aes_256_ecb());
}
#define INIT_CIPHERS() STMT_BEGIN { \
    if (PREDICT_UNLIKELY(NULL == aes128ctr)) {  \
      init_ciphers();                           \
    }                                           \
  } STMT_END

/* We have 2 strategies for getting the AES block cipher: Via OpenSSL's
 * AES_encrypt function, or via OpenSSL's EVP_EncryptUpdate function.
 *
 * If there's any hardware acceleration in play, we want to be using EVP_* so
 * we can get it.  Otherwise, we'll want AES_*, which seems to be about 5%
 * faster than indirecting through the EVP layer.
 */

/* We have 2 strategies for getting a plug-in counter mode: use our own, or
 * use OpenSSL's.
 *
 * Here we have a counter mode that's faster than the one shipping with
 * OpenSSL pre-1.0 (by about 10%!).  But OpenSSL 1.0.0 added a counter mode
 * implementation faster than the one here (by about 7%).  So we pick which
 * one to used based on the Openssl version above.  (OpenSSL 1.0.0a fixed a
 * critical bug in that counter mode implementation, so we need to test to
 * make sure that we have a fixed version.)
 */

#ifdef USE_EVP_AES_CTR

/* We don't actually define the struct here. */

aes_cnt_cipher_t *
aes_new_cipher(const uint8_t *key, const uint8_t *iv, int key_bits)
{
  INIT_CIPHERS();
  EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *c = NULL;
  switch (key_bits) {
    case 128: c = aes128ctr; break;
    case 192: c = aes192ctr; break;
    case 256: c = aes256ctr; break;
    default: tor_assert_unreached(); // LCOV_EXCL_LINE
  }
  EVP_EncryptInit(cipher, c, key, iv);
  return (aes_cnt_cipher_t *) cipher;
}
void
aes_cipher_free_(aes_cnt_cipher_t *cipher_)
{
  if (!cipher_)
    return;
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *) cipher_;
  EVP_CIPHER_CTX_reset(cipher);
  EVP_CIPHER_CTX_free(cipher);
}

/** Changes the key of the cipher;
 * sets the IV to 0.
 */
void
aes_cipher_set_key(aes_cnt_cipher_t *cipher_, const uint8_t *key, int key_bits)
{
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *) cipher_;
  uint8_t iv[16] = {0};
  const EVP_CIPHER *c = NULL;
  switch (key_bits) {
    case 128: c = aes128ctr; break;
    case 192: c = aes192ctr; break;
    case 256: c = aes256ctr; break;
    default: tor_assert_unreached(); // LCOV_EXCL_LINE
  }

  // No need to call EVP_CIPHER_CTX_Reset here; EncryptInit already
  // does it for us.
  EVP_EncryptInit(cipher, c, key, iv);
}
/** Change the IV of this stream cipher without changing the key.
 *
 * Requires that the cipher stream position is at an even multiple of 16 bytes.
 */
void
aes_cipher_set_iv_aligned(aes_cnt_cipher_t *cipher_, const uint8_t *iv)
{
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *) cipher_;
#ifdef LIBRESSL_VERSION_NUMBER
  EVP_CIPHER_CTX_set_iv(cipher, iv, 16);
#else
  // We would have to do this if the cipher's position were not aligned:
  // EVP_CIPHER_CTX_set_num(cipher, 0);

  memcpy(EVP_CIPHER_CTX_iv_noconst(cipher), iv, 16);
#endif
}
void
aes_crypt_inplace(aes_cnt_cipher_t *cipher_, char *data, size_t len)
{
  int outl;
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *) cipher_;

  tor_assert(len < INT_MAX);

  EVP_EncryptUpdate(cipher, (unsigned char*)data,
                    &outl, (unsigned char*)data, (int)len);
}
int
evaluate_evp_for_aes(int force_val)
{
  (void) force_val;
  log_info(LD_CRYPTO, "This version of OpenSSL has a known-good EVP "
           "counter-mode implementation. Using it.");
  return 0;
}
int
evaluate_ctr_for_aes(void)
{
  return 0;
}
#else /* !defined(USE_EVP_AES_CTR) */

/*======================================================================*/
/* Interface to AES code, and counter implementation */

/** Implements an AES counter-mode cipher. */
struct aes_cnt_cipher_t {
/** This next element (however it's defined) is the AES key. */
  union {
    EVP_CIPHER_CTX evp;
    AES_KEY aes;
  } key;

#if !defined(WORDS_BIGENDIAN)
#define USING_COUNTER_VARS
  /** These four values, together, implement a 128-bit counter, with
   * counter0 as the low-order word and counter3 as the high-order word. */
  uint32_t counter3;
  uint32_t counter2;
  uint32_t counter1;
  uint32_t counter0;
#endif /* !defined(WORDS_BIGENDIAN) */

  union {
    /** The counter, in big-endian order, as bytes. */
    uint8_t buf[16];
    /** The counter, in big-endian order, as big-endian words.  Note that
     * on big-endian platforms, this is redundant with counter3...0,
     * so we just use these values instead. */
    uint32_t buf32[4];
  } ctr_buf;

  /** The encrypted value of ctr_buf. */
  uint8_t buf[16];
  /** Our current stream position within buf. */
  unsigned int pos;

  /** True iff we're using the evp implementation of this cipher. */
  uint8_t using_evp;
};

/** True iff we should prefer the EVP implementation for AES, either because
 * we're testing it or because we have hardware acceleration configured */
static int should_use_EVP = 0;

/** Check whether we should use the EVP interface for AES. If <b>force_val</b>
 * is nonnegative, we use use EVP iff it is true.  Otherwise, we use EVP
 * if there is an engine enabled for aes-ecb. */
int
evaluate_evp_for_aes(int force_val)
{
  ENGINE *e;

  if (force_val >= 0) {
    should_use_EVP = force_val;
    return 0;
  }
#ifdef DISABLE_ENGINES
  should_use_EVP = 0;
#else
  e = ENGINE_get_cipher_engine(NID_aes_128_ecb);

  if (e) {
    log_info(LD_CRYPTO, "AES engine \"%s\" found; using EVP_* functions.",
               ENGINE_get_name(e));
    should_use_EVP = 1;
  } else {
    log_info(LD_CRYPTO, "No AES engine found; using AES_* functions.");
    should_use_EVP = 0;
  }
#endif /* defined(DISABLE_ENGINES) */

  return 0;
}

/** Test the OpenSSL counter mode implementation to see whether it has the
 * counter-mode bug from OpenSSL 1.0.0. If the implementation works, then
 * we will use it for future encryption/decryption operations.
 *
 * We can't just look at the OpenSSL version, since some distributions update
 * their OpenSSL packages without changing the version number.
 **/
int
evaluate_ctr_for_aes(void)
{
  /* Result of encrypting an all-zero block with an all-zero 128-bit AES key.
   * This should be the same as encrypting an all-zero block with an all-zero
   * 128-bit AES key in counter mode, starting at position 0 of the stream.
   */
  static const unsigned char encrypt_zero[] =
    "\x66\xe9\x4b\xd4\xef\x8a\x2c\x3b\x88\x4c\xfa\x59\xca\x34\x2b\x2e";
  unsigned char zero[16];
  unsigned char output[16];
  unsigned char ivec[16];
  unsigned char ivec_tmp[16];
  unsigned int pos, i;
  AES_KEY key;
  memset(zero, 0, sizeof(zero));
  memset(ivec, 0, sizeof(ivec));
  AES_set_encrypt_key(zero, 128, &key);

  pos = 0;
  /* Encrypting a block one byte at a time should make the error manifest
   * itself for known bogus openssl versions. */
  for (i=0; i<16; ++i)
    AES_ctr128_encrypt(&zero[i], &output[i], 1, &key, ivec, ivec_tmp, &pos);

  if (fast_memneq(output, encrypt_zero, 16)) {
    /* Counter mode is buggy */
    /* LCOV_EXCL_START */
    log_err(LD_CRYPTO, "This OpenSSL has a buggy version of counter mode; "
                  "quitting tor.");
    exit(1); // exit ok: openssl is broken.
    /* LCOV_EXCL_STOP */
  }
  return 0;
}

#if !defined(USING_COUNTER_VARS)
#define COUNTER(c, n) ((c)->ctr_buf.buf32[3-(n)])
#else
#define COUNTER(c, n) ((c)->counter ## n)
#endif

static void aes_set_key(aes_cnt_cipher_t *cipher, const uint8_t *key,
                        int key_bits);
static void aes_set_iv(aes_cnt_cipher_t *cipher, const uint8_t *iv);

/**
 * Return a newly allocated counter-mode AES128 cipher implementation,
 * using the 128-bit key <b>key</b> and the 128-bit IV <b>iv</b>.
 */
aes_cnt_cipher_t*
aes_new_cipher(const uint8_t *key, const uint8_t *iv, int bits)
{
  aes_cnt_cipher_t* result = tor_malloc_zero(sizeof(aes_cnt_cipher_t));

  aes_set_key(result, key, bits);
  aes_set_iv(result, iv);

  return result;
}

/** Set the key of <b>cipher</b> to <b>key</b>, which is
 * <b>key_bits</b> bits long (must be 128, 192, or 256).  Also resets
 * the counter to 0.
 */
static void
aes_set_key(aes_cnt_cipher_t *cipher, const uint8_t *key, int key_bits)
{
  if (should_use_EVP) {
    const EVP_CIPHER *c = 0;
    switch (key_bits) {
      case 128: c = aes128ecb; break;
      case 192: c = aes192ecb; break;
      case 256: c = aes256ecb; break;
      default: tor_assert(0); // LCOV_EXCL_LINE
    }
    EVP_EncryptInit(&cipher->key.evp, c, key, NULL);
    cipher->using_evp = 1;
  } else {
    AES_set_encrypt_key(key, key_bits,&cipher->key.aes);
    cipher->using_evp = 0;
  }

#ifdef USING_COUNTER_VARS
  cipher->counter0 = 0;
  cipher->counter1 = 0;
  cipher->counter2 = 0;
  cipher->counter3 = 0;
#endif /* defined(USING_COUNTER_VARS) */

  memset(cipher->ctr_buf.buf, 0, sizeof(cipher->ctr_buf.buf));

  cipher->pos = 0;

  memset(cipher->buf, 0, sizeof(cipher->buf));
}

/** Release storage held by <b>cipher</b>
 */
void
aes_cipher_free_(aes_cnt_cipher_t *cipher)
{
  if (!cipher)
    return;
  if (cipher->using_evp) {
    EVP_CIPHER_CTX_cleanup(&cipher->key.evp);
  }
  memwipe(cipher, 0, sizeof(aes_cnt_cipher_t));
  tor_free(cipher);
}

#if defined(USING_COUNTER_VARS)
#define UPDATE_CTR_BUF(c, n) STMT_BEGIN                 \
  (c)->ctr_buf.buf32[3-(n)] = htonl((c)->counter ## n); \
  STMT_END
#else
#define UPDATE_CTR_BUF(c, n)
#endif /* defined(USING_COUNTER_VARS) */

/** Encrypt <b>len</b> bytes from <b>input</b>, storing the results in place.
 * Uses the key in <b>cipher</b>, and advances the counter by <b>len</b> bytes
 * as it encrypts.
 */
void
aes_crypt_inplace(aes_cnt_cipher_t *cipher, char *data, size_t len)
{
  /* Note that the "128" below refers to the length of the counter,
   * not the length of the AES key. */
  if (cipher->using_evp) {
    /* In openssl 1.0.0, there's an if'd out EVP_aes_128_ctr in evp.h.  If
     * it weren't disabled, it might be better just to use that.
     */
    CRYPTO_ctr128_encrypt((const unsigned char *)data,
                          (unsigned char *)data,
                          len,
                          &cipher->key.evp,
                          cipher->ctr_buf.buf,
                          cipher->buf,
                          &cipher->pos,
                          evp_block128_fn);
  } else {
    AES_ctr128_encrypt((const unsigned char *)data,
                       (unsigned char *)data,
                       len,
                       &cipher->key.aes,
                       cipher->ctr_buf.buf,
                       cipher->buf,
                       &cipher->pos);
  }
}

#endif /* defined(USE_EVP_AES_CTR) */

/* ========
 * Functions for "raw" (ECB) AES.
 *
 * I'm choosing the name "raw" here because ECB is not a mode;
 * it's a disaster.  The only way to use this safely is
 * within a real construction.
 */

/**
 * Create a new instance of AES using a key of length 'key_bits'
 * for raw block encryption.
 *
 * This is even more low-level than counter-mode, and you should
 * only use it with extreme caution.
 */
aes_raw_t *
aes_raw_new(const uint8_t *key, int key_bits, bool encrypt)
{
  INIT_CIPHERS();
  EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
  tor_assert(cipher);
  const EVP_CIPHER *c = NULL;
  switch (key_bits) {
    case 128: c = aes128ecb; break;
    case 192: c = aes192ecb; break;
    case 256: c = aes256ecb; break;
    default: tor_assert_unreached();
  }

  // No need to call EVP_CIPHER_CTX_Reset here; EncryptInit already
  // does it for us.
  int r = EVP_CipherInit(cipher, c, key, NULL, encrypt);
  tor_assert(r == 1);
  EVP_CIPHER_CTX_set_padding(cipher, 0);
  return (aes_raw_t *)cipher;
}
/**
 * Replace the key on an existing aes_raw_t.
 *
 * This may be faster than freeing and reallocating.
 */
void
aes_raw_set_key(aes_raw_t **cipher_, const uint8_t *key,
                int key_bits, bool encrypt)
{
  const EVP_CIPHER *c = *(EVP_CIPHER**) cipher_;
  switch (key_bits) {
    case 128: c = aes128ecb; break;
    case 192: c = aes192ecb; break;
    case 256: c = aes256ecb; break;
    default: tor_assert_unreached();
  }
  aes_raw_t *cipherp = *cipher_;
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *)cipherp;
  int r = EVP_CipherInit(cipher, c, key, NULL, encrypt);
  tor_assert(r == 1);
  EVP_CIPHER_CTX_set_padding(cipher, 0);
}

/**
 * Release storage held by 'cipher'.
 */
void
aes_raw_free_(aes_raw_t *cipher_)
{
  if (!cipher_)
    return;
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *)cipher_;
#ifdef OPENSSL_1_1_API
  EVP_CIPHER_CTX_reset(cipher);
#else
  EVP_CIPHER_CTX_cleanup(cipher);
#endif
  EVP_CIPHER_CTX_free(cipher);
}
#define aes_raw_free(cipher) \
  FREE_AND_NULL(aes_raw_t, aes_raw_free_, (cipher))
/**
 * Encrypt a single 16-byte block with 'cipher',
 * which must have been initialized for encryption.
 */
void
aes_raw_encrypt(const aes_raw_t *cipher, uint8_t *block)
{
  int outl = 16;
  int r = EVP_EncryptUpdate((EVP_CIPHER_CTX *)cipher, block, &outl, block, 16);
  tor_assert(r == 1);
  tor_assert(outl == 16);
}
/**
 * Decrypt a single 16-byte block with 'cipher',
 * which must have been initialized for decryption.
 */
void
aes_raw_decrypt(const aes_raw_t *cipher, uint8_t *block)
{
  int outl = 16;
  int r = EVP_DecryptUpdate((EVP_CIPHER_CTX *)cipher, block, &outl, block, 16);
  tor_assert(r == 1);
  tor_assert(outl == 16);
}
