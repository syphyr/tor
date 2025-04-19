/* Copyright (c) 2025, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file polyval.h
 * \brief Implementation for polyval universal hash function.
 *
 * Polyval, which was first defined for AES-GCM-SIV, is a
 * universal hash based on multiplication in GF(2^128).
 * Unlike the more familiar GHASH, it is defined to work on
 * little-endian inputs, and so is more straightforward and efficient
 * on little-endian architectures.
 *
 * In Tor we use it as part of the Counter Galois Onion relay
 * encryption format.
 **/

/* Implementation notes:
 *
 * Our implementation is based on the GHASH code from BearSSL
 * by Thomas Pornin.  There are three implementations:
 *
 * pclmul.c -- An x86-only version, based on the CLMUL instructions
 * introduced for westlake processors in 2010.
 *
 * ctmul64.c -- A portable contant-time implementation for 64-bit
 * processors.
 *
 * ctmul.c -- A portable constant-time implementation for 32-bit
 * processors with an efficient 32x32->64 multiply instruction.
 *
 * Note that the "ctmul" implementations are only constant-time
 * if the corresponding CPU multiply and rotate instructions are
 * also constant-time.  But that's an architectural assumption we
 * make in Tor.
 */

#include "ext/polyval/polyval.h"

#include <string.h>

typedef pv_u128_ u128;

/* ========
 * We declare these functions, to help implement polyval.
 *
 * They have different definitions depending on our representation
 * of 128-bit integers.
 */
/**
 * Read a u128-bit little-endian integer from 'bytes',
 * which may not be aligned.
 */
static inline u128 u128_from_bytes(const uint8_t *bytes);
/**
 * Store a u128-bit little-endian integer to 'bytes_out',
 * which may not be aligned.
 */
static inline void u128_to_bytes(u128, uint8_t *bytes_out);
/**
 * XOR a u128 into the y field of a polyval_t struct.
 *
 * (Within the polyval struct, perform "y ^= v").
 */
static inline void pv_xor_y(polyval_t *, u128 v);
/**
 * Initialize any derived fields in pv.
 */
static inline void pv_init_extra(polyval_t *pv);

/* ========
 * The function which we expect our backend to implement.
 */
/**
 * Within the polyval struct, perform "y *= h".
 *
 * (This is a carryless multiply in the Polyval galois field)
 */
static void pv_mul_y_h(polyval_t *);

/* =====
 * Endianness conversion for big-endian platforms
 */
#ifdef WORDS_BIG_ENDIAN
#ifdef __GNUC__
#define bswap64(x) __builtin_bswap64(x)
#define bswap32(x) __builtin_bswap32(x)
#else
/* The (compiler should optimize these into a decent bswap instruction) */
static inline uint64_t
bswap64(uint64_t v)
{
  return
    ((value & 0xFF00000000000000) >> 56) |
    ((value & 0x00FF000000000000) >> 48) |
    ((value & 0x0000FF0000000000) >> 40) |
    ((value & 0x000000FF00000000) >> 32) |
    ((value & 0x00000000FF000000) >> 24) |
    ((value & 0x0000000000FF0000) >> 16) |
    ((value & 0x000000000000FF00) >> 8) |
    ((value & 0x00000000000000FF));
}
static inline uint64_t
bswap32(uint64_t v)
{
  return
    ((value & 0xFF000000) >> 24) |
    ((value & 0x00FF0000) >> 16) |
    ((value & 0x0000FF00) >> 8) |
    ((value & 0x000000FF));
}
#endif
#endif

#ifdef WORDS_BIG_ENDIAN
#define convert_byte_order64(x) bswap64(x)
#define convert_byte_order32(x) bswap32(x)
#else
#define convert_byte_order64(x) (x)
#define convert_byte_order32(x) (x)
#endif

#ifdef PV_USE_PCLMUL

#include "ext/polyval/pclmul.c"

static inline u128
u128_from_bytes(const uint8_t *bytes)
{
  return _mm_loadu_si128((const u128*)bytes);
}
static inline void
u128_to_bytes(u128 val, uint8_t *bytes_out)
{
  _mm_storeu_si128((u128*)bytes_out, val);
}
static inline void
pv_xor_y(polyval_t *pv, u128 v)
{
  pv->y = _mm_xor_si128(pv->y, v);
}
static inline void
pv_init_extra(polyval_t *pv)
{
  (void)pv;
}
#elif defined(PV_USE_CTMUL64)

#include "ext/polyval/ctmul64.c"

static inline u128
u128_from_bytes(const uint8_t *bytes)
{
  u128 r;
  memcpy(&r.lo, bytes, 8);
  memcpy(&r.hi, bytes + 8, 8);
  r.lo = convert_byte_order64(r.lo);
  r.hi = convert_byte_order64(r.hi);
  return r;
}
static inline void
u128_to_bytes(u128 val, uint8_t *bytes_out)
{
  uint64_t lo = convert_byte_order64(val.lo);
  uint64_t hi = convert_byte_order64(val.hi);
  memcpy(bytes_out, &lo, 8);
  memcpy(bytes_out + 8, &hi, 8);
}
static inline void
pv_xor_y(polyval_t *pv, u128 val)
{
  pv->y.lo ^= val.lo;
  pv->y.hi ^= val.hi;
}
static inline void
pv_init_extra(polyval_t *pv)
{
  pv->hr.lo = rev64(pv->h.lo);
  pv->hr.hi = rev64(pv->h.hi);
}
#elif defined(PV_USE_CTMUL)
#include "ext/polyval/ctmul.c"

static inline u128
u128_from_bytes(const uint8_t *bytes)
{
  u128 r;
  memcpy(&r.v, bytes, 16);
  for (int i = 0; i < 4; ++i) {
    r.v[i] = convert_byte_order32(r.v[i]);
  }
  return r;
}
static inline void
u128_to_bytes(u128 val, uint8_t *bytes_out)
{
  uint32_t v[4];
  for (int i = 0; i < 4; ++i) {
    v[i] = convert_byte_order32(val.v[i]);
  }
  memcpy(bytes_out, v, 16);
}
static inline void
pv_xor_y(polyval_t *pv, u128 val)
{
  for (int i = 0; i < 4; ++i) {
    pv->y.v[i] ^= val.v[i];
  }
}
static inline void
pv_init_extra(polyval_t *pv)
{
  (void)pv;
}
#endif

void
polyval_init(polyval_t *pv, const uint8_t *key)
{
  pv->h = u128_from_bytes(key);
  memset(&pv->y, 0, sizeof(u128));
  pv_init_extra(pv);
}
void
polyval_add_block(polyval_t *pv, const uint8_t *block)
{
  u128 b = u128_from_bytes(block);
  pv_xor_y(pv, b);
  pv_mul_y_h(pv);
}
void
polyval_add_zpad(polyval_t *pv, const uint8_t *data, size_t n)
{
  while (n > 16) {
    polyval_add_block(pv, data);
    data += 16;
    n -= 16;
  }
  if (n) {
    uint8_t block[16];
    memset(&block, 0, sizeof(block));
    memcpy(block, data, n);
    polyval_add_block(pv, block);
  }
}
void
polyval_get_tag(const polyval_t *pv, uint8_t *tag_out)
{
  u128_to_bytes(pv->y, tag_out);
}
void
polyval_reset(polyval_t *pv)
{
  memset(&pv->y, 0, sizeof(u128));
}

#if 0
#include <stdio.h>
int
main(int c, char **v)
{
  // From RFC 8452 appendix A
  uint8_t key[16] =
    { 0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76,
      0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b  };
  uint8_t block1[16] =
    { 0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6,
      0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01, 0xa2, 0x62 };
  uint8_t block2[16] = {
    0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06,
    0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9, 0xf3, 0x62 };
  uint8_t expect_result[16] = {
    0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa,
    0xe5, 0xb7, 0x86, 0x6c, 0xf5, 0xe5, 0xb7, 0x7e };

  polyval_t pv;
  uint8_t tag[16];
  polyval_init(&pv, key);
  polyval_add_block(&pv, block1);
  polyval_add_block(&pv, block2);
  polyval_get_tag(&pv, tag);
  if (!memcmp(expect_result, tag, 16)) {
    puts("OK");
    return 0;
  }  else {
    puts("NOPE");
    return 1;
  }
}
#endif
