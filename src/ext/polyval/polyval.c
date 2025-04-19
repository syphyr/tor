/* Copyright (c) 2025, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file polyval.h
 * \brief Implementation for polyval universal hash function.
 *
 * XXXX write more.
 **/

#include "ext/polyval/polyval.h"

#include <string.h>

typedef struct pv_u128_ u128;

static inline u128 u128_from_bytes(const uint8_t *bytes);
static inline void u128_to_bytes(u128 u128, uint8_t *bytes_out);
static inline void pv_xor(polyval_t *, u128);
static inline void pv_init_extra(polyval_t *pv);

/* Functions which we expect our multiply implementation to declare. */
static inline void pv_mul_y_h(polyval_t *);

#ifdef WORDS_BIG_ENDIAN
#ifdef __GNUC__
#define bswap64(x) __builtin_bswap64(x)
#else
static inline uint64_t bswap64(uint64_t v)
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
#endif
#endif

#ifdef WORDS_BIG_ENDIAN
#define convert_byte_order(x) bswap64(x)
#else
#define convert_byte_order(x) (x)
#endif

#ifdef PV_USE_CTMUL64
static inline u128
u128_from_bytes(const uint8_t *bytes)
{
  u128 r;
  memcpy(&r.lo, bytes, 8);
  memcpy(&r.hi, bytes + 8, 8);
  r.lo = convert_byte_order(r.lo);
  r.hi = convert_byte_order(r.hi);
  return r;
}
static inline void
u128_to_bytes(u128 val, uint8_t *bytes_out)
{
  uint64_t lo = convert_byte_order(val.lo);
  uint64_t hi = convert_byte_order(val.hi);
  memcpy(bytes_out, &lo, 8);
  memcpy(bytes_out + 8, &hi, 8);
}
static inline void
pv_xor(polyval_t *pv, u128 val)
{
  pv->y.lo ^= val.lo;
  pv->y.hi ^= val.hi;
}
static inline void
pv_init_extra(polyval_t *pv)
{

}
static inline void pv_mul_y_h(polyval_t *pv)
{

}

// #include "ext/polyval/ctmul64.c"
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
  pv_xor(pv, b);
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
