/* Copyright (c) 2025, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file polyval.h
 * \brief APIs for polyval universal hash function.
 **/

#ifndef TOR_POLYVAL_H
#define TOR_POLYVAL_H

#include "orconfig.h"
#include "lib/cc/torint.h"

#define PV_USE_CTMUL64

#ifdef PV_USE_CTMUL64
/** A 128-bit integer represented as its low and high portion. */
struct pv_u128_ {
  uint64_t lo;
  uint64_t hi;
};
#endif

/**
 * State for an instance of the polyval hash.
 **/
typedef struct polyval_t {
  /** The key itself. */
  struct pv_u128_ h;
  /** The elements of the key in bit-reversed form.
   * (Used as an optimization.) */
  struct pv_u128_ hr;
  /** The accumulator */
  struct pv_u128_ y;
} polyval_t;

#define POLYVAL_KEY_LEN 16
#define POLYVAL_BLOCK_LEN 16
#define POLYVAL_TAG_LEN 16

void polyval_init(polyval_t *, const uint8_t *key);
void polyval_add_block(polyval_t *, const uint8_t *block);
void polyval_add_zpad(polyval_t *, const uint8_t *data, size_t n);
void polyval_get_tag(const polyval_t *, uint8_t *tag_out);
/**
 * Reset a polyval instance to its original state,
 * retaining its key.
 */
void polyval_reset(polyval_t *);


#endif
