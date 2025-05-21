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

/* Decide which implementation to use. */
#if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) \
  || defined(_M_X64) || defined(_M_IX86) || defined(__i486)       \
  || defined(__i386__)
/* Use intel intrinsics for carryless multiply.
 *
 * TODO: In theory we should detect whether we have the relevant instructions,
 * but they are all at least 15 years old.
 */
#define PV_USE_PCLMUL
#elif SIZEOF_VOID_P >= 8
/* It's a 64-bit architecture; use the generic 64-bit constant-time
 * implementation.
 */
#define PV_USE_CTMUL64
#elif SIZEOF_VOID_P == 4
/* It's a 64-bit architecture; use the generic 32-bit constant-time
 * implementation.
 */
#define PV_USE_CTMUL
#else
#error "sizeof(void*) is implausibly weird."
#endif

/**
 * Declare a 128 bit integer type.
 # The exact representation will depend on which implementation we've chosen.
 */
#ifdef PV_USE_PCLMUL
#include <emmintrin.h>
typedef __m128i pv_u128_;
#elif defined(PV_USE_CTMUL64)
typedef struct pv_u128_ {
  uint64_t lo;
  uint64_t hi;
} pv_u128_;
#elif defined(PV_USE_CTMUL)
typedef struct pv_u128_ {
  uint32_t v[4];
} pv_u128_;
#endif

/** A key for a polyval hash, plus any precomputed key material. */
typedef struct polyval_key_t {
  pv_u128_ h;
} polyval_key_t;

/**
 * State for an instance of the polyval hash.
 **/
typedef struct polyval_t {
  /** The key used for this instance of polyval. */
  polyval_key_t key;
  /** The accumulator */
  pv_u128_ y;
} polyval_t;

/**
 * Length of a polyval key, in bytes.
 */
#define POLYVAL_KEY_LEN 16
/**
 * Length of a polyval block, in bytes.
 */
#define POLYVAL_BLOCK_LEN 16
/**
 * Length of a polyval tag (output), in bytes.
 */
#define POLYVAL_TAG_LEN 16

/** Do any necessary precomputation from a polyval key,
 * and store it.
 */
void polyval_key_init(polyval_key_t *, const uint8_t *key);
/**
 * Initialize a polyval instance with a given key.
 */
void polyval_init(polyval_t *, const uint8_t *key);
/**
 * Initialize a polyval instance with a preconstructed key.
 */
void polyval_init_from_key(polyval_t *, const polyval_key_t *key);
/**
 * Update a polyval instance with a new 16-byte block.
 */
void polyval_add_block(polyval_t *, const uint8_t *block);
/**
 * Update a polyval instance with 'n' bytes from 'data'.
 * If 'n' is not evenly divisible by 16, pad it at the end with zeros.
 *
 * NOTE: This is not a general-purpose padding construction;
 * it can be insecure if your are using it in context where the input length
 * is variable.
 */
void polyval_add_zpad(polyval_t *, const uint8_t *data, size_t n);
/**
 * Copy the 16-byte tag from a polyval instance into 'tag_out'
 */
void polyval_get_tag(const polyval_t *, uint8_t *tag_out);
/**
 * Reset a polyval instance to its original state,
 * retaining its key.
 */
void polyval_reset(polyval_t *);

#endif
