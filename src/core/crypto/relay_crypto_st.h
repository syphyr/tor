/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_crypto_st.h
 * @brief Relay-cell encryption state structure.
 **/

#ifndef RELAY_CRYPTO_ST_H
#define RELAY_CRYPTO_ST_H

#include "core/crypto/tor1_crypt_st.h"
#include "core/crypto/relay_crypto_cgo.h"

typedef enum relay_crypto_kind_t {
  RCK_TOR1,
} relay_crypto_kind_t;

struct relay_crypto_t {
  relay_crypto_kind_t kind;
  union {
    struct tor1_crypt_t tor1;
  } c;
};

#endif /* !defined(RELAY_CRYPTO_ST_H) */
