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

struct relay_crypto_t {
  struct tor1_crypt_t tor1;
};

#endif /* !defined(RELAY_CRYPTO_ST_H) */
