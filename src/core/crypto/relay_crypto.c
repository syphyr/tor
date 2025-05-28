/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_crypto.h
 * @brief Header for relay_crypto.c
 **/

#include "core/or/or.h"
#include "core/or/circuitlist.h"
#include "core/or/crypt_path.h"
#include "app/config/config.h"
#include "lib/crypt_ops/crypto_cipher.h"
#include "lib/crypt_ops/crypto_util.h"
#include "core/crypto/relay_crypto.h"
#include "core/crypto/relay_crypto_tor1.h"
#include "core/or/sendme.h"

#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"

/* TODO CGO: This file will be largely incorrect when we have
 * CGO crypto. */

// XXXX: Remove this definition once I'm done refactoring.
#define pvt_crypto crypto_crypt_path_private_field

/** Return the sendme tag within the <b>crypto</b> object,
 * along with its length.
 *
 * This is the digest from the most recent cell that we originated
 * or recognized, _in either direction_.
 * Calls to any encryption function on `crypto` may invalidate
 * this digest.
 */
const uint8_t *
relay_crypto_get_sendme_tag(relay_crypto_t *crypto,
                            size_t *len_out)
{
  tor_assert(crypto);
  *len_out = DIGEST_LEN;
  return crypto->tor1.sendme_digest;
}

/** Do the appropriate en/decryptions for <b>cell</b> arriving on
 * <b>circ</b> in direction <b>cell_direction</b>.
 *
 * If cell_direction == CELL_DIRECTION_IN:
 *   - If we're at the origin (we're the OP), for hops 1..N,
 *     decrypt cell. If recognized, stop.
 *   - Else (we're not the OP), encrypt one hop. Cell is not recognized.
 *
 * If cell_direction == CELL_DIRECTION_OUT:
 *   - decrypt one hop. Check if recognized.
 *
 * If cell is recognized, set *recognized to 1, and set
 * *layer_hint to the hop that recognized it.
 *
 * Return -1 to indicate that we should mark the circuit for close,
 * else return 0.
 */
int
relay_decrypt_cell(circuit_t *circ, cell_t *cell,
                   cell_direction_t cell_direction,
                   crypt_path_t **layer_hint, char *recognized)
{
  tor_assert(circ);
  tor_assert(cell);
  tor_assert(recognized);
  tor_assert(cell_direction == CELL_DIRECTION_IN ||
             cell_direction == CELL_DIRECTION_OUT);

  if (cell_direction == CELL_DIRECTION_IN) {
    if (CIRCUIT_IS_ORIGIN(circ)) { /* We're at the beginning of the circuit.
                                    * We'll want to do layered decrypts. */
      crypt_path_t *thishop, *cpath = TO_ORIGIN_CIRCUIT(circ)->cpath;
      thishop = cpath;
      if (thishop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Relay cell before first created cell? Closing.");
        return -1;
      }
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        tor_assert(thishop);

        bool rec = tor1_crypt_client_backward(
                                       &thishop->pvt_crypto.tor1, cell);
        if (rec) {
          *recognized = 1;
          *layer_hint = thishop;
          return 0;
        }
        thishop = thishop->next;
      } while (thishop != cpath && thishop->state == CPATH_STATE_OPEN);
      log_fn(LOG_PROTOCOL_WARN, LD_OR,
             "Incoming cell at client not recognized. Closing.");
      return -1;
    } else {
      /* We're in the middle. Encrypt one layer. */
      relay_crypto_t *crypto = &TO_OR_CIRCUIT(circ)->crypto;
      tor1_crypt_relay_backward(&crypto->tor1, cell);
    }
  } else /* cell_direction == CELL_DIRECTION_OUT */ {
    /* We're in the middle. Decrypt one layer. */
    relay_crypto_t *crypto = &TO_OR_CIRCUIT(circ)->crypto;

    bool rec = tor1_crypt_relay_forward(&crypto->tor1, cell);
    if (rec) {
      *recognized = 1;
      return 0;
    }
  }
  return 0;
}

/**
 * Encrypt a cell <b>cell</b> that we are creating, and sending outbound on
 * <b>circ</b> until the hop corresponding to <b>layer_hint</b>.
 *
 * The integrity field and recognized field of <b>cell</b>'s relay headers
 * must be set to zero.
 */
void
relay_encrypt_cell_outbound(cell_t *cell,
                            origin_circuit_t *circ,
                            crypt_path_t *layer_hint)
{
  crypt_path_t *thishop = layer_hint;

  tor1_crypt_client_originate(&thishop->pvt_crypto.tor1, cell);
  thishop = thishop->prev;

  while (thishop != circ->cpath->prev) {
    tor1_crypt_client_forward(&thishop->pvt_crypto.tor1, cell);
    thishop = thishop->prev;
  }
}

/**
 * Encrypt a cell <b>cell</b> that we are creating, and sending on
 * <b>circuit</b> to the origin.
 *
 * The integrity field and recognized field of <b>cell</b>'s relay headers
 * must be set to zero.
 */
void
relay_encrypt_cell_inbound(cell_t *cell,
                           or_circuit_t *or_circ)
{
  tor1_crypt_relay_originate(&or_circ->crypto.tor1, cell);
}

/**
 * Release all storage held inside <b>crypto</b>, but do not free
 * <b>crypto</b> itself: it lives inside another object.
 */
void
relay_crypto_clear(relay_crypto_t *crypto)
{
  tor1_crypt_clear(&crypto->tor1);
}

/** Initialize <b>crypto</b> from the key material in key_data.
 *
 * If <b>is_hs_v3</b> is set, this cpath will be used for next gen hidden
 * service circuits and <b>key_data</b> must be at least
 * HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN bytes in length.
 *
 * If <b>is_hs_v3</b> is not set, key_data must contain CPATH_KEY_MATERIAL_LEN
 * bytes, which are used as follows:
 *   - 20 to initialize f_digest
 *   - 20 to initialize b_digest
 *   - 16 to key f_crypto
 *   - 16 to key b_crypto
 *
 * (If 'reverse' is true, then f_XX and b_XX are swapped.)
 *
 * Return 0 if init was successful, else -1 if it failed.
 */
int
relay_crypto_init(relay_crypto_alg_t alg,
                  relay_crypto_t *crypto,
                  const char *key_data, size_t key_data_len)
{
  switch (alg) {
    /* Tor1 cases: the booleans are "reverse" and "is_hs_v3". */
    case RELAY_CRYPTO_ALG_TOR1:
      return tor1_crypt_init(&crypto->tor1, key_data, key_data_len,
                             false, false);
    case RELAY_CRYPTO_ALG_TOR1_HSC:
      return tor1_crypt_init(&crypto->tor1, key_data, key_data_len,
                             false, true);
    case RELAY_CRYPTO_ALG_TOR1_HSS:
      return tor1_crypt_init(&crypto->tor1, key_data, key_data_len,
                             true, true);
  }
  tor_assert_unreached();
}

/** Return the amount of key material we need to initialize
 * the given relay crypto algorithm.
 *
 * Return -1 if the algorithm is unrecognized.
 */
ssize_t
relay_crypto_key_material_len(relay_crypto_alg_t alg)
{
  switch (alg) {
    case RELAY_CRYPTO_ALG_TOR1:
      return tor1_key_material_len(false);
    case RELAY_CRYPTO_ALG_TOR1_HSC:
    case RELAY_CRYPTO_ALG_TOR1_HSS:
      return tor1_key_material_len(true);
  }
  return -1;
}

/** Assert that <b>crypto</b> is valid and set. */
void
relay_crypto_assert_ok(const relay_crypto_t *crypto)
{
  tor1_crypt_assert_ok(&crypto->tor1);
}
