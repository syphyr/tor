/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay.h
 * \brief Header file for relay.c.
 **/

#ifndef TOR_RELAY_CRYPTO_H
#define TOR_RELAY_CRYPTO_H

int relay_crypto_init(relay_crypto_t *crypto,
                      const char *key_data, size_t key_data_len,
                      int reverse, int is_hs_v3);

int relay_decrypt_cell(circuit_t *circ, cell_t *cell,
                       cell_direction_t cell_direction,
                       crypt_path_t **layer_hint, char *recognized);
void relay_encrypt_cell_outbound(cell_t *cell, origin_circuit_t *or_circ,
                            crypt_path_t *layer_hint);
void relay_encrypt_cell_inbound(cell_t *cell, or_circuit_t *or_circ);

void relay_crypto_clear(relay_crypto_t *crypto);

void relay_crypto_assert_ok(const relay_crypto_t *crypto);

uint8_t *relay_crypto_get_sendme_digest(relay_crypto_t *crypto);

void tor1_save_sendme_digest(tor1_crypt_t *crypto,
                             bool is_foward_digest);

void tor1_crypt_client_originate(tor1_crypt_t *tor1,
                            cell_t *cell,
                            bool record_sendme_digest);
void tor1_crypt_relay_originate(tor1_crypt_t *tor1,
                           cell_t *cell,
                           bool record_sendme_digest);
void tor1_crypt_relay_backward(tor1_crypt_t *tor1, cell_t *cell);
bool tor1_crypt_relay_forward(tor1_crypt_t *tor1, cell_t *cell);
bool tor1_crypt_client_backward(tor1_crypt_t *tor1, cell_t *cell);
void tor1_crypt_client_forward(tor1_crypt_t *tor1, cell_t *cell);

void tor1_crypt_one_payload(crypto_cipher_t *cipher, uint8_t *in);
void tor1_set_digest_v0(crypto_digest_t *digest, cell_t *cell);

#endif /* !defined(TOR_RELAY_CRYPTO_H) */
