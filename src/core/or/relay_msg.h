/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_msg.h
 * \brief Header file for relay_msg.c.
 **/

#ifndef TOR_RELAY_MSG_H
#define TOR_RELAY_MSG_H

#include "core/or/or.h"

#include "core/or/relay_msg_st.h"

/* Relay message */
void relay_msg_free_(relay_msg_t *msg);
void relay_msg_clear(relay_msg_t *msg);
relay_msg_t *relay_msg_copy(const relay_msg_t *msg);
void relay_msg_set(const uint8_t relay_cell_proto, const uint8_t cmd,
                   const streamid_t streamd_id, const uint8_t *payload,
                   const uint16_t payload_len, relay_msg_t *msg);

int relay_msg_encode_cell(relay_cell_fmt_t format,
                          const relay_msg_t *msg,
                          cell_t *cell_out) ATTR_WUR;
relay_msg_t *relay_msg_decode_cell(
                          relay_cell_fmt_t format,
                          const cell_t *cell) ATTR_WUR;

#define relay_msg_free(msg) \
  FREE_AND_NULL(relay_msg_t, relay_msg_free_, (msg))

/* Getters */
relay_cell_fmt_t relay_msg_get_format(const circuit_t *circ,
                                      const crypt_path_t *cpath);

#ifdef RELAY_MSG_PRIVATE

#endif /* RELAY_MSG_PRIVATE */

#endif /* TOR_RELAY_MSG_H */
