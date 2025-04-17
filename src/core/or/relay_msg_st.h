/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_msg_st.h
 * @brief A relay message which contains a relay command and parameters,
 *        if any, that is from a relay cell.
 **/

#ifndef TOR_RELAY_MSG_ST_H
#define TOR_RELAY_MSG_ST_H

#include "core/or/or.h"

/** A relay message object which contains pointers to the header and payload.
 *
 * One acquires a relay message through the use of an iterator. Once you get a
 * reference, the getters MUST be used to access data.
 *
 * This CAN NOT be made opaque so to avoid heap allocation in the fast path. */
typedef struct relay_msg_t {
  /* Relay cell protocol version of this message. */
  relay_cell_fmt_t relay_cell_proto;
  /* Relay command of a message. */
  uint8_t command;
  /* Length of the message body. */
  uint16_t length;
  /* Optional routing header: stream ID of a message or 0. */
  streamid_t stream_id;
  /* Indicate if this is a message from a relay early cell. */
  bool is_relay_early;
  /* Message body of a relay message. */
  // TODO #41051: This is an owned copy of the body.
  // It might be better to turn this into a non-owned pointer into
  // the cell body, if we can, to save a copy.
  uint8_t *body;
} relay_msg_t;

#endif /* !defined(TOR_RELAY_MSG_ST_H) */
