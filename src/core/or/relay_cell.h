/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_cell.h
 * \brief Header file for relay_cell.c.
 **/

#ifndef TOR_RELAY_CELL_H
#define TOR_RELAY_CELL_H

#include "core/or/or.h"

#include "core/or/cell_st.h"

/* TODO #41051: Most of these functions no longer make sense under CGO,
 * and we are only going to use the new proto format with CGO. */

/* Getters. */
bool relay_cell_is_recognized(const cell_t *cell);
uint8_t *relay_cell_get_digest(cell_t *cell);
size_t relay_cell_get_digest_len(const cell_t *cell);

/* Setters. */
void relay_cell_set_digest(cell_t *cell, uint8_t *cell_digest);
void relay_cell_pad_payload(cell_t *cell, size_t data_len);

/*
 * NOTE: The following are inlined for performance reasons. These values are
 * accessed everywhere and so, even if not expensive, we avoid a function call.
 */

/** Return true iff 'cmd' uses a stream ID when using
 * the v1 relay message format. */
static bool
relay_cmd_expects_streamid_in_v1(uint8_t relay_command)
{
  switch (relay_command) {
    case RELAY_COMMAND_BEGIN:
    case RELAY_COMMAND_BEGIN_DIR:
    case RELAY_COMMAND_CONNECTED:
    case RELAY_COMMAND_DATA:
    case RELAY_COMMAND_END:
    case RELAY_COMMAND_RESOLVE:
    case RELAY_COMMAND_RESOLVED:
    case RELAY_COMMAND_XOFF:
    case RELAY_COMMAND_XON:
      return true;
    default:
      return false;
  }
}

/** Return the size of the relay cell payload for the given relay
 * cell format. */
static inline size_t
relay_cell_max_payload_size(relay_cell_fmt_t format,
                            uint8_t relay_command)
{
  switch (format) {
    case RELAY_CELL_FORMAT_V0:
      return CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V0;
    case RELAY_CELL_FORMAT_V1: {
      if (relay_cmd_expects_streamid_in_v1(relay_command)) {
        return CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V1_WITH_STREAM_ID;
      } else {
        return CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V1_NO_STREAM_ID;
      }
    }
    default:
      tor_fragile_assert();
      return 0;
  }
}

#ifdef RELAY_CELL_PRIVATE

#endif /* RELAY_CELL_PRIVATE */

#endif /* TOR_RELAY_CELL_H */
