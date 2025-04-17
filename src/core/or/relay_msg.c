/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_msg.c
 * \brief XXX: Write a brief introduction to this module.
 **/

#define RELAY_MSG_PRIVATE

#include "app/config/config.h"

#include "core/or/cell_st.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "core/or/relay_msg.h"
#include "lib/crypt_ops/crypto_rand.h"

#include "core/or/cell_st.h"
#include "core/or/relay_msg_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/or_circuit_st.h"

/*
 * Public API
 */

/** Free the given relay message. */
void
relay_msg_free_(relay_msg_t *msg)
{
  if (!msg) {
    return;
  }
  tor_free(msg->body);
  tor_free(msg);
}

/** Clear a relay message as in free its content and reset all fields to 0.
 * This is useful for stack allocated memory. */
void
relay_msg_clear(relay_msg_t *msg)
{
  tor_assert(msg);
  tor_free(msg->body);
  memset(msg, 0, sizeof(*msg));
}

/* Positions of fields within a v0 message. */
#define V0_CMD_OFFSET 0
#define V0_STREAM_ID_OFFSET 3
#define V0_LEN_OFFSET 9
#define V0_PAYLOAD_OFFSET 11

/* Positions of fields within a v1 message. */
#define V1_CMD_OFFSET 16
#define V1_LEN_OFFSET 17
#define V1_STREAM_ID_OFFSET 19
#define V1_PAYLOAD_OFFSET_NO_STREAM_ID 19
#define V1_PAYLOAD_OFFSET_WITH_STREAM_ID 21

/** Allocate a new relay message and copy the content of the given message. */
relay_msg_t *
relay_msg_copy(const relay_msg_t *msg)
{
  relay_msg_t *new = tor_malloc_zero(sizeof(*msg));

  memcpy(new, msg, sizeof(*msg));
  new->body = tor_memdup_nulterm(msg->body, msg->length);
  memcpy(new->body, msg->body, new->length);

  return new;
}

/** Set a relay message data into the given message. Useful for stack allocated
 * messages. */
void
relay_msg_set(const uint8_t relay_cell_proto, const uint8_t cmd,
              const streamid_t stream_id, const uint8_t *payload,
              const uint16_t payload_len, relay_msg_t *msg)
{
  // TODO #41051: Should this free msg->body?
  msg->relay_cell_proto = relay_cell_proto;
  msg->command = cmd;
  msg->stream_id = stream_id;

  msg->length = payload_len;
  msg->body = tor_malloc_zero(msg->length);
  memcpy(msg->body, payload, msg->length);
}

/* Add random bytes to the unused portion of the payload, to foil attacks
 * where the other side can predict all of the bytes in the payload and thus
 * compute the authenticated SENDME cells without seeing the traffic. See
 * proposal 289. */
static void
relay_cell_pad(cell_t *cell, size_t end_of_message)
{
  // We add 4 bytes of zero before padding, for forward-compatibility.
  const size_t skip = 4;

  if (end_of_message + skip >= CELL_PAYLOAD_SIZE) {
    /* nothing to do. */
    return;
  }

  crypto_fast_rng_getbytes(get_thread_fast_rng(),
                           &cell->payload[end_of_message + skip],
                           CELL_PAYLOAD_SIZE - (end_of_message + skip));
}

/** Encode the relay message in 'msg' into cell, according to the
 * v0 rules. */
static int
encode_v0_cell(const relay_msg_t *msg,
               cell_t *cell_out)
{
  IF_BUG_ONCE(msg->length > CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V0) {
    return -1;
  }

  uint8_t *out = cell_out->payload;

  out[V0_CMD_OFFSET] = (uint8_t) msg->command;
  set_uint16(out+V0_STREAM_ID_OFFSET, htons(msg->stream_id));
  set_uint16(out+V0_LEN_OFFSET, htons(msg->length));
  memcpy(out + RELAY_HEADER_SIZE_V0, msg->body, msg->length);
  relay_cell_pad(cell_out, RELAY_HEADER_SIZE_V0 + msg->length);

  return 0;
}

/** Encode the relay message in 'msg' into cell, according to the
 * v0 rules. */
static int
encode_v1_cell(const relay_msg_t *msg,
               cell_t *cell_out)
{
  bool expects_streamid = relay_cmd_expects_streamid_in_v1(msg->command);
  size_t maxlen;
  if (expects_streamid) {
    maxlen = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V1_WITH_STREAM_ID;
  } else {
    maxlen = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V1_NO_STREAM_ID;
  }

  IF_BUG_ONCE(msg->length > maxlen) {
    return -1;
  }
  uint8_t *out = cell_out->payload;
  out[V1_CMD_OFFSET] = msg->command;
  set_uint16(out+V1_LEN_OFFSET, htons(msg->length));
  size_t payload_offset;
  if (expects_streamid) {
    IF_BUG_ONCE(msg->stream_id == 0) {
      return -1;
    }
    set_uint16(out+V1_STREAM_ID_OFFSET, htons(msg->stream_id));
    payload_offset = V1_PAYLOAD_OFFSET_WITH_STREAM_ID;
  } else {
    IF_BUG_ONCE(msg->stream_id != 0) {
      return -1;
    }

    payload_offset = V1_PAYLOAD_OFFSET_NO_STREAM_ID;
  }

  memcpy(out + payload_offset, msg->body, msg->length);
  relay_cell_pad(cell_out, payload_offset + msg->length);
  return 0;
}

/** Try to decode 'cell' into a newly allocated V0 relay message.
 *
 * Return NULL on error.
 */
static relay_msg_t *
decode_v0_cell(const cell_t *cell)
{
  relay_msg_t *out = tor_malloc_zero(sizeof(relay_msg_t));
  out->is_relay_early = (cell->command == CELL_RELAY_EARLY);

  const uint8_t *body = cell->payload;
  out->command = get_uint8(body + V0_CMD_OFFSET);
  out->stream_id = ntohs(get_uint16(body + V0_STREAM_ID_OFFSET));
  out->length = ntohs(get_uint16(body + V0_LEN_OFFSET));

  if (out->length > CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V0) {
    goto err;
  }
  out->body = tor_memdup_nulterm(body + V0_PAYLOAD_OFFSET, out->length);

  return out;
 err:
  relay_msg_free(out);
  return NULL;
}

/** Try to decode 'cell' into a newly allocated V0 relay message.
 *
 * Return NULL on error.
 */
static relay_msg_t *
decode_v1_cell(const cell_t *cell)
{
  relay_msg_t *out = tor_malloc_zero(sizeof(relay_msg_t));
  out->is_relay_early = (cell->command == CELL_RELAY_EARLY);

  const uint8_t *body = cell->payload;
  out->command = get_uint8(body + V1_CMD_OFFSET);
  if (! is_known_relay_command(out->command))
    goto err;
  out->length = ntohs(get_uint16(body + V1_LEN_OFFSET));
  size_t payload_offset;
  if (relay_cmd_expects_streamid_in_v1(out->command)) {
    out->stream_id = ntohs(get_uint16(body + V1_STREAM_ID_OFFSET));
    payload_offset = V1_PAYLOAD_OFFSET_WITH_STREAM_ID;
  } else {
    payload_offset = V1_PAYLOAD_OFFSET_NO_STREAM_ID;
  }

  if (out->length > CELL_PAYLOAD_SIZE - payload_offset)
    goto err;
  out->body = tor_memdup_nulterm(body + payload_offset, out->length);

  return out;
 err:
  relay_msg_free(out);
  return NULL;
}
/**
 * Encode 'msg' into 'cell' according to the rules of 'format'.
 *
 * Does not set any "recognized", "digest" or "tag" fields,
 * since those are necessarily part of the crypto logic.
 *
 * Clears the circuit ID on the cell.
 *
 * Return 0 on success, and -1 if 'msg' is not well-formed.
 */
int
relay_msg_encode_cell(relay_cell_fmt_t format,
                      const relay_msg_t *msg,
                      cell_t *cell_out)
{
  memset(cell_out, 0, sizeof(cell_t));
  cell_out->relay_cell_proto = format;
  cell_out->command = msg->is_relay_early ?
    CELL_RELAY_EARLY : CELL_RELAY;

  switch (format) {
    case RELAY_CELL_FORMAT_V0:
      return encode_v0_cell(msg, cell_out);
    case RELAY_CELL_FORMAT_V1:
      return encode_v1_cell(msg, cell_out);
    default:
      tor_fragile_assert();
      return -1;
  }
}

/**
 * Decode 'cell' (which must be RELAY or RELAY_EARLY) into a newly allocated
 * 'relay_msg_t'.
 *
 * Return NULL on error.
 */
relay_msg_t *
relay_msg_decode_cell(relay_cell_fmt_t format,
                      const cell_t *cell)
{
  // TODO #41051: Either remove the format argument here,
  // or the format field in cell_t.
  tor_assert(cell->relay_cell_proto == format);

  switch (format) {
    case RELAY_CELL_FORMAT_V0:
      return decode_v0_cell(cell);
    case RELAY_CELL_FORMAT_V1:
      return decode_v1_cell(cell);
    default:
      tor_fragile_assert();
      return NULL;
  }
}

/** Return the format to use.
 *
 * NULL can be passed but not for both. */
/* TODO #41051: Rename this. */
relay_cell_fmt_t
relay_msg_get_format(const circuit_t *circ, const crypt_path_t *cpath)
{
  if (circ && CIRCUIT_IS_ORCIRC(circ)) {
    return CONST_TO_OR_CIRCUIT(circ)->relay_cell_format;
  } else if (cpath) {
    return cpath->relay_cell_format;
  } else {
    /* We end up here when both params are NULL, which is not allowed, or when
     * only an origin circuit is given (which again is not allowed). */
    tor_assert_unreached();
  }
}
