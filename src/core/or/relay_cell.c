/* Copyright (c) 2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_cell.c
 * \brief This file handles most of the encoding and parsing of relay cells for
 *    all supported versions.
 **/

#include <stddef.h>
#include <stdint.h>
#define RELAY_CELL_PRIVATE

#include "core/or/relay_cell.h"
#include "core/or/relay.h"

#include "lib/arch/bytes.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/log/util_bug.h"

/*
 * NOTE: As a starter of this file, it is important to note that trunnel is not
 * used due to its heavy reliance on memory allocation. Parsing and encoding
 * cells is a critical piece of the fast path and MUST be done with little
 * as possible memory allocation or copy.
 *
 * And so, you will notice the direct access into a cell_t memory and relying
 * on offset instead of copying data into an object representing a header.
 */

/*
 * Relay cell header static values.
 *
 * We don't copy the header back into a structure for performance reason. When
 * accessing the header, we simply use offset within the cell_t payload.
 *
 * NOTE: We might want to move to a nicer static data structure containing all
 * these and indexed by version but for now with the very few relay cell
 * protocol and considering the future of C-tor this is simpler and enough.
 */

/* The "recognized" field by version. */
#define RECOGNIZED_OFFSET_V0 (1)
#define RECOGNIZED_OFFSET_V1 (0)

/* The "digest" field by version. */
#define DIGEST_OFFSET_V0 (5)
#define DIGEST_OFFSET_V1 (2)

/**
 * TODO #41051: Remove this entirely.
 *
 * I've moved this functionality into relay_msg.c, where it lives
 * more happily.  This function shouldn't have any callsites left
 * at the end of this branch.
 **/
void
relay_cell_pad_payload(cell_t *cell, size_t data_len)
{
  (void)cell;
  (void)data_len;
}

/** Return true iff the given cell recognized field is zero. */
bool
relay_cell_is_recognized(const cell_t *cell)
{
  switch (cell->relay_cell_proto) {
    case 0: return get_uint16(cell->payload + RECOGNIZED_OFFSET_V0) == 0;
    case 1: return get_uint16(cell->payload + RECOGNIZED_OFFSET_V1) == 0;
    default:
      /* Reaching this means we've failed to validate the supported relay cell
       * version. */
      tor_fragile_assert();
      return false;
  }
}

/** Return a pointer from inside the given cell pointing to the start of the
 * relay cell digest for the given protocol version.
 *
 * This is part of the fast path. No memory allocation. */
uint8_t *
relay_cell_get_digest(cell_t *cell)
{
  switch (cell->relay_cell_proto) {
    case 0: return cell->payload + DIGEST_OFFSET_V0;
    case 1: return cell->payload + DIGEST_OFFSET_V1;
    default:
      /* Reaching this means we've failed to validate the supported relay cell
       * version. Return the start of the payload, it will simply never
       * validate and ultimately will close the circuit. */
      tor_fragile_assert();
      return cell->payload;
  }
}

/** Return the relay cell digest length based on the given protocol version. */
size_t
relay_cell_get_digest_len(const cell_t *cell)
{
/* Specified in tor-spec.txt */
#define RELAY_CELL_DIGEST_LEN_V0 (4)
#define RELAY_CELL_DIGEST_LEN_V1 (14)

  switch (cell->relay_cell_proto) {
    case 0: return RELAY_CELL_DIGEST_LEN_V0;
    case 1: return RELAY_CELL_DIGEST_LEN_V1;
    default:
      /* Reaching this means we've failed to validate the supported relay cell
       * version. This length will simply never validate and ultimately the
       * circuit will be closed. */
      tor_fragile_assert();
      return 0;
  }
}

/** Set the given cell_digest value into the cell for the given relay cell
 * protocol version.
 *
 * This is part of the fast path. No memory allocation. */
void
relay_cell_set_digest(cell_t *cell, uint8_t *new_cell_digest)
{
  uint8_t *cell_digest_ptr = relay_cell_get_digest(cell);
  size_t cell_digest_len = relay_cell_get_digest_len(cell);

  memcpy(cell_digest_ptr, new_cell_digest, cell_digest_len);
}
